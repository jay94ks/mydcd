// SPDX-License-Identifier: Apache-2.0

package sfev

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jay94ks/seafield/internal/peercred"
	"golang.org/x/net/http2"
	"golang.org/x/sys/unix"
)

// Config is one container's endpoint.
type Config struct {
	// Name names the container in logs.
	Name string
	// Dir is the host directory that is bind-mounted read-only at
	// ContainerDir. It must exist; the endpoint creates only the socket.
	Dir string
	// Anchor is the container's init process, held by pidfd since start.
	// A peer must share its cgroup and PID namespace. The endpoint keeps its
	// own duplicate of the pidfd.
	Anchor peercred.Process
	// UID and GID are the service's user. A peer must run as exactly these.
	// A peer with UID 0 passes only when UID is 0 too.
	UID, GID uint32
	// Fetch reads the approved values; see Fetch.
	Fetch Fetch
	// Logf receives value-free notes (refused peers, revocations).
	// Nil uses the standard logger.
	Logf func(format string, args ...any)
}

// Endpoint is one container's sfev.sock.
type Endpoint struct {
	cfg       Config
	anchor    peercred.Process
	path      string
	listener  *net.UnixListener
	verifying chan struct{}

	mu     sync.Mutex
	slot   *session
	closed bool
	done   chan struct{}
	wg     sync.WaitGroup
}

// Open creates the socket in cfg.Dir (0600, owned by cfg.UID/GID) and starts
// accepting. The caller publishes events with Publish and ends it with Close.
func Open(cfg Config) (*Endpoint, error) {
	if cfg.Fetch == nil || cfg.Anchor.PID <= 0 || cfg.Anchor.FD < 0 || !filepath.IsAbs(cfg.Dir) {
		return nil, errors.New("sfev: incomplete endpoint config")
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	info, err := os.Lstat(cfg.Dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("sfev: %s is not a directory", cfg.Dir)
	}
	anchorFD, err := unix.FcntlInt(uintptr(cfg.Anchor.FD), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	anchor := peercred.Process{PID: cfg.Anchor.PID, UID: cfg.Anchor.UID, GID: cfg.Anchor.GID, FD: anchorFD}
	path := filepath.Join(cfg.Dir, SocketName)
	if err = os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = anchor.Close()
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		_ = anchor.Close()
		return nil, err
	}
	listener.SetUnlinkOnClose(true)
	if err = errors.Join(os.Chmod(path, 0o600), os.Lchown(path, int(cfg.UID), int(cfg.GID))); err != nil {
		_ = listener.Close()
		_ = anchor.Close()
		return nil, err
	}
	e := &Endpoint{cfg: cfg, anchor: anchor, path: path, listener: listener, verifying: make(chan struct{}, MaxVerifying), done: make(chan struct{})}
	e.wg.Add(1)
	go e.accept()
	return e, nil
}

// Path is the socket's host path.
func (e *Endpoint) Path() string { return e.path }

// Publish tells the open connection, if any, about ev. Changed reaches only
// an open watch; Revoked ends any connection.
func (e *Endpoint) Publish(ev Event) {
	e.mu.Lock()
	s := e.slot
	e.mu.Unlock()
	if s != nil {
		s.notify(ev)
	}
}

// Close sends closing to an open watch, ends every connection and removes
// the socket.
func (e *Endpoint) Close() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	close(e.done)
	s := e.slot
	e.mu.Unlock()
	err := e.listener.Close()
	if s != nil {
		s.notify(Event{Kind: closingEvent})
	}
	e.wg.Wait()
	return errors.Join(err, e.anchor.Close())
}

// closingEvent is internal: Close's last word to a watch.
const closingEvent EventKind = 100

func (e *Endpoint) accept() {
	defer e.wg.Done()
	for {
		conn, err := e.listener.AcceptUnix()
		if err != nil {
			select {
			case <-e.done:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			e.cfg.Logf("sfev %s: accept: %v", e.cfg.Name, err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		select {
		case e.verifying <- struct{}{}:
		default:
			// Too many unidentified connections: drop without a word.
			_ = conn.Close()
			continue
		}
		e.wg.Add(1)
		go e.admit(conn)
	}
}

// admit identifies conn and gives it the slot, or refuses it.
func (e *Endpoint) admit(conn *net.UnixConn) {
	defer e.wg.Done()
	_ = conn.SetDeadline(time.Now().Add(VerifyTimeout))
	peer, err := e.identify(conn)
	<-e.verifying
	if err != nil {
		e.cfg.Logf("sfev %s: refused a connection: %v", e.cfg.Name, err)
		_ = conn.Close()
		return
	}
	e.mu.Lock()
	if e.closed || e.slot != nil {
		closed := e.closed
		e.mu.Unlock()
		_ = peer.Close()
		if !closed {
			// Another connection holds the slot; it is kept. The refused
			// one is answered 409 on every stream until VerifyTimeout.
			refuse(conn)
		}
		_ = conn.Close()
		return
	}
	s := newSession(e, conn, peer)
	e.slot = s
	e.mu.Unlock()
	_ = conn.SetDeadline(time.Time{})
	s.run()
	e.mu.Lock()
	if e.slot == s {
		e.slot = nil
	}
	e.mu.Unlock()
}

// identify proves the peer is a live process of this container running as
// the service's user.
func (e *Endpoint) identify(conn *net.UnixConn) (peercred.Process, error) {
	peer, err := peercred.Peer(conn)
	if err != nil {
		return peer, err
	}
	if err = e.sameContainer(peer); err != nil {
		_ = peer.Close()
		return peercred.Process{FD: -1}, err
	}
	if peer.UID != e.cfg.UID || peer.GID != e.cfg.GID {
		_ = peer.Close()
		return peercred.Process{FD: -1}, fmt.Errorf("%w: user %d:%d is not the service user", peercred.ErrIdentity, peer.UID, peer.GID)
	}
	return peer, nil
}

func (e *Endpoint) sameContainer(peer peercred.Process) error {
	return peercred.SameContainer(peer, e.anchor)
}

// h2 limits for one connection.
const (
	maxStreams = 8
	// writeTimeout bounds one write to the client; a client that stops
	// reading loses its connection, never sfcd's goroutine.
	writeTimeout = 10 * time.Second
)

func h2Server() *http2.Server {
	return &http2.Server{MaxConcurrentStreams: maxStreams, WriteByteTimeout: writeTimeout, MaxReadFrameSize: 16 << 10}
}

func h2Base(h http.Handler) *http.Server {
	return &http.Server{Handler: h, MaxHeaderBytes: MaxRequestHeader, ErrorLog: log.New(io.Discard, "", 0)}
}

// refuse answers a connection that found the slot held: h2c prior
// knowledge, 409 on every stream, closed after VerifyTimeout.
func refuse(conn *net.UnixConn) {
	_ = conn.SetDeadline(time.Now().Add(VerifyTimeout))
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusConflict, "another connection holds this container's socket")
	})
	h2Server().ServeConn(conn, &http2.ServeConnOpts{Handler: h, BaseConfig: h2Base(h)})
}

// session is the connection holding the slot. It speaks h2c only; every
// request is one HTTP/2 stream on it.
type session struct {
	e    *Endpoint
	conn *net.UnixConn
	peer peercred.Process

	mu      sync.Mutex
	changed bool
	revoked *string
	closing bool
	// watching: a /v1/watch stream is open (at most one).
	watching bool
	signal   chan struct{}
	ended    chan struct{}
	endOnce  sync.Once
	// sent is what the watch last carried, as key → value digest and the
	// revision, so a later change sends only what differs. No value is kept.
	sentRevision string
	sent         map[string][32]byte
}

func newSession(e *Endpoint, conn *net.UnixConn, peer peercred.Process) *session {
	return &session{e: e, conn: conn, peer: peer, signal: make(chan struct{}, 1), ended: make(chan struct{})}
}

func (s *session) notify(ev Event) {
	s.mu.Lock()
	switch ev.Kind {
	case Changed:
		s.changed = true
	case Revoked:
		reason := ev.Reason
		s.revoked = &reason
	case closingEvent:
		s.closing = true
	}
	watching := s.watching
	s.mu.Unlock()
	if !watching && ev.Kind != Changed {
		// No watch to speak on: end the connection now.
		s.end()
		return
	}
	select {
	case s.signal <- struct{}{}:
	default:
	}
}

func (s *session) end() {
	s.endOnce.Do(func() {
		close(s.ended)
		_ = s.conn.Close()
	})
}

func (s *session) run() {
	defer s.peer.Close()
	defer s.end()
	stop := s.watchPeerExit()
	defer stop()
	s.mu.Lock()
	early := s.revoked != nil || s.closing
	s.mu.Unlock()
	if early {
		return
	}
	// The h2c preface must arrive within VerifyTimeout; then no idle limit.
	_ = s.conn.SetReadDeadline(time.Now().Add(VerifyTimeout))
	h := http.HandlerFunc(s.serve)
	h2Server().ServeConn(s.conn, &http2.ServeConnOpts{Handler: h, BaseConfig: h2Base(h)})
}

// watchPeerExit ends the session when the peer process exits.
func (s *session) watchPeerExit() func() {
	var pipe [2]int
	if err := unix.Pipe2(pipe[:], unix.O_CLOEXEC); err != nil {
		return func() {}
	}
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		defer unix.Close(pipe[0])
		fds := []unix.PollFd{{Fd: int32(s.peer.FD), Events: unix.POLLIN}, {Fd: int32(pipe[0]), Events: unix.POLLIN}}
		for {
			_, err := unix.Poll(fds, -1)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if err == nil && fds[0].Revents != 0 {
				s.end()
			}
			return
		}
	}()
	var once sync.Once
	// Wait for the poll to end so the peer's pidfd is never polled after
	// it is closed.
	return func() { once.Do(func() { _ = unix.Close(pipe[1]); <-exited }) }
}

// serve answers one stream.
func (s *session) serve(w http.ResponseWriter, r *http.Request) {
	// The first request proves the preface arrived; from now on the
	// connection may wait for events without a read deadline.
	_ = s.conn.SetReadDeadline(time.Time{})
	if r.ProtoMajor != 2 {
		writeError(w, http.StatusHTTPVersionNotSupported, "h2c only")
		return
	}
	if r.ContentLength > 0 || r.ContentLength < 0 && r.Body != nil && r.Body != http.NoBody && !emptyBody(r) {
		writeError(w, http.StatusRequestEntityTooLarge, "requests carry no body")
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "only GET")
		return
	}
	switch {
	case r.URL.Path == "/v1/watch":
		s.watch(w, r)
	case r.URL.Path == "/v1/secrets":
		if snap, ok := s.fetch(w, r.Context()); ok {
			writeJSON(w, http.StatusOK, valuesBody{Revision: snap.Revision, Values: snap.Values})
		}
	case strings.HasPrefix(r.URL.Path, "/v1/secrets/"):
		key := strings.TrimPrefix(r.URL.Path, "/v1/secrets/")
		snap, ok := s.fetch(w, r.Context())
		if !ok {
			return
		}
		value, found := snap.Values[key]
		if key == "" || strings.Contains(key, "/") || !found {
			writeError(w, http.StatusNotFound, "no such key")
			return
		}
		writeJSON(w, http.StatusOK, keyBody{Revision: snap.Revision, Key: key, Value: value})
	default:
		writeError(w, http.StatusNotFound, "unknown path")
	}
}

// emptyBody reports whether a body of unknown length is in fact empty
// (END_STREAM came with the headers).
func emptyBody(r *http.Request) bool {
	var b [1]byte
	n, err := r.Body.Read(b[:])
	return n == 0 && errors.Is(err, io.EOF)
}

type valuesBody struct {
	Revision string            `json:"revision"`
	Values   map[string]string `json:"values"`
}

type keyBody struct {
	Revision string `json:"revision"`
	Key      string `json:"key"`
	Value    string `json:"value"`
}

type eventBody struct {
	Type     string            `json:"type"`
	Revision string            `json:"revision,omitempty"`
	Values   map[string]string `json:"values,omitempty"`
	Removed  []string          `json:"removed,omitempty"`
	Reason   string            `json:"reason,omitempty"`
}

// fetch reads values for a single request and answers its error itself.
func (s *session) fetch(w http.ResponseWriter, ctx context.Context) (Snapshot, bool) {
	snap, err := s.read(ctx)
	if err != nil {
		writeError(w, statusOf(err), err.Error())
		return Snapshot{}, false
	}
	return snap, true
}

// read checks the peer again, then fetches and bounds the values.
func (s *session) read(parent context.Context) (Snapshot, error) {
	if err := s.e.sameContainer(s.peer); err != nil {
		return Snapshot{}, fmt.Errorf("%w: peer left the container", ErrDenied)
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	go func() {
		select {
		case <-s.ended:
			cancel()
		case <-ctx.Done():
		}
	}()
	snap, err := s.e.cfg.Fetch(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	if size(snap) > MaxValues {
		return Snapshot{}, ErrTooLarge
	}
	// The process may have left while the values were read.
	if err = s.e.sameContainer(s.peer); err != nil {
		return Snapshot{}, fmt.Errorf("%w: peer left the container", ErrDenied)
	}
	return snap, nil
}

func size(snap Snapshot) int {
	n := len(snap.Revision)
	for k, v := range snap.Values {
		n += len(k) + len(v)
	}
	return n
}

func statusOf(err error) int {
	switch {
	case errors.Is(err, ErrDenied):
		return http.StatusForbidden
	case errors.Is(err, ErrTooLarge):
		return http.StatusRequestEntityTooLarge
	default:
		return http.StatusServiceUnavailable
	}
}

// watch streams events on this stream until it, or the connection, ends.
func (s *session) watch(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if s.watching {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "a watch is already open on this connection")
		return
	}
	s.watching = true
	// Clear before reading: a Changed published while the snapshot is read
	// stays set and is read again by the first loop pass below.
	s.changed = false
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.watching = false
		s.mu.Unlock()
	}()
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "stream not supported")
		return
	}
	snap, err := s.read(r.Context())
	if err != nil {
		writeError(w, statusOf(err), err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	stream := &eventWriter{w: w, f: flusher}
	if !stream.event(eventBody{Type: "snapshot", Revision: snap.Revision, Values: snap.Values}) {
		return
	}
	s.mu.Lock()
	s.sentRevision, s.sent = snap.Revision, digests(snap)
	s.mu.Unlock()
	for {
		select {
		case <-s.ended:
			return
		case <-r.Context().Done():
			return
		case <-s.signal:
		}
		s.mu.Lock()
		revoked, closing, changed := s.revoked, s.closing, s.changed
		s.changed = false
		s.mu.Unlock()
		switch {
		case revoked != nil:
			s.e.cfg.Logf("sfev %s: approval revoked: %s", s.e.cfg.Name, *revoked)
			stream.event(eventBody{Type: "revoked", Reason: *revoked})
			s.endSoon()
			return
		case closing:
			stream.event(eventBody{Type: "closing"})
			s.endSoon()
			return
		case changed:
			if !s.sendChanged(r.Context(), stream) {
				return
			}
		}
	}
}

// endSoon ends the connection once the handler returned, so its last event
// and the stream end reach the client first.
func (s *session) endSoon() {
	go func() {
		time.Sleep(50 * time.Millisecond)
		s.end()
	}()
}

func (s *session) sendChanged(ctx context.Context, stream *eventWriter) bool {
	snap, err := s.read(ctx)
	switch {
	case errors.Is(err, ErrDenied) || errors.Is(err, ErrTooLarge):
		reason := strconv.Itoa(statusOf(err))
		s.e.cfg.Logf("sfev %s: stream ended (%s): %v", s.e.cfg.Name, reason, err)
		stream.event(eventBody{Type: "revoked", Reason: reason})
		s.endSoon()
		return false
	case err != nil:
		// Not readable yet (quorum or holder unreachable): the next event
		// tries again; the app keeps what it has.
		s.e.cfg.Logf("sfev %s: values not readable yet: %v", s.e.cfg.Name, err)
		return true
	}
	s.mu.Lock()
	sentRevision, sent := s.sentRevision, s.sent
	s.mu.Unlock()
	if snap.Revision == sentRevision {
		return true
	}
	now := digests(snap)
	changed := map[string]string{}
	for k, v := range snap.Values {
		if old, ok := sent[k]; !ok || old != now[k] {
			changed[k] = v
		}
	}
	var removed []string
	for k := range sent {
		if _, ok := now[k]; !ok {
			removed = append(removed, k)
		}
	}
	sort.Strings(removed)
	if !stream.event(eventBody{Type: "changed", Revision: snap.Revision, Values: changed, Removed: removed}) {
		return false
	}
	s.mu.Lock()
	s.sentRevision, s.sent = snap.Revision, now
	s.mu.Unlock()
	return true
}

// digests keys a snapshot by value digest; equal digests mean equal values.
func digests(snap Snapshot) map[string][32]byte {
	out := make(map[string][32]byte, len(snap.Values))
	for k, v := range snap.Values {
		out[k] = sha256.Sum256([]byte(v))
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	data, err := json.Marshal(body)
	if err != nil {
		status, data = http.StatusInternalServerError, []byte(`{"error":"encode"}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(append(data, '\n'))
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, struct {
		Error string `json:"error"`
	}{message})
}

// eventWriter writes one NDJSON event per flush on an HTTP/2 stream.
type eventWriter struct {
	w http.ResponseWriter
	f http.Flusher
}

func (e *eventWriter) event(body eventBody) bool {
	data, err := json.Marshal(body)
	if err != nil {
		return false
	}
	if _, err = e.w.Write(append(data, '\n')); err != nil {
		return false
	}
	e.f.Flush()
	return true
}
