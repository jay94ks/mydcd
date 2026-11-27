// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/jay94ks/seafield/pkg/sfcp/enginemux"
	"github.com/jay94ks/seafield/pkg/sfcp/wire"
)

// Engine purposes run only on the local engine socket (/run/sfe/sfcd.sock)
// between sfcd and the Seafield engine (sfed), never over QUIC or the
// management socket. Bodies follow Management: field 1 is strict JSON
// {Schema, Op, OpID, BootID, ...}; a reply is {Schema, OpID, Result:
// "applied"|"not-applied"|"unknown", Reason, ...}. Kind 4 is a data chunk
// (WriteChunk) bound to sha256 of the request's field 1; purpose 32 pushes
// event batches as kind 16 after its answer. Descriptors travel with a frame (enginemux.MaxFDs) and are
// named in JSON by their order.
const (
	EngineEvents  Purpose = 32 // sfed serves: event subscription, pushed batches
	EngineLog     Purpose = 33 // sfed serves: log read, chunks
	EngineLogAck  Purpose = 34 // sfed serves: log acknowledgement
	EngineVolume  Purpose = 35 // sfcd serves: volume create/get/list/mount/unmount/remove
	EngineNetwork Purpose = 36 // sfcd serves: network create/created/join/leave/delete
	EngineImage   Purpose = 37 // sfcd serves: manifest and blob by repository@digest, from an offset
	EngineExec    Purpose = 38 // sfed serves: kill an exec's whole process tree
)

// DefaultEngineSocket is where sfcd listens for its engine.
const DefaultEngineSocket = "/run/sfe/sfcd.sock"

type engineSpec struct {
	name  string
	kinds map[uint8]kindSpec
	// sfcd serves the purpose (sfed calls it); otherwise sfed serves it.
	sfcd bool
	// longLived handlers own their stream beyond the call deadline.
	longLived bool
}

// Budgets count field headers (8 bytes each); they match the engine's copy.
func engineUnary() map[uint8]kindSpec {
	return map[uint8]kindSpec{1: {fields: []int{-1}, budget: 8 + 64<<10}, 2: {fields: []int{-1}, budget: 8 + 128<<10}}
}
func engineBulk() map[uint8]kindSpec {
	k := engineUnary()
	k[4] = kindSpec{fields: []int{8, -1, 32}, budget: chunkBudget}
	return k
}

// engineEvents: 1 subscribe, 2 its answer, 16 each pushed event batch.
func engineEvents() map[uint8]kindSpec {
	k := engineUnary()
	k[16] = kindSpec{fields: []int{-1}, budget: 8 + 128<<10}
	return k
}

var enginePurposes = map[Purpose]engineSpec{
	EngineEvents:  {name: "engine-events", kinds: engineEvents(), longLived: true},
	EngineLog:     {name: "engine-log", kinds: engineBulk(), longLived: true},
	EngineLogAck:  {name: "engine-log-ack", kinds: engineUnary()},
	EngineVolume:  {name: "engine-volume", kinds: engineUnary(), sfcd: true},
	EngineNetwork: {name: "engine-network", kinds: engineUnary(), sfcd: true},
	EngineImage:   {name: "engine-image", kinds: engineBulk(), sfcd: true, longLived: true},
	EngineExec:    {name: "engine-exec", kinds: engineUnary()},
}

func engineRule(p Purpose, kind uint8) ([]int, int) {
	s, ok := enginePurposes[p]
	if !ok {
		return nil, 0
	}
	k, ok := s.kinds[kind]
	if !ok {
		return nil, 0
	}
	return k.fields, k.budget
}

// engineCodec checks frames on the engine socket; it knows only engine
// purposes, as codec knows none of them.
var engineCodec = wire.Rules(func(p Purpose, kind uint8) (wire.Rule, bool) {
	fields, budget := engineRule(p, kind)
	return wire.Rule{Fields: fields, Budget: budget}, budget > 0
})

// EngineRequest is the common head of every engine request body.
type EngineRequest struct {
	Schema uint8
	Op     string
	OpID   string
	BootID string
}

// Engine results.
const (
	EngineApplied    = "applied"
	EngineNotApplied = "not-applied"
	EngineUnknown    = "unknown"
)

// EngineReply is the common head of every engine reply body.
type EngineReply struct {
	Schema uint8
	OpID   string
	Result string
	Reason string `json:",omitempty"`
}

// EngineResult maps a failed Call to the result the caller reports: nothing
// sent is not-applied, anything after the first byte is unknown.
func EngineResult(err error) string {
	switch {
	case err == nil:
		return EngineApplied
	case CallSent(err):
		return EngineUnknown
	}
	return EngineNotApplied
}

// EngineStream is one stream on the engine socket.
type EngineStream struct{ st *enginemux.Stream }

func (s EngineStream) Read(p []byte) (int, error)            { return s.st.Read(p) }
func (s EngineStream) Write(p []byte) (int, error)           { return s.st.Write(p) }
func (s EngineStream) Close() error                          { return s.st.Close() }
func (s EngineStream) SetDeadline(t time.Time) error         { return s.st.SetDeadline(t) }
func (s EngineStream) SetReadDeadline(t time.Time) error     { return s.st.SetReadDeadline(t) }
func (s EngineStream) SetWriteDeadline(t time.Time) error    { return s.st.SetWriteDeadline(t) }
func (s EngineStream) CancelRead(code quic.StreamErrorCode)  { s.st.CancelRead(uint64(code)) }
func (s EngineStream) CancelWrite(code quic.StreamErrorCode) { s.st.CancelWrite(uint64(code)) }
func (s EngineStream) ID() uint64                            { return s.st.ID() }
func (s EngineStream) Attach(fds ...int) error               { return s.st.Attach(fds...) }
func (s EngineStream) TakeFDs() []int                        { return s.st.TakeFDs() }
func (s EngineStream) WriteFrame(f Frame) error {
	f.Request = s.ID()
	return engineCodec.WriteFrame(s.st, f)
}
func (s EngineStream) ReadFrame(limit int) (Frame, error) { return engineCodec.ReadFrame(s.st, limit) }

// EngineSession is the one live connection from the engine.
type EngineSession struct {
	t   *Transport
	mux *enginemux.Session
}

// Done is closed when the engine connection ends.
func (e *EngineSession) Done() <-chan struct{} { return e.mux.Done() }
func (e *EngineSession) Close() error          { return e.mux.Close() }

// Open starts a stream for a call to a purpose sfed serves.
func (e *EngineSession) Open(ctx context.Context) (EngineStream, error) {
	if err := ctx.Err(); err != nil {
		return EngineStream{}, err
	}
	st, err := e.mux.Open()
	return EngineStream{st}, err
}

// Call is Session.Call on the engine socket: the stream assigns the request
// ID, and only purposes sfed serves may be called.
func (e *EngineSession) Call(ctx context.Context, request Frame, o CallOptions) (Frame, error) {
	admit := func(f Frame) error {
		s, ok := enginePurposes[f.Purpose]
		if !ok || s.sfcd || f.Purpose != request.Purpose {
			return ErrAdmission
		}
		return nil
	}
	return call(ctx, request, o, caller{codec: engineCodec, rule: engineRule, admit: admit, assigns: true,
		open: func(ctx context.Context) (Stream, uint64, error) {
			st, err := e.Open(ctx)
			if err != nil {
				return nil, 0, err
			}
			return st, st.ID(), nil
		}})
}

// EngineHandler serves one op of a purpose sfcd serves. first is the request
// frame; req is its decoded common head. The handler writes the reply on st
// (EngineStream.WriteFrame) and owns any descriptors (st.TakeFDs).
type EngineHandler func(ctx context.Context, e *EngineSession, st EngineStream, first Frame, req EngineRequest) error

type engineOp struct {
	p  Purpose
	op string
}

type engineState struct {
	mu       sync.Mutex
	handlers map[engineOp]EngineHandler
	current  *EngineSession
	found    func(*EngineSession)
	ln       *net.UnixListener
	socket   *ownedSocket
	// check admits the dialing process; tests replace it.
	check func(*net.UnixConn) error
	// allowed are extra executables admitted besides the installed sfed.
	allowed []string
}

// AllowEnginePeer admits one more executable on the engine socket besides
// the installed sfed: a test binary or a fake engine. The peer must still
// run as root and is still pinned by pidfd. exe is an absolute clean path;
// call it before ListenEngine. sfcd itself never calls it.
func (t *Transport) AllowEnginePeer(exe string) error {
	if exe == "" || !filepath.IsAbs(exe) || filepath.Clean(exe) != exe {
		return ErrAdmission
	}
	t.engine.mu.Lock()
	defer t.engine.mu.Unlock()
	if t.engine.ln != nil {
		return ErrAdmission
	}
	t.engine.allowed = append(t.engine.allowed, exe)
	return nil
}

// HandleEngine registers h for one op of a purpose sfcd serves.
func (t *Transport) HandleEngine(p Purpose, op string, h EngineHandler) error {
	s, ok := enginePurposes[p]
	if !ok || !s.sfcd || op == "" || h == nil {
		return ErrAdmission
	}
	t.engine.mu.Lock()
	defer t.engine.mu.Unlock()
	if t.engine.handlers == nil {
		t.engine.handlers = map[engineOp]EngineHandler{}
	}
	if _, dup := t.engine.handlers[engineOp{p, op}]; dup {
		return fmt.Errorf("engine op %s/%s already registered", s.name, op)
	}
	t.engine.handlers[engineOp{p, op}] = h
	return nil
}

// Engine returns the live engine connection, if any.
func (t *Transport) Engine() (*EngineSession, bool) {
	t.engine.mu.Lock()
	defer t.engine.mu.Unlock()
	return t.engine.current, t.engine.current != nil
}

// OnEngine registers f to run, on its own goroutine, each time the engine
// connects (for example to open the event subscription).
func (t *Transport) OnEngine(f func(*EngineSession)) {
	t.engine.mu.Lock()
	t.engine.found = f
	t.engine.mu.Unlock()
}

// ListenEngine opens the engine socket (root-owned 0600, parent not writable
// by group/other). Only a root process whose executable is an installed sfed
// (or one AllowEnginePeer named) is admitted; no TLS or login. One engine connection is live at a time: a
// new one replaces the old.
func (t *Transport) ListenEngine(path string) error {
	if path == "" {
		path = DefaultEngineSocket
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("engine socket path must be absolute and clean")
	}
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return err
	}
	stat, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || !parent.IsDir() || parent.Mode().Perm()&0022 != 0 || stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) {
		return errors.New("engine socket parent must be owned and not writable by group/other")
	}
	t.engine.mu.Lock()
	defer t.engine.mu.Unlock()
	if t.engine.ln != nil {
		return errors.New("engine socket already open")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		if removeErr := removeStaleSocket(path, -1); removeErr != nil {
			return fmt.Errorf("engine socket path must be absent: %w", errors.Join(err, os.ErrExist, removeErr))
		}
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return err
	}
	ln.SetUnlinkOnClose(false)
	owned, err := pinSocket(path)
	if err != nil {
		_ = ln.Close()
		return err
	}
	if err = os.Chmod(path, 0600); err != nil {
		_ = ln.Close()
		return errors.Join(err, owned.remove())
	}
	t.engine.ln, t.engine.socket = ln, owned
	if t.engine.check == nil {
		allowed := slices.Clone(t.engine.allowed)
		t.engine.check = func(c *net.UnixConn) error {
			return enginemux.CheckPeerExe(c, func(exe string) bool {
				return enginemux.Installed(exe, "sfed") || slices.Contains(allowed, exe)
			})
		}
	}
	t.wg.Add(1)
	go t.acceptEngine(ln)
	return nil
}

func (t *Transport) closeEngine() error {
	t.engine.mu.Lock()
	ln, socket, current := t.engine.ln, t.engine.socket, t.engine.current
	t.engine.ln, t.engine.socket, t.engine.current = nil, nil, nil
	t.engine.mu.Unlock()
	var err error
	if ln != nil {
		err = ln.Close()
	}
	if current != nil {
		_ = current.Close()
	}
	if socket != nil {
		err = errors.Join(err, socket.remove())
	}
	return err
}

func (t *Transport) acceptEngine(ln *net.UnixListener) {
	defer t.wg.Done()
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			t.serverFailure("engine", "accept", Identity{}, Frame{}, err)
			return
		}
		t.engine.mu.Lock()
		check := t.engine.check
		t.engine.mu.Unlock()
		if err := check(c); err != nil {
			t.serverFailure("engine", "peer", Identity{}, Frame{}, err)
			_ = c.Close()
			continue
		}
		e := &EngineSession{t: t, mux: enginemux.Server(c)}
		t.engine.mu.Lock()
		old, found := t.engine.current, t.engine.found
		t.engine.current = e
		t.engine.mu.Unlock()
		if old != nil {
			_ = old.Close()
		}
		t.wg.Add(1)
		go func() { defer t.wg.Done(); t.serveEngine(e) }()
		if found != nil {
			t.wg.Add(1)
			go func() { defer t.wg.Done(); found(e) }()
		}
	}
}

func (t *Transport) serveEngine(e *EngineSession) {
	defer func() {
		t.engine.mu.Lock()
		if t.engine.current == e {
			t.engine.current = nil
		}
		t.engine.mu.Unlock()
	}()
	stop := context.AfterFunc(t.ctx, func() { _ = e.Close() })
	defer stop()
	for {
		raw, err := e.mux.Accept()
		if err != nil {
			return
		}
		t.wg.Add(1)
		go func() {
			defer t.wg.Done()
			t.serveEngineStream(e, EngineStream{raw})
		}()
	}
}

// serveEngineStream resets the stream only when it fails. A served stream
// ends with FIN alone: a reset right after the answer would make the engine
// drop fds that arrived with it but were not taken yet.
func (t *Transport) serveEngineStream(e *EngineSession, st EngineStream) {
	served := false
	defer func() {
		if !served {
			st.CancelRead(0)
		}
	}()
	_ = st.SetReadDeadline(time.Now().Add(30 * time.Second))
	first, err := st.ReadFrame(MaxBody)
	if err != nil {
		t.serverFailure("engine", "receive", Identity{}, Frame{}, err)
		return
	}
	spec, ok := enginePurposes[first.Purpose]
	var req EngineRequest
	if !ok || !spec.sfcd || first.Kind != 1 || json.Unmarshal(first.Fields[0].Value, &req) != nil || req.Schema != 1 || req.Op == "" {
		t.serverFailure("engine", "admit", Identity{}, first, ErrAdmission)
		return
	}
	t.engine.mu.Lock()
	h := t.engine.handlers[engineOp{first.Purpose, req.Op}]
	t.engine.mu.Unlock()
	if h == nil {
		reply, _ := json.Marshal(EngineReply{Schema: 1, OpID: req.OpID, Result: EngineNotApplied, Reason: "unknown-op"})
		if st.WriteFrame(Frame{Purpose: first.Purpose, Kind: 2, Fields: []Field{{Tag: 1, Required: true, Value: reply}}}) == nil {
			served = st.Close() == nil
		}
		return
	}
	ctx, cancel := context.WithTimeout(t.ctx, localManagementTimeout)
	if spec.longLived {
		ctx, cancel = context.WithCancel(t.ctx)
	}
	defer cancel()
	_ = st.SetReadDeadline(time.Time{})
	if err := h(ctx, e, st, first, req); err != nil {
		t.serverFailure("engine", "handler", Identity{}, first, err)
		return
	}
	served = st.Close() == nil
}
