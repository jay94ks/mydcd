// SPDX-License-Identifier: Apache-2.0

package mydcp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/jay94ks/mydcd/internal/identity"
)

const DefaultManagementSocket = "/var/run/mydc.sock"

const localManagementTimeout = 30 * time.Second

type ownedSocket struct {
	path string
	info os.FileInfo
	pin  *os.File // retains the filesystem inode until the final identity check
}

func (s *ownedSocket) remove() error {
	if s.pin == nil {
		return errors.New("management socket inode pin missing; path preserved")
	}
	defer s.pin.Close()
	pinned, err := s.pin.Stat()
	if err != nil || !os.SameFile(pinned, s.info) {
		return errors.Join(err, errors.New("management socket inode pin lost; path preserved"))
	}
	current, err := os.Lstat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if current.Mode()&os.ModeSocket == 0 || !os.SameFile(current, s.info) {
		return errors.New("management socket path replaced; foreign entry preserved")
	}
	return os.Remove(s.path)
}

func ValidateManagementSocket(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || len(path) > 107 || strings.ContainsAny(path, "\x00\r\n\t\\?#%") {
		return errors.New("management_socket must be a clean absolute Unix socket path")
	}
	return nil
}

func managementEndpoint(endpoint string) (string, error) {
	if !strings.HasPrefix(endpoint, "unix:") {
		return "", nil
	}
	if !strings.HasPrefix(endpoint, "unix:///") {
		return "", ErrAdmission
	}
	path := strings.TrimPrefix(endpoint, "unix://")
	if strings.ContainsAny(path, "?#%") || ValidateManagementSocket(path) != nil {
		return "", ErrAdmission
	}
	return path, nil
}

// localConnection retains the real TLS/challenge binding across login's
// challenge/proof exchanges. Management exchanges are sequential on Unix;
// they are never inserted into QUIC's packet/replication session cache.
type localConnection struct {
	ctx       context.Context
	cancel    context.CancelFunc
	conn      *tls.Conn
	uid       uint32
	transport *Transport
	active    chan struct{}
	// Guarded by transport.mu. Measured from handshake/exchange start, before
	// the peer can begin its next idle wait; intentionally conservative.
	reuseUntil time.Time
	done       chan struct{}
	closed     atomic.Bool
	once       sync.Once
	err        error
}

func (s *localConnection) finish() error {
	s.once.Do(func() {
		s.closed.Store(true)
		s.cancel()
		s.err = s.conn.NetConn().Close()
		close(s.done)
		s.transport.mu.Lock()
		delete(s.transport.localConnections, s)
		for key, session := range s.transport.localSessions {
			if session.local == s {
				delete(s.transport.localSessions, key)
			}
		}
		s.transport.mu.Unlock()
	})
	return s.err
}

func peerUID(c *net.UnixConn) (uint32, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var controlErr error
	err = raw.Control(func(fd uintptr) {
		cred, e := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		controlErr = e
		if e == nil {
			uid = cred.Uid
		}
	})
	return uid, errors.Join(err, controlErr)
}

func (t *Transport) trackLocal(c *net.UnixConn, server bool, expected Identity) (*localConnection, error) {
	uid, err := peerUID(c)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	config := t.self.TLS(server, func(key [32]byte) bool {
		_, ok := t.lookupFor(Identity(key), Handshake)
		return ok && (server || Identity(key) == expected)
	})
	if server {
		config = t.serverTLS()
	}
	var secure *tls.Conn
	if server {
		secure = tls.Server(c, config)
	} else {
		secure = tls.Client(c, config)
	}
	ctx, cancel := context.WithCancel(t.ctx)
	stream := &localConnection{ctx: ctx, cancel: cancel, conn: secure, uid: uid, transport: t, active: make(chan struct{}, 1), done: make(chan struct{}), reuseUntil: time.Now().Add(localManagementTimeout)}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.localClosed || len(t.localConnections) >= 64 {
		cancel()
		_ = c.Close()
		return nil, ErrBudget
	}
	t.localConnections[stream] = struct{}{}
	return stream, nil
}

func (t *Transport) authenticateLocal(ctx context.Context, stream *localConnection, client bool) (*Session, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	if err := stream.conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = stream.finish() })
	defer stop()
	if err := stream.conn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if !client && stream.conn.ConnectionState().NegotiatedProtocol == discoveryALPN {
		if err := t.serveDiscovery(stream.conn, stream.conn.ConnectionState()); err != nil {
			t.serverFailure("unix", "discovery", Identity{}, Frame{}, err)
		}
		return nil, ErrAdmission // Public ALPN never enters a management session.
	}
	if stream.conn.ConnectionState().NegotiatedProtocol != "mydcp-go-1" {
		return nil, ErrAdmission
	}
	key, err := identity.PeerKey(stream.conn.ConnectionState())
	if err != nil {
		return nil, err
	}
	peer, ok := t.lookupFor(Identity(key), Handshake)
	if !ok || peer.Key != Identity(key) {
		return nil, ErrAdmission
	}
	gate, challenge, err := t.authenticateStream(stream.conn, Identity(key), peer, client)
	if err != nil {
		return nil, err
	}
	return &Session{transport: t, peer: peer, gate: gate, peerChallenge: challenge, local: stream}, nil
}

func (t *Transport) dialUnix(ctx context.Context, peer Peer, path string) (*Session, error) {
	for {
		t.mu.Lock()
		if t.closed || t.localClosed {
			t.mu.Unlock()
			return nil, net.ErrClosed
		}
		if cached := t.localSessions[peer.Key]; cached != nil && !cached.local.closed.Load() {
			if !time.Now().Before(cached.local.reuseUntil) && len(cached.local.active) == 0 {
				// Fence acquisition under the same lock as OpenManagement. Close
				// outside it: finish also removes this exact cache entry.
				cached.local.closed.Store(true)
				t.mu.Unlock()
				_ = cached.local.finish()
				continue
			}
			t.mu.Unlock()
			return cached, nil
		}
		if wait := t.dials[peer.Key]; wait != nil {
			t.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		wait := make(chan struct{})
		t.dials[peer.Key] = wait
		t.wg.Add(1)
		t.mu.Unlock()
		defer t.wg.Done()
		defer func() { t.mu.Lock(); delete(t.dials, peer.Key); close(wait); t.mu.Unlock() }()
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		stop := context.AfterFunc(t.ctx, cancel)
		defer stop()
		c, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
		if err != nil {
			return nil, err
		}
		stream, err := t.trackLocal(c.(*net.UnixConn), false, peer.Key)
		if err != nil {
			return nil, err
		}
		s, err := t.authenticateLocal(ctx, stream, true)
		if err != nil {
			_ = stream.finish()
			return nil, err
		}
		if s.peer.Key != peer.Key || s.peer.ID != peer.ID {
			_ = stream.finish()
			return nil, ErrAdmission
		}
		t.mu.Lock()
		if t.closed || t.localClosed || stream.closed.Load() {
			t.mu.Unlock()
			_ = stream.finish()
			return nil, net.ErrClosed
		}
		t.localSessions[peer.Key] = s
		t.mu.Unlock()
		return s, nil
	}
}

// unixListener is one management socket. Every listener admits the same
// TLS + MYDCP authentication; only the socket file's owner differs.
type unixListener struct {
	ln      *net.UnixListener
	socket  *ownedSocket
	primary bool
}

// ListenUnix opens the host management socket (0600, owned by this user).
// It refuses any existing entry except a stale socket: a socket owned by this
// user that refuses connections because its daemon crashed. It never unlinks
// a live daemon's socket or any other kind of file. The daemon chooses its
// node-local path; library Runtime.Open does not bind a host-global
// management socket implicitly.
func (t *Transport) ListenUnix(path string) error {
	if path == "" {
		path = DefaultManagementSocket
	}
	return t.listenUnix(path, -1, true)
}

// ListenUnixOwned opens one more management socket whose file is owned by
// uid (0600), for a node app container that runs as that UID
// (devel/design/node-apps.md). It admits exactly what ListenUnix admits:
// the same TLS, the same user login, the same purposes. The UID is not a
// credential. A stale socket left by a crash may be owned by uid as well.
func (t *Transport) ListenUnixOwned(path string, uid uint32) error {
	if uid == 0 || uid > math.MaxInt32 {
		return errors.New("node app socket owner must be a non-root UID")
	}
	return t.listenUnix(path, int(uid), false)
}

func (t *Transport) listenUnix(path string, owner int, primary bool) error {
	if err := ValidateManagementSocket(path); err != nil {
		return err
	}
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return err
	}
	stat, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || !parent.IsDir() || parent.Mode().Perm()&0022 != 0 || stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) {
		return errors.New("management socket parent must be owned and not writable by group/other")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.localClosed {
		return net.ErrClosed
	}
	for _, l := range t.localListeners {
		if l.primary && primary || l.socket.path == path {
			return net.ErrClosed
		}
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		if removeErr := removeStaleSocket(path, owner); removeErr != nil {
			return fmt.Errorf("management socket path must be absent: %w", errors.Join(err, os.ErrExist, removeErr))
		}
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return err
	}
	ln.SetUnlinkOnClose(false)
	info, err := os.Lstat(path)
	if err != nil {
		_ = ln.Close()
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		_ = ln.Close()
		return errors.New("management socket replaced during bind")
	}
	// The listener's kernel FD alone does not retain the pathname inode after
	// Close. Pin it through the final remove check so unlink/rebind cannot
	// recycle its inode number and make a foreign socket look like our own.
	fd, err := unix.Open(path, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = ln.Close()
		return err
	}
	pin := os.NewFile(uintptr(fd), path)
	pinned, err := pin.Stat()
	if err != nil || !os.SameFile(info, pinned) {
		_ = pin.Close()
		_ = ln.Close()
		return errors.Join(err, errors.New("management socket replaced before inode pin"))
	}
	owned := &ownedSocket{path: path, info: info, pin: pin}
	if err = os.Chmod(path, 0600); err != nil {
		_ = ln.Close()
		return errors.Join(err, owned.remove())
	}
	if owner >= 0 {
		if err = os.Lchown(path, owner, -1); err != nil {
			_ = ln.Close()
			return errors.Join(err, owned.remove())
		}
	}
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, current) {
		_ = ln.Close()
		_ = pin.Close()
		return errors.Join(err, errors.New("management socket replaced during setup"))
	}
	t.localListeners = append(t.localListeners, unixListener{ln: ln, socket: owned, primary: primary})
	t.wg.Add(1)
	go t.acceptUnix(ln)
	return nil
}

// CloseUnix stops local admission on every management socket and cancels
// their live requests without closing the node network needed for module
// retirement. Each original pinned path is removed after listener/connection
// closure, before unrelated worker waits. Transport.Close still joins every
// handler; a request is never deemed unrun.
func (t *Transport) CloseUnix() error {
	t.localCloseOnce.Do(func() {
		t.mu.Lock()
		t.localClosed = true
		listeners := t.localListeners
		connections := make([]*localConnection, 0, len(t.localConnections))
		for c := range t.localConnections {
			connections = append(connections, c)
		}
		t.mu.Unlock()
		for _, l := range listeners {
			_ = l.ln.Close()
		}
		for _, c := range connections {
			_ = c.finish()
		}
		for _, l := range listeners {
			t.localCloseErr = errors.Join(t.localCloseErr, l.socket.remove())
		}
	})
	return t.localCloseErr
}

// ManagementAddr is the host management socket opened by ListenUnix.
func (t *Transport) ManagementAddr() net.Addr {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, l := range t.localListeners {
		if l.primary {
			return l.ln.Addr()
		}
	}
	return nil
}

func (t *Transport) acceptUnix(ln *net.UnixListener) {
	defer t.wg.Done()
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			t.serverFailure("unix", "accept", Identity{}, Frame{}, err)
			return
		}
		stream, err := t.trackLocal(c, true, Identity{})
		if err != nil {
			t.serverFailure("unix", "track-connection", Identity{}, Frame{}, err)
			continue
		}
		t.mu.Lock()
		if t.closed || t.localClosed {
			t.mu.Unlock()
			_ = stream.finish()
			return
		}
		t.wg.Add(1)
		t.mu.Unlock()
		go func() { defer t.wg.Done(); defer stream.finish(); t.serveUnix(stream) }()
	}
}

func (t *Transport) serveUnix(connection *localConnection) {
	s, err := t.authenticateLocal(connection.ctx, connection, false)
	if err != nil {
		state := connection.conn.ConnectionState()
		// Public discovery logs only its own failures and never becomes a
		// management session. Its successful return is not an auth rejection.
		if state.HandshakeComplete && state.NegotiatedProtocol == discoveryALPN {
			return
		}
		stage := "authenticate"
		if !state.HandshakeComplete {
			stage = "tls-handshake"
		}
		t.serverFailure("unix", stage, Identity{}, Frame{}, err)
		return
	}
	for {
		if err := connection.conn.SetDeadline(time.Now().Add(localManagementTimeout)); err != nil {
			t.serverFailure("unix", "deadline", s.peer.Key, Frame{}, err)
			return
		}
		stream := &localStream{connection: connection}
		first, err := ReadFrame(stream, MaxBody)
		if err != nil {
			if !idleUnixClose(stream, err) {
				t.serverFailure("unix", "receive", s.peer.Key, Frame{}, err)
			}
			return
		}
		if !localPurpose(first.Purpose) {
			t.serverFailure("unix", "admit", s.peer.Key, first, ErrAdmission)
			return
		}
		if err := s.Admit(first, first.Purpose, false); err != nil {
			t.serverFailure("unix", "admit", s.peer.Key, first, err)
			return
		}
		ctx, cancel := context.WithTimeout(connection.ctx, localManagementTimeout)
		handlerContext := ctx
		if first.Purpose == NodeShell || first.Purpose == ContainerSession || first.Purpose == ImageContent || first.Purpose == VolumeFile {
			// Header parsing is still capped. Its handler must authenticate
			// before installing per-direction idle/write deadlines.
			handlerContext = connection.ctx
		}
		err = t.handleUnix(handlerContext, s, stream, first)
		cancel()
		if first.Purpose == NodeShell || first.Purpose == ContainerSession || first.Purpose == ImageContent || first.Purpose == VolumeFile {
			return
		} // one duplex conversation owns this local connection
		if err != nil {
			return // The exact failing handler/EOF boundary already logged it.
		}
	}
}

func (t *Transport) handleUnix(ctx context.Context, s *Session, stream *localStream, first Frame) error {
	permit := t.limits[first.Purpose]
	select {
	case permit <- struct{}{}:
	default:
		t.serverFailure("unix", "capacity", s.peer.Key, first, ErrBudget)
		return ErrBudget
	}
	defer func() { <-permit }()
	t.mu.Lock()
	h := t.managementHandlers[first.Purpose]
	t.mu.Unlock()
	if h == nil {
		t.serverFailure("unix", "dispatch", s.peer.Key, first, ErrAdmission)
		return ErrAdmission
	}
	if err := h(ctx, s, stream, first); err != nil {
		t.serverFailure("unix", "handler", s.peer.Key, first, err)
		return err
	}
	if first.Purpose == NodeShell || first.Purpose == ContainerSession || first.Purpose == ImageContent || first.Purpose == VolumeFile {
		return stream.Close()
	}
	// Ordinary requests have one frame; streaming app inputs consume their own
	// ordered data and EOF. Extra input never becomes a new management request.
	var extra [1]byte
	if n, err := stream.Read(extra[:]); n != 0 || err != io.EOF {
		cause := err
		if cause == nil || cause == io.EOF {
			cause = ErrFrame
		}
		t.serverFailure("unix", "receive-eof", s.peer.Key, first, cause)
		return ErrFrame
	}
	err := stream.Close()
	t.serverFailure("unix", "send-eof", s.peer.Key, first, err)
	return err
}

// removeStaleSocket unlinks path only when it is a socket owned by this user
// (or by owner, the UID a node app socket was handed to; -1 for none) and
// nothing accepts connections on it. The parent was already checked to be
// unwritable by group/other, so nobody else can swap the entry meanwhile.
func removeStaleSocket(path string, owner int) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSocket == 0 || stat.Uid != uint32(os.Geteuid()) && (owner < 0 || stat.Uid != uint32(owner)) {
		return errors.New("existing entry is not a stale socket of this user")
	}
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err == nil {
		_ = conn.Close()
		return errors.New("another daemon is listening on the socket")
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return err
	}
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, current) {
		return errors.Join(err, errors.New("socket replaced during stale check"))
	}
	return os.Remove(path)
}
