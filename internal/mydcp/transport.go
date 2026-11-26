// SPDX-License-Identifier: Apache-2.0

package mydcp

import (
	"context"
	"errors"
	"fmt"
	"github.com/jay94ks/mydcd/internal/identity"
	quic "github.com/quic-go/quic-go"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Peer struct {
	ID, Endpoint string
	Policy
}
type Lookup func(Identity) (Peer, bool)
type PurposeLookup func(Identity, Purpose) (Peer, bool)
type Handler func(context.Context, *Session, *quic.Stream, Frame) error
type Transport struct {
	linkConnections    map[Identity]linkConnection
	publicNode         string
	publicSlots        chan struct{}
	self               *identity.Identity
	cluster            [32]byte
	lookup             Lookup
	purposeLookup      PurposeLookup
	ctx                context.Context
	cancel             context.CancelFunc
	mu                 sync.Mutex
	listener           *quic.Listener
	underlay           *quic.Transport
	socket             *net.UDPConn
	closeErr           error
	sessions           map[Identity]*Session
	dials              map[Identity]chan struct{}
	connections        map[*quic.Conn]struct{}
	handlers           map[Purpose]Handler
	managementHandlers map[Purpose]ManagementHandler
	localListener      *net.UnixListener
	localSocket        *ownedSocket
	localConnections   map[*localConnection]struct{}
	localSessions      map[Identity]*Session
	localClosed        bool
	localCloseOnce     sync.Once
	localCloseErr      error
	packetHandler      func(*Session, Frame) error
	closed             bool
	wg                 sync.WaitGroup
	workers            chan struct{}
	limits             map[Purpose]chan struct{}
	closeDone          chan struct{}
	next               atomic.Uint64
	packetsDelivered   atomic.Uint64
	livePeers          map[Identity]int
	peerLost           func(Peer)
	peerFound          func(Peer)
	packetsDropped     atomic.Uint64
	packetDropReasons  [6]atomic.Uint64
}
type Session struct {
	transport       *Transport
	conn            *quic.Conn
	peer            Peer
	gate            *Gate
	path            *connectionPath
	peerChallenge   [32]byte
	authenticatedAt uint64
	local           *localConnection
}

func NewTransport(self *identity.Identity, cluster [32]byte, lookup Lookup) (*Transport, error) {
	if self == nil || cluster == [32]byte{} || lookup == nil {
		return nil, ErrAdmission
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Transport{publicSlots: make(chan struct{}, 4), self: self, cluster: cluster, lookup: lookup, ctx: ctx, cancel: cancel, sessions: map[Identity]*Session{}, dials: map[Identity]chan struct{}{}, connections: map[*quic.Conn]struct{}{}, handlers: map[Purpose]Handler{}, managementHandlers: map[Purpose]ManagementHandler{}, localConnections: map[*localConnection]struct{}{}, localSessions: map[Identity]*Session{}, workers: make(chan struct{}, 64), closeDone: make(chan struct{}), limits: map[Purpose]chan struct{}{NodeShell: make(chan struct{}, 64), Management: make(chan struct{}, 16), Raft: make(chan struct{}, 32), Snapshot: make(chan struct{}, 2), Observation: make(chan struct{}, 8), PathControl: make(chan struct{}, 8), User: make(chan struct{}, 16), Membership: make(chan struct{}, 8), SecretInput: make(chan struct{}, 8), SecretFetch: make(chan struct{}, 4), VolumeTransfer: make(chan struct{}, 1), CheckerArtifact: make(chan struct{}, 2), CheckerProbe: make(chan struct{}, 2), ContainerSession: make(chan struct{}, 8), CertificateMaterial: make(chan struct{}, 2), VolumeFile: make(chan struct{}, 2), ImageContent: make(chan struct{}, 2)}}, nil
}

// NewTransportWithPurposeLookup keeps current identity/control admission
// independent of packet policy derivation. Purpose zero is an explicit full
// Peer query; it is never an admitted wire purpose.
func NewTransportWithPurposeLookup(self *identity.Identity, cluster [32]byte, lookup PurposeLookup) (*Transport, error) {
	if lookup == nil {
		return nil, ErrAdmission
	}
	t, err := NewTransport(self, cluster, func(key Identity) (Peer, bool) { return lookup(key, 0) })
	if err == nil {
		t.purposeLookup = lookup
	}
	return t, err
}

func (t *Transport) lookupFor(key Identity, purpose Purpose) (Peer, bool) {
	if t.purposeLookup != nil {
		return t.purposeLookup(key, purpose)
	}
	return t.lookup(key)
}
func (t *Transport) NextRequest() uint64 {
	n := t.next.Add(1)
	if n == 0 {
		panic("MYDCP request ordinal exhausted")
	}
	return n
}
func (t *Transport) LocalKey() Identity             { return Identity(t.self.Public) }
func (t *Transport) Peer(key Identity) (Peer, bool) { return t.lookup(key) }
func (t *Transport) On(p Purpose, h Handler) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || h == nil || p == Handshake || p == Packet || t.handlers[p] != nil {
		return ErrAdmission
	}
	t.handlers[p] = h
	return nil
}
func (t *Transport) Listen(address string) error {
	local, err := resolveUDP(t.ctx, address)
	if err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.underlay != nil {
		return errors.New("transport already started/closed")
	}
	socket, err := net.ListenUDP("udp", local)
	if err != nil {
		return err
	}
	underlay := &quic.Transport{Conn: socket, ConnContext: acceptPath}
	ln, err := underlay.Listen(t.serverTLS(), quicConfig())
	if err != nil {
		_ = underlay.Close()
		_ = socket.Close()
		return err
	}
	t.socket = socket
	t.underlay = underlay
	t.listener = ln
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		for {
			conn, err := ln.Accept(t.ctx)
			if err != nil {
				t.serverFailure("quic", "accept", Identity{}, Frame{}, err)
				return
			}
			t.mu.Lock()
			if t.closed {
				t.mu.Unlock()
				_ = conn.CloseWithError(0, "stopped")
				return
			}
			if len(t.connections) >= 128 {
				t.mu.Unlock()
				t.serverFailure("quic", "connection-capacity", Identity{}, Frame{}, ErrBudget)
				_ = conn.CloseWithError(2, "connection capacity")
				continue
			}

			t.connections[conn] = struct{}{}
			t.wg.Add(1)
			t.mu.Unlock()
			go func() {
				defer t.wg.Done()
				if conn.ConnectionState().TLS.NegotiatedProtocol == discoveryALPN {
					t.serveQUICDiscovery(conn)
					return
				}
				session, err := t.authenticate(t.ctx, conn, false)
				if err != nil {
					t.serverFailure("quic", "authenticate", Identity{}, Frame{}, err)
					_ = conn.CloseWithError(1, "authentication rejected")
					t.forget(conn)
					return
				}
				t.serve(session)
			}()
		}
	}()
	return nil
}

// Every MYDCP connection sends a QUIC PING after keepAlivePeriod without
// other packets and is closed after idleTimeout without any. This is what
// detects a lost peer within seconds; Raft heartbeats run far less often
// (see cluster.newEngine) and only learn about the loss through OnPeerLost.
const (
	keepAlivePeriod = time.Second
	idleTimeout     = 3 * time.Second
	shutdownMessage = "shutdown"
)

func quicConfig() *quic.Config {
	return &quic.Config{HandshakeIdleTimeout: 5 * time.Second, MaxIdleTimeout: idleTimeout, KeepAlivePeriod: keepAlivePeriod, MaxIncomingStreams: 64, MaxIncomingUniStreams: -1, InitialStreamReceiveWindow: 256 << 10, MaxStreamReceiveWindow: 2 << 20, InitialConnectionReceiveWindow: 2 << 20, MaxConnectionReceiveWindow: 8 << 20, EnableDatagrams: true, Tracer: pathTrace}
}
func (t *Transport) Addr() net.Addr {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.listener == nil {
		return nil
	}
	return t.listener.Addr()
}
func (t *Transport) forget(c *quic.Conn) { t.mu.Lock(); defer t.mu.Unlock(); delete(t.connections, c) }
func (t *Transport) Dial(ctx context.Context, peer Peer) (*Session, error) {
	current, ok := t.lookupFor(peer.Key, Handshake)
	if !ok || current.ID != peer.ID || current.Endpoint != "" && current.Endpoint != peer.Endpoint {
		return nil, ErrAdmission
	}
	if local, err := managementEndpoint(peer.Endpoint); err != nil {
		return nil, err
	} else if local != "" {
		return t.dialUnix(ctx, peer, local)
	}
	for {
		t.mu.Lock()
		if t.closed {
			t.mu.Unlock()
			return nil, net.ErrClosed
		}
		if s := t.sessions[peer.Key]; s != nil && s.conn.Context().Err() == nil {
			t.mu.Unlock()
			return s, nil
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
		var dialErr error
		func() {
			defer t.wg.Done()
			defer func() { t.mu.Lock(); delete(t.dials, peer.Key); close(wait); t.mu.Unlock() }()
			path := newConnectionPath()
			ctx, cancel := context.WithCancel(context.WithValue(ctx, pathContextKey{}, path))
			defer cancel()
			stop := context.AfterFunc(t.ctx, cancel)
			defer stop()
			var c *quic.Conn
			var s *Session
			var err error
			defer func() { dialErr = err }()
			address, resolveErr := resolveUDP(ctx, peer.Endpoint)
			err = resolveErr
			if err != nil {
				return
			}
			t.mu.Lock()
			if t.closed {
				err = net.ErrClosed
			} else if t.underlay == nil {
				t.socket, err = net.ListenUDP("udp", nil)
				if err == nil {
					t.underlay = &quic.Transport{Conn: t.socket, ConnContext: acceptPath}
				}
			}
			underlay := t.underlay
			t.mu.Unlock()
			if err != nil {
				return
			}
			if err = path.bindRoute(address); err != nil {
				return
			}
			c, err = underlay.Dial(ctx, address, t.self.TLS(false, func(key [32]byte) bool {
				_, approved := t.lookupFor(Identity(key), Handshake)
				return approved && Identity(key) == peer.Key
			}), quicConfig())
			if err == nil {
				t.mu.Lock()
				if t.closed {
					err = net.ErrClosed
				} else {
					t.connections[c] = struct{}{}
				}
				t.mu.Unlock()
			}
			if err == nil {
				s, err = t.authenticate(ctx, c, true)
			}
			if err == nil && s.peer.Key != peer.Key {
				err = ErrAdmission
			}
			if err != nil {
				if c != nil {
					_ = c.CloseWithError(1, "dial/authentication failed")
					t.forget(c)
				}
				return
			}
			t.mu.Lock()
			if !t.closed {
				t.sessions[peer.Key] = s
				t.wg.Add(1)
				go func() { defer t.wg.Done(); t.serve(s) }()
			}
			t.mu.Unlock()
		}()
		t.mu.Lock()
		s := t.sessions[peer.Key]
		t.mu.Unlock()
		if s != nil && s.conn.Context().Err() == nil {
			return s, nil
		}
		if dialErr == nil {
			dialErr = net.ErrClosed
		}
		return nil, fmt.Errorf("MYDCP authentication/dial failed for %s: %w", peer.ID, dialErr)
	}
}
func (t *Transport) authenticate(parent context.Context, c *quic.Conn, client bool) (*Session, error) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	key, err := identity.PeerKey(c.ConnectionState().TLS)
	if err != nil {
		return nil, err
	}
	peer, ok := t.lookupFor(Identity(key), Handshake)
	if !ok || peer.Key != Identity(key) {
		return nil, ErrAdmission
	}
	var stream *quic.Stream
	if client {
		stream, err = c.OpenStreamSync(ctx)
	} else {
		stream, err = c.AcceptStream(ctx)
	}
	if err != nil {
		return nil, err
	}
	defer stream.CancelRead(0)
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
	gate, peerChallenge, err := t.authenticateStream(stream, Identity(key), peer, client)
	if err != nil {
		return nil, err
	}
	path, _ := c.Context().Value(pathContextKey{}).(*connectionPath)
	if path == nil {
		return nil, errors.New("MYDCP missing native connection path")
	}
	session := &Session{transport: t, conn: c, peer: peer, gate: gate, path: path, peerChallenge: peerChallenge, authenticatedAt: uint64(time.Now().UnixMilli())}
	t.observeMemberSession(session, peer)
	return session, nil
}
func (t *Transport) serve(s *Session) {
	defer t.forget(s.conn)
	t.sessionStarted(s)
	t.wg.Add(1)
	go func() { defer t.wg.Done(); t.receivePackets(s) }()
	for {
		stream, err := s.conn.AcceptStream(t.ctx)
		if err != nil {
			t.serverFailure("quic", "accept-stream", s.peer.Key, Frame{}, err)
			t.sessionEnded(s, err)
			return
		}
		select {
		case t.workers <- struct{}{}:
		default:
			t.serverFailure("quic", "parse-capacity", s.peer.Key, Frame{}, ErrBudget)
			stream.CancelRead(2)
			stream.CancelWrite(2)
			continue
		}
		t.wg.Add(1)
		go func() {
			defer t.wg.Done()
			parsing := true
			defer func() {
				if parsing {
					<-t.workers
				}
			}()
			defer stream.CancelRead(0)
			defer stream.Close()
			ctx, cancel := context.WithTimeout(t.ctx, 30*time.Second)
			defer cancel()
			if err := stream.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
				t.serverFailure("quic", "deadline", s.peer.Key, Frame{}, err)
			}
			first, err := ReadFrame(stream, MaxBody)
			if err != nil {
				t.serverFailure("quic", "receive", s.peer.Key, Frame{}, err)
				stream.CancelWrite(3)
				return
			}
			<-t.workers
			parsing = false
			permit := t.limits[first.Purpose]
			if permit == nil {
				t.serverFailure("quic", "dispatch", s.peer.Key, first, ErrAdmission)
				stream.CancelWrite(2)
				return
			}
			select {
			case permit <- struct{}{}:
			default:
				t.serverFailure("quic", "capacity", s.peer.Key, first, ErrBudget)
				stream.CancelWrite(2)
				return
			}
			defer func() { <-permit }()

			if err = s.Admit(first, first.Purpose, false); err != nil {
				t.serverFailure("quic", "admit", s.peer.Key, first, err)
				stream.CancelWrite(4)
				return
			}
			t.mu.Lock()
			handler := t.handlers[first.Purpose]
			t.mu.Unlock()
			handlerContext := ctx
			if first.Purpose == VolumeTransfer || first.Purpose == CheckerArtifact || first.Purpose == CheckerProbe || first.Purpose == NodeShell || first.Purpose == ContainerSession || first.Purpose == ImageContent || first.Purpose == VolumeFile {
				// Parsing remains bounded by30s. The dedicated transfer handler
				// validates/binds the ORIGINAL plan deadline and idle I/O budget.
				handlerContext = t.ctx
			}
			if handler == nil {
				t.serverFailure("quic", "dispatch", s.peer.Key, first, ErrAdmission)
				stream.CancelWrite(5)
			} else if err := handler(handlerContext, s, stream, first); err != nil {
				t.serverFailure("quic", "handler", s.peer.Key, first, err)
				stream.CancelWrite(5)
			}
		}()
	}
}

// OnPeerLost registers f to run when the last connection to a peer ends
// for a reason other than a deliberate close (see peerWentAway): idle
// timeout, stateless reset, a transport error on either side or the peer's
// shutdown. A connection this node closed itself (shutdown, path retirement,
// failed dial) does not count. f runs on
// its own goroutine.
func (t *Transport) OnPeerLost(f func(Peer)) {
	t.mu.Lock()
	t.peerLost = f
	t.mu.Unlock()
}

// sessionStarted counts a live session; the first one to a cluster member
// reports OnPeerConnected.
func (t *Transport) sessionStarted(s *Session) {
	t.mu.Lock()
	if t.livePeers == nil {
		t.livePeers = map[Identity]int{}
	}
	t.livePeers[s.peer.Key]++
	first := t.livePeers[s.peer.Key] == 1
	found, closed := t.peerFound, t.closed
	t.mu.Unlock()
	if found != nil && first && !closed && (s.peer.Member || s.peer.Replicate) {
		t.wg.Add(1)
		go func() { defer t.wg.Done(); found(s.peer) }()
	}
}

// OnPeerConnected registers f to run when a cluster member that had no
// connection to this node gets one (inbound or outbound), for example after
// it restarted. f runs on its own goroutine.
func (t *Transport) OnPeerConnected(f func(Peer)) {
	t.mu.Lock()
	t.peerFound = f
	t.mu.Unlock()
}

func (t *Transport) sessionEnded(s *Session, cause error) {
	t.mu.Lock()
	t.livePeers[s.peer.Key]--
	last := t.livePeers[s.peer.Key] <= 0
	if last {
		delete(t.livePeers, s.peer.Key)
	}
	f := t.peerLost
	closed := t.closed
	t.mu.Unlock()
	// Only cluster members matter to Raft; CLI and other client sessions end
	// all the time.
	if f != nil && last && !closed && (s.peer.Member || s.peer.Replicate) && peerWentAway(cause) {
		log.Printf("MYDCP peer lost: peer=%s cause=%v", s.peer.ID, cause)
		t.wg.Add(1)
		go func() { defer t.wg.Done(); f(s.peer) }()
	}
}

// peerWentAway reports whether a connection ended for a reason other than a
// deliberate close: by this node (application close) or by the peer for
// anything but its shutdown (path retirement, rejected dial). Idle timeout,
// stateless reset and transport errors on either side, such as a local
// send failure when this node's own link is cut, all count.
func peerWentAway(err error) bool {
	var app *quic.ApplicationError
	if errors.As(err, &app) {
		return app.Remote && app.ErrorMessage == shutdownMessage
	}
	return err != nil && !errors.Is(err, context.Canceled)
}

func (s *Session) Peer() Peer              { return s.peer }
func (s *Session) Challenge() [32]byte     { return s.gate.challenge }
func (s *Session) PeerChallenge() [32]byte { return s.peerChallenge }
func (s *Session) RemoteAddr() net.Addr {
	if s.local != nil {
		return s.local.conn.RemoteAddr()
	}
	return s.conn.RemoteAddr()
}

// RetirePath discards native MTU observations by retiring their connection.
// Replication callers retain their own original RPC/result semantics.
func (s *Session) RetirePath() error {
	if s.local != nil {
		return s.local.finish()
	}
	return s.conn.CloseWithError(0, "underlay route changed")
}
func (s *Session) Admit(f Frame, purpose Purpose, datagram bool) error {
	if s.local != nil && (!localPurpose(purpose) || datagram || f.Kind == 3) {
		return ErrAdmission
	}
	var started time.Time
	var lookupTime time.Duration
	admitted := false
	if purpose == Raft {
		started = time.Now()
		defer func() {
			if elapsed := time.Since(started); elapsed >= 100*time.Millisecond {
				log.Printf("raft stream admission slow: peer=%s request=%d elapsed=%s lookup=%s admitted=%t", s.peer.ID, f.Request, elapsed, lookupTime, admitted)
			}
		}()
	}
	peer, ok := s.transport.lookupFor(s.peer.Key, purpose)
	if !started.IsZero() {
		lookupTime = time.Since(started)
	}
	if !ok {
		return ErrAdmission
	}
	err := s.gate.AdmitOn(purpose, f, peer.Policy, false, datagram)
	admitted = err == nil
	if admitted && !datagram && peer.Member && peer.Report {
		// A connection authenticated while joining can become a full member
		// later. Track it only after current purpose admission allows it.
		s.transport.observeMemberSession(s, peer)
	}
	return err
}
func (s *Session) Open(ctx context.Context) (*quic.Stream, error) {
	if s.conn == nil {
		return nil, ErrAdmission
	}
	stream, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(10 * time.Second)
	}
	_ = stream.SetDeadline(deadline)
	return stream, nil
}
func (t *Transport) Close() error {
	t.mu.Lock()
	if t.closed {
		done := t.closeDone
		t.mu.Unlock()
		<-done
		return t.closeErr
	}
	t.closed = true
	t.cancel()
	ln := t.listener
	underlay, socket := t.underlay, t.socket
	connections := make([]*quic.Conn, 0, len(t.connections))
	for c := range t.connections {
		connections = append(connections, c)
	}
	t.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	t.closeErr = errors.Join(t.closeErr, t.CloseUnix())
	for _, c := range connections {
		_ = c.CloseWithError(0, shutdownMessage)
	}
	if underlay != nil {
		t.closeErr = errors.Join(t.closeErr, underlay.Close())
	}
	if socket != nil {
		if err := socket.Close(); t.closeErr == nil {
			t.closeErr = err
		}
	}
	t.wg.Wait()
	close(t.closeDone)
	return t.closeErr
}

func resolveUDP(ctx context.Context, address string) (*net.UDPAddr, error) {
	address = strings.TrimPrefix(address, "mydcp://")
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, err
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, uint16(p))), nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, errors.New("endpoint has no IP address")
	}
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(ips[0], uint16(p))), nil
}
