// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/jay94ks/seafield/internal/buildinfo"
	"github.com/jay94ks/seafield/internal/identity"
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
	publicNode    string
	publicSlots   chan struct{}
	self          *identity.Identity
	cluster       [32]byte
	lookup        Lookup
	purposeLookup PurposeLookup
	ctx           context.Context
	cancel        context.CancelFunc
	mu            sync.Mutex
	listener      *quic.Listener
	underlay      *quic.Transport
	socket        *net.UDPConn
	closeErr      error
	// peers holds sessions, dials, liveness and link records per peer.
	peers map[Identity]*peerState
	// own is the feature set this node announces: buildinfo.Own, except in
	// tests.
	own buildinfo.Features
	// features caches the cluster feature intersection (features.go).
	features featureCache
	// version is the build version this node announces (handshake tag 128):
	// buildinfo.Version(), except in tests. versionLogged keeps the
	// once-per-peer log lines (version.go); guarded by mu.
	version       string
	versionLogged map[Identity]string
	// engine is the local engine socket (engine.go).
	engine engineState
	// inboundOnly keeps this node from dialing other nodes over QUIC; it
	// only uses sessions they open (node.yaml node.inbound_only).
	inboundOnly bool
	// starting holds server failures while the node is starting (startup.go).
	starting           startupRefusals
	connections        map[*quic.Conn]struct{}
	handlers           map[Purpose]Handler
	managementHandlers map[Purpose]ManagementHandler
	localListeners     []unixListener
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
	streams            streamLimits
	closeDone          chan struct{}
	next               atomic.Uint64
	packetsDelivered   atomic.Uint64
	peerLost           func(Peer)
	peerFound          func(Peer)
	// contacts holds, per member ID, when any packet from it last arrived.
	contacts          sync.Map // string -> *peerContact
	packetsDropped    atomic.Uint64
	packetDropReasons [6]atomic.Uint64
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
	// outbound is true when this node opened the connection.
	outbound bool
	// via names the member whose transit session carries this session's
	// QUIC packets; empty for a direct connection, the only kind before
	// 0.1.1 (devel/design/sfcp-transit.md). Nothing else about a session
	// depends on it: the peer is still authenticated end to end.
	via string
}

func NewTransport(self *identity.Identity, cluster [32]byte, lookup Lookup) (*Transport, error) {
	if self == nil || cluster == [32]byte{} || lookup == nil {
		return nil, ErrAdmission
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Transport{publicSlots: make(chan struct{}, 4), self: self, cluster: cluster, lookup: lookup, ctx: ctx, cancel: cancel, connections: map[*quic.Conn]struct{}{}, handlers: map[Purpose]Handler{}, managementHandlers: map[Purpose]ManagementHandler{}, localConnections: map[*localConnection]struct{}{}, localSessions: map[Identity]*Session{}, own: buildinfo.Own, version: buildinfo.Version(), workers: make(chan struct{}, 64), closeDone: make(chan struct{}), limits: newPurposeLimits()}, nil
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
		panic("SFCP request ordinal exhausted")
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
				t.adoptSession(session)
				t.serve(session)
			}()
		}
	}()
	return nil
}

// Liveness is one mechanism (Jay 2026-11-28 10:42–10:45 KST): any packet
// received from a peer, of any kind, counts as contact (LastReceived), and
// only when nothing at all has arrived for keepAlivePeriod does the
// connection send a QUIC PING. Traffic that is already flowing therefore
// carries no extra heartbeat. A connection with nothing received for
// idleTimeout is closed and OnPeerLost fires. Raft sends no periodic
// heartbeat of its own; it reads LastReceived (cluster.newEngine).
const (
	keepAlivePeriod = 10 * time.Second
	idleTimeout     = 30 * time.Second
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
		if s := t.channelOf(peer.Key); s.live() {
			t.mu.Unlock()
			return s, nil
		}
		if t.inboundOnly {
			t.mu.Unlock()
			return nil, fmt.Errorf("%w: %s has not connected to this inbound-only node", ErrNotConnected, peer.ID)
		}
		if wait := t.ensurePeer(peer.Key).dial; wait != nil {
			t.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		wait := make(chan struct{})
		path := newConnectionPath()
		ctx, cancel := context.WithCancel(context.WithValue(ctx, pathContextKey{}, path))
		// handshake bounds only reaching the peer. An inbound session from
		// the peer aborts it: a node behind NAT connects out and this node
		// never needs its endpoint. Authentication of a connection that
		// already exists is never aborted, so two nodes dialing each other
		// at once cannot both drop their connections.
		handshake, abort := context.WithCancel(ctx)
		record := t.ensurePeer(peer.Key)
		record.dial, record.abort = wait, abort
		t.wg.Add(1)
		t.mu.Unlock()
		var dialErr error
		func() {
			defer t.wg.Done()
			defer func() {
				t.mu.Lock()
				record.dial, record.abort = nil, nil
				t.forgetPeer(peer.Key)
				close(wait)
				t.mu.Unlock()
			}()
			defer cancel()
			defer abort()
			stop := context.AfterFunc(t.ctx, cancel)
			defer stop()
			var c *quic.Conn
			var s *Session
			var err error
			defer func() { dialErr = err }()
			address, resolveErr := resolveUDP(handshake, peer.Endpoint)
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
			c, err = underlay.Dial(handshake, address, t.self.TLS(false, func(key [32]byte) bool {
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
			s.outbound = true
			t.mu.Lock()
			if !t.closed {
				t.wg.Add(1)
				t.mu.Unlock()
				t.adoptSession(s)
				go func() { defer t.wg.Done(); t.serve(s) }()
				return
			}
			t.mu.Unlock()
		}()
		t.mu.Lock()
		s := t.channelOf(peer.Key)
		t.mu.Unlock()
		// The adopted channel can be the peer's inbound session rather than
		// the one just dialed; the dial may also have been aborted for it.
		if s.live() {
			return s, nil
		}
		if dialErr == nil {
			dialErr = net.ErrClosed
		}
		return nil, &PeerUnreachableError{Peer: peer.ID, Err: dialErr}
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
		return nil, errors.New("SFCP missing native connection path")
	}
	session := &Session{transport: t, conn: c, peer: peer, gate: gate, path: path, peerChallenge: peerChallenge, authenticatedAt: uint64(time.Now().UnixMilli())}
	if peer.ID != "" {
		contact := t.contactOf(peer.ID)
		contact.touch()
		path.contact.Store(contact)
	}
	t.observeMemberSession(session, peer)
	return session, nil
}
func (t *Transport) serve(s *Session) {
	defer t.forget(s.conn)
	defer t.releaseSession(s)
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
			if t.limits[first.Purpose] == nil && !purposes[first.Purpose].unlimited {
				t.serverFailure("quic", "dispatch", s.peer.Key, first, ErrAdmission)
				stream.CancelWrite(2)
				return
			}
			release, ok := t.acquire(s.peer.Key, first.Purpose)
			if !ok {
				t.serverFailure("quic", "capacity", s.peer.Key, first, ErrBudget)
				stream.CancelWrite(2)
				return
			}
			defer release()

			if err = s.Admit(first, first.Purpose, false); err != nil {
				t.serverFailure("quic", "admit", s.peer.Key, first, err)
				stream.CancelWrite(4)
				return
			}
			t.mu.Lock()
			handler := t.handlers[first.Purpose]
			t.mu.Unlock()
			handlerContext := ctx
			if longLivedPurpose(first.Purpose) {
				// Parsing remains bounded by 30s. The dedicated transfer handler
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

// adoptSession makes an authenticated QUIC session, inbound or outbound, a
// channel Dial reuses for its peer. SFCP is a mesh: whichever node connects
// first carries traffic both ways, so a public node never dials a node behind
// NAT. When two live sessions to the same peer exist (both nodes dialed at
// once, or one reconnected before the old connection timed out), both nodes
// pick the same one by preferSession; the other is kept, not closed, because
// the peer may still have streams on it, and takes over if the chosen one
// ends. An inbound session also aborts this node's dial to the peer that is
// still waiting for its handshake.
func (t *Transport) adoptSession(s *Session) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || !s.live() {
		return
	}
	p := t.ensurePeer(s.peer.Key)
	if p.sessions == nil {
		p.sessions = map[*Session]struct{}{}
	}
	p.sessions[s] = struct{}{}
	if current := p.channel; !current.live() || preferSession(s, current, t.LocalKey()) {
		p.channel = s
	}
	if p.abort != nil && !s.outbound {
		p.abort()
	}
}

// releaseSession forgets an ended session and hands its peer's channel to the
// preferred remaining live session, if any.
func (t *Transport) releaseSession(s *Session) {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := s.peer.Key
	p := t.peerOf(key)
	if p == nil {
		return
	}
	defer t.forgetPeer(key)
	delete(p.sessions, s)
	if p.channel != s {
		return
	}
	p.channel = nil
	for other := range p.sessions {
		if other.live() && (p.channel == nil || preferSession(other, p.channel, t.LocalKey())) {
			p.channel = other
		}
	}
}

// preferSession reports whether a should carry a peer's traffic instead of b,
// both live sessions to the same peer. Both nodes decide alike: a session
// opened by the node with the smaller key wins; between two opened by the
// same node, the newer wins, since that node only dials again after giving
// up on the older one.
func preferSession(a, b *Session, local Identity) bool {
	ai, bi := a.initiator(local), b.initiator(local)
	if ai != bi {
		return bytes.Compare(ai[:], bi[:]) < 0
	}
	return a.authenticatedAt > b.authenticatedAt
}

func (s *Session) initiator(local Identity) Identity {
	if s.outbound {
		return local
	}
	return s.peer.Key
}

func (s *Session) live() bool {
	return s != nil && s.conn != nil && s.conn.Context().Err() == nil
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

// sessionStarted counts a live session. The first one to a peer starts its
// unbroken-link time (ConnectedSince) and, for a cluster member, reports
// OnPeerConnected.
func (t *Transport) sessionStarted(s *Session) {
	t.mu.Lock()
	p := t.ensurePeer(s.peer.Key)
	p.live++
	if s.peer.Member || s.peer.Replicate {
		t.features.saw(s.peer.Key, s.PeerFeatures())
	}
	first := p.live == 1
	if first {
		p.since = time.Now()
	}
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

// peerContact is the last time any packet from one peer arrived.
type peerContact struct{ at atomic.Int64 }

func (c *peerContact) touch() { c.at.Store(time.Now().UnixNano()) }

func (t *Transport) contactOf(id string) *peerContact {
	if c, ok := t.contacts.Load(id); ok {
		return c.(*peerContact)
	}
	c, _ := t.contacts.LoadOrStore(id, &peerContact{})
	return c.(*peerContact)
}

// LastReceived is when any packet (data, ACK or PING alike) last arrived
// from the member id over an authenticated connection; zero if never. It is
// the one liveness signal: Raft uses it instead of its own heartbeats.
func (t *Transport) LastReceived(id string) time.Time {
	c, ok := t.contacts.Load(id)
	if !ok {
		return time.Time{}
	}
	n := c.(*peerContact).at.Load()
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n)
}

// ConnectedSince reports since when this node has had at least one
// authenticated connection to key without a gap, and whether it has one now.
// Callers use it to trust that a peer that would report a change has stayed
// reachable since some earlier time.
func (t *Transport) ConnectedSince(key Identity) (time.Time, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	p := t.peerOf(key)
	if p == nil || p.live <= 0 {
		return time.Time{}, false
	}
	return p.since, true
}

func (t *Transport) sessionEnded(s *Session, cause error) {
	t.mu.Lock()
	last := true
	if p := t.peerOf(s.peer.Key); p != nil {
		p.live--
		last = p.live <= 0
		if last {
			p.live, p.since = 0, time.Time{}
			t.forgetPeer(s.peer.Key)
		}
	}
	f := t.peerLost
	closed := t.closed
	t.mu.Unlock()
	// Only cluster members matter to Raft; CLI and other client sessions end
	// all the time.
	if f != nil && last && !closed && (s.peer.Member || s.peer.Replicate) && peerWentAway(cause) {
		log.Printf("SFCP peer lost: peer=%s cause=%v", s.peer.ID, cause)
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

func (s *Session) Peer() Peer { return s.peer }

// Via is the member a transit session goes through, or "" when the
// connection to the peer is direct.
func (s *Session) Via() string { return s.via }

// PeerVersion is the build version the peer announced in this session's
// handshake (tag 128), or "" when its build does not announce one.
func (s *Session) PeerVersion() string {
	if s.gate == nil {
		return ""
	}
	return s.gate.version
}

// PeerFeatures is the feature set the peer announced in this session's
// handshake (live: it changes only by reconnecting with another build).
func (s *Session) PeerFeatures() buildinfo.Features {
	if s.gate == nil {
		return buildinfo.Features{}
	}
	return s.gate.features
}

// Supports reports whether both ends may use this purpose/kind: each has
// the features it needs. Send helpers check it before writing a frame.
func (s *Session) Supports(p Purpose, kind uint8) bool {
	needs := needsOf(p, kind)
	if len(needs) == 0 {
		return true
	}
	return s.gate != nil && s.gate.common.Meets(needs...)
}
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
	if s.local != nil && (!localPurpose(purpose) || datagram || f.Kind == KindRelay) {
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
	t.SetStarting(false) // summarize what a node that never finished starting refused
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
	t.closeErr = errors.Join(t.closeErr, t.closeEngine())
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
	address = strings.TrimPrefix(address, "sfcp://")
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

// ErrNotConnected: an inbound-only node has no session from the peer.
var ErrNotConnected = errors.New("SFCP peer not connected")

// SetInboundOnly stops this node from dialing other nodes over QUIC. It is
// for a node most others cannot be reached from, such as a public ingress
// gateway in front of servers behind NAT: they connect to it, and it uses
// those sessions both ways. Management Unix sockets are unaffected.
func (t *Transport) SetInboundOnly(on bool) {
	t.mu.Lock()
	t.inboundOnly = on
	t.mu.Unlock()
}

// InboundOnly reports whether SetInboundOnly is on.
func (t *Transport) InboundOnly() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.inboundOnly
}

// Connected reports whether this node has a live authenticated QUIC session
// to key, opened by either side.
func (t *Transport) Connected(key Identity) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.channelOf(key).live()
}

// DialWait dials peer again after each failure until it gets a session or ctx
// ends. A dial fails before anything is sent, so trying again never repeats a
// request. It suits a peer that may connect to this node first, such as an
// existing member reaching a joining node that cannot reach it: the peer's
// inbound session ends the wait at once (see adoptSession).
func (t *Transport) DialWait(ctx context.Context, peer Peer) (*Session, error) {
	for {
		s, err := t.Dial(ctx, peer)
		if err == nil || ctx.Err() != nil {
			return s, err
		}
		select {
		case <-ctx.Done():
			return nil, err
		case <-t.ctx.Done():
			return nil, err
		case <-time.After(time.Second):
		}
	}
}

// PeerUnreachableError: no session to Peer (a server name) could be opened.
// Work that needs that server waits for it; it is not this server's fault.
type PeerUnreachableError struct {
	Peer string
	Err  error
}

func (e *PeerUnreachableError) Error() string {
	return fmt.Sprintf("SFCP authentication/dial failed for %s: %v", e.Peer, e.Err)
}
func (e *PeerUnreachableError) Unwrap() error { return e.Err }
