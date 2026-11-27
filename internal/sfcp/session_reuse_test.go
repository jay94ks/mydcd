// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/identity"
	quic "github.com/quic-go/quic-go"
)

type reusePair struct {
	public, nat       *Transport
	publicKey, natKey Identity
	peers             map[Identity]Peer
}

// newReusePair builds a public node that listens and a node behind NAT whose
// recorded endpoint never answers: a bound UDP socket nobody reads.
func newReusePair(t *testing.T) *reusePair {
	t.Helper()
	sink, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	pub, err := identity.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	nat, err := identity.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := &reusePair{publicKey: Identity(pub.Public), natKey: Identity(nat.Public), peers: map[Identity]Peer{}}
	policy := func(key Identity) Policy {
		return Policy{Key: key, Read: true, Respond: true, Member: true, Report: true}
	}
	p.peers[p.natKey] = Peer{ID: "home", Endpoint: sink.LocalAddr().String(), Policy: policy(p.natKey)}
	lookup := func(key Identity) (Peer, bool) { peer, ok := p.peers[key]; return peer, ok }
	if p.public, err = NewTransport(pub, [32]byte{1}, lookup); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.public.Close() })
	if p.nat, err = NewTransport(nat, [32]byte{1}, lookup); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.nat.Close() })
	echo := func(ctx context.Context, s *Session, stream *quic.Stream, f Frame) error {
		f.Kind = 2
		return WriteFrame(stream, f)
	}
	for _, tr := range []*Transport{p.public, p.nat} {
		if err := tr.On(Management, echo); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.public.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	p.peers[p.publicKey] = Peer{ID: "vps", Endpoint: p.public.Addr().String(), Policy: policy(p.publicKey)}
	return p
}

func roundTrip(t *testing.T, ctx context.Context, s *Session) {
	t.Helper()
	stream, err := s.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.CancelRead(0)
	defer stream.Close()
	f := sample()
	f.Kind = 3
	if err := WriteFrame(stream, f); err != nil {
		t.Fatal(err)
	}
	reply, err := ReadFrame(stream, MaxBody)
	if err != nil || reply.Request != f.Request || s.Admit(reply, Management, false) != nil {
		t.Fatal("round trip over reused session", err)
	}
}

func TestDialReusesInboundSessionFromNodeBehindNAT(t *testing.T) {
	p := newReusePair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := p.nat.Dial(ctx, p.peers[p.publicKey])
	if err != nil {
		t.Fatal(err)
	}
	// The public node's view of the inbound session is adopted right after
	// authentication; wait for it instead of racing the accept goroutine.
	deadline := time.Now().Add(2 * time.Second)
	for {
		p.public.mu.Lock()
		s := p.public.channelOf(p.natKey)
		p.public.mu.Unlock()
		if s.live() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("inbound session was never adopted")
		}
		time.Sleep(10 * time.Millisecond)
	}
	started := time.Now()
	in, err := p.public.Dial(ctx, p.peers[p.natKey])
	if err != nil {
		t.Fatal("public node dialed the unreachable endpoint instead of reusing the inbound session:", err)
	}
	if time.Since(started) > time.Second || in.outbound || in.conn.LocalAddr().String() != out.conn.RemoteAddr().String() {
		t.Fatal("Dial did not return the inbound session")
	}
	// Both ends name the NAT node as the one that opened the session.
	if l, ok := p.public.LinkObservation("vps", p.peers[p.natKey]); !ok || l.Dialer != "home" {
		t.Fatal("public end dialer", l.Dialer, ok)
	}
	if l, ok := p.nat.LinkObservation("home", p.peers[p.publicKey]); !ok || l.Dialer != "home" {
		t.Fatal("NAT end dialer", l.Dialer, ok)
	}
	roundTrip(t, ctx, in)  // public → NAT over the NAT node's connection
	roundTrip(t, ctx, out) // and the original direction still works

	// When the connection ends, the peer is unreachable again: no stale reuse.
	_ = out.conn.CloseWithError(0, "test")
	for time.Now().Before(deadline.Add(3 * time.Second)) {
		p.public.mu.Lock()
		s, n := p.public.channelOf(p.natKey), p.public.sessionCount(p.natKey)
		p.public.mu.Unlock()
		if s == nil && n == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("ended inbound session was not released")
}

func TestInboundSessionAbortsPendingDialToNodeBehindNAT(t *testing.T) {
	p := newReusePair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	type result struct {
		s   *Session
		err error
		at  time.Duration
	}
	done := make(chan result, 1)
	started := time.Now()
	go func() {
		s, err := p.public.Dial(ctx, p.peers[p.natKey])
		done <- result{s, err, time.Since(started)}
	}()
	time.Sleep(200 * time.Millisecond) // the public node is now stuck in its handshake
	out, err := p.nat.Dial(ctx, p.peers[p.publicKey])
	if err != nil {
		t.Fatal(err)
	}
	r := <-done
	if r.err != nil {
		t.Fatal("pending dial did not resolve to the inbound session:", r.err)
	}
	if r.at > 3*time.Second || r.s.outbound || r.s.conn.LocalAddr().String() != out.conn.RemoteAddr().String() {
		t.Fatal("pending dial waited for its own handshake", r.at)
	}
	roundTrip(t, ctx, r.s)
}

func TestSimultaneousDialsConvergeOnOneSession(t *testing.T) {
	for i := 0; i < 3; i++ {
		p := newReusePair(t)
		if err := p.nat.Listen("127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
		home := p.peers[p.natKey]
		home.Endpoint = p.nat.Addr().String()
		p.peers[p.natKey] = home
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		errs := make(chan error, 2)
		go func() { _, err := p.public.Dial(ctx, p.peers[p.natKey]); errs <- err }()
		go func() { _, err := p.nat.Dial(ctx, p.peers[p.publicKey]); errs <- err }()
		for range 2 {
			if err := <-errs; err != nil {
				t.Fatal(err)
			}
		}
		// Both nodes must end up using the same connection.
		deadline := time.Now().Add(3 * time.Second)
		for {
			p.public.mu.Lock()
			a := p.public.channelOf(p.natKey)
			p.public.mu.Unlock()
			p.nat.mu.Lock()
			b := p.nat.channelOf(p.publicKey)
			p.nat.mu.Unlock()
			if a.live() && b.live() && a.conn.LocalAddr().String() == b.conn.RemoteAddr().String() && a.conn.RemoteAddr().String() == b.conn.LocalAddr().String() {
				roundTrip(t, ctx, a)
				roundTrip(t, ctx, b)
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("nodes chose different sessions")
			}
			time.Sleep(10 * time.Millisecond)
		}
		cancel()
	}
}

func TestPreferSessionAndReleasePromotesStandby(t *testing.T) {
	local, peer := Identity{2}, Identity{1}
	if bytes.Compare(peer[:], local[:]) >= 0 {
		t.Fatal("test keys")
	}
	inbound := &Session{peer: Peer{Policy: Policy{Key: peer}}, authenticatedAt: 1}
	outbound := &Session{peer: Peer{Policy: Policy{Key: peer}}, authenticatedAt: 2, outbound: true}
	if !preferSession(inbound, outbound, local) || preferSession(outbound, inbound, local) {
		t.Fatal("session opened by the smaller key must win on both nodes")
	}
	newer := &Session{peer: Peer{Policy: Policy{Key: peer}}, authenticatedAt: 3}
	if !preferSession(newer, inbound, local) {
		t.Fatal("a newer session from the same initiator must win")
	}

	// Promotion on release, with real connections for liveness.
	p := newReusePair(t)
	if err := p.nat.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	home := p.peers[p.natKey]
	home.Endpoint = p.nat.Addr().String()
	p.peers[p.natKey] = home
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, err := p.nat.Dial(ctx, p.peers[p.publicKey])
	if err != nil {
		t.Fatal(err)
	}
	// A second live session from the other side, made as a race would.
	p.public.mu.Lock()
	chosen := p.public.channelOf(p.natKey)
	p.public.peerOf(p.natKey).channel = nil
	p.public.mu.Unlock()
	second, err := p.public.Dial(ctx, p.peers[p.natKey])
	if err != nil || second == chosen {
		t.Fatal("second session", err)
	}
	p.public.adoptSession(chosen)
	p.public.mu.Lock()
	want, standby := p.public.channelOf(p.natKey), chosen
	if want == chosen {
		standby = second
	}
	n := p.public.sessionCount(p.natKey)
	p.public.mu.Unlock()
	if n != 2 {
		t.Fatal("both sessions tracked", n)
	}
	_ = want.conn.CloseWithError(0, "test")
	deadline := time.Now().Add(3 * time.Second)
	for {
		p.public.mu.Lock()
		s := p.public.channelOf(p.natKey)
		p.public.mu.Unlock()
		if s == standby {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("standby session did not take over")
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = first
	roundTrip(t, ctx, standby)
}

func TestInboundOnlyNodeNeverDialsAndWaitsForThePeer(t *testing.T) {
	p := newReusePair(t)
	p.public.SetInboundOnly(true)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// The NAT node is listening this time, so only the option stops the dial.
	if err := p.nat.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	home := p.peers[p.natKey]
	home.Endpoint = p.nat.Addr().String()
	p.peers[p.natKey] = home
	if _, err := p.public.Dial(ctx, home); !errors.Is(err, ErrNotConnected) {
		t.Fatal("inbound-only node dialed", err)
	}
	if p.public.Connected(p.natKey) || p.nat.Connected(p.publicKey) {
		t.Fatal("a connection was made")
	}
	done := make(chan *Session, 1)
	go func() {
		s, err := p.public.DialWait(ctx, home)
		if err != nil {
			t.Error(err)
		}
		done <- s
	}()
	time.Sleep(300 * time.Millisecond)
	out, err := p.nat.Dial(ctx, p.peers[p.publicKey])
	if err != nil {
		t.Fatal(err)
	}
	s := <-done
	if s == nil || s.outbound || s.conn.LocalAddr().String() != out.conn.RemoteAddr().String() {
		t.Fatal("DialWait did not return the inbound session")
	}
	roundTrip(t, ctx, s)
}

// sessionCount is the number of live QUIC sessions to key. Caller holds t.mu.
func (t *Transport) sessionCount(key Identity) int {
	if p := t.peerOf(key); p != nil {
		return len(p.sessions)
	}
	return 0
}
