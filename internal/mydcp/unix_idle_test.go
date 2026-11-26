// SPDX-License-Identifier: Apache-2.0

package mydcp

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func unixIdleEcho(t *testing.T, server *Transport) (*atomic.Int32, <-chan *localConnection) {
	t.Helper()
	calls := new(atomic.Int32)
	connections := make(chan *localConnection, 8)
	if err := server.OnManagement(User, func(ctx context.Context, s *Session, stream Stream, frame Frame) error {
		calls.Add(1)
		connections <- s.local
		var extra [1]byte
		if n, err := stream.Read(extra[:]); n != 0 || err != io.EOF {
			return ErrFrame
		}
		frame.Kind = 2
		return WriteFrame(stream, frame)
	}); err != nil {
		t.Fatal(err)
	}
	return calls, connections
}

func unixIdleExchange(t *testing.T, ctx context.Context, session *Session, id uint64) {
	t.Helper()
	stream, err := session.OpenManagement(ctx)
	if err != nil {
		t.Fatal(err)
	}
	unixIdleStreamExchange(t, stream, session, id)
}

func unixIdleStreamExchange(t *testing.T, stream Stream, session *Session, id uint64) {
	t.Helper()
	defer stream.CancelRead(0)
	defer stream.CancelWrite(0)
	if err := WriteFrame(stream, u0UserFrame(id, []byte("idle-reuse"))); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	frame, err := ReadFrame(stream, MaxBody)
	if err != nil || frame.Request != id || session.Admit(frame, User, false) != nil {
		t.Fatalf("exchange reply: frame=%+v err=%v", frame, err)
	}
	var extra [1]byte
	if n, err := stream.Read(extra[:]); n != 0 || err != io.EOF {
		t.Fatalf("exchange EOF: n=%d err=%v", n, err)
	}
}

func TestUnixIdleServerExpiryRedialsBeforeNextRequest(t *testing.T) {
	server, client, peer, path := u0UnixPair(t)
	calls, connections := unixIdleEcho(t, server)
	if err := server.ListenUnix(path); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	first, err := client.Dial(ctx, peer)
	if err != nil {
		t.Fatal(err)
	}
	unixIdleExchange(t, ctx, first, 71)
	remote := <-connections
	// Exercise the real production deadline, without changing the server budget
	// or forcing a socket close. No request is sent while the peer expires.
	select {
	case <-remote.done:
	case <-ctx.Done():
		t.Fatal("server did not reach its idle close", ctx.Err())
	}
	second, err := client.Dial(ctx, peer)
	if err != nil {
		t.Fatal(err)
	}
	if second == first {
		t.Fatalf("stale session returned after real server idle close: client_closed=%t handler_calls=%d; next request has not been sent", first.local.closed.Load(), calls.Load())
	}
	unixIdleExchange(t, ctx, second, 72)
	if calls.Load() != 2 {
		t.Fatalf("request lost or replayed: handler_calls=%d", calls.Load())
	}
}

func expireUnixReuse(s *Session) {
	s.transport.mu.Lock()
	s.local.reuseUntil = time.Now().Add(-time.Second)
	s.transport.mu.Unlock()
}

func TestUnixIdleBusyExchangeIsNotClosedByDial(t *testing.T) {
	server, client, peer, path := u0UnixPair(t)
	calls, _ := unixIdleEcho(t, server)
	if err := server.ListenUnix(path); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, err := client.Dial(ctx, peer)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := first.OpenManagement(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.CancelRead(0)
	// Model a long exchange at the local cache boundary; the peer remains live.
	expireUnixReuse(first)
	cached, err := client.Dial(ctx, peer)
	if err != nil || cached != first || first.local.closed.Load() {
		t.Fatal("cache expiry interrupted an acquired exchange", err)
	}
	unixIdleStreamExchange(t, stream, first, 81)
	fresh, err := client.Dial(ctx, peer)
	if err != nil || fresh == first || !first.local.closed.Load() {
		t.Fatal("completed expired exchange was retained", err)
	}
	unixIdleExchange(t, ctx, fresh, 82)
	if calls.Load() != 2 {
		t.Fatal("lost or repeated exchange", calls.Load())
	}
}

func TestUnixIdleRetainedSessionRejectsLateOpenBeforeSend(t *testing.T) {
	server, client, peer, path := u0UnixPair(t)
	calls, _ := unixIdleEcho(t, server)
	if err := server.ListenUnix(path); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := client.Dial(ctx, peer)
	if err != nil {
		t.Fatal(err)
	}
	unixIdleExchange(t, ctx, s, 91)
	expireUnixReuse(s)
	stream, err := s.OpenManagement(ctx)
	if stream != nil || !errors.Is(err, net.ErrClosed) || calls.Load() != 1 {
		t.Fatal("expired retained session opened/sent a new request", stream, err, calls.Load())
	}
	s.transport.mu.Lock()
	cached, tracked := s.transport.localSessions[peer.Key], len(s.transport.localConnections)
	s.transport.mu.Unlock()
	if cached != nil || tracked != 0 {
		t.Fatal("expired connection remained tracked")
	}
	fresh, err := client.Dial(ctx, peer)
	if err != nil || fresh == s {
		t.Fatal("explicit fresh dial failed", err)
	}
	unixIdleExchange(t, ctx, fresh, 92)
}

func TestUnixIdleConcurrentDialsReplaceOnlyOneExpiredSession(t *testing.T) {
	server, client, peer, path := u0UnixPair(t)
	_, _ = unixIdleEcho(t, server)
	if err := server.ListenUnix(path); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	old, err := client.Dial(ctx, peer)
	if err != nil {
		t.Fatal(err)
	}
	expireUnixReuse(old)
	type result struct {
		s   *Session
		err error
	}
	results := make(chan result, 8)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); s, err := client.Dial(ctx, peer); results <- result{s, err} }()
	}
	wg.Wait()
	close(results)
	var fresh *Session
	for r := range results {
		if r.err != nil || r.s == old {
			t.Fatal("stale/concurrent dial", r.err)
		}
		if fresh != nil && fresh != r.s {
			t.Fatal("duplicate fresh sessions")
		}
		fresh = r.s
	}
	if !old.local.closed.Load() || fresh.PeerChallenge() == old.PeerChallenge() {
		t.Fatal("old binding retained")
	}
	unixIdleExchange(t, ctx, fresh, 101)
}
