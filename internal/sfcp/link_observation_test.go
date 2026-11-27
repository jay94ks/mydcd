// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"context"
	"github.com/jay94ks/seafield/internal/identity"
	"testing"
	"time"
)

func TestMemberMeshObservationKeepsOtherAuthenticatedConnectionAlive(t *testing.T) {
	a, e := identity.Ephemeral()
	if e != nil {
		t.Fatal(e)
	}
	defer clear(a.Private)
	b, e := identity.Ephemeral()
	if e != nil {
		t.Fatal(e)
	}
	defer clear(b.Private)
	peers := map[Identity]Peer{Identity(a.Public): {ID: "a", Policy: Policy{Key: Identity(a.Public), Member: true, Report: true, Read: true, Respond: true}}, Identity(b.Public): {ID: "b", Policy: Policy{Key: Identity(b.Public), Member: true, Report: true, Read: true, Respond: true}}}
	lookup := func(k Identity) (Peer, bool) { p, ok := peers[k]; return p, ok }
	left, e := NewTransport(a, [32]byte{42}, lookup)
	if e != nil {
		t.Fatal(e)
	}
	defer left.Close()
	right, e := NewTransport(b, [32]byte{42}, lookup)
	if e != nil {
		t.Fatal(e)
	}
	defer right.Close()
	if e = left.Listen("127.0.0.1:0"); e != nil {
		t.Fatal(e)
	}
	if e = right.Listen("127.0.0.1:0"); e != nil {
		t.Fatal(e)
	}
	ap, bp := peers[Identity(a.Public)], peers[Identity(b.Public)]
	ap.Endpoint, bp.Endpoint = left.Addr().String(), right.Addr().String()
	peers[ap.Key], peers[bp.Key] = ap, bp
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ab, e := left.Dial(ctx, bp)
	if e != nil {
		t.Fatal(e)
	}
	// right reuses left's connection now; drop it from right's channel so
	// right dials its own second connection, as two nodes dialing at once do.
	for {
		right.mu.Lock()
		adopted := right.channelOf(ap.Key) != nil
		if adopted {
			right.peerOf(ap.Key).channel = nil
		}
		right.mu.Unlock()
		if adopted {
			break
		}
		time.Sleep(time.Millisecond)
	}
	ba, e := right.Dial(ctx, ap)
	if e != nil {
		t.Fatal(e)
	}
	wait := func(check func() bool) {
		t.Helper()
		for !check() {
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(time.Millisecond):
			}
		}
	}
	wait(func() bool {
		left.mu.Lock()
		defer left.mu.Unlock()
		return len(left.peerOf(bp.Key).link.connections) == 2
	})
	// Repeated purpose admission must not register another close callback for
	// every frame on alternating inbound/outbound member connections.
	left.mu.Lock()
	var tracked []*Session
	for session := range left.peerOf(bp.Key).link.connections {
		tracked = append(tracked, session)
	}
	left.mu.Unlock()
	for _, session := range tracked {
		for i := 0; i < 10; i++ {
			left.observeMemberSession(session, bp)
		}
	}
	if e = ab.conn.CloseWithError(0, "fixture closes one of two paths"); e != nil {
		t.Fatal(e)
	}
	state, ok := left.LinkObservation("a", bp)
	if !ok || state.State == "down" || len(state.Outages) != 0 {
		t.Fatal("one closed connection became a member outage", state)
	}
	kept, err := left.ReconnectBrokenMember(ctx, "a", bp)
	if err != nil || kept.State != "already-connected" || !kept.KeptExisting || ba.conn.Context().Err() != nil {
		t.Fatal("reconnect disrupted surviving authenticated member path", err)
	}
	if e = ba.conn.CloseWithError(0, "fixture closes final path"); e != nil {
		t.Fatal(e)
	}
	wait(func() bool { state, ok = left.LinkObservation("a", bp); return ok && state.State == "down" })
	if len(state.Outages) != 1 || state.Outages[0].StartedAt == 0 || state.Outages[0].EndedAt != 0 {
		t.Fatal("final connection did not produce one real outage", state)
	}
	reconnected, err := left.ReconnectBrokenMember(ctx, "a", bp)
	if err != nil || reconnected.State != "reconnected" || reconnected.KeptExisting || reconnected.PairID != state.ID || reconnected.HandshakeAt < state.LastHandshakeAt {
		t.Fatal("actual broken member link did not authenticate again", err)
	}
	state, ok = left.LinkObservation("a", bp)
	if !ok || state.State == "down" || len(state.Outages) != 1 || state.Outages[0].EndedAt == 0 {
		t.Fatal("same PairID outage not closed by actual handshake")
	}
	if _, err := left.ReconnectBrokenMember(ctx, "a", ap); err == nil {
		t.Fatal("self reconnect accepted")
	}
}
