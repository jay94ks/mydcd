// SPDX-License-Identifier: Apache-2.0

package mydcp

import (
	"context"
	"fmt"
	"testing"

	quic "github.com/quic-go/quic-go"
)

func TestPeerWentAwayClassifiesConnectionEnds(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		want bool
	}{
		{"idle timeout", &quic.IdleTimeoutError{}, true},
		{"stateless reset", &quic.StatelessResetError{}, true},
		{"remote transport error", &quic.TransportError{Remote: true, ErrorCode: quic.InternalError}, true},
		{"local transport error (own link cut)", &quic.TransportError{ErrorCode: quic.InternalError, ErrorMessage: "sendmsg: operation not permitted"}, true},
		{"wrapped idle timeout", fmt.Errorf("accept: %w", &quic.IdleTimeoutError{}), true},
		{"peer shutdown", &quic.ApplicationError{Remote: true, ErrorMessage: shutdownMessage}, true},
		{"peer path retirement", &quic.ApplicationError{Remote: true, ErrorMessage: "underlay route changed"}, false},
		{"peer rejected dial", &quic.ApplicationError{Remote: true, ErrorCode: 1, ErrorMessage: "dial/authentication failed"}, false},
		{"own shutdown", &quic.ApplicationError{ErrorMessage: shutdownMessage}, false},
		{"own path retirement", &quic.ApplicationError{ErrorMessage: "underlay route changed"}, false},
		{"own context canceled", context.Canceled, false},
		{"nil", nil, false},
	} {
		if got := peerWentAway(c.err); got != c.want {
			t.Errorf("%s: peerWentAway(%v) = %t, want %t", c.name, c.err, got, c.want)
		}
	}
}

func TestSessionEndedReportsOnlyTheLastLostMemberConnection(t *testing.T) {
	newTransport := func() (*Transport, chan Peer) {
		lost := make(chan Peer, 8)
		tr := &Transport{livePeers: map[Identity]int{}}
		tr.OnPeerLost(func(p Peer) { lost <- p })
		return tr, lost
	}
	session := func(tr *Transport, key byte, member bool) *Session {
		s := &Session{transport: tr, peer: Peer{ID: fmt.Sprintf("node-%d", key), Policy: Policy{Key: Identity{key}, Member: member}}}
		tr.livePeers[s.peer.Key]++
		return s
	}
	drain := func(tr *Transport, lost chan Peer) []string {
		tr.wg.Wait()
		var ids []string
		for {
			select {
			case p := <-lost:
				ids = append(ids, p.ID)
			default:
				return ids
			}
		}
	}
	idle := &quic.IdleTimeoutError{}

	// Two connections to one member: only the second end reports, once.
	tr, lost := newTransport()
	first, second := session(tr, 1, true), session(tr, 1, true)
	tr.sessionEnded(first, idle)
	if got := drain(tr, lost); len(got) != 0 {
		t.Fatalf("reported while another connection to the peer was live: %v", got)
	}
	tr.sessionEnded(second, idle)
	if got := drain(tr, lost); len(got) != 1 || got[0] != "node-1" {
		t.Fatalf("last lost connection reported %v, want [node-1]", got)
	}
	if _, ok := tr.livePeers[Identity{1}]; ok {
		t.Fatal("live count kept after the last connection ended")
	}

	// A reconnect after the loss counts afresh.
	again := session(tr, 1, true)
	tr.sessionEnded(again, &quic.ApplicationError{Remote: true, ErrorMessage: shutdownMessage})
	if got := drain(tr, lost); len(got) != 1 {
		t.Fatalf("peer shutdown after reconnect reported %v, want one report", got)
	}

	// A deliberate close is not a loss.
	retired := session(tr, 2, true)
	tr.sessionEnded(retired, &quic.ApplicationError{ErrorMessage: "underlay route changed"})
	if got := drain(tr, lost); len(got) != 0 {
		t.Fatalf("own path retirement reported %v", got)
	}

	// Client sessions (CLI, wallets) end all the time and never report.
	client := session(tr, 3, false)
	tr.sessionEnded(client, idle)
	if got := drain(tr, lost); len(got) != 0 {
		t.Fatalf("non-member session reported %v", got)
	}

	// A joining replica (Replicate only) does report.
	joining := &Session{transport: tr, peer: Peer{ID: "joiner", Policy: Policy{Key: Identity{4}, Replicate: true}}}
	tr.livePeers[joining.peer.Key]++
	tr.sessionEnded(joining, idle)
	if got := drain(tr, lost); len(got) != 1 || got[0] != "joiner" {
		t.Fatalf("replicating peer reported %v, want [joiner]", got)
	}

	// Once this transport is closed, nothing reports.
	tr.closed = true
	gone := session(tr, 5, true)
	tr.sessionEnded(gone, idle)
	if got := drain(tr, lost); len(got) != 0 {
		t.Fatalf("closed transport reported %v", got)
	}

	// Without a handler nothing panics.
	plain := &Transport{livePeers: map[Identity]int{}}
	s := session(plain, 6, true)
	plain.sessionEnded(s, idle)
	plain.wg.Wait()
}

func TestSessionStartedReportsOnlyTheFirstMemberConnection(t *testing.T) {
	found := make(chan Peer, 8)
	tr := &Transport{}
	tr.OnPeerConnected(func(p Peer) { found <- p })
	session := func(key byte, member bool) *Session {
		return &Session{transport: tr, peer: Peer{ID: fmt.Sprintf("node-%d", key), Policy: Policy{Key: Identity{key}, Member: member}}}
	}
	drain := func() []string {
		tr.wg.Wait()
		var ids []string
		for {
			select {
			case p := <-found:
				ids = append(ids, p.ID)
			default:
				return ids
			}
		}
	}
	first := session(1, true)
	tr.sessionStarted(first)
	tr.sessionStarted(session(1, true))
	tr.sessionStarted(session(2, false)) // a client, not a member
	if got := drain(); len(got) != 1 || got[0] != "node-1" {
		t.Fatalf("connected reports %v, want [node-1]", got)
	}
	// After the last connection ends, the next one reports again.
	tr.sessionEnded(first, nil)
	tr.sessionEnded(session(1, true), nil)
	tr.sessionStarted(session(1, true))
	if got := drain(); len(got) != 1 || got[0] != "node-1" {
		t.Fatalf("reconnect reports %v, want [node-1]", got)
	}
}
