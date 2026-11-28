// SPDX-License-Identifier: Apache-2.0

package app

import (
	"errors"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/sfcp"
)

func TestMeshLinksDialOnlyPeersWithoutSessionAndBackOff(t *testing.T) {
	a := sfcp.Peer{ID: "a", Policy: sfcp.Policy{Key: sfcp.Identity{1}}}
	b := sfcp.Peer{ID: "b", Policy: sfcp.Policy{Key: sfcp.Identity{2}}}
	connected := map[sfcp.Identity]bool{a.Key: true}
	isConnected := func(k sfcp.Identity) bool { return connected[k] }
	var links meshLinks
	now := time.Unix(1000, 0)
	ids := func(ps []sfcp.Peer) (out []string) {
		for _, p := range ps {
			out = append(out, p.ID)
		}
		return out
	}
	if got := ids(links.due(now, []sfcp.Peer{a, b}, isConnected)); len(got) != 1 || got[0] != "b" {
		t.Fatal("must dial only the peer without a session", got)
	}
	if got := links.due(now, []sfcp.Peer{a, b}, isConnected); len(got) != 0 {
		t.Fatal("a dial in flight must not start another", ids(got))
	}
	links.done(now, b.Key, false)
	if got := links.due(now.Add(500*time.Millisecond), []sfcp.Peer{a, b}, isConnected); len(got) != 0 {
		t.Fatal("retried before backoff")
	}
	// Backoff doubles up to its cap.
	at := now
	for want := meshLinkFirstRetry; ; want = min(2*want, meshLinkMaxRetry) {
		at = at.Add(want)
		if got := links.due(at, []sfcp.Peer{b}, isConnected); len(got) != 1 {
			t.Fatal("no retry after", want)
		}
		links.done(at, b.Key, false)
		if links.peers[b.Key].retry == meshLinkMaxRetry {
			break
		}
	}
	// Once the peer connects (to us or we to it), dialing stops and resets.
	connected[b.Key] = true
	if got := links.due(at.Add(time.Hour), []sfcp.Peer{a, b}, isConnected); len(got) != 0 || links.peers[b.Key].retry != 0 {
		t.Fatal("dialed a connected peer")
	}
	// A peer that is no longer a member is forgotten.
	links.due(at, []sfcp.Peer{a}, isConnected)
	if _, ok := links.peers[b.Key]; ok {
		t.Fatal("removed peer kept")
	}
}

// A dial failing the same way is logged once, again when the failure changes,
// and once when it recovers.
func TestMeshLinksLogEachOutcomeChangeOnce(t *testing.T) {
	var links meshLinks
	peer := sfcp.Peer{ID: "a", Key: sfcp.Identity{1}}
	now := time.Now()
	links.due(now, []sfcp.Peer{peer}, func(sfcp.Identity) bool { return false })
	refused, lost := errors.New("refused"), errors.New("lost")
	for i, step := range []struct {
		err  error
		want bool
	}{{nil, false}, {refused, true}, {refused, false}, {lost, true}, {nil, true}, {nil, false}} {
		if got := links.logged(peer.Key, step.err); got != step.want {
			t.Fatalf("step %d: logged = %v", i, got)
		}
	}
}
