// SPDX-License-Identifier: Apache-2.0

package app

import (
	"errors"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

func TestPeerLookupReusesOnlyCurrentSuccessfulCommittedView(t *testing.T) {
	var cache peerLookupCache
	engine := &cluster.Engine{}
	v := cluster.View{RaftIndex: 1, Term: 1}
	key := mydcp.Identity{1}
	builds := 0
	derive := func() (mydcp.Peer, bool) {
		builds++
		return mydcp.Peer{Policy: mydcp.Policy{Key: key, Member: true, Tunnel: true}}, true
	}
	for range 3 {
		p, ok := cache.resolve(engine, v, nil, key, derive)
		if !ok || !p.Member || !p.Tunnel {
			t.Fatal("current member rejected")
		}
	}
	if builds != 1 {
		t.Fatal("same committed policy reparsed", builds)
	}
	deny := func() (mydcp.Peer, bool) { return mydcp.Peer{Policy: mydcp.Policy{Key: key}}, false }
	if p, ok := cache.resolve(engine, v, errors.New("failed durable read"), key, deny); ok || p.Member || p.Tunnel {
		t.Fatal("read failure reused old grant")
	}
	v.RaftIndex++
	if p, ok := cache.resolve(engine, v, nil, key, deny); ok || p.Member || p.Tunnel {
		t.Fatal("committed revocation reused old grant")
	}
	if p, ok := cache.resolve(&cluster.Engine{}, v, nil, key, deny); ok || p.Tunnel {
		t.Fatal("different Engine reused grant")
	}
	for i := 0; i < 130; i++ {
		cache.resolve(engine, v, nil, mydcp.Identity{byte(i)}, deny)
	}
	if len(cache.peers) > 64 {
		t.Fatal("unregistered key cache unbounded")
	}
	old := v
	old.RaftIndex--
	cache.resolve(engine, old, nil, key, derive)
	if p, ok := cache.resolve(engine, v, nil, key, deny); ok || p.Tunnel {
		t.Fatal("late old builder replaced revoked policy")
	}
}
