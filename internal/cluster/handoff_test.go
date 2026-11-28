// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"

	"github.com/hashicorp/raft"
)

// A stopping leader hands leadership to another voter; a follower has
// nothing to hand off (devel/design/upgrades.md 3-5).
func TestRealBoundaryLeadershipHandOff(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	nodes := make([]realNode, 3)
	peers := map[sfcp.Identity]sfcp.Peer{}
	byID := map[string]sfcp.Peer{}
	var mu sync.RWMutex
	lookup := func(k sfcp.Identity) (sfcp.Peer, bool) {
		mu.RLock()
		defer mu.RUnlock()
		p, ok := peers[k]
		return p, ok
	}
	resolve := func(id raft.ServerID, a raft.ServerAddress) (sfcp.Peer, bool) {
		mu.RLock()
		defer mu.RUnlock()
		p, ok := byID[string(id)]
		return p, ok && p.Endpoint == string(a)
	}
	defer func() {
		for i := range nodes {
			if nodes[i].engine != nil {
				_ = nodes[i].engine.Close()
			}
			if nodes[i].mesh != nil {
				_ = nodes[i].mesh.Close()
			}
		}
	}()
	for i := range nodes {
		n := &nodes[i]
		var e error
		if n.identity, e = identity.Create(filepath.Join(t.TempDir(), "identity")); e != nil {
			t.Fatal(e)
		}
		n.root = t.TempDir()
		key := sfcp.Identity(n.identity.Public)
		p := sfcp.Peer{ID: fmt.Sprint(i), Policy: sfcp.Policy{Key: key, Member: true, Respond: true, Snapshot: true}}
		if n.mesh, e = sfcp.NewTransport(n.identity, [32]byte{6}, lookup); e != nil {
			t.Fatal(e)
		}
		if e = n.mesh.Listen("127.0.0.1:0"); e != nil {
			t.Fatal(e)
		}
		n.address = n.mesh.Addr().String()
		p.Endpoint = n.address
		mu.Lock()
		peers[key] = p
		byID[p.ID] = p
		mu.Unlock()
	}
	var servers []raft.Server
	for i := range nodes {
		servers = append(servers, raft.Server{ID: raft.ServerID(fmt.Sprint(i)), Address: raft.ServerAddress(nodes[i].address), Suffrage: raft.Voter})
	}
	for i := range nodes {
		var e error
		n := &nodes[i]
		if n.engine, e = Open(Options{ID: fmt.Sprint(i), Root: n.root, Admin: nodes[0].identity.Actor(), Cluster: [32]byte{6}, Mesh: n.mesh, Resolve: resolve, Servers: servers, Bootstrap: i == 0}); e != nil {
			t.Fatal(e)
		}
	}
	leaderOf := func() int {
		for i := range nodes {
			if nodes[i].engine.IsLeader() {
				return i
			}
		}
		return -1
	}
	wait := func(f func() bool) {
		t.Helper()
		for !f() {
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	leader := -1
	wait(func() bool { leader = leaderOf(); return leader >= 0 })
	follower := (leader + 1) % len(nodes)
	if done, err := nodes[follower].engine.HandOffLeadership(ctx); done || err != nil {
		t.Fatal("follower handed off", done, err)
	}
	if done, err := nodes[leader].engine.HandOffLeadership(ctx); !done || err != nil {
		t.Fatal("leader did not hand off", done, err)
	}
	wait(func() bool { l := leaderOf(); return l >= 0 && l != leader })
	if done, err := (*Engine)(nil).HandOffLeadership(ctx); done || err != nil {
		t.Fatal("nil engine")
	}
}
