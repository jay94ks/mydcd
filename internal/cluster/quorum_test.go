// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"

	"github.com/hashicorp/raft"
)

func TestRealBoundaryEvenVoterQuorumAndNonvoter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	nodes := make([]realNode, 5)
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
		n.identity, e = identity.Create(filepath.Join(t.TempDir(), "identity"))
		if e != nil {
			t.Fatal(e)
		}
		n.root = t.TempDir()
		key := sfcp.Identity(n.identity.Public)
		p := sfcp.Peer{ID: fmt.Sprint(i), Policy: sfcp.Policy{Key: key, Member: true, Respond: true, Snapshot: true}}
		mu.Lock()
		peers[key] = p
		byID[p.ID] = p
		mu.Unlock()
		n.mesh, e = sfcp.NewTransport(n.identity, [32]byte{5}, lookup)
		if e != nil {
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
	servers := []raft.Server{}
	for i := range nodes {
		s := raft.Voter
		if i == 4 {
			s = raft.Nonvoter
		}
		servers = append(servers, raft.Server{ID: raft.ServerID(fmt.Sprint(i)), Address: raft.ServerAddress(nodes[i].address), Suffrage: s})
	}
	for i := range nodes {
		var e error
		n := &nodes[i]
		n.engine, e = Open(Options{ID: fmt.Sprint(i), Root: n.root, Admin: nodes[0].identity.Actor(), Cluster: [32]byte{5}, Mesh: n.mesh, Resolve: resolve, Servers: servers, Bootstrap: i == 0})
		if e != nil {
			t.Fatal(e)
		}
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
	wait(func() bool {
		for i := 0; i < 4; i++ {
			if nodes[i].engine != nil && nodes[i].engine.IsLeader() {
				leader = i
				return true
			}
		}
		return false
	})
	c := state.Command{Actor: nodes[0].identity.Actor(), Epoch: 1, RequestID: "before", Key: "network/even", Value: "before"}
	first, e := nodes[leader].engine.Submit(ctx, c)
	if e != nil || first.Result.Code != state.Applied {
		t.Fatal(first, e)
	}
	wait(func() bool {
		v, e := nodes[4].engine.Read(ctx, false)
		return e == nil && v.State.Object(c.Key).Value == "before"
	})
	old := leader
	if e = nodes[old].engine.Close(); e != nil {
		t.Fatal(e)
	}
	nodes[old].engine = nil
	_ = nodes[old].mesh.Close()
	nodes[old].mesh = nil
	wait(func() bool {
		for i := 0; i < 4; i++ {
			if nodes[i].engine != nil && nodes[i].engine.IsLeader() {
				leader = i
				return true
			}
		}
		return false
	})
	c.RequestID = "three-voters"
	c.Expected = first.Result.Revision
	c.Value = "three"
	next, e := nodes[leader].engine.Submit(ctx, c)
	if e != nil || next.Result.Code != state.Applied {
		t.Fatal("N4 Q3 one failed", next, e)
	}
	second := -1
	for i := 0; i < 4; i++ {
		if i != leader && nodes[i].engine != nil {
			second = i
			break
		}
	}
	if e = nodes[second].engine.Close(); e != nil {
		t.Fatal(e)
	}
	nodes[second].engine = nil
	_ = nodes[second].mesh.Close()
	nodes[second].mesh = nil
	// Two voters plus an active nonvoter cannot replace the committed Q3.
	c.RequestID = "two-voters"
	c.Expected = next.Result.Revision
	c.Value = "forbidden"
	short, stop := context.WithTimeout(ctx, 1200*time.Millisecond)
	_, e = nodes[leader].engine.Submit(short, c)
	stop()
	if e == nil {
		t.Fatal("nonvoter counted toward quorum")
	}
	for i := range nodes {
		if nodes[i].engine != nil {
			v, e := nodes[i].engine.Read(ctx, false)
			if e != nil || v.State.Object(c.Key).Value == "forbidden" {
				t.Fatal("minority state", i, v, e)
			}
		}
	}
	config, e := nodes[4].engine.Configuration(ctx)
	if e != nil || len(config.Servers) != 5 {
		t.Fatal("failure shrank roster", config, e)
	}
	t.Log("N4/Q3: real voter handoff with one fault; two voters + nonvoter cannot commit; original configuration retained")
}
