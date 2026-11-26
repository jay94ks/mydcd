// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"

	"github.com/hashicorp/raft"
)

// Latest reads used to append one LogBarrier each, so an idle cluster's
// commit index rose with every permit or work read (R14). Only the first
// latest read of a leader term may write; later ones must still observe
// every command committed before they started.
func TestRealBoundaryLatestReadsDoNotGrowRaftLog(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	nodes := make([]realNode, 3)
	peers := map[mydcp.Identity]mydcp.Peer{}
	byID := map[string]mydcp.Peer{}
	var mu sync.RWMutex
	lookup := func(k mydcp.Identity) (mydcp.Peer, bool) {
		mu.RLock()
		defer mu.RUnlock()
		p, ok := peers[k]
		return p, ok
	}
	resolve := func(id raft.ServerID, a raft.ServerAddress) (mydcp.Peer, bool) {
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
	servers := []raft.Server{}
	for i := range nodes {
		n := &nodes[i]
		var err error
		if n.identity, err = identity.Create(filepath.Join(t.TempDir(), "identity")); err != nil {
			t.Fatal(err)
		}
		n.root = t.TempDir()
		key := mydcp.Identity(n.identity.Public)
		if n.mesh, err = mydcp.NewTransport(n.identity, [32]byte{6}, lookup); err != nil {
			t.Fatal(err)
		}
		if err = n.mesh.Listen("127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
		n.address = n.mesh.Addr().String()
		p := mydcp.Peer{ID: fmt.Sprint(i), Endpoint: n.address, Policy: mydcp.Policy{Key: key, Member: true, Respond: true, Snapshot: true}}
		mu.Lock()
		peers[key], byID[p.ID] = p, p
		mu.Unlock()
		servers = append(servers, raft.Server{ID: raft.ServerID(p.ID), Address: raft.ServerAddress(n.address), Suffrage: raft.Voter})
	}
	for i := range nodes {
		var err error
		if nodes[i].engine, err = Open(Options{ID: fmt.Sprint(i), Root: nodes[i].root, Admin: nodes[0].identity.Actor(), Cluster: [32]byte{6}, Mesh: nodes[i].mesh, Resolve: resolve, Servers: servers, Bootstrap: i == 0}); err != nil {
			t.Fatal(err)
		}
	}
	var leader *Engine
	for leader == nil {
		for i := range nodes {
			if nodes[i].engine.IsLeader() {
				leader = nodes[i].engine
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	if _, err := leader.Read(ctx, true); err != nil {
		t.Fatal(err)
	}
	c := state.Command{Actor: nodes[0].identity.Actor(), Epoch: 1, RequestID: "first", Key: "network/read-index", Value: "first"}
	committed, err := leader.Submit(ctx, c)
	if err != nil || committed.Result.Code != state.Applied {
		t.Fatal(committed, err)
	}
	last := leader.raft.LastIndex()
	for i := 0; i < 20; i++ {
		v, err := leader.Read(ctx, true)
		if err != nil || v.Local || v.State.Object(c.Key).Value != "first" {
			t.Fatal("latest read missed a committed command", err)
		}
	}
	if got := leader.raft.LastIndex(); got != last {
		t.Fatalf("latest reads appended %d Raft log entries", got-last)
	}
	// A command committed between reads is still observed by the next one.
	c.RequestID, c.Value, c.Expected = "second", "second", committed.Result.Revision
	if committed, err = leader.Submit(ctx, c); err != nil || committed.Result.Code != state.Applied {
		t.Fatal(committed, err)
	}
	if v, err := leader.Read(ctx, true); err != nil || v.State.Object(c.Key).Value != "second" {
		t.Fatal("latest read after a commit missed it", err)
	}
	// The leader counts exactly what it appended this term.
	writes, since := leader.WriteCounts()
	got := map[string]uint64{}
	for _, w := range writes {
		got[w.Kind] = w.Count
	}
	if since.IsZero() || len(got) != 2 || got["read-barrier"] != 1 || got["mutate network/…"] != 2 {
		t.Fatal("leader write counts", writes)
	}
}

func TestWriteLabelKeepsOnlySymbolicActions(t *testing.T) {
	for _, c := range []struct {
		command state.Command
		want    string
	}{
		{state.Command{Kind: state.ModuleReport, Key: "control/apps", Value: `{"Action":"observe","Key":"secret/path"}`}, "report control/apps observe"},
		{state.Command{Kind: state.Module, Key: "control/access", Value: `{"Change":{"Action":"put-user"}}`}, "change control/access put-user"},
		{state.Command{Kind: state.ModuleReport, Key: "control/volumes", Value: `{"Kind":"Has Space/../x"}`}, "report control/volumes"},
		{state.Command{Kind: state.Mutate, Key: "network/a", Value: `{"Action":"observe"}`}, "mutate network/…"},
		{state.Command{Kind: state.Module, Key: "control/vault/acme", Value: `{"Change":{"Action":"put-secret"}}`}, "change control/vault/… put-secret"},
		{state.Command{Kind: state.ModuleReport, Key: "control/network-sources/bridge/acme/services/node-a"}, "report control/network-sources/…"},
	} {
		if got := writeLabel(c.command); got != c.want {
			t.Errorf("writeLabel = %q, want %q", got, c.want)
		}
	}
}
