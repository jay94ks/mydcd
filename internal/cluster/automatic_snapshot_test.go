// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"

	"github.com/hashicorp/raft"
)

func TestRealBoundaryRaftAutomaticFollowerSnapshotAndTailRecovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	var nodes [2]realNode
	peers := make(map[mydcp.Identity]mydcp.Peer)
	byID := make(map[string]mydcp.Peer)
	var peersMu sync.RWMutex
	lookup := func(key mydcp.Identity) (mydcp.Peer, bool) {
		peersMu.RLock()
		defer peersMu.RUnlock()
		p, ok := peers[key]
		return p, ok
	}
	resolve := func(id raft.ServerID, address raft.ServerAddress) (mydcp.Peer, bool) {
		peersMu.RLock()
		defer peersMu.RUnlock()
		p, ok := byID[string(id)]
		return p, ok && p.Endpoint == string(address)
	}
	defer func() {
		for i := range nodes {
			n := &nodes[i]
			if n.engine != nil {
				if err := n.engine.Close(); err != nil {
					t.Error(err)
				}
			}
			if n.mesh != nil {
				_ = n.mesh.Close()
			}
		}
	}()
	for i := range nodes {
		n := &nodes[i]
		var err error
		n.root = filepath.Join(t.TempDir(), "state")
		n.identity, err = identity.Create(filepath.Join(t.TempDir(), "identity"))
		if err != nil {
			t.Fatal(err)
		}
		n.mesh, err = mydcp.NewTransport(n.identity, [32]byte{73}, lookup)
		if err == nil {
			err = n.mesh.Listen("127.0.0.1:0")
		}
		if err != nil {
			t.Fatal(err)
		}
		n.address = n.mesh.Addr().String()
		p := mydcp.Peer{ID: fmt.Sprint(i + 1), Endpoint: n.address, Policy: mydcp.Policy{Key: mydcp.Identity(n.identity.Public), Member: true, Snapshot: true, Respond: true, Read: true}}
		peersMu.Lock()
		peers[p.Key], byID[p.ID] = p, p
		peersMu.Unlock()
	}
	servers := make([]raft.Server, 0, 2)
	for i := range nodes {
		servers = append(servers, raft.Server{ID: raft.ServerID(fmt.Sprint(i + 1)), Address: raft.ServerAddress(nodes[i].address), Suffrage: raft.Voter})
	}
	for i := range nodes {
		n := &nodes[i]
		n.options = Options{ID: fmt.Sprint(i + 1), Root: n.root, Admin: nodes[0].identity.Actor(), Cluster: [32]byte{73}, Mesh: n.mesh, Resolve: resolve, Servers: servers, Bootstrap: i == 0, TrackConfiguration: true}
		var err error
		n.engine, err = Open(n.options)
		if err != nil {
			t.Fatal(err)
		}
	}
	wait := func(label string, predicate func() bool) {
		t.Helper()
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for !predicate() {
			select {
			case <-ctx.Done():
				t.Fatal(label, ctx.Err())
			case <-tick.C:
			}
		}
	}
	leader := -1
	wait("N2 leader", func() bool {
		for i := range nodes {
			if nodes[i].engine.IsLeader() {
				leader = i
				return true
			}
		}
		return false
	})
	command := state.Command{Actor: nodes[0].identity.Actor(), Epoch: 1, RequestID: "original", Key: "network/tun", Value: "original"}
	first, err := nodes[leader].engine.Submit(ctx, command)
	if err != nil || first.Result.Code != state.Applied {
		t.Fatal("original committed request", first, err)
	}
	last := first
	// This finite sequence triggers the production snapshot threshold. It
	// exercises original receipt replay, not a throughput/load measurement.
	for range 256 {
		last, err = nodes[leader].engine.Submit(ctx, command)
		if err != nil || last.Result != first.Result {
			t.Fatal("original replay changed its result", last, err)
		}
	}
	follower := &nodes[1-leader]
	var snapshotIndex uint64
	wait("follower SDK automatic durable snapshot without manual Snapshot", func() bool {
		snapshotIndex, _ = strconv.ParseUint(follower.engine.raft.Stats()["last_snapshot_index"], 10, 64)
		return snapshotIndex >= last.RaftIndex
	})
	tailCommand := command
	tailCommand.RequestID, tailCommand.Expected, tailCommand.Value = "tail", first.Result.Revision, "after-snapshot"
	tail, err := nodes[leader].engine.Submit(ctx, tailCommand)
	if err != nil || tail.Result.Code != state.Applied || tail.RaftIndex <= snapshotIndex {
		t.Fatal("tail must follow original snapshot", tail, snapshotIndex, err)
	}
	wait("original follower persists tail", func() bool {
		v, err := follower.engine.Read(ctx, false)
		return err == nil && v.State.Object(command.Key).Value == tailCommand.Value
	})
	if err = follower.engine.Close(); err != nil {
		t.Fatal(err)
	}
	follower.engine = nil
	if err = follower.mesh.Close(); err != nil {
		t.Fatal(err)
	}
	follower.mesh, err = mydcp.NewTransport(follower.identity, [32]byte{73}, lookup)
	if err == nil {
		err = follower.mesh.Listen(follower.address)
	}
	if err != nil {
		t.Fatal(err)
	}
	follower.options.Mesh = follower.mesh
	follower.engine, err = Open(follower.options)
	if err != nil {
		t.Fatal(err)
	}
	wait("original snapshot plus tail reaches strict durable replay floor", func() bool {
		s, _, _, err := follower.engine.fsm.view(true)
		return err == nil && s.Object(command.Key).Value == tailCommand.Value
	})
	v, err := follower.engine.Read(ctx, false)
	result, found := v.State.LookupResult(command)
	configuration, configErr := follower.engine.InstalledConfiguration(ctx, false)
	if err != nil || configErr != nil || !found || result != first.Result || len(configuration.Configuration.Servers) != 2 || configuration.Index == 0 {
		t.Fatal("snapshot lost original receipt/configuration", result, found, err, configErr)
	}
	t.Log("actual N2 SDK automatic snapshot", snapshotIndex, "then original tail", tail.RaftIndex, "same DB/key strict replay-ready, original receipt and configuration retained")
}
