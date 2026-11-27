// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	raft "github.com/hashicorp/raft"
)

type realNode struct {
	identity      *identity.Identity
	mesh          *sfcp.Transport
	engine        *Engine
	root, address string
	options       Options
}

func TestRealBoundaryRaftQUICDurabilitySnapshotAndHandoff(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	fixtureID := func(i int) string {
		if os.Getenv("SFC_TEST_RQ6_CURRENT_VIEW_SDK") == "1" {
			return fmt.Sprintf("node-%d", i+1)
		}
		return fmt.Sprint(i + 1)
	}
	nodes := make([]realNode, 4)
	peers := map[sfcp.Identity]sfcp.Peer{}
	byID := map[string]sfcp.Peer{}
	var mu sync.RWMutex
	lookup := func(key sfcp.Identity) (sfcp.Peer, bool) {
		mu.RLock()
		defer mu.RUnlock()
		p, ok := peers[key]
		return p, ok
	}
	resolve := func(id raft.ServerID, address raft.ServerAddress) (sfcp.Peer, bool) {
		mu.RLock()
		defer mu.RUnlock()
		p, ok := byID[string(id)]
		return p, ok && p.Endpoint == string(address)
	}
	for i := range nodes {
		n := &nodes[i]
		var err error
		n.identity, err = identity.Create(filepath.Join(t.TempDir(), "identity"))
		if err != nil {
			t.Fatal(err)
		}
		n.root = filepath.Join(t.TempDir(), "state")
		key := sfcp.Identity(n.identity.Public)
		p := sfcp.Peer{ID: fixtureID(i), Policy: sfcp.Policy{Key: key, Member: true, Snapshot: true, Respond: true, Read: true, Manage: i == 0}}
		mu.Lock()
		peers[key] = p
		byID[p.ID] = p
		mu.Unlock()
		n.mesh, err = sfcp.NewTransport(n.identity, [32]byte{1}, lookup)
		if err != nil {
			t.Fatal(err)
		}
		if err = n.mesh.Listen("127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
		n.address = n.mesh.Addr().String()
		p.Endpoint = n.address
		mu.Lock()
		peers[key] = p
		byID[p.ID] = p
		mu.Unlock()
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
		suffrage := raft.Voter
		if i == 3 {
			suffrage = raft.Nonvoter
		}
		servers = append(servers, raft.Server{ID: raft.ServerID(fixtureID(i)), Address: raft.ServerAddress(nodes[i].address), Suffrage: suffrage})
	}
	for i := range nodes {
		n := &nodes[i]
		n.options = Options{ID: fixtureID(i), Root: n.root, Admin: nodes[0].identity.Actor(), Cluster: [32]byte{1}, Mesh: n.mesh, Resolve: resolve, Servers: servers, Bootstrap: i == 0}
		if os.Getenv("SFC_TEST_RQ6_CURRENT_VIEW_SDK") == "1" {
			configureCurrentViewSDK(&n.options, nodes)
		}
		var err error
		n.engine, err = Open(n.options)
		if err != nil {
			t.Fatal(err)
		}
		if err = n.engine.ServeManagement(); err != nil {
			t.Fatal(err)
		}
	}
	wait := func(what string, predicate func() bool) {
		t.Helper()
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			if predicate() {
				return
			}
			select {
			case <-ticker.C:
			case <-ctx.Done():
				t.Fatal("timeout: " + what)
			}
		}
	}
	leader := -1
	wait("initial leader", func() bool {
		for i := 0; i < 3; i++ {
			if nodes[i].engine != nil && nodes[i].engine.IsLeader() {
				leader = i
				return true
			}
		}
		return false
	})
	if os.Getenv("SFC_TEST_RQ6_CURRENT_VIEW_SDK") == "1" {
		// Managed policy rejects the legacy native mutation below. This branch
		// starts with its real signed enrollment in the same SDK fixture.
		verifyCurrentViewSDK(t, ctx, nodes, leader, wait, lookup)
		return
	}
	command := state.Command{Actor: nodes[0].identity.Actor(), Epoch: 1, RequestID: "create", Key: "network/tun", Value: "mtu=1400"}
	first, err := nodes[leader].engine.Submit(ctx, command)
	if err != nil || first.Result.Code != state.Applied || first.RaftIndex <= first.Result.Index {
		t.Fatal("actual Raft config/no-op index boundary", first, err)
	}
	wait("all voters and non-voter apply", func() bool {
		for i := range nodes {
			v, err := nodes[i].engine.Read(ctx, false)
			if err != nil || v.State.Object(command.Key).Value != command.Value {
				return false
			}
		}
		return true
	})
	if os.Getenv("SFC_TEST_RQ4_COMPACT_SDK") == "1" {
		verifyManualCompactSDK(t, ctx, nodes, leader, wait, lookup)
		return
	}
	if err = nodes[leader].engine.Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	duplicate, err := nodes[leader].engine.Submit(ctx, command)
	if err != nil || duplicate.Result != first.Result {
		t.Fatal("duplicate lost receipt", duplicate, err)
	}
	if duplicate.RaftIndex != first.RaftIndex+1 {
		t.Fatal("Submit inserted an extra log before the ordered Apply", first.RaftIndex, duplicate.RaftIndex)
	}
	// Close the leader, retain its exact DB/key/root, and require a voter handoff.
	oldLeader := leader
	n := &nodes[oldLeader]
	if err = n.engine.Close(); err != nil {
		t.Fatal(err)
	}
	n.engine = nil
	_ = n.mesh.Close()
	n.mesh = nil
	wait("new leader", func() bool {
		for i := 0; i < 3; i++ {
			if nodes[i].engine != nil && nodes[i].engine.IsLeader() {
				leader = i
				return true
			}
		}
		return false
	})
	command.RequestID = "update"
	command.Expected = first.Result.Revision
	command.Value = "mtu=1380"
	updated, err := nodes[leader].engine.Submit(ctx, command)
	if err != nil || updated.Result.Code != state.Applied {
		t.Fatal(updated, err)
	}
	// Reopen the original source with its snapshot plus a newer durable suffix.
	n.mesh, err = sfcp.NewTransport(n.identity, [32]byte{1}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if err = n.mesh.Listen(n.address); err != nil {
		t.Fatal(err)
	}
	n.options.Mesh = n.mesh
	n.engine, err = Open(n.options)
	if err != nil {
		t.Fatal(err)
	}
	if err = n.engine.ServeManagement(); err != nil {
		t.Fatal(err)
	}
	wait("same DB replay/catchup", func() bool {
		v, err := n.engine.Read(ctx, false)
		return err == nil && v.State.Object(command.Key).Value == command.Value
	})
	latest, err := nodes[leader].engine.Read(ctx, true)
	if err != nil || latest.Local || latest.State.Object(command.Key).Value != command.Value {
		t.Fatal("latest barrier", err)
	}
	configuration, err := nodes[leader].engine.Configuration(ctx)
	if err != nil || len(configuration.Servers) != 4 {
		t.Fatal("lost original voting configuration", err)
	}
	// A fresh approved non-voter must install the actual library snapshot after
	// prefix compaction; it cannot reconstruct state from retained command logs.
	replica := &nodes[3]
	if err = replica.engine.Close(); err != nil {
		t.Fatal(err)
	}
	replica.engine = nil
	if err = replica.mesh.Close(); err != nil {
		t.Fatal(err)
	}
	replica.mesh = nil
	if err = os.RemoveAll(filepath.Join(replica.root, "control")); err != nil {
		t.Fatal(err)
	}
	reload := nodes[leader].engine.raft.ReloadableConfig()
	reload.TrailingLogs = 0
	if err = nodes[leader].engine.raft.ReloadConfig(reload); err != nil {
		t.Fatal(err)
	}
	if err = nodes[leader].engine.Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	replica.mesh, err = sfcp.NewTransport(replica.identity, [32]byte{1}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if err = replica.mesh.Listen(replica.address); err != nil {
		t.Fatal(err)
	}
	replica.options.Mesh = replica.mesh
	replica.engine, err = Open(replica.options)
	if err != nil {
		t.Fatal(err)
	}
	if err = replica.engine.ServeManagement(); err != nil {
		t.Fatal(err)
	}
	wait("remote snapshot installation", func() bool {
		v, err := replica.engine.Read(ctx, false)
		return err == nil && v.State.Object(command.Key).Value == command.Value && replica.engine.raft.Stats()["last_snapshot_index"] != "0"
	})
	// The receiver removes its staged file after it answers the sender, and
	// the sender after the answer arrives; both follow FSM publication.
	wait("snapshot staging cleanup", func() bool {
		for i := range nodes {
			files, err := filepath.Glob(filepath.Join(nodes[i].root, "control", "staging", ".sfc-snapshot-*"))
			if err != nil || len(files) != 0 {
				return false
			}
		}
		return true
	})
	follower := (leader + 1) % 3
	if follower == 0 {
		follower = (follower + 1) % 3
	}
	mu.RLock()
	target := byID[nodes[follower].options.ID]
	mu.RUnlock()
	wire := state.Command{Actor: nodes[0].identity.Actor(), RequestID: "wire-submit", Epoch: 1, Key: "network/wire", Value: "signed original caller"}
	encoded, err := state.EncodeCommand(wire)
	if err != nil {
		t.Fatal(err)
	}
	request := ManagementRequest{Method: "submit", Command: encoded, Latest: true}
	reply, err := CallManagement(ctx, nodes[0].mesh, nodes[0].identity, [32]byte{1}, target, request)
	if err != nil || reply.Committed == nil || reply.Committed.Result.Code != state.Applied || reply.Node != nodes[leader].options.ID {
		t.Fatal("actual signed single-hop management", reply, err)
	}
	request.Method = "result"
	result, err := CallManagement(ctx, nodes[0].mesh, nodes[0].identity, [32]byte{1}, target, request)
	if err != nil || !result.Found || result.Result == nil || *result.Result != reply.Committed.Result {
		t.Fatal("durable original result query", result, err)
	}
	// A relay already marked as forwarded cannot ask another follower to relay.
	request.Schema = 1
	request.Method = "submit"
	request.Nonce = [16]byte{9}
	body, _ := json.Marshal(request)
	relay := signedRequest{Caller: sfcp.Identity(nodes[0].identity.Public), Body: body, Signature: ed25519.Sign(nodes[0].identity.Private, signingBytes([32]byte{1}, body)), Forwarded: true}
	noSecond, _, err := exchange(ctx, nodes[0].mesh, target, relay, sfcp.KindRelay)
	if err != nil || noSecond.Code != "not-leader" {
		t.Fatal("second forwarding allowed", noSecond, err)
	}
	relay.Signature[0] ^= 1
	if _, _, err = exchange(ctx, nodes[0].mesh, target, relay, sfcp.KindRelay); err == nil {
		t.Fatal("forged original signature accepted")
	}
	// A current non-voter cannot serve latest from its applied local state.
	readCtx, readCancel := context.WithTimeout(ctx, time.Second)
	_, readErr := replica.engine.Read(readCtx, true)
	readCancel()
	if readErr == nil {
		t.Fatal("non-voter served latest without leadership")
	}
	// Disconnect both other voters while leaving this leader and its synced
	// FSM alive. A previous successful latest view is no quorum for this call.
	for i := 0; i < 3; i++ {
		if i != leader {
			if err = nodes[i].mesh.Close(); err != nil {
				t.Fatal(err)
			}
			nodes[i].mesh = nil
		}
	}
	readCtx, readCancel = context.WithTimeout(ctx, 2*time.Second)
	_, readErr = nodes[leader].engine.Read(readCtx, true)
	readCancel()
	if readErr == nil {
		t.Fatal("latest reused previous quorum after both voters disconnected")
	}
	local, err := nodes[leader].engine.Read(ctx, false)
	if err != nil || !local.Local || local.State.Object(command.Key).Value != command.Value {
		t.Fatal("quorum refusal lost local durable state", err)
	}
}
