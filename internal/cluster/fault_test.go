// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"context"
	"errors"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/quic-go/quic-go"
)

func TestRealBoundaryCommittedWriteFailureAndSameDBReplay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	self, err := identity.Create(filepath.Join(t.TempDir(), "identity"))
	if err != nil {
		t.Fatal(err)
	}
	peer := sfcp.Peer{ID: "node", Policy: sfcp.Policy{Key: sfcp.Identity(self.Public), Member: true, Snapshot: true, Respond: true}}
	var peerMu sync.RWMutex
	lookup := func(key sfcp.Identity) (sfcp.Peer, bool) {
		peerMu.RLock()
		defer peerMu.RUnlock()
		return peer, key == peer.Key
	}
	mesh, err := sfcp.NewTransport(self, [32]byte{1}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if err = mesh.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	peerMu.Lock()
	peer.Endpoint = mesh.Addr().String()
	peerMu.Unlock()
	resolve := func(id raft.ServerID, address raft.ServerAddress) (sfcp.Peer, bool) {
		return peer, string(id) == peer.ID && string(address) == peer.Endpoint
	}
	o := Options{ID: peer.ID, Root: t.TempDir(), Admin: self.Actor(), Cluster: [32]byte{1}, Mesh: mesh, Resolve: resolve, Bootstrap: true, Servers: []raft.Server{{ID: raft.ServerID(peer.ID), Address: raft.ServerAddress(peer.Endpoint), Suffrage: raft.Voter}}}
	engine, err := Open(o)
	if err != nil {
		_ = mesh.Close()
		t.Fatal(err)
	}
	defer func() {
		if engine != nil {
			_ = engine.Close()
		}
		if mesh != nil {
			_ = mesh.Close()
		}
	}()
	wait := func(check func() bool) {
		t.Helper()
		for !check() {
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	wait(engine.IsLeader)
	first := state.Command{Actor: self.Actor(), Epoch: 1, RequestID: "first", Key: "network/test", Value: "before"}
	applied, err := engine.Submit(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	// Make the actual bbolt store unavailable, rather than injecting a fake FSM
	// return. The committed command must not produce a success response.
	if err = engine.db.Close(); err != nil {
		t.Fatal(err)
	}
	second := first
	second.RequestID = "uncertain"
	second.Expected = applied.Result.Revision
	second.Value = "after"
	if _, err = engine.Submit(ctx, second); !errors.Is(err, ErrUnknown) {
		t.Fatal("write failure reported a known success/non-execution", err)
	}
	select {
	case failure := <-engine.Failure():
		if failure == nil {
			t.Fatal("missing fatal write error")
		}
	case <-ctx.Done():
		t.Fatal("storage failure did not stop native owner")
	}
	if _, err = engine.Read(ctx, false); err == nil {
		t.Fatal("failed FSM published a healthy view")
	}
	_ = engine.Close()
	_ = mesh.Close()
	mesh, err = sfcp.NewTransport(self, [32]byte{1}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if err = mesh.Listen(peer.Endpoint); err != nil {
		t.Fatal(err)
	}
	o.Mesh = mesh
	engine, err = Open(o)
	if err != nil {
		t.Fatal(err)
	}
	wait(func() bool {
		v, err := engine.Read(ctx, false)
		return err == nil && v.State.Object(second.Key).Value == second.Value
	})
	v, err := engine.Read(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	result, found := v.State.LookupResult(second)
	if !found || result.Code != state.Applied || v.State.Index() != 2 {
		t.Fatal("committed uncertain request was lost or re-executed", result, v.State.Index())
	}
}

func TestRealBoundaryManagementDisconnectDoesNotRetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientID, err := identity.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	serverID, err := identity.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	clientPeer := sfcp.Peer{ID: "caller", Policy: sfcp.Policy{Key: sfcp.Identity(clientID.Public), Manage: true}}
	serverPeer := sfcp.Peer{ID: "server", Policy: sfcp.Policy{Key: sfcp.Identity(serverID.Public), Respond: true}}
	var peerMu sync.RWMutex
	lookup := func(key sfcp.Identity) (sfcp.Peer, bool) {
		peerMu.RLock()
		defer peerMu.RUnlock()
		if key == clientPeer.Key {
			return clientPeer, true
		}
		return serverPeer, key == serverPeer.Key
	}
	server, _ := sfcp.NewTransport(serverID, [32]byte{1}, lookup)
	defer server.Close()
	var received atomic.Int32
	if err = server.On(sfcp.Management, func(_ context.Context, _ *sfcp.Session, stream *quic.Stream, _ sfcp.Frame) error {
		received.Add(1)
		stream.CancelWrite(90)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = server.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	peerMu.Lock()
	serverPeer.Endpoint = server.Addr().String()
	peerMu.Unlock()
	client, _ := sfcp.NewTransport(clientID, [32]byte{1}, lookup)
	defer client.Close()
	command, _ := state.EncodeCommand(state.Command{Actor: clientID.Actor(), Epoch: 1, RequestID: "one", Key: "network/x", Value: "x"})
	r := ManagementRequest{Method: "submit", Command: command, Latest: true}
	_, err = CallManagement(ctx, client, clientID, [32]byte{1}, serverPeer, r)
	var outcome *ManagementError
	if !errors.As(err, &outcome) || outcome.Phase != sfcp.Unknown || received.Load() != 1 {
		t.Fatal("sent operation was retried or classified not-sent", err, received.Load())
	}
	before, cancelBefore := context.WithCancel(ctx)
	cancelBefore()
	_, err = CallManagement(before, client, clientID, [32]byte{1}, serverPeer, r)
	if !errors.As(err, &outcome) || outcome.Phase != sfcp.NotSent || received.Load() != 1 {
		t.Fatal("cancelled prepared request was sent", err, received.Load())
	}
}
