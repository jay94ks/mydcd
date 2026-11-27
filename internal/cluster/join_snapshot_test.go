// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/sfcp"

	"github.com/hashicorp/raft"
)

// The SDK setup here deliberately compacts the owned source log. This tests
// the real managed indexed Snapshot/directory/A2 replication adapter. CLI
// invitation/installation/promotion has its own actual multi-node test.
func TestRealManagedJoiningReplicationInstallsDirectorySnapshot(t *testing.T) {
	f := newControlBoundary(t, func(f *controlBoundary) {
		socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address := socket.LocalAddr().String()
		_ = socket.Close()
		peer := f.peers[sfcp.Identity(f.node.Public)]
		peer.Endpoint = address
		f.peers[peer.Key] = peer
		f.policy.TrustRoot, f.policy.Genesis = f.node.Public, config.Peer{ID: "node", Key: f.node.Actor(), Endpoint: address, Voter: true}
		f.options.Validate, f.options.Reduce, f.options.AdmitModule, f.options.ModuleID = f.policy.Validate, f.policy.Reduce, f.policy.AdmitModule, f.policy.ID()
		f.options.TrackConfiguration = true
		f.options.Resolve = func(id raft.ServerID, address raft.ServerAddress) (sfcp.Peer, bool) {
			f.mu.RLock()
			defer f.mu.RUnlock()
			for _, p := range f.peers {
				if p.ID == string(id) && p.Endpoint == string(address) {
					return p, true
				}
			}
			return sfcp.Peer{}, false
		}
	})
	f.enroll()
	target, err := identity.Create(filepath.Join(t.TempDir(), "joining-key"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(target.Private)
	p := sfcp.Peer{ID: "learner", Policy: sfcp.Policy{Key: sfcp.Identity(target.Public), Replicate: true, Snapshot: true, Respond: true}}
	f.mu.Lock()
	f.peers[p.Key] = p
	f.mu.Unlock()
	mesh, err := sfcp.NewTransport(target, f.policy.Cluster, f.lookup)
	if err != nil {
		t.Fatal(err)
	}
	defer mesh.Close()
	if err = mesh.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	p.Endpoint = mesh.Addr().String()
	f.mu.Lock()
	f.peers[p.Key] = p
	f.mu.Unlock()
	actual, err := f.engine.InstalledConfiguration(f.ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	// Populate and persist the same signed managed directory/A2 Dispatch before
	// compacting its source logs. The target must restore the original job too.
	catalog := f.catalog()
	user, _ := catalog.User("admin")
	session := access.Session{Schema: 1, ID: "snapshot-admin", Cluster: f.policy.Cluster, User: user.ID, Credential: "key", AccountRevision: user.Revision, Key: f.client.Public, Issuer: f.node.Public, IssuerEpoch: 1, IssuedAt: 1, ExpiresAt: 100, Scopes: []access.Scope{{Tenant: "*", Actions: []access.Action{access.ManageCluster}}}}
	session.Signature = ed25519.Sign(f.node.Private, access.SessionBytes(session))
	raw, _ := control.ChangeBytes("invite-node", "admin", 0, control.NodeInvitation{Peer: config.Peer{ID: p.ID, Key: target.Actor(), Endpoint: p.Endpoint}, JoinID: "join-snapshot"})
	var change control.Change
	_ = json.Unmarshal(raw, &change)
	operation := control.UserOperation{Schema: 1, Session: session, At: 2, Epoch: 1, RequestID: "invite-snapshot", Change: change}
	operation.Signature = ed25519.Sign(f.client.Private, control.OperationBytes(operation))
	cmd, err := operation.Command()
	if err != nil {
		t.Fatal(err)
	}
	if committed, err := f.engine.Submit(f.ctx, cmd); err != nil || committed.Result.Code != state.Applied {
		t.Fatal("managed snapshot invitation", committed.Result, err)
	}
	before := f.view()
	directory, err := f.policy.Members(before.State)
	if err != nil {
		t.Fatal(err)
	}
	entry, _ := directory.Entry(p.ID)
	report := control.MemberReport{Schema: 1, Cluster: f.policy.Cluster, Reporter: f.node.Public, Action: "dispatch", Node: p.ID, Expected: entry.Revision, JobID: entry.Job.Pending.ID, ConfigurationIndex: actual.Index, Epoch: 1, RequestID: "dispatch-snapshot", RootRevision: before.State.Object(control.MembersKey).Revision}
	report.Signature = ed25519.Sign(f.node.Private, control.MemberReportBytes(report))
	cmd, err = report.Command()
	if err != nil {
		t.Fatal(err)
	}
	if committed, err := f.engine.Submit(f.ctx, cmd); err != nil || committed.Result.Code != state.Applied {
		t.Fatal("durable pre-SDK dispatch", committed.Result, err)
	}
	position := f.view().RaftIndex
	reload := f.engine.raft.ReloadableConfig()
	reload.TrailingLogs = 0
	if err := f.engine.raft.ReloadConfig(reload); err != nil {
		t.Fatal(err)
	}
	if err := f.engine.Snapshot(f.ctx); err != nil {
		t.Fatal(err)
	}
	var removed raft.Log
	if err := f.engine.log.GetLog(position, &removed); !errors.Is(err, raft.ErrLogNotFound) {
		t.Fatal("source Snapshot prefix remains in log store", position, err)
	}
	// Invoke one SDK change only after the original Dispatch is committed.
	if err = f.engine.await(f.ctx, func() raft.Future {
		return f.engine.raft.AddNonvoter(raft.ServerID(p.ID), raft.ServerAddress(p.Endpoint), actual.Index, remaining(f.ctx))
	}); err != nil {
		t.Fatal(err)
	}
	options := f.options
	options.ID, options.Root, options.Mesh, options.Bootstrap, options.Servers = p.ID, t.TempDir(), mesh, false, nil
	replica, err := Open(options)
	if err != nil {
		t.Fatal(err)
	}
	defer replica.Close()
	f.wait(func() bool {
		view, err := replica.Read(f.ctx, false)
		if err != nil {
			return false
		}
		catalog, err := f.policy.Catalog(view.State)
		if err != nil {
			return false
		}
		directory, err := f.policy.Members(view.State)
		if err != nil {
			return false
		}
		entry, ok := directory.Entry(p.ID)
		users, _ := catalog.Counts()
		return users == 1 && ok && entry.Job.Pending != nil && entry.Job.Pending.Phase == reconcile.Dispatched && entry.BaseIndex == actual.Index
	})
	f.wait(func() bool {
		cfg, err := replica.InstalledConfiguration(f.ctx, false)
		return err == nil && len(cfg.Configuration.Servers) == 2 && cfg.Index > actual.Index
	})
	snapshots, err := filepath.Glob(filepath.Join(options.Root, "control", "snapshots", "*", "state.bin"))
	if err != nil || len(snapshots) == 0 {
		t.Fatal("no real received native Snapshot", err)
	}
	input, err := os.Open(snapshots[0])
	if err != nil {
		t.Fatal(err)
	}
	header := make([]byte, snapshotHeaderSize+12)
	_, err = io.ReadFull(input, header)
	_ = input.Close()
	if err != nil || string(header[:4]) != "MDS1" || string(header[snapshotHeaderSize:snapshotHeaderSize+4]) != "MDC1" || binary.LittleEndian.Uint64(header[snapshotHeaderSize+4:]) != actual.Index {
		t.Fatal("indexed native Snapshot payload lost its original configuration floor", err)
	}
	if current, _ := f.lookup(p.Key); current.Member || !current.Replicate {
		t.Fatal("test silently granted full membership")
	}
	t.Log("actual compacted SDK snapshot crossed SFCP to replication-only nonvoter; original managed directory/A2 dispatch/catalog/configuration index installed")
}
