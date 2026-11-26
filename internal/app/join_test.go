// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/bootstrap"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/membership"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
	"gopkg.in/yaml.v3"
)

func TestRealManagedJoinNonvoterAndExplicitPromotion(t *testing.T) {
	testRealManagedJoin(t, false)
}

func TestRealRuntimeInstalledNodeIdentityRotationRestartsTLSAndRevokesOldCurrentAuthority(t *testing.T) {
	testRealManagedJoin(t, false, "node-identity")
}

func TestRealRuntimeForceRemovalRequiresFreshProbeAndPreservesHistory(t *testing.T) {
	testRealManagedJoin(t, false, "node-force")
}

func TestRealRuntimeNodeIsolationRestoreLeaderRemovalAndQuorum(t *testing.T) {
	testRealManagedJoin(t, false, "node-runtime")
}

func TestRealAppPlanStreamMemberRelay(t *testing.T) {
	testRealManagedJoin(t, true)
}

func testRealManagedJoin(t *testing.T, streamPlan bool, scenario ...string) {
	budget := 45 * time.Second
	nativeDetails := len(scenario) > 0 && scenario[0] == "details-native"
	nativeObservations := nativeDetails || len(scenario) > 0 && scenario[0] == "observations-native"
	if nativeObservations {
		budget = 180 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	root, err := os.MkdirTemp("", "mydc-managed-join-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Log("preserved original managed join DBs", root)
			return
		}
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	})
	key := func(name string) *identity.Identity {
		t.Helper()
		self, err := identity.Create(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { clear(self.Private) })
		return self
	}
	vacant := func() string {
		t.Helper()
		p, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		a := p.LocalAddr().String()
		_ = p.Close()
		return a
	}
	nodeConfig := func(id string) config.Node {
		c := config.Node{Version: 1, Common: config.Common{}, Modules: map[string]config.Module{"network": {}, "workload": {}, "ingress": {}}}
		c.Node.ID, c.Node.Listen = id, vacant()
		c.Node.StateDir, c.Node.IdentityDir = filepath.Join(root, id, "state"), filepath.Join(root, id, "key")
		if nativeObservations {
			if err := yaml.Unmarshal([]byte("network: {enabled: true, docker_socket: 'unix:///var/run/docker.sock'}\nworkload: {enabled: true}\ningress: {enabled: false}\n"), &c.Modules); err != nil {
				t.Fatal(err)
			}
		}
		return c
	}
	admin := key("admin")
	aCfg := nodeConfig("node-a")
	initialized, err := Initialize(ctx, aCfg, admin.Public, "init-three")
	if err != nil {
		t.Fatal(err)
	}
	a, err := Open(aCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if a != nil {
			_ = a.Close()
		}
	}()
	if _, err = a.InstallConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	clusterID := initialized.Installation.Root.Cluster
	sourceKey := a.Identity.Public
	policy := control.Policy{Cluster: clusterID, BootstrapKey: admin.Public, TrustRoot: sourceKey, Genesis: initialized.Installation.Genesis}
	self, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(self.Private)
	peers := map[mydcp.Identity]mydcp.Peer{}
	var peerMu sync.RWMutex
	client := userauth.Client{Self: self, Cluster: clusterID}
	addPeer := func(p config.Peer) mydcp.Peer {
		k, _ := identity.ParseKey(p.Key)
		v := mydcp.Peer{ID: p.ID, Endpoint: p.Endpoint, Policy: mydcp.Policy{Key: mydcp.Identity(k), Respond: true}}
		peerMu.Lock()
		peers[v.Key] = v
		peerMu.Unlock()
		client.Peers = append(client.Peers, v)
		return v
	}
	source := addPeer(initialized.Installation.Genesis)
	client.Mesh, err = mydcp.NewTransport(self, clusterID, func(k mydcp.Identity) (mydcp.Peer, bool) {
		peerMu.RLock()
		defer peerMu.RUnlock()
		p, ok := peers[k]
		return p, ok
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Mesh.Close()
	enrolled, err := client.Enroll(ctx, source, control.Enrollment{Schema: 1, RequestID: "first-admin", User: access.User{ID: "admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: admin.Public, Enabled: true}}}}, admin.Private)
	if err != nil || enrolled.Result == nil || enrolled.Result.Code != state.Applied {
		t.Fatal("enroll", err)
	}
	session, err := client.Login(ctx, source, "admin", admin.Private)
	if err != nil {
		t.Fatal("login", err)
	}
	submit := func(id, action string, expected uint64, payload any) {
		t.Helper()
		raw, _ := control.ChangeBytes(action, "admin", expected, payload)
		var ch control.Change
		_ = json.Unmarshal(raw, &ch)
		op, err := client.Prepare(ctx, source, session, id, ch)
		if err != nil {
			t.Fatal("prepare", action, err)
		}
		out, err := client.Operation(ctx, source, op, false)
		if err != nil || out.Result == nil || out.Result.Code != state.Applied {
			t.Fatal("submit", action, out.Result, err)
		}
	}
	directory := func(r *Runtime) membership.Directory {
		t.Helper()
		view, err := r.Engine().Read(ctx, false)
		if err != nil {
			t.Fatal(err)
		}
		d, err := policy.Members(view.State)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	wait := func(label string, check func() bool) {
		t.Helper()
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for !check() {
			select {
			case <-ctx.Done():
				t.Fatal(label, ctx.Err())
			case <-tick.C:
			}
		}
	}
	if len(scenario) > 0 && scenario[0] == "tenant-retirement" {
		verifyControlOnlyTenantRetirement(t, ctx, a, client, source, session, policy, submit, wait)
		return
	}
	type joined struct {
		config  config.Node
		runtime *Runtime
		inv     membership.Invitation
		record  bootstrap.Record
		peer    mydcp.Peer
	}
	var nodes []*joined
	defer func() {
		for _, n := range nodes {
			if n.runtime != nil {
				_ = n.runtime.Close()
			}
		}
	}()
	for i, id := range []string{"node-b", "node-c"} {
		cfg := nodeConfig(id)
		nodeKey, err := identity.Create(cfg.Node.IdentityDir)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(nodeKey.Private)
		target := config.Peer{ID: id, Key: nodeKey.Actor(), Endpoint: cfg.Node.Listen}
		submit("invite-"+id, "invite-node", 0, control.NodeInvitation{Peer: target, JoinID: "join-" + id})
		inv, err := client.NodeInvitation(ctx, source, session, id)
		if err != nil {
			t.Fatal("invitation", id, err)
		}
		// Wrong pins fail before creating the target's state root.
		if _, err = bootstrap.PrepareJoin(cfg, inv, clusterID, [32]byte{99}); err == nil {
			t.Fatal("untrusted invitation accepted")
		}
		if _, err = os.Stat(cfg.Node.StateDir); !os.IsNotExist(err) {
			t.Fatal("bad pin created state root", err)
		}
		runtime, record, err := Join(ctx, cfg, inv, clusterID, sourceKey)
		if err != nil {
			t.Fatal("real join", id, err)
		}
		n := &joined{cfg, runtime, inv, record, addPeer(target)}
		nodes = append(nodes, n)
		own, ok := record.Root.Installed.Member(id)
		if !ok || own.Voter || record.Ack == nil || record.Root.Operation != inv.JoinID {
			t.Fatal("nonvoter/local ACK contract")
		}
		wait("installed member replication", func() bool { e, ok := directory(runtime).Entry(id); return ok && e.Phase == membership.Ready })
		e, _ := directory(a).Entry(id)
		if !reflect.DeepEqual(e.Ack, record.Ack) || e.Peer.Voter || e.Job.Pending != nil {
			t.Fatal("original persisted ACK mismatch")
		}
		native, err := a.Engine().InstalledConfiguration(ctx, true)
		if err != nil || len(native.Configuration.Servers) != i+2 {
			t.Fatal("native nonvoter addition", err)
		}
		voters := 0
		for _, server := range native.Configuration.Servers {
			if server.Suffrage == raft.Voter {
				voters++
			}
		}
		if voters != i+1 {
			t.Fatal("implicit voter promotion", voters)
		}
		if len(scenario) > 0 && scenario[0] == "user-client" {
			verifyNonvoterContainerClient(t, ctx, runtime, clusterID, source, n.peer, filepath.Join(filepath.Dir(n.config.Node.StateDir), "user.sock"), admin.Private)
			return
		}
		if len(scenario) > 0 && scenario[0] == "lifecycle-editor" {
			verifyLifecycleEditorRemoteProvider(t, ctx, a, runtime, client, source, session, policy, submit, root)
			return
		}
		if len(scenario) > 0 && scenario[0] == "task-measurement-identity" {
			verifyRetainedTaskMeasurementIdentity(t, ctx, &n.runtime, policy, submit, wait)
			return
		}
		if streamPlan {
			if len(scenario) > 0 && scenario[0] == "volume-move-recipe" {
				verifyVolumeMoveAuthority(t, ctx, a, &n.runtime, n.config, client, session, source, policy, submit, wait, true)
				return
			}
			if len(scenario) > 0 && scenario[0] == "volume-move" {
				verifyVolumeMoveAuthority(t, ctx, a, &n.runtime, n.config, client, session, source, policy, submit, wait)
				return
			}
			if len(scenario) > 0 && scenario[0] == "tunnel" {
				verifyAppTunnelAdmission(t, ctx, a, runtime, client, session, source, policy, submit)
				return
			}
			verifyAppPlanStreamRelay(t, ctx, a, runtime, client, session, n.peer, policy, submit, wait)
			return
		}
		// Exactly one separate current administrator proposal enables SDK AddVoter.
		if _, err := client.Login(ctx, n.peer, "admin", admin.Private); err == nil {
			t.Fatal("installed non-voter issued a user session")
		} else {
			var denied *userauth.Error
			if !errors.As(err, &denied) || denied.Code != "not-session-issuer" {
				t.Fatal("non-voter login failed for an unexpected reason", err)
			}
		}
		submit("promote-"+id, "promote-node", e.Revision, control.NodeSelection{ID: id})
		wait("explicit native promotion", func() bool {
			e, ok := directory(a).Entry(id)
			return ok && e.Phase == membership.Active && e.Peer.Voter
		})
		wait("issuer's own installed voter prefix", func() bool {
			for _, key := range directory(runtime).SessionIssuers() {
				if key == runtime.Identity.Public {
					return true
				}
			}
			return false
		})
		fresh, err := client.Login(ctx, n.peer, "admin", admin.Private)
		if err != nil || fresh.Issuer != runtime.Identity.Public || fresh.Approval == nil {
			t.Fatal("active follower must issue its own independently approved grant", err)
		}
		if err := runtime.Engine().Snapshot(ctx); err != nil {
			t.Fatal("indexed local Snapshot", err)
		}
		if len(scenario) > 0 && scenario[0] == "observations" {
			verifyTwoNodeObservations(t, ctx, a, runtime, client, session, source, n.peer, policy, submit, wait)
			return
		}
		if len(scenario) > 0 && scenario[0] == "events" {
			verifyTwoNodeEventBoundary(t, ctx, a, runtime, client, session, source, submit, wait)
			return
		}
		if len(scenario) > 0 && scenario[0] == "raft-events" {
			verifyRaftEventIdentity(t, ctx, a, client, session, source, wait)
			return
		}
		if nativeObservations {
			verifyTwoNodeNativeObservations(t, ctx, a, runtime, aCfg, cfg, client, session, source, n.peer, policy, submit, wait, root, nativeDetails)
			return
		}
	}
	// The original source can die; two dynamically admitted voters elect and
	// authorize user sessions from their current shared issuer directory.
	if len(scenario) > 0 && scenario[0] == "node-identity" {
		verifyRuntimeIdentityRotation(t, ctx, []*Runtime{a, nodes[0].runtime, nodes[1].runtime}, client, session, policy, submit, wait)
		return
	}
	if len(scenario) > 0 && scenario[0] == "node-force" {
		verifyRuntimeForceRemoval(t, ctx, []*Runtime{a, nodes[0].runtime, nodes[1].runtime}, client, session, policy, wait)
		return
	}
	if len(scenario) > 0 && scenario[0] == "node-runtime" {
		verifyRuntimeNodeLifecycle(t, ctx, []*Runtime{a, nodes[0].runtime, nodes[1].runtime}, client, session, admin.Private, policy, submit, wait)
		return
	}
	if err = a.Close(); err != nil {
		t.Fatal(err)
	}
	a = nil
	wait("new majority leader", func() bool { return nodes[0].runtime.Engine().IsLeader() || nodes[1].runtime.Engine().IsLeader() })
	live := nodes[0]
	if !live.runtime.Engine().IsLeader() {
		live = nodes[1]
	}
	newSession, err := client.Login(ctx, live.peer, "admin", admin.Private)
	if err != nil || newSession.Issuer == sourceKey || newSession.Issuer != live.runtime.Identity.Public {
		t.Fatal("new dynamic issuer login", err)
	}
	viewed, err := client.Query(ctx, nodes[0].peer, newSession, "whoami", "")
	if err != nil || viewed.User == nil || viewed.User.ID != "admin" {
		t.Fatal("new issuer/follower relay", err)
	}
	// Reopen a joining voter using the SAME local Join record, root, key and ACK.
	restart := nodes[0]
	oldAck := restart.record.Ack
	oldIdentity := restart.runtime.Identity.Public
	if _, err = restart.runtime.InstallConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	if err = restart.runtime.Close(); err != nil {
		t.Fatal(err)
	}
	restart.runtime = nil
	restart.runtime, err = Open(restart.config)
	if err != nil {
		t.Fatal("same root reopen", err)
	}
	wait("restart current quorum", func() bool { return restart.runtime.Engine().IsLeader() || nodes[1].runtime.Engine().IsLeader() })
	resumed, err := restart.runtime.ResumeInstallation(ctx)
	if err != nil || restart.runtime.Identity.Public != oldIdentity || !reflect.DeepEqual(resumed.Ack, oldAck) || resumed.Root.Intent != "join" || resumed.Root.Operation != restart.inv.JoinID {
		t.Fatal("same DB/ACK resume", err)
	}
	if wrong := restart.config; true {
		wrong.Common.Cluster = fmt.Sprintf("%064x", 999)
		if r, err := Open(wrong); err == nil {
			_ = r.Close()
			t.Fatal("join root switched clusters")
		}
	}
	t.Log("actual MYDCP/SDK N1 -> two nonvoter installs/ACKs -> explicit N3/Q2, source death, new issuer and same DB/key/original ACK reopen")
}
