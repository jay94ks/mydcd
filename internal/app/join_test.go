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
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/bootstrap"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	"gopkg.in/yaml.v3"
)

func TestRealManagedJoinNonvoterAndExplicitPromotion(t *testing.T) {
	testRealManagedJoin(t, false)
}

func TestRealRuntimeInstalledNodeIdentityRotationRestartsTLSAndRevokesOldCurrentAuthority(t *testing.T) {
	testRealManagedJoin(t, false, "node-identity")
}

// A joined voter whose address changed is moved with set-node-endpoint and
// `sfcd set-listen`, keeps its vote and helps elect a leader at its new
// address.
func TestRealJoinedVoterEndpointMove(t *testing.T) {
	testRealManagedJoin(t, false, "endpoint-move")
}

func TestRealRuntimeForceRemovalRequiresFreshProbeAndPreservesHistory(t *testing.T) {
	testRealManagedJoin(t, false, "node-force")
}

func TestRealRuntimeNodeIsolationRestoreLeaderRemovalAndQuorum(t *testing.T) {
	testRealManagedJoin(t, false, "node-runtime")
}

// A public node that never dials (node.inbound_only), like an ingress
// gateway in front of servers behind NAT, still joins: the source member
// connects to the invited endpoint and the join requests use that session.
func TestRealInboundOnlyNodeJoinsOverTheSourceConnection(t *testing.T) {
	testRealManagedJoin(t, false, "inbound-only")
}

// The invitation source can stop being the leader after it signed the
// invitation; it relays the joining node's requests to the leader.
func TestRealJoinThroughFollowerSource(t *testing.T) {
	testRealManagedJoin(t, false, "source-follower")
}

// After the leader changes, the new leader keeps replicating to a node that
// never dials (node.inbound_only), such as a public ingress gateway.
func TestRealInboundOnlyNodeFollowsANewLeader(t *testing.T) {
	// Reports must keep reaching the leader's node table across the changes.
	interval := observationInterval
	observationInterval = time.Second
	t.Cleanup(func() { observationInterval = interval })
	testRealManagedJoin(t, false, "source-follower", "leader-change")
}

func TestRealAppPlanStreamMemberRelay(t *testing.T) {
	testRealManagedJoin(t, true)
}

func testRealManagedJoin(t *testing.T, streamPlan bool, scenario ...string) {
	budget := 45 * time.Second
	if len(scenario) > 1 && scenario[1] == "leader-change" {
		budget = 120 * time.Second
	}
	nativeDetails := len(scenario) > 0 && scenario[0] == "details-native"
	nativeObservations := nativeDetails || len(scenario) > 0 && scenario[0] == "observations-native"
	if nativeObservations {
		budget = 180 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	root, err := os.MkdirTemp("", "sfc-managed-join-")
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
			if err := yaml.Unmarshal([]byte("network: {enabled: true}\nworkload: {enabled: true}\ningress: {enabled: false}\n"), &c.Modules); err != nil {
				t.Fatal(err)
			}
			c.EngineAPI = testEngineAPI()
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
	peers := map[sfcp.Identity]sfcp.Peer{}
	var peerMu sync.RWMutex
	client := userauth.Client{Self: self, Cluster: clusterID}
	addPeer := func(p config.Peer) sfcp.Peer {
		k, _ := identity.ParseKey(p.Key)
		v := sfcp.Peer{ID: p.ID, Endpoint: p.Endpoint, Policy: sfcp.Policy{Key: sfcp.Identity(k), Respond: true}}
		peerMu.Lock()
		peers[v.Key] = v
		peerMu.Unlock()
		client.Peers = append(client.Peers, v)
		return v
	}
	source := addPeer(initialized.Installation.Genesis)
	client.Mesh, err = sfcp.NewTransport(self, clusterID, func(k sfcp.Identity) (sfcp.Peer, bool) {
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
		peer    sfcp.Peer
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
		inboundOnly := len(scenario) > 0 && scenario[0] == "inbound-only"
		cfg.Node.InboundOnly = inboundOnly
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
		if inboundOnly {
			if !runtime.Mesh.InboundOnly() || !runtime.Mesh.Connected(sfcp.Identity(sourceKey)) {
				t.Fatal("inbound-only joined node lost its source session")
			}
			if _, err := runtime.Mesh.Dial(ctx, sfcp.Peer{ID: "nobody", Endpoint: vacant(), Policy: sfcp.Policy{Key: sfcp.Identity{7}}}); err == nil {
				t.Fatal("inbound-only node dialed")
			}
			// A client that reaches and trusts only the inbound-only node
			// logs in through it, reads the members and logs out.
			gateway := client
			gateway.Peers = []sfcp.Peer{n.peer}
			gateway.TrustIssuer = func(p sfcp.Peer) error {
				if p.Key != source.Key {
					t.Error("relayed issuer", p.ID)
				}
				gateway.Peers = append(gateway.Peers, p)
				return nil
			}
			relayed, err := gateway.Login(ctx, n.peer, "admin", admin.Private)
			if err != nil || relayed.Issuer != [32]byte(source.Key) {
				t.Fatal("login through the inbound-only node", err)
			}
			if page, err := gateway.MemberPage(ctx, n.peer, relayed, ""); err != nil || len(page.Members) != 2 {
				t.Fatal("members through the inbound-only node", err)
			}
			raw, _ := control.ChangeBytes("revoke-session", relayed.User, relayed.AccountRevision, control.SessionRevocation{User: relayed.User, Session: relayed.ID})
			var revoke control.Change
			_ = json.Unmarshal(raw, &revoke)
			op, err := gateway.Prepare(ctx, n.peer, relayed, "logout-gateway", revoke)
			if err != nil {
				t.Fatal("logout prepare through the inbound-only node", err)
			}
			if out, err := gateway.Operation(ctx, n.peer, op, false); err != nil || out.Result == nil || out.Result.Code != state.Applied {
				t.Fatal("logout through the inbound-only node", err)
			}
			if _, err := gateway.Whoami(ctx, n.peer, relayed); err == nil {
				t.Fatal("revoked session still admitted")
			}
			return
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
		// A non-voter relays a private-key login to the leader, which issues
		// the session. A client that trusts only the non-voter learns the
		// issuer from it, and refuses the login when it cannot record that.
		if relayed, err := client.Login(ctx, n.peer, "admin", admin.Private); err != nil || relayed.Issuer != [32]byte(source.Key) || relayed.Approval == nil {
			t.Fatal("installed non-voter must relay login to the leader", err)
		}
		narrow := client
		narrow.Peers = []sfcp.Peer{n.peer}
		var untrusted *userauth.UntrustedIssuerError
		if _, err := narrow.Login(ctx, n.peer, "admin", admin.Private); !errors.As(err, &untrusted) || untrusted.Node != source.ID {
			t.Fatal("relayed login from an unrecorded issuer", err)
		}
		var learned []sfcp.Peer
		narrow.TrustIssuer = func(p sfcp.Peer) error { learned = append(learned, p); return nil }
		if relayed, err := narrow.Login(ctx, n.peer, "admin", admin.Private); err != nil || relayed.Issuer != [32]byte(source.Key) || len(learned) != 1 || learned[0].Key != source.Key || learned[0].ID != source.ID || learned[0].Endpoint == "" {
			t.Fatal("relayed login must name the leader as issuer", err, learned)
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
	if len(scenario) > 0 && scenario[0] == "endpoint-move" {
		// node-c's address changes (a home server's IP): sfcd stops, node.yaml
		// gets the new listen, `sfcd set-listen` accepts it locally, the
		// cluster records it with set-node-endpoint, and sfcd starts again.
		moved := nodes[1]
		if err := moved.runtime.Close(); err != nil {
			t.Fatal(err)
		}
		moved.runtime = nil
		old := moved.config.Node.Listen
		moved.config.Node.Listen = vacant()
		if r, err := Open(moved.config); err == nil {
			_ = r.Close()
			t.Fatal("a changed listen opened without set-listen")
		}
		if was, err := bootstrap.SetListen(moved.config); err != nil || was != old {
			t.Fatal("set-listen", was, err)
		}
		e, _ := directory(a).Entry("node-c")
		submit("move-node-c", "set-node-endpoint", e.Revision, control.NodeEndpointChange{ID: "node-c", Endpoint: moved.config.Node.Listen})
		r, err := Open(moved.config)
		if err != nil {
			t.Fatal("reopen moved node", err)
		}
		moved.runtime = r
		wait("moved endpoint installed", func() bool {
			e, ok := directory(a).Entry("node-c")
			if !ok || e.Peer.Endpoint != moved.config.Node.Listen || e.Job.Pending != nil || e.Phase != membership.Active {
				return false
			}
			native, err := a.Engine().InstalledConfiguration(ctx, true)
			for _, server := range native.Configuration.Servers {
				if err == nil && string(server.ID) == "node-c" {
					return string(server.Address) == moved.config.Node.Listen && server.Suffrage == raft.Voter
				}
			}
			return false
		})
		// The first server goes; node-b and the moved node-c keep a majority
		// and elect a leader between themselves.
		if err := a.Close(); err != nil {
			t.Fatal(err)
		}
		a = nil
		wait("leader among node-b and the moved node-c", func() bool {
			return nodes[0].runtime.Engine().IsLeader() || moved.runtime.Engine().IsLeader()
		})
		live := nodes[0]
		if moved.runtime.Engine().IsLeader() {
			live = moved
		}
		// The client learns the moved address the way `sfcli context` would.
		live.peer = addPeer(config.Peer{ID: live.config.Node.ID, Key: live.inv.Target.Key, Endpoint: live.config.Node.Listen})
		if _, err := client.Login(ctx, live.peer, "admin", admin.Private); err != nil {
			t.Fatal("login after the move", err)
		}
		// A restart with the moved listen keeps working.
		if err := moved.runtime.Close(); err != nil {
			t.Fatal(err)
		}
		if moved.runtime, err = Open(moved.config); err != nil {
			t.Fatal("restart moved node", err)
		}
		wait("leader after the moved node restarted", func() bool {
			return nodes[0].runtime.Engine().IsLeader() || moved.runtime.Engine().IsLeader()
		})
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
	if len(scenario) > 0 && scenario[0] == "source-follower" {
		wait("source leads", func() bool { return a.Engine().IsLeader() })
		cfg := nodeConfig("node-d")
		cfg.Node.InboundOnly = true // it cannot reach the new leader by itself either
		nodeKey, err := identity.Create(cfg.Node.IdentityDir)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(nodeKey.Private)
		target := config.Peer{ID: "node-d", Key: nodeKey.Actor(), Endpoint: cfg.Node.Listen}
		submit("invite-node-d", "invite-node", 0, control.NodeInvitation{Peer: target, JoinID: "join-node-d"})
		inv, err := client.NodeInvitation(ctx, source, session, "node-d")
		if err != nil {
			t.Fatal("invitation", err)
		}
		// The source signed the invitation as leader, then stops leading.
		next := nodes[0]
		if err := a.Engine().TransferLeadership(ctx, next.config.Node.ID, next.config.Node.Listen); err != nil {
			t.Fatal("transfer leadership", err)
		}
		wait("source is a follower", func() bool { return next.runtime.Engine().IsLeader() && !a.Engine().IsLeader() })
		runtime, record, err := Join(ctx, cfg, inv, clusterID, sourceKey)
		if err != nil {
			t.Fatal("join through follower source", err)
		}
		nodes = append(nodes, &joined{cfg, runtime, inv, record, addPeer(target)})
		if record.Ack == nil || a.Engine().IsLeader() {
			t.Fatal("no join ACK, or the source led again")
		}
		wait("joined through follower", func() bool { e, ok := directory(next.runtime).Entry("node-d"); return ok && membership.FullMember(e) })
		if len(scenario) < 2 || scenario[1] != "leader-change" {
			return
		}
		d := nodes[len(nodes)-1]
		// As in operation, the joined node runs again from its installation.
		if err := d.runtime.Close(); err != nil {
			t.Fatal(err)
		}
		if d.runtime, err = Open(d.config); err != nil {
			t.Fatal("reopen inbound-only node", err)
		}
		voters := []*Runtime{a, nodes[0].runtime, nodes[1].runtime}
		// The leader of the newest term: one that lost leadership can still
		// believe it leads for a moment.
		leader := func() *Runtime {
			var best *Runtime
			for _, r := range voters {
				if r != nil && r.Engine().IsLeader() && (best == nil || r.Engine().CurrentObservedTerm() > best.Engine().CurrentObservedTerm()) {
					best = r
				}
			}
			return best
		}
		// The leader's stored reports, which the node table shows.
		reported := func(l *Runtime, lv cluster.View, node string, since uint64, term uint64) bool {
			rows, err := l.nodeObservations(ctx, lv)
			if err != nil {
				return false
			}
			for _, report := range rows {
				if report.Node == node && report.Consensus != nil {
					return report.At >= since && report.Consensus.Term == term
				}
			}
			return false
		}
		caughtUp := func(label string) {
			t.Helper()
			since := uint64(time.Now().UnixMilli())
			// A new leader commits an entry of its own term at once.
			wait(label, func() bool {
				l := leader()
				if l == nil {
					return false
				}
				lv, err := l.Engine().Read(ctx, false)
				if err != nil {
					return false
				}
				dv, err := d.runtime.Engine().Read(ctx, false)
				if err != nil || dv.Term != lv.Term || dv.RaftIndex < lv.RaftIndex {
					return false
				}
				// What the node reports to the cluster must say so too.
				c, err := d.runtime.Engine().ConsensusObservation(ctx)
				if err != nil {
					t.Log(label, "consensus observation:", err)
					return false
				}
				lc, err := l.Engine().ConsensusObservation(ctx)
				if err != nil {
					return false
				}
				if c.Term != lc.Term || c.AppliedIndex < lc.CommitIndex {
					t.Logf("%s: consensus term=%d applied=%d commit=%d last=%d; leader term=%d commit=%d", label, c.Term, c.AppliedIndex, c.CommitIndex, c.LastIndex, lc.Term, lc.CommitIndex)
					return false
				}
				for _, r := range append(voters, d.runtime) {
					if r != nil && !reported(l, lv, r.Engine().ObservedNodeID(), since, lc.Term) {
						return false
					}
				}
				return true
			})
		}
		caughtUp("inbound-only node replicated by the first leader")
		// A leadership transfer, then a restart of the leader, as in the lab.
		third := nodes[1]
		if err := next.runtime.Engine().TransferLeadership(ctx, third.config.Node.ID, third.config.Node.Listen); err != nil {
			t.Fatal("transfer leadership", err)
		}
		wait("third node leads", func() bool { return third.runtime.Engine().IsLeader() })
		caughtUp("inbound-only node follows a transferred leader")
		if err := third.runtime.Close(); err != nil {
			t.Fatal(err)
		}
		voters[2] = nil
		wait("leader after restart", func() bool { return leader() != nil })
		if third.runtime, err = Open(third.config); err != nil {
			t.Fatal("reopen leader", err)
		}
		voters[2] = third.runtime
		caughtUp("inbound-only node follows a re-elected leader")
		// The lab sequence: a follower voter X restarts; later the other two
		// voters (the leader among them) stop together, quorum is lost for a
		// while, one comes back and X leads in a newer term.
		type voter struct {
			config config.Node
			slot   **Runtime
		}
		all := []voter{{aCfg, &a}, {nodes[0].config, &nodes[0].runtime}, {nodes[1].config, &nodes[1].runtime}}
		restartVoter := func(v voter) {
			t.Helper()
			if err := (*v.slot).Close(); err != nil {
				t.Fatal(err)
			}
			r, err := Open(v.config)
			if err != nil {
				t.Fatal("reopen voter", err)
			}
			*v.slot = r
			voters = []*Runtime{a, nodes[0].runtime, nodes[1].runtime}
		}
		var x voter
		var others []voter
		for _, v := range all {
			if x.slot == nil && !(*v.slot).Engine().IsLeader() {
				x = v
			} else {
				others = append(others, v)
			}
		}
		restartVoter(x)
		caughtUp("inbound-only node after a follower voter restarted")
		for _, v := range others {
			if err := (*v.slot).Close(); err != nil {
				t.Fatal(err)
			}
			*v.slot = nil
		}
		voters = []*Runtime{a, nodes[0].runtime, nodes[1].runtime}
		time.Sleep(15 * time.Second)
		back, err := Open(others[0].config)
		if err != nil {
			t.Fatal(err)
		}
		*others[0].slot = back
		voters = []*Runtime{a, nodes[0].runtime, nodes[1].runtime}
		wait("leader after quorum returns", func() bool { return leader() != nil })
		if back, err = Open(others[1].config); err != nil {
			t.Fatal(err)
		}
		*others[1].slot = back
		voters = []*Runtime{a, nodes[0].runtime, nodes[1].runtime}
		t.Log("leader after quorum loss is the restarted follower:", leader() == *x.slot)
		caughtUp("inbound-only node follows the leader after quorum loss")
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
	viewed, err := client.Whoami(ctx, nodes[0].peer, newSession)
	if err != nil || viewed.User.ID != "admin" {
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
	t.Log("actual SFCP/SDK N1 -> two nonvoter installs/ACKs -> explicit N3/Q2, source death, new issuer and same DB/key/original ACK reopen")
}
