// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// Native modules are disabled. NativeReady/Gone are signed node-fact fixtures;
// this test proves actual authentication/SFCP/Raft/storage, not Docker closure.
func TestRealManagedVolumePermitQuorumCurrentPolicyAndSameDB(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	root := t.TempDir()
	key := func(name string) *identity.Identity {
		t.Helper()
		v, e := identity.Create(filepath.Join(root, name))
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { clear(v.Private) })
		return v
	}
	adminKey, bobKey := key("admin"), key("bob")
	configuration := func(id string) config.Node {
		t.Helper()
		p, e := net.ListenPacket("udp4", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		address := p.LocalAddr().String()
		_ = p.Close()
		c := config.Node{Version: 1, Common: config.Common{}, Modules: map[string]config.Module{"network": {}, "workload": {}, "ingress": {}}}
		c.Node.ID, c.Node.Listen = id, address
		c.Node.StateDir, c.Node.IdentityDir = filepath.Join(root, id+"-state"), filepath.Join(root, id+"-key")
		return c
	}
	cfg := configuration("node-a")
	initialized, err := Initialize(ctx, cfg, adminKey.Public, "init-volume")
	if err != nil {
		t.Fatal(err)
	}
	a, err := Open(cfg)
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
	policy := control.Policy{Cluster: clusterID, BootstrapKey: adminKey.Public, TrustRoot: a.Identity.Public, Genesis: initialized.Installation.Genesis}
	peer := sfcp.Peer{ID: cfg.Node.ID, Endpoint: cfg.Node.Listen, Policy: sfcp.Policy{Key: sfcp.Identity(a.Identity.Public), Respond: true}}
	clientFor := func() *userauth.Client {
		t.Helper()
		id, e := identity.Ephemeral()
		if e != nil {
			t.Fatal(e)
		}
		mesh, e := sfcp.NewTransport(id, clusterID, func(k sfcp.Identity) (sfcp.Peer, bool) { return peer, k == peer.Key })
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { _ = mesh.Close(); clear(id.Private) })
		return &userauth.Client{Mesh: mesh, Self: id, Cluster: clusterID, Peers: []sfcp.Peer{peer}}
	}
	admin := clientFor()
	enrolled, err := admin.Enroll(ctx, peer, control.Enrollment{Schema: 1, RequestID: "enroll-volume", User: access.User{ID: "admin", Username: "admin", SystemAdmin: true, Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: adminKey.Public, Enabled: true}}}}, adminKey.Private)
	if err != nil || enrolled.Result == nil || enrolled.Result.Code != state.Applied {
		t.Fatal("enroll", err)
	}
	adminSession, err := admin.Login(ctx, peer, "admin", adminKey.Private)
	if err != nil {
		t.Fatal(err)
	}
	var others []*Runtime
	var configs []config.Node
	read := func() cluster.View {
		t.Helper()
		for {
			for _, node := range append([]*Runtime{a}, others...) {
				if node == nil {
					continue
				}
				v, e := node.Engine().Read(ctx, true)
				if e == nil {
					return v
				}
				if !errors.Is(e, raft.ErrNotLeader) && !errors.Is(e, raft.ErrLeadershipLost) {
					t.Fatal(e)
				}
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	submit := func(id, action string, expected uint64, payload any, want state.Code) {
		t.Helper()
		raw, e := control.ChangeBytes(action, "admin", expected, payload)
		if e != nil {
			t.Fatal(e)
		}
		var change control.Change
		_ = json.Unmarshal(raw, &change)
		op, e := admin.Prepare(ctx, peer, adminSession, id, change)
		if e != nil {
			t.Fatal("prepare", id, e)
		}
		reply, e := admin.Operation(ctx, peer, op, false)
		if e != nil || reply.Result == nil || reply.Result.Code != want {
			t.Fatal("operation", id, reply.Code, reply.Result, want, e)
		}
	}
	catalog := func() access.Catalog {
		t.Helper()
		c, e := policy.Catalog(read().State)
		if e != nil {
			t.Fatal(e)
		}
		return c
	}
	for _, tenant := range []string{"tenant", "other"} {
		submit("create-"+tenant, "create-tenant", 0, control.TenantID{ID: tenant}, state.Applied)
		v, _ := catalog().Tenant(tenant)
		submit("nodes-"+tenant, "set-nodes", v.Revision, control.NodeChangeTo(tenant, v.AllowedNodes, []string{cfg.Node.ID}), state.Applied)
	}
	submit("bob-user", "put-user", 0, access.User{ID: "bob", Username: "bob", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: bobKey.Public, Enabled: true}}}, state.Applied)
	submit("bob-role", "set-membership", 0, access.Membership{Tenant: "other", User: "bob", Role: access.Manager, Enabled: true}, state.Applied)
	bob := clientFor()
	bobSession, err := bob.Login(ctx, peer, "bob", bobKey.Private)
	if err != nil {
		t.Fatal(err)
	}
	scope := volumes.Scope{Cluster: clusterID, Tenant: "tenant", App: "app", ID: "database", Generation: 1}
	nativeSpec := volumes.NativeSpec{Schema: 1, Scope: scope, Node: cfg.Node.ID, NodeKey: a.Identity.Public, Materialization: "initial", UID: 10001, GID: 10001, Mode: 0750, Retain: true}
	raw, _ := json.Marshal(nativeSpec)
	native, err := (&engine.Client{Owner: engine.Owner(clusterID, a.Identity.Public)}).Identity("volume", volumes.NativeKey(nativeSpec), reconcile.Resource{Generation: 1, Present: true, Spec: string(raw)})
	if err != nil {
		t.Fatal(err)
	}
	fact := volumes.NativeReady{Schema: 1, Spec: nativeSpec, Generation: 1, Owner: volumes.Owner{Node: cfg.Node.ID, Key: a.Identity.Public, Native: native.Name}}
	fact.Signature = ed25519.Sign(a.Identity.Private, volumes.NativeReadyBytes(fact))
	submit("volume-create", "create-volume", 0, fact, state.Applied)
	submit("volume-writer", "acquire-volume", 1, control.VolumeAcquire{Scope: scope, Consumer: "database-task", Generation: 1, Writable: true}, state.Applied)
	registry, err := policy.Volumes(read().State)
	if err != nil {
		t.Fatal(err)
	}
	core, _ := registry.Volume(scope)
	consumer := core.Consumers()[0]
	gate, err := volumes.NewGate(scope, consumer.Owner, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	gate, request, err := gate.Request(consumer, [32]byte{2})
	if err != nil {
		t.Fatal(err)
	}
	permit, err := cluster.CallVolumePermit(ctx, a.Mesh, a.Identity, clusterID, peer, request)
	if err != nil {
		t.Fatal("actual owner quorum permit", err)
	}
	if _, err = gate.Accept(permit); err != nil {
		t.Fatal("permit did not feed same product gate", err)
	}
	input, _ := json.Marshal(request)
	if _, err = cluster.CallManagement(ctx, a.Mesh, a.Identity, clusterID, peer, cluster.ManagementRequest{Method: "volume-permit", Input: input}); err == nil {
		t.Fatal("cached/local permit accepted")
	}
	if _, err = cluster.CallManagement(ctx, a.Mesh, a.Identity, clusterID, peer, cluster.ManagementRequest{Method: "volume-permit", Latest: true, Key: a.Identity.Actor(), Input: input}); err == nil {
		t.Fatal("caller selected via request Key")
	}
	if _, err = cluster.CallManagement(ctx, bob.Mesh, bob.Self, clusterID, peer, cluster.ManagementRequest{Method: "volume-permit", Latest: true, Input: input}); err == nil {
		t.Fatal("user impersonated native member")
	}
	page, err := admin.VolumePage(ctx, peer, adminSession, "tenant", "")
	if err != nil || len(page.Items) != 1 || page.Items[0].Consumers != 1 {
		t.Fatal("volume page", err)
	}
	if page, err = bob.VolumePage(ctx, peer, bobSession, "other", ""); err != nil || len(page.Items) != 0 {
		t.Fatal("cross-tenant page leaked", err)
	}
	if _, err = bob.VolumePage(ctx, peer, bobSession, "tenant", ""); err == nil {
		t.Fatal("cross-tenant query allowed")
	}
	if err = a.Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if err = a.Close(); err != nil {
		t.Fatal(err)
	}
	a = nil
	a, err = Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_ = read()
	if _, err = cluster.CallVolumePermit(ctx, a.Mesh, a.Identity, clusterID, peer, request); err != nil {
		t.Fatal("same DB original grant/consumer", err)
	}
	tenant, _ := catalog().Tenant("tenant")
	submit("revoke-node", "set-nodes", tenant.Revision, control.NodeChangeTo("tenant", tenant.AllowedNodes, nil), state.Applied)
	if _, err = cluster.CallVolumePermit(ctx, a.Mesh, a.Identity, clusterID, peer, request); err == nil {
		t.Fatal("current revoked grant bypassed")
	}
	tenant, _ = catalog().Tenant("tenant")
	submit("restore-node", "set-nodes", tenant.Revision, control.NodeChangeTo("tenant", tenant.AllowedNodes, []string{cfg.Node.ID}), state.Applied)
	// Dynamic real N3/Q2 supplies the read barrier, not a mock permission bit.
	defer func() {
		for _, r := range others {
			if r != nil {
				_ = r.Close()
			}
		}
	}()
	for _, id := range []string{"node-b", "node-c"} {
		c := configuration(id)
		node, e := identity.Create(c.Node.IdentityDir)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { clear(node.Private) })
		submit("invite-"+id, "invite-node", 0, control.NodeInvitation{Peer: config.Peer{ID: id, Key: node.Actor(), Endpoint: c.Node.Listen}, JoinID: "join-" + id}, state.Applied)
		inv, e := admin.NodeInvitation(ctx, peer, adminSession, id)
		if e != nil {
			t.Fatal(e)
		}
		r, _, e := Join(ctx, c, inv, clusterID, a.Identity.Public)
		if e != nil {
			t.Fatal("join", id, e)
		}
		others = append(others, r)
		configs = append(configs, c)
		for {
			d, e := policy.Members(read().State)
			entry, ok := d.Entry(id)
			if e == nil && ok && entry.Phase == membership.Ready {
				submit("promote-"+id, "promote-node", entry.Revision, control.NodeSelection{ID: id}, state.Applied)
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(20 * time.Millisecond):
			}
		}
		for {
			d, e := policy.Members(read().State)
			entry, ok := d.Entry(id)
			// The leader records the installed Raft configuration in the
			// directory afterwards. The next invitation is prepared against the
			// directory revision, so wait for that record too.
			if e == nil && ok && entry.Phase == membership.Active && entry.Peer.Voter && topologyVoter(d, id) {
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	target, _ := a.Mesh.Peer(sfcp.Identity(others[0].Identity.Public))
	if _, err = cluster.CallVolumePermit(ctx, a.Mesh, a.Identity, clusterID, target, request); err != nil {
		t.Fatal("authenticated member relay changed original caller", err)
	}
	for i := range others {
		if err = others[i].Close(); err != nil {
			t.Fatal(err)
		}
		others[i] = nil
	}
	short, stop := context.WithTimeout(ctx, 500*time.Millisecond)
	_, err = cluster.CallVolumePermit(short, a.Mesh, a.Identity, clusterID, peer, request)
	stop()
	if err == nil {
		t.Fatal("minority returned fresh write activation")
	}
	others[0], err = Open(configs[0])
	if err != nil {
		t.Fatal("same voter DB restore", err)
	}
	_ = read()
	if _, err = cluster.CallVolumePermit(ctx, a.Mesh, a.Identity, clusterID, peer, request); err != nil {
		t.Fatal("same consumer permit after quorum restoration", err)
	}
	gone := volumes.Gone{Scope: scope, Consumer: consumer, Stopped: true, MountsGone: true}
	gone.Signature = ed25519.Sign(a.Identity.Private, volumes.GoneBytes(gone))
	submit("release-original", "release-volume", core.Revision(), gone, state.Applied)
	if _, err = cluster.CallVolumePermit(ctx, a.Mesh, a.Identity, clusterID, peer, request); err == nil {
		t.Fatal("returned consumer got permission")
	}
	t.Log("actual user/SFCP/Raft/bbolt volume grants, original node caller/relay, current tenant/node policy, bounded tenant pages, Snapshot/same DB, dynamic N3/Q2 minority denial/restoration, original signed fact release; no native writer was started")
}

func topologyVoter(d membership.Directory, id string) bool {
	topology, err := d.Topology()
	if err != nil {
		return false
	}
	member, ok := topology.Configuration().Member(id)
	return ok && member.Voter
}
