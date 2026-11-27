// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/workload"
)

// Native modules stay disabled. Owner closure signatures below verify committed
// cleanup authority only; they are fixtures, not evidence of Docker/kernel work.
func TestRealManagedResourceAuthorityQuotasCIDRAndSameDB(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	root := t.TempDir()
	makeIdentity := func(name string) *identity.Identity {
		t.Helper()
		v, err := identity.Create(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { clear(v.Private) })
		return v
	}
	adminKey, aliceKey, bobKey := makeIdentity("admin"), makeIdentity("alice"), makeIdentity("bob")
	probe, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.LocalAddr().String()
	_ = probe.Close()
	cfg := config.Node{Version: 1, Common: config.Common{}, Modules: map[string]config.Module{"network": {}, "workload": {}, "ingress": {}}}
	cfg.Node.ID, cfg.Node.Listen = "node-a", address
	cfg.Node.StateDir, cfg.Node.IdentityDir = filepath.Join(root, "state"), filepath.Join(root, "node-key")
	initialized, err := Initialize(ctx, cfg, adminKey.Public, "init-resources")
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if runtime != nil {
			_ = runtime.Close()
		}
	}()
	if _, err = runtime.InstallConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	clusterID := initialized.Installation.Root.Cluster
	policy := control.Policy{Cluster: clusterID, BootstrapKey: adminKey.Public, TrustRoot: runtime.Identity.Public, Genesis: initialized.Installation.Genesis}
	peer := sfcp.Peer{ID: cfg.Node.ID, Endpoint: address, Policy: sfcp.Policy{Key: sfcp.Identity(runtime.Identity.Public), Respond: true}}
	clientFor := func() *userauth.Client {
		t.Helper()
		self, err := identity.Ephemeral()
		if err != nil {
			t.Fatal(err)
		}
		mesh, err := sfcp.NewTransport(self, clusterID, func(k sfcp.Identity) (sfcp.Peer, bool) { return peer, k == peer.Key })
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = mesh.Close(); clear(self.Private) })
		return &userauth.Client{Mesh: mesh, Self: self, Cluster: clusterID, Peers: []sfcp.Peer{peer}}
	}
	admin := clientFor()
	enrolled, err := admin.Enroll(ctx, peer, control.Enrollment{Schema: 1, RequestID: "enroll-resources", User: access.User{ID: "admin", Username: "admin", SystemAdmin: true, Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: adminKey.Public, Enabled: true}}}}, adminKey.Private)
	if err != nil || enrolled.Result == nil || enrolled.Result.Code != state.Applied {
		t.Fatal("enroll", err)
	}
	adminSession, err := admin.Login(ctx, peer, "admin", adminKey.Private)
	if err != nil {
		t.Fatal(err)
	}
	read := func() cluster.View {
		t.Helper()
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for {
			view, err := runtime.Engine().Read(ctx, true)
			if err == nil {
				return view
			}
			if !errors.Is(err, raft.ErrNotLeader) && !errors.Is(err, raft.ErrLeadershipLost) {
				t.Fatal(err)
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-tick.C:
			}
		}
	}
	resources := func() control.Resources {
		t.Helper()
		r, err := policy.Resources(read().State)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	catalog := func() access.Catalog {
		t.Helper()
		c, err := policy.Catalog(read().State)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	prepare := func(client *userauth.Client, session access.Session, id, action string, expected uint64, payload any) control.UserOperation {
		t.Helper()
		raw, err := control.ChangeBytes(action, session.User, expected, payload)
		if err != nil {
			t.Fatal(err)
		}
		var change control.Change
		_ = json.Unmarshal(raw, &change)
		op, err := client.Prepare(ctx, peer, session, id, change)
		if err != nil {
			t.Fatal("prepare", id, err)
		}
		return op
	}
	apply := func(client *userauth.Client, op control.UserOperation, want state.Code) state.Result {
		t.Helper()
		reply, err := client.Operation(ctx, peer, op, false)
		if err != nil || reply.Result == nil || reply.Result.Code != want {
			t.Fatal("apply", op.RequestID, reply.Code, reply.Result, want, err)
		}
		return *reply.Result
	}
	propose := func(id, action string, expected uint64, payload any) state.Result {
		t.Helper()
		return apply(admin, prepare(admin, adminSession, id, action, expected, payload), state.Applied)
	}
	for _, id := range []string{"first", "second"} {
		propose("tenant-"+id, "create-tenant", 0, control.TenantID{ID: id})
		v, _ := catalog().Tenant(id)
		propose("node-grant-"+id, "set-nodes", v.Revision, control.NodeChangeTo(id, v.AllowedNodes, []string{cfg.Node.ID}))
	}
	for _, entry := range []struct {
		id, tenant string
		key        *identity.Identity
	}{{"alice", "first", aliceKey}, {"bob", "second", bobKey}} {
		propose("user-"+entry.id, "put-user", 0, access.User{ID: entry.id, Username: entry.id, Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: entry.key.Public, Enabled: true}}})
		propose("member-"+entry.id, "set-membership", 0, access.Membership{Tenant: entry.tenant, User: entry.id, Role: access.Manager, Enabled: true})
	}
	for _, tenant := range []string{"", "first", "second"} {
		cpu, mem, nets := uint64(8e9), uint64(8<<30), uint64(2)
		if tenant != "" {
			cpu, mem, nets = 4e9, 4<<30, 1
		}
		propose("quota-"+tenant, "set-node-quota", 0, tenancy.NodeLimit{Tenant: tenant, Node: cfg.Node.ID, Capacity: workload.Resources{CPU: cpu, Memory: mem}, Networks: nets})
	}
	alice, bob := clientFor(), clientFor()
	aliceSession, err := alice.Login(ctx, peer, "alice", aliceKey.Private)
	if err != nil {
		t.Fatal(err)
	}
	bobSession, err := bob.Login(ctx, peer, "bob", bobKey.Private)
	if err != nil {
		t.Fatal(err)
	}
	denied := prepare(alice, aliceSession, "manager-cannot-grow-node", "set-node-quota", 0, tenancy.NodeLimit{Node: cfg.Node.ID, Capacity: workload.Resources{CPU: ^uint64(0), Memory: ^uint64(0)}})
	apply(alice, denied, state.Forbidden)
	fakeOwner := tenancy.Reservation{Key: "workload/task/first/app/spoof", Tenant: "first", Node: cfg.Node.ID, Owner: aliceKey.Public, Need: workload.Resources{CPU: 1, Memory: 1}}
	apply(alice, prepare(alice, aliceSession, "spoof-owner", "reserve-task", resources().Quotas.Revision(), fakeOwner), state.Forbidden)
	// Each caller gets only its own resources, while collisions use the full view.
	network := tenancy.TUNDefinition{Tenant: "first", Name: "private", Members: []tenancy.TUNNode{{Node: cfg.Node.ID, Pools: []tenancy.Subnet{{ID: "v4", Prefix: netip.MustParsePrefix("10.70.0.0/24"), Gateway: netip.MustParseAddr("10.70.0.1"), MTU: 1400}}}}}
	apply(alice, prepare(alice, aliceSession, "network-first", "create-tun-network", resources().Networks.Revision(), network), state.Applied)
	overlap := network
	overlap.Tenant, overlap.Name = "second", "other"
	overlap.Members = []tenancy.TUNNode{network.Members[0]}
	conflict := apply(bob, prepare(bob, bobSession, "overlap-other-tenant", "create-tun-network", resources().Networks.Revision(), overlap), state.ConditionFailed)
	if conflict.Code != state.ConditionFailed || len(resources().Networks.VisibleNetworks(catalog(), "bob")) != 0 {
		t.Fatal("global CIDR conflict did not retain existing owner")
	}
	r := resources()
	first := tenancy.Reservation{Key: "workload/task/first/app/php", Tenant: "first", Node: cfg.Node.ID, Need: workload.Resources{CPU: 4e9, Memory: 4 << 30}}
	second := first
	second.Key, second.Tenant = "workload/task/second/app/mysql", "second"
	one := prepare(alice, aliceSession, "reserve-first", "reserve-task", r.Quotas.Revision(), first)
	stale := prepare(bob, bobSession, "reserve-second-old-CAS", "reserve-task", r.Quotas.Revision(), second)
	original := apply(alice, one, state.Applied)
	oldRejection := apply(bob, stale, state.ConditionFailed)
	apply(bob, prepare(bob, bobSession, "reserve-second-new-intent", "reserve-task", resources().Quotas.Revision(), second), state.Applied)
	used, _ := resources().Quotas.Usage("", cfg.Node.ID)
	if used != (workload.Resources{CPU: 8e9, Memory: 8 << 30}) {
		t.Fatal("actual committed global usage", used)
	}
	extra := first
	extra.Key, extra.Need = "workload/task/first/app/overflow", workload.Resources{CPU: 1, Memory: 1}
	apply(alice, prepare(alice, aliceSession, "exhausted", "reserve-task", resources().Quotas.Revision(), extra), state.ConditionFailed)
	global, _ := resources().Quotas.Limit("", cfg.Node.ID)
	revision := global.Revision
	global.Revision = 0
	global.Capacity.CPU = 7e9
	apply(admin, prepare(admin, adminSession, "shrink-below-held", "set-node-quota", revision, global), state.ConditionFailed)
	plan, err := policy.PlanningResources(read().State, "alice", "first")
	if err != nil || len(plan.Nodes) != 1 || plan.Nodes[cfg.Node.ID].Used != first.Need || plan.Nodes[cfg.Node.ID].Capacity != first.Need || plan.Reserved[first.Key] != first.Need || len(plan.Features) != 0 {
		t.Fatal("planner did not consume exact current scoped reservation view", err)
	}
	if plan.Current[first.Key].Present {
		t.Fatal("reservation fabricated a native desired task/Ready")
	}
	if _, err = policy.PlanningResources(read().State, "bob", "first"); err == nil {
		t.Fatal("foreign tenant planning view")
	}
	page, err := alice.Resources(ctx, peer, aliceSession, userauth.ResourcesQuery{Tenant: "first"})
	if err != nil || page.RootRevision == 0 || page.QuotaRevision == 0 {
		t.Fatal("resource query/CAS", err)
	}
	for _, e := range page.Items {
		if e.Limit != nil && e.Limit.Tenant != "first" || e.Network != nil && e.Network.Tenant != "first" || e.Reservation != nil && e.Reservation.Tenant != "first" {
			t.Fatal("cross-tenant resource disclosure")
		}
	}
	if _, err = alice.Resources(ctx, peer, aliceSession, userauth.ResourcesQuery{Tenant: "second"}); err == nil {
		t.Fatal("foreign tenant query accepted")
	}
	if _, err = alice.Resources(ctx, peer, aliceSession, userauth.ResourcesQuery{}); err == nil {
		t.Fatal("manager obtained global resource catalog")
	}
	// Revoked placement does not strand cleanup or release its old budget early.
	tenant, _ := catalog().Tenant("first")
	propose("revoke-node-first", "set-nodes", tenant.Revision, control.NodeChangeTo("first", tenant.AllowedNodes, nil))
	apply(alice, prepare(alice, aliceSession, "revoked-node-create", "reserve-task", resources().Quotas.Revision(), extra), state.Forbidden)
	held, _ := resources().Quotas.Reservation(first.Key)
	apply(alice, prepare(alice, aliceSession, "drain-first", "drain-reservation", held.Revision, control.ReservationSelection{Tenant: "first", Key: first.Key}), state.Applied)
	held, _ = resources().Quotas.Reservation(first.Key)
	used, _ = resources().Quotas.Usage("", cfg.Node.ID)
	if used.CPU != 8e9 {
		t.Fatal("Drain returned capacity")
	}
	proof := tenancy.ReservationClosure{Schema: 1, Cluster: clusterID, Key: held.Key, Node: held.Node, Owner: held.Owner, Generation: held.Generation, DrainRevision: held.Revision, NativeGone: true, PendingRefs: 1}
	proof.Signature = ed25519.Sign(runtime.Identity.Private, tenancy.ReservationClosureBytes(proof))
	apply(alice, prepare(alice, aliceSession, "pending-native-reference", "release-reservation", held.Revision, proof), state.ConditionFailed)
	proof.PendingRefs = 0
	proof.Signature = ed25519.Sign(bobKey.Private, tenancy.ReservationClosureBytes(proof))
	apply(alice, prepare(alice, aliceSession, "wrong-closure-owner", "release-reservation", held.Revision, proof), state.ConditionFailed)
	proof.Signature = ed25519.Sign(runtime.Identity.Private, tenancy.ReservationClosureBytes(proof))
	apply(alice, prepare(alice, aliceSession, "settled-budget-proof", "release-reservation", held.Revision, proof), state.Applied)
	used, _ = resources().Quotas.Usage("", cfg.Node.ID)
	if used.CPU != 4e9 {
		t.Fatal("verified metadata closure not released")
	}
	// The last member leaving deletes the network, even after its server
	// was revoked: drain, then leave with the owner's closure.
	n, _ := resources().Networks.NamedNetwork("first", "private", cfg.Node.ID)
	apply(alice, prepare(alice, aliceSession, "drain-network", "drain-network", n.Revision, control.NetworkSelection{Tenant: "first", ID: n.ID}), state.Applied)
	apply(bob, prepare(bob, bobSession, "drained-still-collides", "create-tun-network", resources().Networks.Revision(), overlap), state.ConditionFailed)
	n, _ = resources().Networks.Network("first", n.ID)
	closed := tenancy.NetworkClosure{Cluster: clusterID, Tenant: n.Tenant, Network: n.ID, Node: n.Node, Owner: n.Owner, Generation: n.Generation, Revision: n.Revision, NativeGone: true}
	closed.Signature = ed25519.Sign(runtime.Identity.Private, tenancy.NetworkClosureBytes(closed))
	apply(alice, prepare(alice, aliceSession, "leave-last", "leave-tun-network", n.Revision, closed), state.Applied)
	if _, ok := resources().Networks.Network("first", n.ID); ok {
		t.Fatal("the last member left but the network stayed")
	}
	apply(bob, prepare(bob, bobSession, "CIDR-after-original-proof", "create-tun-network", resources().Networks.Revision(), overlap), state.Applied)
	recreated, _ := resources().Networks.NamedNetwork("second", "other", cfg.Node.ID)
	if recreated.Generation <= n.Generation {
		t.Fatal("CIDR reuse lost generation floor")
	}
	// Grow the tenant allowance explicitly, then exercise bounded pagination.
	limit, _ := resources().Quotas.Limit("second", cfg.Node.ID)
	revision = limit.Revision
	limit.Revision = 0
	limit.Capacity = workload.Resources{CPU: 5e9, Memory: 5 << 30}
	propose("grow-second-limit", "set-node-quota", revision, limit)
	for _, id := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"} {
		v := second
		v.Key = "workload/task/second/app/" + id
		v.Need = workload.Resources{CPU: 1, Memory: 1}
		apply(bob, prepare(bob, bobSession, "reserve-small-"+id, "reserve-task", resources().Quotas.Revision(), v), state.Applied)
	}
	page, err = bob.Resources(ctx, peer, bobSession, userauth.ResourcesQuery{Tenant: "second"})
	if err != nil || len(page.Items) != 8 || page.Next == "" {
		t.Fatal("first resource page", err)
	}
	last, err := bob.Resources(ctx, peer, bobSession, userauth.ResourcesQuery{Tenant: "second", After: page.Next})
	if err != nil || len(last.Items) == 0 || last.RootRevision != page.RootRevision || last.Next != "" {
		t.Fatal("resource continuation", err)
	}
	for _, e := range append(page.Items, last.Items...) {
		if strings.Contains(e.Key, "/first/") {
			t.Fatal("pagination leaked another tenant")
		}
	}
	before := resources()
	beforeView := read()
	if err = runtime.Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if err = runtime.Close(); err != nil {
		t.Fatal(err)
	}
	runtime = nil
	runtime, err = Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runtime.InstallConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	after := resources()
	if !reflect.DeepEqual(before, after) {
		t.Fatal("same DB lost ownership/quotas/CIDR")
	}
	result, err := alice.Result(ctx, peer, aliceSession, one)
	if err != nil || result.Result == nil || *result.Result != original {
		t.Fatal("original reservation receipt lost", err)
	}
	result, err = bob.Result(ctx, peer, bobSession, stale)
	if err != nil || result.Result == nil || *result.Result != oldRejection {
		t.Fatal("original CAS rejection lost", err)
	}
	if read().State.Index() != beforeView.State.Index() {
		t.Fatal("reopen/result read mutated shared state")
	}
	t.Log("actual SFCP current user/tenant scopes -> one Raft/FSM quota+CIDR root/receipt -> scoped planning/paging -> indexed Snapshot/same DB; owner closure inputs are fixtures, no native success claimed")
}
