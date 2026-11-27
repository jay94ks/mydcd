// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"crypto/ed25519"
	"net/netip"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/tenancy"
)

// screenNetwork is the fake's screen-shaped row of a network (the web
// builds the same from the resources rows); member is one of its members.
func screenNetwork(t *testing.T, c Conn, tenant, name string) *Network {
	t.Helper()
	f := fc(c).f
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, row := f.w.networkRow(tenant, name); row != nil {
		return row
	}
	t.Fatalf("no network %s/%s", tenant, name)
	return nil
}

func member(t *testing.T, c Conn, tenant, name, node string) NetworkMember {
	t.Helper()
	for _, m := range screenNetwork(t, c, tenant, name).Members {
		if m.Node == node {
			return m
		}
	}
	t.Fatalf("no member %s/%s on %s", tenant, name, node)
	return NetworkMember{}
}

func TestNetworkClosure(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	admin := passwordLogin(t, f, "admin", "admin")
	alice := passwordLogin(t, f, "alice", "alice")
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))

	_, err := fc(bob).networkClosure(ctx, "shop", "shop-net")
	wantCode(t, err, CodeDenied)
	_, err = fc(alice).networkClosure(ctx, "payments", "payments-net-node-a")
	wantCode(t, err, CodeDenied)
	_, err = fc(alice).networkClosure(ctx, "shop", "shop-net-node-c")
	wantCode(t, err, CodeMissing)

	// TUN member: plan → drain → closure → fence with that closure.
	m := member(t, admin, "payments", "payments-net", "node-a")
	target := m.Source
	target.Pools = []tenancy.Subnet{{ID: "main", Prefix: netip.MustParsePrefix("10.31.0.0/24"), Gateway: netip.MustParseAddr("10.31.0.1"), MTU: 1500}}
	// the target is a definition (tenancy.validDefinition): a stored row's
	// Generation/Revision/PendingChange/Draining, or another node's Owner, is refused
	for name, bad := range map[string]func(*tenancy.Network){
		"generation": func(n *tenancy.Network) {},
		"pending":    func(n *tenancy.Network) { n.Generation, n.Revision, n.PendingChange = 0, 0, 1 },
		"draining":   func(n *tenancy.Network) { n.Generation, n.Revision, n.Draining = 0, 0, true },
		"owner":      func(n *tenancy.Network) { n.Generation, n.Revision, n.Owner = 0, 0, fakeNodeKey("node-b") },
	} {
		x := target
		bad(&x)
		if _, res := submit(t, admin, ActionPlanNetworkChange, m.Revision, control.NetworkChangePlan{Tenant: "payments", ID: m.ID, Change: "c1", Target: x}, rootFor(t, admin, ActionPlanNetworkChange)); res.Code != ResultInvalid {
			t.Fatalf("%s: %+v", name, res)
		}
	}
	target.Generation, target.Revision, target.PendingChange, target.Draining = 0, 0, 0, false
	if _, res := submit(t, admin, ActionPlanNetworkChange, m.Revision, control.NetworkChangePlan{Tenant: "payments", ID: m.ID, Change: "c1", Target: target}, rootFor(t, admin, ActionPlanNetworkChange)); res.Code != ResultApplied {
		t.Fatalf("plan %+v", res)
	}
	if v, _ := fc(admin).networkClosure(ctx, "payments", m.ID); v.Draining || v.Closed != nil {
		t.Fatalf("closed before drain %+v", v)
	}
	m = member(t, admin, "payments", "payments-net", "node-a")
	if _, res := submit(t, admin, ActionDrainNetwork, m.Revision, control.NetworkSelection{Tenant: "payments", ID: m.ID}, rootFor(t, admin, ActionDrainNetwork)); res.Code != ResultApplied {
		t.Fatalf("drain %+v", res)
	}
	v, err := fc(admin).networkClosure(ctx, "payments", m.ID)
	closed := v.Closed
	if err != nil || closed == nil || !v.Draining || len(v.Endpoints) != 0 {
		t.Fatalf("closure %+v %v", v, err)
	}
	m = member(t, admin, "payments", "payments-net", "node-a")
	if !closed.NativeGone || closed.Revision != m.Revision || closed.Owner != m.Source.Owner ||
		!ed25519.Verify(ed25519.PublicKey(closed.Owner[:]), tenancy.NetworkClosureBytes(*closed), closed.Signature) {
		t.Fatalf("closure %+v member %+v", closed, m)
	}
	forged := *closed
	forged.Signature = ed25519.Sign(FixtureKey("node-b"), tenancy.NetworkClosureBytes(forged))
	fence := func(p NetworkClosure) Result {
		_, res := submit(t, admin, ActionFenceNetworkChange, m.Change.Revision, NetworkChangeFence{Tenant: "payments", ID: m.ID, Generation: m.Change.Generation, Closed: p}, rootFor(t, admin, ActionFenceNetworkChange))
		return res
	}
	if res := fence(forged); res.Code != ResultInvalid {
		t.Fatalf("forged fence %+v", res)
	}
	if res := fence(*closed); res.Code != ResultApplied {
		t.Fatalf("fence %+v", res)
	}
	if m = member(t, admin, "payments", "payments-net", "node-a"); m.Change.Phase != "fenced" {
		t.Fatalf("after fence %+v", m.Change)
	}
	// A member whose change is fenced does not leave.
	if _, res := submit(t, admin, ActionLeaveTUN, m.Revision, *closed, rootFor(t, admin, ActionLeaveTUN)); res.Code == ResultApplied {
		t.Fatalf("fenced member left %+v", res)
	}

	// A member with running tasks: pending until they stop.
	b := member(t, alice, "shop", "shop-net", "node-a")
	if _, res := submit(t, bob, ActionDrainNetwork, b.Revision, control.NetworkSelection{Tenant: "shop", ID: b.ID}, rootFor(t, bob, ActionDrainNetwork)); res.Code != ResultForbidden {
		t.Fatalf("viewer drain %+v", res)
	}
	if _, res := submit(t, alice, ActionDrainNetwork, b.Revision, control.NetworkSelection{Tenant: "shop", ID: b.ID}, rootFor(t, alice, ActionDrainNetwork)); res.Code != ResultApplied {
		t.Fatalf("drain %+v", res)
	}
	v, _ = fc(alice).networkClosure(ctx, "shop", b.ID)
	if !v.Draining || v.Closed != nil || v.NativeGone || len(v.Endpoints) == 0 || v.PendingEndpoints != uint64(len(v.Endpoints)) {
		t.Fatalf("pending %+v", v)
	}
	f.mu.Lock()
	for _, a := range f.w.apps {
		for i := range a.tasks {
			if a.tasks[i].Node == "node-a" {
				a.tasks[i].Observed = "exited"
			}
		}
	}
	for _, e := range f.w.standalones {
		if e.view.Node == "node-a" {
			e.view.State = "exited"
		}
	}
	f.mu.Unlock()
	v, _ = fc(alice).networkClosure(ctx, "shop", b.ID)
	if v.Closed == nil {
		t.Fatalf("no closure after tasks stopped %+v", v)
	}
	b = member(t, alice, "shop", "shop-net", "node-a")
	if _, res := submit(t, alice, ActionLeaveTUN, b.Revision, *v.Closed, rootFor(t, alice, ActionLeaveTUN)); res.Code != ResultApplied {
		t.Fatalf("leave %+v", res)
	}
	if n := member(t, alice, "shop", "shop-net", "node-b"); n.Node != "node-b" {
		t.Fatalf("other member %+v", n)
	}
}

func TestNetworkUsers(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))

	u, err := fc(bob).networkUsers(ctx, "shop", "shop-net")
	if err != nil || u.Apps != 2 || u.Standalones == 0 {
		t.Fatalf("shop-net users %+v %v", u, err)
	}
	var web *NetworkUser
	for i := range u.Users {
		if u.Users[i].App == "php-shop" && u.Users[i].Service == "web" {
			web = &u.Users[i]
		}
	}
	if web == nil || web.Kind != NetworkUserService || web.Node != "node-a" || !web.Attached || len(web.Selection) == 0 {
		t.Fatalf("php-shop web %+v", u.Users)
	}
	_, err = fc(bob).networkUsers(ctx, "payments", "payments-net")
	wantCode(t, err, CodeDenied)
	_, err = fc(alice).networkUsers(ctx, "shop", "no-such-net")
	wantCode(t, err, CodeMissing)

	// Down the app: it drops out.
	apps, _ := alice.Apps(ctx, "shop", "")
	var a AppView
	for _, x := range apps.Items {
		if x.App == "shop-worker" {
			a = x
		}
	}
	if _, res := submit(t, alice, ActionDownApp, a.Revision, control.AppDown{Tenant: "shop", App: "shop-worker", Operation: "down-w"}, rootFor(t, alice, ActionDownApp)); res.Code != ResultApplied {
		t.Fatalf("down %+v", res)
	}
	if v, _ := fc(alice).networkUsers(ctx, "shop", "shop-net"); v.Apps != 1 {
		t.Fatalf("after down %+v", v)
	}
}

// The vault page carries the Approvals revision (vault-revoke-approval's Expected).
func TestVaultApprovalRevision(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	p, err := alice.Vault(ctx, "shop", "")
	a, err2 := fc(alice).vaultApprovals(ctx, "shop", "", "")
	if err != nil || err2 != nil || p.ApprovalRevision != a.Collection {
		t.Fatalf("vault %d approvals %d %v %v", p.ApprovalRevision, a.Collection, err, err2)
	}
}
