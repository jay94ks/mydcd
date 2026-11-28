// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/ingress"
)

// REQ-22 in sfcd's real shape: one `ingresses` read with Parts and
// offsets, Raft blocks and tenant host policies.
func TestIngressesReal(t *testing.T) {
	f, clk := newTestFake(t)
	f.SetIdleTimeout(0)
	admin := passwordLogin(t, f, "admin", "admin")
	alice := passwordLogin(t, f, "alice", "alice")
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))

	read := func(c Conn, q control.IngressQuery) control.IngressPage {
		t.Helper()
		p, err := c.QueryIngresses(ctx, q)
		if err != nil {
			t.Fatalf("ingresses %+v: %v", q, err)
		}
		if p.Schema != 1 || p.Index == 0 || len(p.Mappings) > 1 {
			t.Fatalf("ingresses %+v: frame %+v", q, p)
		}
		return p
	}
	keys := func(c Conn, q control.IngressQuery) []string {
		t.Helper()
		var out []string
		for {
			p := read(c, q)
			for _, m := range p.Mappings {
				out = append(out, m.Key)
			}
			if p.Next == "" {
				return out
			}
			q.After = p.Next
		}
	}
	run := func(c Conn, action string, expected uint64, payload any) ResultCode {
		t.Helper()
		_, res := submit(t, c, action, expected, payload, rootFor(t, c, action))
		return res.Code
	}

	// Mappings: one a page; tenant users see their own; system all.
	if got := keys(admin, control.IngressQuery{}); len(got) != 3 || got[0] != "ingress/app/payments/payments-api/node-c" {
		t.Fatalf("admin keys %v", got)
	}
	if got := keys(bob, control.IngressQuery{}); len(got) != 2 {
		t.Fatalf("bob keys %v", got)
	}
	if _, err := bob.QueryIngresses(ctx, control.IngressQuery{Tenant: "payments"}); err == nil {
		t.Fatal("bob read payments")
	}
	p := read(alice, control.IngressQuery{Tenant: "shop", Node: "node-a"})
	row := p.Mappings[0]
	if row.Key != "ingress/app/shop/php-shop/node-a" || row.Owner != pub32(FixtureKey("node-a")) || row.Generation != 4 || !row.Ready || row.Runtime == nil ||
		row.ListenersTotal != 2 || row.RoutesTotal != 2 || row.BackendsTotal != 1 || row.CertificatesTotal != 1 || row.Next != 0 {
		t.Fatalf("mapping %+v", row)
	}
	if c := row.Runtime.Certificates[0]; c.Host != "shop.example.com" || c.Fingerprint == ([32]byte{}) {
		t.Fatalf("certificate observation %+v", c)
	}
	if row.Runtime.Metrics.Instance.Requests != 0 {
		t.Fatal("mappings part carries metrics")
	}
	if len(p.Nodes) != 1 || p.Nodes[0].Node != "node-a" || p.Nodes[0].Enabled == nil || p.Nodes[0].MaxIngressInstances == 0 || len(p.Nodes[0].Gateways) != 2 {
		t.Fatalf("nodes %+v", p.Nodes)
	}
	for _, g := range p.Nodes[0].Gateways {
		if g.SourceRejected != 0 || g.Unmatched != 0 || g.BindingsTotal == 0 {
			t.Fatalf("tenant gateway summary %+v", g)
		}
	}
	m := read(alice, control.IngressQuery{Key: row.Key, Part: "metrics"}).Mappings[0].Runtime.Metrics
	if m.WindowSeconds != 60 || m.Instance.Requests == 0 || len(m.Routes) != 2 || m.Errors != nil {
		t.Fatalf("metrics %+v", m)
	}
	e := read(alice, control.IngressQuery{Key: row.Key, Part: "errors"}).Mappings[0]
	if len(e.Runtime.Metrics.Errors) != 16 || e.Next != 16 {
		t.Fatalf("errors %d next %d", len(e.Runtime.Metrics.Errors), e.Next)
	}
	if e2 := read(alice, control.IngressQuery{Key: row.Key, Part: "errors", Offset: 16}).Mappings[0]; len(e2.Runtime.Metrics.Errors) != 8 || e2.Next != 0 {
		t.Fatalf("errors page 2 %d", len(e2.Runtime.Metrics.Errors))
	}

	// A route block on alice's route: Expected 0, then visible and applied.
	b := ingress.Block{ID: "maint-1", Scope: "route", Tenant: "shop", App: "php-shop", Node: "node-a", Key: row.Key, Route: "shop-admin", Host: "shop.example.com", Prefix: "/admin",
		Response: "503", ExpiresAt: uint64(clk.now().Unix() + 3600), Reason: "점검"}
	if code := run(bob, ActionIngressBlock, 0, control.IngressBlockChange{Block: b}); code != ResultForbidden {
		t.Fatalf("viewer block %v", code)
	}
	nb := ingress.Block{ID: "node-1", Scope: "node", Node: "node-a", Response: "503", Reason: "x"}
	if code := run(alice, ActionIngressBlock, 0, control.IngressBlockChange{Block: nb}); code != ResultForbidden {
		t.Fatalf("tenant node block %v", code)
	}
	if code := run(alice, ActionIngressBlock, 0, control.IngressBlockChange{Block: b}); code != ResultApplied {
		t.Fatalf("block %v", code)
	}
	if code := run(alice, ActionIngressBlock, 0, control.IngressBlockChange{Block: b}); code != ResultConditionFailed {
		t.Fatalf("same ID %v", code)
	}
	missing := b
	missing.ID, missing.Route = "maint-2", "nope"
	if code := run(alice, ActionIngressBlock, 0, control.IngressBlockChange{Block: missing}); code != ResultConditionFailed {
		t.Fatalf("missing route %v", code)
	}
	bl := read(alice, control.IngressQuery{Tenant: "shop", Node: "node-a", Part: "blocks"})
	if len(bl.Blocks) != 1 || bl.Blocks[0].Revision != 1 || !bl.Blocks[0].Active || bl.Blocks[0].Block.Actor != "u-alice" || len(bl.Blocks[0].Applications) != 1 || !bl.Blocks[0].Applications[0].Applied || bl.Mappings != nil {
		t.Fatalf("blocks %+v", bl)
	}
	if rb := read(alice, control.IngressQuery{Key: row.Key}).Mappings[0]; len(rb.Blocks) != 1 || len(rb.Runtime.Blocks) != 1 {
		t.Fatalf("mapping blocks %+v", rb.Blocks)
	}
	if code := run(alice, ActionIngressBlockExtend, 1, control.IngressBlockSelection{ID: "maint-1", ExpiresAt: b.ExpiresAt + 600}); code != ResultApplied {
		t.Fatalf("extend %v", code)
	}
	if code := run(alice, ActionIngressUnblock, 1, control.IngressBlockSelection{ID: "maint-1"}); code != ResultConditionFailed {
		t.Fatalf("stale unblock %v", code)
	}
	if code := run(alice, ActionIngressUnblock, 2, control.IngressBlockSelection{ID: "maint-1"}); code != ResultApplied {
		t.Fatalf("unblock %v", code)
	}
	if bl := read(alice, control.IngressQuery{Tenant: "shop", Part: "blocks"}); len(bl.Blocks) != 1 || !bl.Blocks[0].Removed || bl.Blocks[0].Active {
		t.Fatalf("removed %+v", bl.Blocks)
	}

	hp := read(alice, control.IngressQuery{Tenant: "shop", Part: "blocks"})
	if hp.RootRevision != rootFor(t, alice, ActionIngressBlock) {
		t.Fatalf("root %d", hp.RootRevision)
	}
}
