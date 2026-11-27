// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/ingress"
)

// Runtime.BlockRevision, a held owner install, route metric
// override, shared listeners counted once and the block event target.
func TestIngressRuntimeKnobs(t *testing.T) {
	f, clk := newTestFake(t)
	f.SetIdleTimeout(0)
	admin := passwordLogin(t, f, "admin", "admin")
	alice := passwordLogin(t, f, "alice", "alice")
	key := "ingress/app/shop/php-shop/node-a"
	page := func() control.IngressPage {
		t.Helper()
		p, err := alice.QueryIngresses(ctx, control.IngressQuery{Key: key})
		if err != nil || len(p.Mappings) != 1 {
			t.Fatalf("mapping %+v %v", p, err)
		}
		return p
	}
	run := func(action string, expected uint64, payload any) ResultCode {
		t.Helper()
		_, res := submit(t, alice, action, expected, payload, rootFor(t, alice, action))
		return res.Code
	}

	if p := page(); p.Mappings[0].Runtime.BlockRevision != p.BlockRevision {
		t.Fatalf("seed installed %d target %d", p.Mappings[0].Runtime.BlockRevision, p.BlockRevision)
	}
	b := ingress.Block{ID: "maint-1", Scope: "route", Tenant: "shop", App: "php-shop", Node: "node-a", Key: key, Route: "shop-admin", Host: "shop.example.com", Prefix: "/admin",
		Response: "503", ExpiresAt: uint64(clk.now().Unix() + 3600), Reason: "점검"}
	if code := run(ActionIngressBlock, 0, control.IngressBlockChange{Block: b}); code != ResultApplied {
		t.Fatalf("block %v", code)
	}
	p := page()
	r := p.Mappings[0].Runtime
	if r.BlockRevision != p.BlockRevision || len(r.Blocks) != 1 || !r.Blocks[0].Applied {
		t.Fatalf("installed %d %+v", r.BlockRevision, r.Blocks)
	}
	// The block event names its target.
	ev, err := seedEvents(alice, "shop", "")
	if err != nil {
		t.Fatal(err)
	}
	var blocked *FixtureEvent
	for i := range ev.Items {
		if ev.Items[i].Kind == EventIngressBlocked {
			blocked = &ev.Items[i]
		}
	}
	if blocked == nil || blocked.App != "php-shop" || blocked.Node != "node-a" || blocked.Ingress == nil || blocked.Ingress.RouteID != "shop-admin" || blocked.Ingress.Prefix != "/admin" {
		t.Fatalf("blocked event %+v", blocked)
	}

	// Held: the unblock commits but node-a still serves the block.
	f.HoldIngressBlocks("node-a", true)
	if code := run(ActionIngressUnblock, 1, control.IngressBlockSelection{ID: "maint-1"}); code != ResultApplied {
		t.Fatalf("unblock %v", code)
	}
	installed := r.BlockRevision
	if p := page(); p.BlockRevision <= installed || p.Mappings[0].Runtime.BlockRevision != installed || len(p.Mappings[0].Runtime.Blocks) != 1 {
		t.Fatalf("held %d target %d %+v", p.Mappings[0].Runtime.BlockRevision, p.BlockRevision, p.Mappings[0].Runtime.Blocks)
	}
	f.HoldIngressBlocks("node-a", false)
	if p := page(); p.Mappings[0].Runtime.BlockRevision != p.BlockRevision || len(p.Mappings[0].Runtime.Blocks) != 0 {
		t.Fatalf("released %+v target %d", p.Mappings[0].Runtime, p.BlockRevision)
	}

	// A held node shows a new block not applied.
	f.HoldIngressBlocks("node-a", true)
	b2 := b
	b2.ID = "maint-2"
	if code := run(ActionIngressBlock, 0, control.IngressBlockChange{Block: b2}); code != ResultApplied {
		t.Fatalf("block 2 %v", code)
	}
	bl, err := alice.QueryIngresses(ctx, control.IngressQuery{Tenant: "shop", Node: "node-a", Part: "blocks"})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range bl.Blocks {
		if v.Block.ID == "maint-2" && (len(v.Applications) != 1 || v.Applications[0].Applied) {
			t.Fatalf("held application %+v", v.Applications)
		}
	}
	f.HoldIngressBlocks("node-a", false)

	// Route metric override and reset.
	metric := func() ingress.Metric {
		t.Helper()
		p, err := alice.QueryIngresses(ctx, control.IngressQuery{Key: key, Part: "metrics"})
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range p.Mappings[0].Runtime.Metrics.Routes {
			if m.ID == "shop-admin" {
				return m
			}
		}
		t.Fatal("no shop-admin metric")
		return ingress.Metric{}
	}
	orig := metric()
	f.SetIngressRouteMetric("shop", "php-shop", "node-a", "shop-admin", ingress.Metric{Requests: 100, Responses: [4]uint64{80, 0, 0, 20}, P95MS: 900})
	if m := metric(); m.ID != "shop-admin" || m.Responses[3] != 20 || m.P95MS != 900 {
		t.Fatalf("override %+v", m)
	}
	f.SetIngressRouteMetric("shop", "php-shop", "node-a", "shop-admin", ingress.Metric{})
	if m := metric(); m.P95MS != orig.P95MS || m.Requests != orig.Requests {
		t.Fatalf("reset %+v", m)
	}

	// Shared listeners count once per node across visible apps.
	p, err = admin.QueryIngresses(ctx, control.IngressQuery{Node: "node-a"})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	want, total := 0, 0
	for q := (control.IngressQuery{Node: "node-a"}); ; {
		pp, err := admin.QueryIngresses(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range pp.Mappings {
			want += countIngressListeners(m.Node, m.Spec.Listeners, seen)
			total += len(m.Spec.Listeners)
		}
		if pp.Next == "" {
			break
		}
		q.After = pp.Next
	}
	shared := []ingress.Listener{{ID: "outside", Shared: "external"}, {ID: "inside", Shared: "local"}}
	two := map[string]bool{}
	if countIngressListeners("node-a", shared, two) != 2 || countIngressListeners("node-a", shared, two) != 0 || countIngressListeners("node-b", shared, two) != 2 {
		t.Fatal("shared listeners counted per app")
	}
	if len(p.Nodes) != 1 || p.Nodes[0].Listeners != want || want > total {
		t.Fatalf("listeners %+v want %d of %d", p.Nodes, want, total)
	}
}
