// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"encoding/json"
	"errors"
	"net/netip"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/ingress"
)

// REQ-62~65 in the real shape: record CAS, Prepare's gateway evidence,
// mapping overlay and the public history.
func TestIngressOperationsReal(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	admin := passwordLogin(t, f, "admin", "admin")
	alice := passwordLogin(t, f, "alice", "alice")
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))
	read := func(c Conn, q control.IngressQuery) (control.IngressPage, error) {
		t.Helper()
		return c.QueryIngresses(ctx, q)
	}
	gw := func(node string) control.NodeGatewaysView {
		t.Helper()
		p, err := read(admin, control.IngressQuery{Node: node, Part: "gateways"})
		if err != nil || len(p.NodeGateways) != 1 || p.Nodes[0].Configuration == nil {
			t.Fatalf("gateways %+v %v", p, err)
		}
		return p.NodeGateways[0]
	}

	// Gateways: file first, system admin only.
	v := gw("node-a")
	if v.Source != "file" || v.Revision != 0 || !v.Configuration.External.Enabled || len(v.Configuration.External.Listeners) == 0 {
		t.Fatalf("file %+v", v)
	}
	if _, err := read(alice, control.IngressQuery{Node: "node-a", Part: "gateways"}); err == nil {
		t.Fatal("alice reads gateways")
	}
	addr := netip.MustParseAddr("203.0.113.21")
	ext := &ingress.Gateway{Enabled: true, Addresses: []netip.Addr{addr}, Ports: []uint16{443},
		Listeners: []ingress.Listener{{ID: "public-https", Address: "203.0.113.21:443", TLS: true, HTTP3: true}}}
	// Evidence comes from Prepare; a payload with it is refused.
	if _, err := admin.Prepare(ctx, Change{Action: ActionSetNodeGateways, Payload: mustPayload(t, control.NodeGatewaysChange{Node: "node-a", External: ext, Evidence: &control.NodeGatewaysEvidence{}})}, rootFor(t, admin, ActionSetNodeGateways)); err == nil {
		t.Fatal("evidence accepted")
	}
	for _, bad := range []*ingress.Gateway{
		{Enabled: true, Addresses: []netip.Addr{netip.MustParseAddr("203.0.113.99")}, Ports: []uint16{443}, Listeners: []ingress.Listener{{ID: "x", Address: "203.0.113.99:443"}}},
		{Enabled: true, Addresses: []netip.Addr{addr}, Ports: []uint16{443}}, // no listener
	} {
		_, err := admin.Prepare(ctx, Change{Action: ActionSetNodeGateways, Payload: mustPayload(t, control.NodeGatewaysChange{Node: "node-a", External: bad})}, rootFor(t, admin, ActionSetNodeGateways))
		var e *Error
		if !errors.As(err, &e) || e.Code != CodeInvalid {
			t.Fatalf("bad gateway %v", err)
		}
	}
	if _, res := submit(t, admin, ActionSetNodeGateways, 0, control.NodeGatewaysChange{Node: "node-a", External: ext}, rootFor(t, admin, ActionSetNodeGateways)); res.Code != ResultApplied {
		t.Fatalf("set gateways %+v", res)
	}
	if v := gw("node-a"); v.Source != "cluster" || v.Revision != 1 || v.AppliedRevision != 1 || v.Configuration.External.Addresses[0] != addr {
		t.Fatalf("cluster %+v", v)
	}
	if _, res := submit(t, admin, ActionSetNodeGateways, 0, control.NodeGatewaysChange{Node: "node-a", External: ext}, rootFor(t, admin, ActionSetNodeGateways)); res.Code != ResultConditionFailed {
		t.Fatalf("stale gateways %+v", res)
	}
	f.FailNodeGateways("node-a", "bind: address in use")
	ext.Listeners[0].HTTP3 = false
	if _, res := submit(t, admin, ActionSetNodeGateways, 1, control.NodeGatewaysChange{Node: "node-a", External: ext}, rootFor(t, admin, ActionSetNodeGateways)); res.Code != ResultApplied {
		t.Fatalf("set gateways 2 %+v", res)
	}
	if v := gw("node-a"); v.Revision != 2 || v.AppliedRevision != 1 || v.Error == "" {
		t.Fatalf("bind failure %+v", v)
	}
	f.FailNodeGateways("node-a", "")

	// Balance: tenant manager, record CAS, overlay on every mapping.
	bal := control.IngressBalanceChange{Tenant: "shop", App: "php-shop", Route: "shop-root", Balance: ingress.Balance{Method: "hash", Key: "cookie:session"}}
	if _, res := submit(t, bob, ActionSetIngressBalance, 0, bal, rootFor(t, bob, ActionSetIngressBalance)); res.Code != ResultForbidden {
		t.Fatalf("viewer balance %+v", res)
	}
	if _, res := submit(t, alice, ActionSetIngressBalance, 0, bal, rootFor(t, alice, ActionSetIngressBalance)); res.Code != ResultApplied {
		t.Fatalf("balance %+v", res)
	}
	if _, res := submit(t, alice, ActionSetIngressBalance, 0, bal, rootFor(t, alice, ActionSetIngressBalance)); res.Code != ResultConditionFailed {
		t.Fatalf("stale balance %+v", res)
	}
	p, err := read(alice, control.IngressQuery{Tenant: "shop", App: "php-shop"})
	if err != nil || len(p.Mappings) != 1 {
		t.Fatalf("mappings %+v %v", p, err)
	}
	r := p.Mappings[0].Spec.Routes[0]
	if r.ID != "shop-root" || r.Balance == nil || r.Balance.Method != "hash" || r.BalanceRevision != 1 {
		t.Fatalf("overlay %+v", r)
	}

	// Drain: node-a, then the rest → LastMapping; undrain with the record.
	drain := control.IngressDrainChange{Tenant: "shop", App: "php-shop", Node: "node-a", DrainSeconds: 60}
	if _, res := submit(t, alice, ActionDrainIngress, 0, drain, rootFor(t, alice, ActionDrainIngress)); res.Code != ResultApplied {
		t.Fatalf("drain %+v", res)
	}
	p, _ = read(alice, control.IngressQuery{Tenant: "shop", App: "php-shop", Node: "node-a"})
	if m := p.Mappings[0]; !m.Draining || m.DrainRevision != 1 || m.DrainDeadline != m.DrainStartedAt+60 || m.LastMapping {
		t.Fatalf("drained %+v", m)
	}
	if _, res := submit(t, alice, ActionDrainIngress, 0, control.IngressDrainChange{Tenant: "shop", App: "php-shop", Node: "node-b"}, rootFor(t, alice, ActionDrainIngress)); res.Code != ResultApplied {
		t.Fatalf("drain b %+v", res)
	}
	p, _ = read(alice, control.IngressQuery{Tenant: "shop", App: "php-shop", Node: "node-b"})
	if m := p.Mappings[0]; !m.LastMapping || m.DrainDeadline != m.DrainStartedAt+30 {
		t.Fatalf("last mapping %+v", m)
	}
	if _, res := submit(t, alice, ActionUndrainIngress, 0, control.IngressDrainChange{Tenant: "shop", App: "php-shop", Node: "node-a"}, rootFor(t, alice, ActionUndrainIngress)); res.Code != ResultConditionFailed {
		t.Fatalf("stale undrain %+v", res)
	}
	if _, res := submit(t, alice, ActionUndrainIngress, 1, control.IngressDrainChange{Tenant: "shop", App: "php-shop", Node: "node-a"}, rootFor(t, alice, ActionUndrainIngress)); res.Code != ResultApplied {
		t.Fatalf("undrain %+v", res)
	}
	p, _ = read(alice, control.IngressQuery{Tenant: "shop", App: "php-shop", Node: "node-a"})
	if m := p.Mappings[0]; m.Draining || m.DrainRevision != 2 {
		t.Fatalf("undrained %+v", m)
	}

	// History: newest first, 8 a page, tenant rows only for alice.
	for i := 0; i < 4; i++ {
		bal.Balance.Method = []string{"random", "round-robin"}[i%2]
		bal.Balance.Key = ""
		if _, res := submit(t, alice, ActionSetIngressBalance, uint64(i+1), bal, rootFor(t, alice, ActionSetIngressBalance)); res.Code != ResultApplied {
			t.Fatalf("balance %d %+v", i, res)
		}
	}
	h, err := read(admin, control.IngressQuery{Part: "history"})
	if err != nil || len(h.History) != 8 || h.Next == "" || h.History[0].Action != ActionSetIngressBalance || h.History[0].Actor != "u-alice" {
		t.Fatalf("history %+v %v", h, err)
	}
	h2, err := read(admin, control.IngressQuery{Part: "history", After: h.Next})
	if err != nil || len(h2.History) != 2 || h2.Next != "" || h2.History[1].Action != ActionSetNodeGateways || h2.History[1].Node != "node-a" {
		t.Fatalf("history 2 %+v %v", h2, err)
	}
	var prev ingress.GatewayConfiguration
	if json.Unmarshal(h2.History[1].Previous, &prev) != nil || !prev.External.Enabled {
		t.Fatalf("gateway previous %s", h2.History[1].Previous)
	}
	if _, err := read(alice, control.IngressQuery{Part: "history"}); err == nil {
		t.Fatal("alice reads the cluster history")
	}
	ah, err := read(alice, control.IngressQuery{Tenant: "shop", Part: "history", App: "php-shop"})
	if err != nil || len(ah.History) != 8 {
		t.Fatalf("alice history %+v %v", ah, err)
	}
	for _, row := range ah.History {
		if row.Tenant != "shop" {
			t.Fatalf("alice sees %+v", row)
		}
	}
	if _, err := read(bob, control.IngressQuery{Tenant: "shop", Part: "history", After: h.Next}); err == nil {
		t.Fatal("another user's cursor")
	}
}
