// SPDX-License-Identifier: Apache-2.0

package sfc

import "testing"

// tunnel-down / tunnel-up events carry Tenant, Network and PairID;
// other workspaces do not see them.
func TestTunnelEventsCarryNetwork(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	admin := passwordLogin(t, f, "admin", "admin")
	alice := passwordLogin(t, f, "alice", "alice")
	find := func(c Conn, tenant, kind string) []FixtureEvent {
		p, err := seedEvents(c, tenant, "")
		if err != nil {
			t.Fatal(err)
		}
		var out []FixtureEvent
		for _, e := range p.Items {
			if e.Kind == kind {
				out = append(out, e)
			}
		}
		return out
	}

	// Fixture event.
	if ev := find(admin, "payments", "tunnel-down"); len(ev) != 1 || ev[0].Network != "payments-net" || ev[0].Tenant != "payments" || ev[0].Target != "node-a/node-c" || ev[0].PairID != "node-a/node-c" {
		t.Fatalf("fixture %+v", ev)
	}
	if ev := find(alice, "shop", "tunnel-down"); len(ev) != 0 {
		t.Fatalf("shop sees %+v", ev)
	}

	f.SetMeshLinkDown("node-c", "node-a", true)
	ev := find(admin, "payments", "tunnel-down")
	if len(ev) != 2 {
		t.Fatalf("events %+v", ev)
	}
	e := ev[1]
	if e.Tenant != "payments" || e.Network != "payments-net" || e.Target != "node-a/node-c" || e.PairID != "node-a/node-c" || e.Scope != "tenant" {
		t.Fatalf("event %+v", e)
	}
	// The old per-network payload is gone: reconnect-tunnel takes only
	// control.TunnelChange.
	old := map[string]string{"Tenant": e.Tenant, "Network": e.Network, "From": "node-a", "To": "node-c"}
	if _, res := submit(t, admin, ActionReconnectTunnel, 0, old, rootFor(t, admin, ActionReconnectTunnel)); res.Code == ResultApplied {
		t.Fatalf("old payload %+v", res)
	}
	f.SetMeshLinkDown("node-a", "node-c", false)
	if up := find(admin, "payments", "tunnel-up"); len(up) != 1 || up[0].Network != "payments-net" || up[0].PairID != "node-a/node-c" {
		t.Fatalf("tunnel-up %+v", up)
	}
}
