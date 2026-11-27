// SPDX-License-Identifier: Apache-2.0

package sfc

import "testing"

// REQ-22 G: ingress fault events; route events by tenant Read, gateway
// events for the system administrator only.
func TestIngressEvents(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	admin := passwordLogin(t, f, "admin", "admin")
	alice := passwordLogin(t, f, "alice", "alice")
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))
	kinds := func(c Conn, tenant string) map[string]FixtureEvent {
		p, err := seedEvents(c, tenant, "")
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]FixtureEvent{}
		for _, e := range p.Items {
			if e.Ingress != nil {
				out[e.Kind] = e
			}
		}
		return out
	}

	f.AddIngressEvent(EventIngressBackendsEmpty, "node-a", "shop", "php-shop", IngressEvent{Gateway: GatewayExternal, RouteID: "shop-root", Host: "shop.example.com", Prefix: "/", Metric: "backends"})
	f.AddIngressEvent(EventIngressBackendsRestored, "node-a", "shop", "php-shop", IngressEvent{Gateway: GatewayExternal, RouteID: "shop-root", Host: "shop.example.com", Prefix: "/"})
	f.AddIngressEvent(EventIngressListenerDown, "node-a", "", "", IngressEvent{Gateway: GatewayExternal, Listener: "shared-a-ext-443"})
	f.AddIngressEvent(EventIngressSourceRejected, "node-c", "", "", IngressEvent{Gateway: GatewayLocal, Value: 100})
	f.AddIngressEvent(EventIngressCertMissing, "node-c", "payments", "payments-api", IngressEvent{Gateway: GatewayLocal, RouteID: "pay-admin", Host: "admin.payments.example.com", Prefix: "/"})

	all := kinds(admin, "")
	if len(all) != 5 {
		t.Fatalf("admin sees %d", len(all))
	}
	ld := all[EventIngressListenerDown]
	if ld.Tenant != "" || ld.Scope != "node" || ld.Node != "node-a" || ld.Ingress.Gateway != GatewayExternal || ld.Detail != "shared-a-ext-443" {
		t.Fatalf("listener %+v %+v", ld, ld.Ingress)
	}
	br := all[EventIngressBackendsRestored]
	if br.Tenant != "shop" || br.App != "php-shop" || br.Ingress.RouteID != "shop-root" || br.Ingress.Host != "shop.example.com" {
		t.Fatalf("restored %+v %+v", br, br.Ingress)
	}
	if sp := all[EventIngressSourceRejected]; sp.Tenant != "" || sp.Ingress.Value != 100 {
		t.Fatalf("spike %+v %+v", sp, sp.Ingress)
	}

	// shop users: only shop route events.
	for _, c := range []Conn{alice, bob} {
		shop := kinds(c, "shop")
		if len(shop) != 2 || shop[EventIngressBackendsEmpty].Ingress.RouteID != "shop-root" {
			t.Fatalf("shop sees %v", shop)
		}
	}
	if pay := kinds(alice, "payments"); len(pay) != 1 || pay[EventIngressCertMissing].Ingress.Host != "admin.payments.example.com" {
		t.Fatalf("payments sees %v", pay)
	}
	_, err := seedEvents(alice, "", "")
	wantCode(t, err, CodeDenied)
}
