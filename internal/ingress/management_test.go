// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func TestEmergencyBlockMatchesSelectedRouteWithoutShorterFallback(t *testing.T) {
	table, err := NewTable([]Route{{ID: "root", Host: "shop.example", Prefix: "/", Service: "web"}, {ID: "admin", Host: "shop.example", Prefix: "/admin", Service: "admin"}})
	if err != nil {
		t.Fatal(err)
	}
	route, err := table.Match("shop.example", "/admin/login")
	if err != nil || route.ID != "admin" {
		t.Fatal(route, err)
	}
	b := Block{ID: "incident", Scope: "route", Tenant: "tenant", App: "shop", Node: "node-a", Key: "ingress/app/tenant/shop/http", Route: route.ID, Host: route.Host, Prefix: route.Prefix, Response: "503", Actor: "admin", CreatedAt: 10, ExpiresAt: 20}
	if !b.Valid() {
		t.Fatal("valid original route block rejected")
	}
	target := RequestTarget{Tenant: "tenant", App: "shop", Node: "node-a", Key: b.Key, Route: route}
	if !b.Matches(target, 19) || b.Matches(target, 20) {
		t.Fatal("route or expiry mismatch")
	}
	route.ID = "recreated"
	target.Route = route
	if !b.Matches(target, 19) {
		t.Fatal("same host/prefix recreation lost original block")
	}
	target.Route.Prefix = "/"
	if b.Matches(target, 19) {
		t.Fatal("block leaked into shorter route")
	}
	target.Route = Route{ID: "login", Host: route.Host, Prefix: "/admin/login", Service: "admin"}
	if b.Matches(target, 19) {
		t.Fatal("arbitrary sub-prefix accepted as original route")
	}
}
func TestBlockSourceGatewayAndTenantIsolation(t *testing.T) {
	b := Block{ID: "source", Scope: "source", Tenant: "tenant", Apps: []string{"shop"}, Source: "192.0.2.0/24", Gateway: "external", Response: "403", Actor: "admin", CreatedAt: 1}
	target := RequestTarget{Tenant: "tenant", App: "shop", Gateway: "external", Source: netip.MustParseAddr("192.0.2.45")}
	if !b.Valid() || !b.Matches(target, 2) {
		t.Fatal("owned source did not match")
	}
	for _, mutation := range []func(*RequestTarget){func(t *RequestTarget) { t.Tenant = "other" }, func(t *RequestTarget) { t.App = "other" }, func(t *RequestTarget) { t.Gateway = "local" }, func(t *RequestTarget) { t.Source = netip.MustParseAddr("198.51.100.1") }} {
		other := target
		mutation(&other)
		if b.Matches(other, 2) {
			t.Fatal("source block crossed target boundary")
		}
	}
	for _, source := range []string{"0.0.0.0/0", "::/0", "192.0.2.1/24", "::ffff:192.0.2.0/120"} {
		bad := b
		bad.Source = source
		if bad.Valid() {
			t.Fatal("invalid/broad source block accepted", source)
		}
	}
}
func TestManagementSameRevisionExpiresWithoutReplacingOriginalPolicy(t *testing.T) {
	m := NewManagement()
	b := Block{ID: "maintenance", Scope: "node", Node: "node-a", Response: "503", Actor: "admin", CreatedAt: 1, ExpiresAt: 10}
	if err := m.UpdateBlocks(1, "node-a", []Block{b}, 2); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Match(RequestTarget{Node: "node-a"}, 9); !ok {
		t.Fatal("live block missing")
	}
	if err := m.UpdateBlocks(1, "node-a", []Block{b}, 11); err != nil {
		t.Fatal("clock observation rewrote original policy", err)
	}
	if _, ok := m.Match(RequestTarget{Node: "node-a"}, 11); ok {
		t.Fatal("expired block continued rejecting")
	}
	if err := m.UpdateBlocks(1, "node-a", nil, 11); err == nil {
		t.Fatal("same revision replaced original configuration")
	}
	if err := m.UpdateBlocks(2, "node-a", nil, 11); err != nil {
		t.Fatal(err)
	}
}
func TestIngressMetricsRollingWindowAndRedactedErrorRing(t *testing.T) {
	m := NewManagement()
	for i := 0; i < 205; i++ {
		m.Record("key", RequestEvent{At: 100000 + uint64(i), Method: "GET", Host: "shop.example", Path: "/path?password=never-retain", Route: "route", Backend: "backend", Gateway: "external", Condition: "canary", Status: 503, Block: "maintenance", Failure: "CONNECT", DurationMS: 100, ReceivedBytes: 4, SentBytes: 10, Source: netip.MustParseAddr("192.0.2.77")})
	}
	got := m.Snapshot("key", 101000)
	if got.WindowSeconds != 60 || got.Instance.Requests != 205 || got.Instance.Blocked != 205 || got.Instance.Responses[3] != 205 || got.Instance.ReceivedBytes != 820 || got.Instance.SentBytes != 2050 || got.Instance.P50MS != 128 || len(got.Errors) != 200 || len(got.Routes) != 1 || len(got.Backends) != 1 || len(got.Gateways) != 1 || len(got.Conditions) != 1 {
		t.Fatal("actual request facts not reflected", got.Instance)
	}
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "never-retain") || strings.Contains(string(raw), "192.0.2.77") || got.Errors[0].Source != "192.0.2.0/24" || got.Errors[0].Path != "/path" {
		t.Fatal("request secrets or complete source retained")
	}
	if next := m.Snapshot("key", 160000); next.Instance.Requests != 0 {
		t.Fatal("expired bucket retained in recent minute")
	}
	m.Record("v6", RequestEvent{At: 200000, Status: 403, Source: netip.MustParseAddr("2001:db8:abcd:1234::1")})
	if m.Snapshot("v6", 200000).Errors[0].Source != "2001:db8:abcd::/48" {
		t.Fatal("IPv6 source mask")
	}
}

func TestIngressOpenConnectionGaugeConsumesDialAndCloseFacts(t *testing.T) {
	m := NewManagement()
	release := m.ConnectionOpened("key", "route", "backend")
	m.Record("key", RequestEvent{At: 1000, Route: "route", Backend: "backend", Status: 200})
	got := m.Snapshot("key", 70000)
	if got.ConnectionKind != "upstream-live" || got.Instance.Requests != 0 || got.Instance.OpenConnections != 1 || len(got.Routes) != 1 || got.Routes[0].OpenConnections != 1 || len(got.Backends) != 1 || got.Backends[0].OpenConnections != 1 {
		t.Fatal("live socket replaced by request counter/window", got)
	}
	release()
	release()
	got = m.Snapshot("key", 70000)
	if got.Instance.OpenConnections != 0 || got.Backends[0].OpenConnections != 0 {
		t.Fatal("close underflow", got)
	}
	late := m.ConnectionOpened("key", "route", "backend")
	m.ForgetMetrics("key")
	newRelease := m.ConnectionOpened("key", "route", "backend")
	defer newRelease()
	late()
	if got = m.Snapshot("key", 70000); got.Instance.OpenConnections != 1 {
		t.Fatal("old close decremented new lifetime", got)
	}
}
