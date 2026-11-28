// SPDX-License-Identifier: Apache-2.0

package ingress

import "testing"

// Two apps of one tenant forced onto the same host+prefix both serve it:
// the gateway keeps one table route and rotates requests across them, and
// the other routes stay up.
func TestSharedGatewayRotatesAcrossAppsOfOneRoute(t *testing.T) {
	g := &sharedGateway{manager: &Manager{hostPolicies: map[string]HostPolicy{"team": {LocalHosts: []string{"*"}}}}, kind: "local", bindings: map[string]gatewayBinding{}}
	for _, app := range []string{"shop", "shop2"} {
		table, _ := NewTable([]Route{{ID: "root", Host: "shop.test", Prefix: "/", Service: "web"}, {ID: "own", Host: app + ".only.test", Prefix: "/", Service: "web"}})
		g.bindings[app] = gatewayBinding{spec: Spec{Tenant: "team", App: app}, table: table}
	}
	g.rebuildLocked()
	seen := map[string]int{}
	for range 4 {
		b, _, err := g.selected("shop.test", "/")
		if err != nil {
			t.Fatal(err)
		}
		seen[b.spec.App]++
	}
	if seen["shop"] != 2 || seen["shop2"] != 2 {
		t.Fatal("requests not split across both apps", seen)
	}
	for _, app := range []string{"shop", "shop2"} {
		if b, _, err := g.selected(app+".only.test", "/"); err != nil || b.spec.App != app {
			t.Fatal("other routes lost", app, err)
		}
	}
}
