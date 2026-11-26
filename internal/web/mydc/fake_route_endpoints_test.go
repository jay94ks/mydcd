// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

func TestRouteEndpoints(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))

	// bob manages no tenant.
	_, err := fc(bob).routeEndpoints(ctx, "payments")
	wantCode(t, err, CodeDenied)
	_, err = fc(alice).routeEndpoints(ctx, "nope")
	wantCode(t, err, CodeMissing)

	// alice manages shop: payments offers payments-net (two servers).
	e, err := fc(alice).routeEndpoints(ctx, "payments")
	if err != nil || len(e.Endpoints) != 2 || e.Endpoints[0].Network != "payments-net" || e.Endpoints[0].Pool != "main" {
		t.Fatalf("endpoints %+v %v", e, err)
	}
	// The result alone builds a proposal that applies.
	res, _ := alice.Resources(ctx, "shop", "")
	var dst control.RouteEndpoint
	for _, x := range e.Endpoints {
		if x.Node == "node-a" {
			dst = x
		}
	}
	q := control.RouteProposal{ID: "shop-to-pay-2", Protocol: 6, Ports: []tenancy.Ports{{First: 8443, Last: 8443}},
		Source: control.RouteEndpoint{Tenant: "shop", Network: "shop-net", Node: "node-a", Pool: "main"}, Destination: dst}
	if _, r := submit(t, alice, ActionProposeRoute, res.Collection, q, rootFor(t, alice, ActionProposeRoute)); r.Code != ResultApplied {
		t.Fatalf("propose %+v", r)
	}

	// Not offered: nothing listed.
	f.SetRouteOpen("payments", "payments-net", false)
	if e, _ := fc(alice).routeEndpoints(ctx, "payments"); len(e.Endpoints) != 0 {
		t.Fatalf("closed %+v", e)
	}
	// The tenant's own manager sees every network.
	if e, _ := fc(alice).routeEndpoints(ctx, "shop"); len(e.Endpoints) == 0 {
		t.Fatalf("own %+v", e)
	}
}
