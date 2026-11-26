// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"github.com/jay94ks/mydcd/internal/web/mydc"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
)

func TestCrossTenantRoutes(t *testing.T) {
	f, _ := newFakeFixture(t)
	n := 0
	op := func() string { n++; return fmt.Sprintf("a7b2c3d4-0000-4000-8000-%012d", n) }
	list := func(tenant string) map[string]any {
		t.Helper()
		code, out := f.do("GET", "/api/v1/t/"+tenant+"/routes", nil)
		if code != 200 {
			t.Fatalf("list %s: %d %v", tenant, code, out)
		}
		return out
	}
	item := func(out map[string]any, id string) map[string]any {
		for _, x := range out["items"].([]any) {
			if m := x.(map[string]any); m["id"] == id {
				return m
			}
		}
		return nil
	}

	// the fixture route, seen from each side
	fakeLogin(t, f, "alice")
	r := item(list("shop"), "shop-to-ledger")
	if r == nil || r["side"] != "source" || r["state"] != "waiting-peer" || r["protocol"] != "tcp" || r["source"].(map[string]any)["name"] != "shop-net" ||
		r["destination"].(map[string]any)["tenant"] != "payments" || r["sourceTenant"] != "shop" {
		t.Fatalf("shop view: %v", r)
	}
	if r := item(list("payments"), "shop-to-ledger"); r == nil || r["side"] != "destination" || r["state"] != "waiting-me" {
		t.Fatalf("payments view: %v", r)
	}
	// alice only reads payments: her approval for it is refused by mydcd
	code, out := f.do("POST", "/api/v1/t/payments/routes/shop/shop-to-ledger/approve", map[string]any{"opId": op()})
	if opState(t, code, out) != "failed" {
		t.Fatalf("viewer approve: %d %v", code, out)
	}
	// shop already approved
	if code, out := f.do("POST", "/api/v1/t/shop/routes/shop/shop-to-ledger/approve", map[string]any{"opId": op()}); code != 409 || errCode(out) != "already-approved" {
		t.Fatalf("double approve: %d %v", code, out)
	}

	// propose: the daemon fills node and pool from rows alice can read
	o1 := op()
	code, out = f.do("POST", "/api/v1/t/shop/routes", map[string]any{"opId": o1, "source": map[string]any{"network": "shop-net", "node": "node-b"},
		"destination": map[string]any{"tenant": "payments", "network": "payments-net", "node": "node-c"}, "protocol": "udp", "ports": []any{53, "8000-8100"}})
	if opState(t, code, out) != "applied" {
		t.Fatalf("propose: %d %v", code, out)
	}
	var q control.RouteProposal
	userPayload(t, f, "u-alice", o1, &q)
	if q.ID != "rt-"+o1[:8] || q.Source.Node != "node-b" || q.Source.Pool != "main" || q.Destination.Network != "payments-net" || q.Destination.Pool != "main" ||
		q.Protocol != 17 || len(q.Ports) != 2 || q.Ports[1].First != 8000 || q.Ports[1].Last != 8100 {
		t.Fatalf("proposal: %+v", q)
	}
	if r := item(list("shop"), q.ID); r == nil || r["phase"] != "pending" || r["state"] != "waiting-me" {
		t.Fatalf("proposed: %v", r)
	}
	// a multi-server destination needs node; bad ports; same tenant
	for _, c := range []struct {
		body map[string]any
		code string
	}{
		{map[string]any{"source": map[string]any{"network": "shop-net", "node": "node-a"}, "destination": map[string]any{"tenant": "payments", "network": "payments-net"}, "protocol": "tcp", "ports": []any{80}}, "destination-node-required"},
		{map[string]any{"source": map[string]any{"network": "shop-net"}, "destination": map[string]any{"tenant": "payments", "network": "payments-net", "node": "node-a"}, "protocol": "tcp", "ports": []any{80}}, "node-required"},
		{map[string]any{"source": map[string]any{"network": "shop-net", "node": "node-a"}, "destination": map[string]any{"tenant": "payments", "network": "payments-net", "node": "node-a"}, "protocol": "tcp", "ports": []any{"90-80"}}, "invalid"},
		{map[string]any{"source": map[string]any{"network": "shop-net", "node": "node-a"}, "destination": map[string]any{"tenant": "shop", "network": "shop-net"}, "protocol": "tcp", "ports": []any{80}}, "invalid"},
		{map[string]any{"source": map[string]any{"network": "shop-net", "node": "node-a"}, "destination": map[string]any{"tenant": "payments", "network": "payments-net", "node": "node-a"}, "protocol": "icmp", "ports": []any{80}}, "invalid"},
	} {
		c.body["opId"] = op()
		if code, out := f.do("POST", "/api/v1/t/shop/routes", c.body); code != 422 || errCode(out) != c.code {
			t.Fatalf("%v: %d %v", c.body, code, out)
		}
	}

	// another workspace's open route endpoints
	code, out = f.do("GET", "/api/v1/t/shop/route-endpoints?tenant=payments", nil)
	if code != 200 || len(out["items"].([]any)) == 0 || out["items"].([]any)[0].(map[string]any)["network"] != "payments-net" {
		t.Fatalf("route endpoints: %d %v", code, out)
	}
	if code, out := f.do("GET", "/api/v1/t/shop/route-endpoints?tenant=nobody", nil); code != 404 {
		t.Fatalf("no such workspace: %d %v", code, out)
	}

	// both sides approve as the system administrator → active; withdraw → revoking
	fakeLogin(t, f, "admin")
	step := func(path string) {
		t.Helper()
		code, out := f.do("POST", path, map[string]any{"opId": op()})
		if opState(t, code, out) != "applied" {
			t.Fatalf("%s: %d %v", path, code, out)
		}
	}
	// a stale expected fails in mydcd
	code, out = f.do("POST", "/api/v1/t/shop/routes/shop/"+q.ID+"/approve", map[string]any{"opId": op(), "expected": 1})
	if opState(t, code, out) != "failed" {
		t.Fatalf("stale approve: %d %v", code, out)
	}
	step("/api/v1/t/shop/routes/shop/" + q.ID + "/approve")
	step("/api/v1/t/payments/routes/shop/" + q.ID + "/approve")
	if r := item(list("payments"), q.ID); r["state"] != "active" || len(r["approvals"].([]any)) != 2 {
		t.Fatalf("active: %v", r)
	}
	step("/api/v1/t/payments/routes/shop/" + q.ID + "/withdraw")
	if r := item(list("shop"), q.ID); r["state"] != "revoking" {
		t.Fatalf("revoking: %v", r)
	}
	if code, out := f.do("POST", "/api/v1/t/shop/routes/shop/"+q.ID+"/approve", map[string]any{"opId": op()}); code != 409 || errCode(out) != "revoking" {
		t.Fatalf("approve revoking: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/t/shop/routes/shop/nope/withdraw", map[string]any{"opId": op()}); code != 404 {
		t.Fatalf("missing: %d %v", code, out)
	}
}

type endpointsConn struct {
	mydc.Conn
	v mydc.RouteEndpoints
}

// PublicRead route-endpoints: one page of the fixed rows.
func (c endpointsConn) PublicRead(_ context.Context, method, _ string, _ control.PublicReadQuery, _ string) (control.PublicReadPage, error) {
	p := control.PublicReadPage{}
	for _, e := range c.v.Endpoints {
		r := control.PublicRouteEndpoint{Tenant: e.Tenant, Network: e.Network, Node: e.Node, Pool: e.Pool}
		p.Rows = append(p.Rows, control.PublicReadRow{RouteEndpoint: &r})
	}
	return p, nil
}

func TestOpenEndpoint(t *testing.T) {
	c := endpointsConn{v: mydc.RouteEndpoints{Tenant: "pay", Endpoints: []control.RouteEndpoint{
		{Tenant: "pay", Network: "ledger", Node: "node-a", Pool: "main"},
		{Tenant: "pay", Network: "ledger", Node: "node-c", Pool: "main"},
		{Tenant: "pay", Network: "solo", Node: "node-b", Pool: "main"},
	}}}
	ctx := context.Background()
	if e, err := openEndpoint(ctx, c, "pay", "solo", "", ""); err != nil || e.Node != "node-b" {
		t.Fatalf("single: %+v %v", e, err)
	}
	if e, err := openEndpoint(ctx, c, "pay", "ledger", "node-c", ""); err != nil || e.Node != "node-c" {
		t.Fatalf("by node: %+v %v", e, err)
	}
	for _, x := range []struct{ network, node, code string }{{"ledger", "", "destination-node-required"}, {"closed", "", "destination-not-open"}, {"ledger", "node-z", "destination-not-open"}} {
		_, err := openEndpoint(ctx, c, "pay", x.network, x.node, "")
		if he, ok := err.(*httpErr); !ok || he.code != x.code {
			t.Fatalf("%v: %v", x, err)
		}
	}
}
