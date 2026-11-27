// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"slices"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/tenancy"
)

// A TUN network change on real sfcd is TestRealServerNetworkChange. Moving
// members needs a TUN network on two servers (clusterfixture.NewIsolated),
// so reconfigure stays on the fake.
func TestNetworkReconfigureMembers(t *testing.T) {
	f, fake := newFakeFixture(t)
	fakeLogin(t, f, "admin")
	n := 0
	op := func() string { n++; return fmt.Sprintf("f1b2c3d4-0000-4000-8000-%012d", n) }
	base := "/api/v1/t/payments/networks/payments-net"
	for _, node := range []string{"node-a", "node-c"} {
		for _, p := range []string{"/change", "/change/drain"} {
			body := map[string]any{"opId": op(), "node": node}
			if p == "/change" {
				body["cidr"] = map[string]string{"node-a": "10.30.0.0/24", "node-c": "10.30.1.0/24"}[node]
			}
			if code, out := f.do("POST", base+p, body); opState(t, code, out) != "applied" {
				t.Fatalf("%s %s: %d %v", p, node, code, out)
			}
		}
		if err := fake.FenceNetworkChange("payments", "payments-net", node); err != nil {
			t.Fatal(err)
		}
	}
	// keep node-a as it is, drop node-c, add node-b
	o := op()
	code, out := f.do("POST", base+"/reconfigure", map[string]any{"opId": o, "members": []map[string]any{
		{"node": "node-a"}, {"node": "node-b", "cidr": "10.30.5.0/24"}}})
	if opState(t, code, out) != "applied" {
		t.Fatalf("reconfigure: %d %v", code, out)
	}
	var rc control.NetworkReconfigure
	userPayload(t, f, "u-admin", o, &rc)
	if len(rc.Target.Members) != 2 || rc.Target.Members[0].Pools[0].Prefix.String() != "10.30.0.0/24" || len(rc.Target.Members[0].Addresses) != 0 || rc.Target.Members[1].Node != "node-b" {
		t.Fatalf("reconfigure payload: %+v", rc.Target)
	}
	// a tunnel address is sfcd's: the request has no field for it
	if code, out := f.do("POST", base+"/reconfigure", map[string]any{"opId": op(), "members": []map[string]any{{"node": "node-a"}, {"node": "node-c", "cidr": "10.30.6.0/24", "tunnel": "10.255.0.9"}}}); code != 400 && code != 422 {
		t.Fatalf("tunnel given: %d %v", code, out)
	}
}

// Adding and removing one server: join, then drain and leave on the
// server's closure. No member needs a planned change.
func TestNetworkJoinAndLeaveOneServer(t *testing.T) {
	f, _ := newFakeFixture(t)
	fakeLogin(t, f, "admin")
	n := 0
	op := func() string { n++; return fmt.Sprintf("a1b2c3d4-0000-4000-8000-%012d", n) }
	base := "/api/v1/t/payments/networks/payments-net"
	o := op()
	code, out := f.do("POST", base+"/members", map[string]any{"opId": o, "node": "node-b", "cidr": "10.30.5.0/24"})
	if opState(t, code, out) != "applied" {
		t.Fatalf("join: %d %v", code, out)
	}
	var j control.NetworkJoin
	userPayload(t, f, "u-admin", o, &j)
	if j.Tenant != "payments" || j.Name != "payments-net" || j.Member.Node != "node-b" || j.Member.Pools[0].Prefix.String() != "10.30.5.0/24" || j.Member.Pools[0].MTU != 1500 || len(j.Member.Addresses) != 0 {
		t.Fatalf("join payload: %+v", j)
	}
	for _, c := range []struct {
		body map[string]any
		code int
		err  string
	}{
		{map[string]any{"opId": op(), "node": "node-b", "cidr": "10.30.6.0/24"}, 409, "already-member"},
		{map[string]any{"opId": op(), "node": "node-d", "cidr": "10.30.5.0/25"}, 422, "invalid"},
		{map[string]any{"opId": op(), "node": "node-d", "cidr": "10.254.5.0/24"}, 422, "system-range"},
	} {
		if code, out := f.do("POST", base+"/members", c.body); code != c.code || errCode(out) != c.err {
			t.Fatalf("%v: %d %v", c.body, code, out)
		}
	}
	// leave needs a drained server
	if code, out := f.do("POST", base+"/members/leave", map[string]any{"opId": op(), "node": "node-b"}); code != 409 || errCode(out) != "not-drained" {
		t.Fatalf("undrained leave: %d %v", code, out)
	}
	if code, out := f.do("POST", base+"/change/drain", map[string]any{"opId": op(), "node": "node-b"}); opState(t, code, out) != "applied" {
		t.Fatalf("drain: %d %v", code, out)
	}
	// while node-b drains, no other server joins
	if code, out := f.do("POST", base+"/members", map[string]any{"opId": op(), "node": "node-d", "cidr": "10.30.8.0/24"}); code != 409 || errCode(out) != "member-changing" {
		t.Fatalf("join while draining: %d %v", code, out)
	}
	o = op()
	if code, out := f.do("POST", base+"/members/leave", map[string]any{"opId": o, "node": "node-b"}); opState(t, code, out) != "applied" {
		t.Fatalf("leave: %d %v", code, out)
	}
	var closed tenancy.NetworkClosure
	userPayload(t, f, "u-admin", o, &closed)
	if closed.Tenant != "payments" || closed.Network != "payments-net-node-b" || closed.Node != "node-b" {
		t.Fatalf("leave payload: %+v", closed)
	}
	code, out = f.do("GET", base+"/change", nil)
	if code != 200 || len(out["members"].([]any)) != 2 {
		t.Fatalf("after leave: %d %v", code, out)
	}
}

// Toggles: local needs one server, and a local network takes no server.
func TestNetworkToggleLocal(t *testing.T) {
	f, fake := newFakeFixture(t)
	fakeLogin(t, f, "admin")
	n := 0
	op := func() string { n++; return fmt.Sprintf("b1b2c3d4-0000-4000-8000-%012d", n) }
	refused := func(path string, body map[string]any, code int, errc string) {
		t.Helper()
		if got, out := f.do("POST", path, body); got != code || errCode(out) != errc {
			t.Fatalf("%s %v: %d %v", path, body, got, out)
		}
	}
	applied := func(path string, body map[string]any) string {
		t.Helper()
		o := op()
		body["opId"] = o
		if code, out := f.do("POST", path, body); opState(t, code, out) != "applied" {
			t.Fatalf("%s %v: %d %v", path, body, code, out)
		}
		return o
	}
	two := "/api/v1/t/payments/networks/payments-net"
	refused(two+"/toggles", map[string]any{"opId": op(), "toggle": "nope", "on": true}, 422, "invalid")
	refused(two+"/toggles", map[string]any{"opId": op(), "toggle": "local", "on": false}, 409, "same-value")
	refused(two+"/toggles", map[string]any{"opId": op(), "toggle": "local", "on": true}, 409, "toggle-not-allowed")
	// a local network on one server
	refused("/api/v1/t/payments/networks", map[string]any{"opId": op(), "kind": "tun", "name": "solo", "toggles": map[string]bool{"local": true}, "members": []map[string]any{
		{"node": "node-a", "cidr": "10.61.0.0/24"}, {"node": "node-c", "cidr": "10.62.0.0/24"}}}, 422, "invalid")
	o := applied("/api/v1/t/payments/networks", map[string]any{"kind": "tun", "name": "solo", "toggles": map[string]bool{"local": true}, "members": []map[string]any{{"node": "node-a", "cidr": "10.61.0.0/24"}}})
	var d tenancy.TUNDefinition
	userPayload(t, f, "u-admin", o, &d)
	if len(d.Toggles) != 1 || d.Toggles[0] != tenancy.ToggleLocal {
		t.Fatalf("create payload %+v", d)
	}
	solo := "/api/v1/t/payments/networks/solo"
	refused(solo+"/members", map[string]any{"opId": op(), "node": "node-c", "cidr": "10.62.0.0/24"}, 409, "toggle-not-allowed")
	refused(solo+"/reconfigure", map[string]any{"opId": op(), "members": []map[string]any{{"node": "node-a"}, {"node": "node-c", "cidr": "10.62.0.0/24"}}}, 409, "toggle-not-allowed")
	o = applied(solo+"/toggles", map[string]any{"toggle": "local", "on": false})
	var set control.NetworkToggleSet
	userPayload(t, f, "u-admin", o, &set)
	if set != (control.NetworkToggleSet{Tenant: "payments", Name: "solo", Toggle: tenancy.ToggleLocal}) {
		t.Fatalf("payload %+v", set)
	}
	applied(solo+"/members", map[string]any{"node": "node-c", "cidr": "10.62.0.0/24"})
	refused(solo+"/toggles", map[string]any{"opId": op(), "toggle": "local", "on": true}, 409, "toggle-not-allowed")
	applied("/api/v1/t/payments/networks", map[string]any{"kind": "tun", "name": "solo2", "toggles": map[string]bool{"local": true}, "members": []map[string]any{{"node": "node-a", "cidr": "10.65.0.0/24"}}})
	solo2 := "/api/v1/t/payments/networks/solo2"
	// a reconfigure keeps the toggles
	for _, p := range []string{"/change", "/change/drain"} {
		body := map[string]any{"node": "node-a"}
		if p == "/change" {
			body["cidr"] = "10.63.0.0/24"
		}
		applied(solo2+p, body)
	}
	if err := fake.FenceNetworkChange("payments", "solo2", "node-a"); err != nil {
		t.Fatal(err)
	}
	o = applied(solo2+"/reconfigure", map[string]any{"members": []map[string]any{{"node": "node-b", "cidr": "10.64.0.0/24"}}})
	var rc control.NetworkReconfigure
	userPayload(t, f, "u-admin", o, &rc)
	if !slices.Equal(rc.Target.Toggles, []tenancy.NetworkToggle{tenancy.ToggleLocal}) {
		t.Fatalf("reconfigure dropped the toggles: %+v", rc.Target)
	}
	// the last server leaving deletes the network
	applied(solo2+"/change/drain", map[string]any{"node": "node-b"})
	applied(solo2+"/members/leave", map[string]any{"node": "node-b"})
	if code, _ := f.do("GET", solo2+"/change", nil); code != 404 {
		t.Fatalf("network kept after its last server left: %d", code)
	}
}
