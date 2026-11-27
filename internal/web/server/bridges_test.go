// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"testing"
)

func TestVirtualBridges(t *testing.T) {
	f, _ := newFakeFixture(t)
	fakeLogin(t, f, "admin")
	n := 0
	op := func() string { n++; return fmt.Sprintf("b7b2c3d4-0000-4000-8000-%012d", n) }
	row := func(tenant, key string) map[string]any {
		t.Helper()
		code, out := f.do("GET", "/api/v1/t/"+tenant+"/resources", nil)
		if code != 200 {
			t.Fatalf("resources %s: %d %v", tenant, code, out)
		}
		for _, x := range out["items"].([]any) {
			if m := x.(map[string]any); m["key"] == key {
				b, _ := m["bridge"].(map[string]any)
				return b
			}
		}
		return nil
	}
	post := func(path string, body map[string]any) (int, map[string]any) {
		body["opId"] = op()
		return f.do("POST", path, body)
	}
	errorCode := func(out map[string]any) string {
		o, _ := out["op"].(map[string]any)
		s, _ := o["errorCode"].(string)
		return s
	}
	create := map[string]any{"name": "pay", "network": "shop-net", "peer": map[string]any{"tenant": "payments", "network": "payments-net"}, "direction": "a-to-b", "protocol": "tcp", "ports": []any{5432}}
	for _, bad := range []map[string]any{
		{"name": "pay", "network": "shop-net", "peer": map[string]any{"network": "shop-net"}},
		{"name": "pay", "network": "shop-net", "peer": map[string]any{"tenant": "payments", "network": "payments-net"}, "direction": "up"},
		{"name": "pay", "network": "shop-net", "peer": map[string]any{"tenant": "payments", "network": "payments-net"}, "ports": []any{80}},
		{"name": "pay", "network": "shop-net", "peer": map[string]any{"tenant": "payments", "network": "sfc-system"}},
	} {
		if code, out := post("/api/v1/t/shop/bridges", bad); code != 422 {
			t.Fatalf("%v: %d %v", bad, code, out)
		}
	}
	endpoints := func() []any {
		t.Helper()
		code, out := f.do("GET", "/api/v1/t/shop/bridge-endpoints?tenant=payments", nil)
		if code != 200 || out["tenant"] != "payments" {
			t.Fatalf("bridge-endpoints: %d %v", code, out)
		}
		return out["items"].([]any)
	}
	if code, out := f.do("GET", "/api/v1/t/shop/bridge-endpoints?tenant=shop", nil); code != 422 {
		t.Fatalf("own tenant endpoints: %d %v", code, out)
	}
	if items := endpoints(); len(items) != 0 {
		t.Fatalf("closed network listed: %v", items)
	}
	// payments-net does not take bridges yet: sfcd refuses with peer-closed
	code, out := post("/api/v1/t/shop/bridges", copyMap(create))
	if opState(t, code, out) != "failed" || errorCode(out) != "peer-closed" {
		t.Fatalf("peer closed: %d %v", code, out)
	}
	if code, out := post("/api/v1/t/payments/networks/payments-net/toggles", map[string]any{"toggle": "bridge-inbound", "on": true}); opState(t, code, out) != "applied" {
		t.Fatalf("inbound: %d %v", code, out)
	}
	if items := endpoints(); len(items) != 1 || fmt.Sprint(items[0]) != "map[network:payments-net tenant:payments]" {
		t.Fatalf("bridge-endpoints after inbound: %v", items)
	}
	if code, out := post("/api/v1/t/shop/bridges", copyMap(create)); opState(t, code, out) != "applied" {
		t.Fatalf("create: %d %v", code, out)
	}
	if b := row("shop", "bridge/shop/pay"); b == nil || b["state"] != "waiting-peer" || b["kind"] != "bridge" || b["direction"] != "a-to-b" || b["protocol"] != "tcp" ||
		b["b"].(map[string]any)["network"] != "payments-net" || b["b"].(map[string]any)["cidr"] != nil {
		t.Fatalf("shop row: %v", b)
	}
	if b := row("payments", "bridge/shop/pay"); b == nil || b["state"] != "waiting-me" {
		t.Fatalf("payments row: %v", b)
	}
	if code, out := post("/api/v1/t/shop/bridges", map[string]any{"name": "back", "network": "shop-net", "peer": map[string]any{"tenant": "payments", "network": "payments-net"}}); code != 409 || errCode(out) != "bridge-exists" {
		t.Fatalf("exists: %d %v", code, out)
	}
	if code, out := post("/api/v1/t/shop/bridges/shop/pay/approve", map[string]any{}); code != 409 || errCode(out) != "already-approved" {
		t.Fatalf("own approve: %d %v", code, out)
	}
	if code, out := post("/api/v1/t/payments/bridges/shop/pay/approve", map[string]any{}); opState(t, code, out) != "applied" {
		t.Fatalf("approve: %d %v", code, out)
	}
	if b := row("shop", "bridge/shop/pay"); b["state"] != "open" || len(b["approvals"].([]any)) != 2 {
		t.Fatalf("open: %v", b)
	}
	if code, out := post("/api/v1/t/payments/bridges/shop/pay/close", map[string]any{}); opState(t, code, out) != "applied" {
		t.Fatalf("close: %d %v", code, out)
	}
	if b := row("payments", "bridge/shop/pay"); b["state"] != "closing" {
		t.Fatalf("closing: %v", b)
	}
	if code, out := post("/api/v1/t/shop/bridges/shop/pay/close", map[string]any{}); code != 409 || errCode(out) != "closing" {
		t.Fatalf("close again: %d %v", code, out)
	}
	if code, out := post("/api/v1/t/shop/bridges/shop/nope/close", map[string]any{}); code != 404 {
		t.Fatalf("missing: %d %v", code, out)
	}
}

func copyMap(m map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		out[k] = v
	}
	return out
}
