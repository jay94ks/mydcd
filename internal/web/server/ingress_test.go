// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"maps"
	"strings"
	"testing"
)

func TestIngressScreens(t *testing.T) {
	f, fk := newFakeFixture(t)
	op := opSeq("1a9e0001")
	fakeLogin(t, f, "admin")
	code, all := f.do("GET", "/api/v1/ingress", nil)
	if code != 200 || len(all["instances"].([]any)) != 3 || len(all["nodes"].([]any)) != 3 || all["summary"] == nil {
		t.Fatalf("admin: %d %v", code, all)
	}
	var nodeA map[string]any
	for _, n := range all["nodes"].([]any) {
		if m := n.(map[string]any); m["node"] == "node-a" {
			nodeA = m
		}
	}
	if nodeA["external"] == nil || nodeA["local"] == nil {
		t.Fatalf("gateways: %v", nodeA)
	}

	bobLogin(t, f)
	_, mine := f.do("GET", "/api/v1/ingress", nil)
	if s := fmt.Sprint(mine); len(mine["instances"].([]any)) != 2 || strings.Contains(s, "payments") || strings.Contains(s, "unmatched") {
		t.Fatalf("bob: %v", mine)
	}
	if code, _ := f.do("GET", "/api/v1/ingress?tenant=payments", nil); code != 403 {
		t.Fatalf("bob payments: %d", code)
	}

	fakeLogin(t, f, "alice")
	code, app := f.do("GET", "/api/v1/t/shop/apps/php-shop/ingress", nil)
	inst, _ := app["instance"].(map[string]any)
	if code != 200 || inst == nil || len(inst["routes"].([]any)) != 2 || app["metrics"].(map[string]any)["codes"] == nil || len(app["errors"].([]any)) == 0 {
		t.Fatalf("app: %d %v", code, app)
	}
	route := inst["routes"].([]any)[1].(map[string]any)

	// Blocks: 0.0.0.0/0 refused; a route by host and prefix; extend; lift.
	if code, out := f.do("POST", "/api/v1/ingress/blocks", map[string]any{"opId": op(), "scope": map[string]any{"kind": "source", "tenant": "shop", "sources": []string{"0.0.0.0/0"}},
		"response": 503, "reason": "x"}); code != 422 {
		t.Fatalf("all sources: %d %v", code, out)
	}
	rs := map[string]any{"kind": "route", "tenant": "shop", "app": "php-shop", "node": "node-a", "host": route["host"], "prefix": route["prefix"]}
	for _, bad := range []map[string]any{{"minutes": -5}, {"untilMidnight": true}, {"until": "2000-01-01T00:00:00+09:00"}, {"until": "tomorrow"}} {
		body := map[string]any{"opId": op(), "scope": rs, "response": 503, "reason": "x"}
		maps.Copy(body, bad)
		if code, out := f.do("POST", "/api/v1/ingress/blocks", body); code != 422 {
			t.Fatalf("%v: %d %v", bad, code, out)
		}
	}
	if code, _ := f.do("GET", "/api/v1/t/shop/apps/php-shop/ingress?node=../x", nil); code != 400 {
		t.Fatalf("bad node: %d", code)
	}
	code, out := f.do("POST", "/api/v1/ingress/blocks", map[string]any{"opId": op(), "scope": map[string]any{"kind": "route", "tenant": "shop", "app": "php-shop", "node": "node-a",
		"host": route["host"], "prefix": route["prefix"]}, "response": 503, "minutes": 30, "reason": "관리자 화면 무차별 대입"})
	if opState(t, code, out) != "applied" {
		t.Fatalf("block: %d %v", code, out)
	}
	_, bl := f.do("GET", "/api/v1/ingress/blocks", nil)
	items := bl["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("blocks: %v", bl)
	}
	b := items[0].(map[string]any)
	id, _ := b["id"].(string)
	if !strings.HasPrefix(id, "web-") || b["state"] != "active" || b["response"] != float64(503) || b["scope"].(map[string]any)["kind"] != "route" || b["until"] == nil {
		t.Fatalf("block view: %v", b)
	}
	_, app = f.do("GET", "/api/v1/t/shop/apps/php-shop/ingress", nil)
	if r := app["instance"].(map[string]any)["routes"].([]any)[1].(map[string]any); r["blocked"] != id {
		t.Fatalf("route blocked: %v", r)
	}
	if code, out := f.do("PUT", "/api/v1/ingress/blocks/"+id, map[string]any{"opId": op(), "minutes": 30, "revision": 999}); code != 409 {
		t.Fatalf("stale extend: %d %v", code, out)
	}
	if code, out := f.do("PUT", "/api/v1/ingress/blocks/"+id, map[string]any{"opId": op(), "minutes": 30, "revision": b["revision"]}); opState(t, code, out) != "applied" {
		t.Fatalf("extend: %d %v", code, out)
	}
	// Lifted but not yet installed on node-a: still shown, lifting.
	fk.HoldIngressBlocks("node-a", true)
	if code, out := f.do("DELETE", "/api/v1/ingress/blocks/"+id, map[string]any{"opId": op()}); opState(t, code, out) != "applied" {
		t.Fatalf("lift: %d %v", code, out)
	}
	_, bl = f.do("GET", "/api/v1/ingress/blocks", nil)
	if items := bl["items"].([]any); len(items) != 1 || items[0].(map[string]any)["state"] != "lifting" || !strings.Contains(fmt.Sprint(items[0].(map[string]any)["nodes"]), "map[node:node-a state:pending]") {
		t.Fatalf("lifting: %v", bl)
	}
	fk.HoldIngressBlocks("node-a", false)
	_, bl = f.do("GET", "/api/v1/ingress/blocks", nil)
	if len(bl["items"].([]any)) != 0 {
		t.Fatalf("after lift: %v", bl)
	}
	// Viewers cannot block.
	bobLogin(t, f)
	if code, out := f.do("POST", "/api/v1/ingress/blocks", map[string]any{"opId": op(), "scope": map[string]any{"kind": "app", "tenant": "shop", "app": "php-shop"},
		"response": "drop", "reason": "x"}); code < 400 && opState(t, code, out) == "applied" {
		t.Fatalf("viewer block: %d %v", code, out)
	}
}

func TestIngressSettings(t *testing.T) {
	f, _ := newFakeFixture(t)
	op := opSeq("1a9e0002")
	fakeLogin(t, f, "admin")
	for _, bad := range []map[string]any{
		{},
		{"external": map[string]any{"enabled": true, "address": "203.0.113.21", "ports": []int{443}, "sources": []string{"10.0.0.0/8"}}},
		{"local": map[string]any{"enabled": true, "iface": "eth1"}},
	} {
		bad["opId"] = op()
		if code, out := f.do("PUT", "/api/v1/nodes/node-a/gateways", bad); code != 422 {
			t.Fatalf("%v: %d %v", bad, code, out)
		}
	}
	code, gw := f.do("GET", "/api/v1/nodes/node-a/gateways", nil)
	if code != 200 || gw["source"] != "file" || gw["revision"] != float64(0) {
		t.Fatalf("gateways before: %d %v", code, gw)
	}
	// listeners must sit on the side's addresses and ports
	if code, out := f.do("PUT", "/api/v1/nodes/node-a/gateways", map[string]any{"opId": op(),
		"external": map[string]any{"enabled": true, "address": "203.0.113.21", "ports": []int{443},
			"listeners": []map[string]any{{"id": "pub", "address": "203.0.113.99:443"}}}}); code != 422 {
		t.Fatalf("listener off the address: %d %v", code, out)
	}
	ext := map[string]any{"enabled": true, "address": "203.0.113.21", "ports": []int{443},
		"listeners": []map[string]any{{"id": "pub", "address": "203.0.113.21:443", "tls": true, "http3": true}}}
	code, out := f.do("PUT", "/api/v1/nodes/node-a/gateways", map[string]any{"opId": op(), "external": ext})
	if opState(t, code, out) != "applied" {
		t.Fatalf("gateways: %d %v", code, out)
	}
	_, gw = f.do("GET", "/api/v1/nodes/node-a/gateways", nil)
	if gw["source"] != "cluster" || gw["revision"] != float64(1) || gw["appliedRevision"] != float64(1) ||
		!strings.Contains(fmt.Sprint(gw["external"]), "id:pub") {
		t.Fatalf("gateways after: %v", gw)
	}
	// a stale revision is refused by mydcd
	code, out = f.do("PUT", "/api/v1/nodes/node-a/gateways", map[string]any{"opId": op(), "revision": 0, "external": ext})
	if opState(t, code, out) == "applied" {
		t.Fatalf("stale gateways: %v", out)
	}

	bal := map[string]any{"method": "hash", "hashKey": "cookie:session", "retry": 1, "fallback": "default",
		"rules": []map[string]any{{"kind": "header", "name": "x-canary", "op": "equals", "value": "1", "group": "track=canary"}}}
	if code, out := f.do("PUT", "/api/v1/t/shop/apps/php-shop/ingress/balance", map[string]any{"opId": op(), "route": "shop-root",
		"balance": map[string]any{"method": "fastest"}}); code != 422 {
		t.Fatalf("bad balance: %d %v", code, out)
	}
	code, out = f.do("PUT", "/api/v1/t/shop/apps/php-shop/ingress/balance", map[string]any{"opId": op(), "route": "shop-root", "balance": bal})
	if opState(t, code, out) != "applied" {
		t.Fatalf("balance: %d %v", code, out)
	}
	_, app := f.do("GET", "/api/v1/t/shop/apps/php-shop/ingress", nil)
	if bh := app["balanceHistory"].([]any); len(bh) != 1 || !strings.Contains(fmt.Sprint(bh[0].(map[string]any)["what"]), "→ hash") || bh[0].(map[string]any)["route"] != "shop-root" {
		t.Fatalf("balanceHistory: %v", bh)
	}
	inst := app["instance"].(map[string]any)
	if rt := inst["routes"].([]any)[0].(map[string]any); rt["balanceRevision"] != float64(1) || rt["originalBalance"] == nil || rt["balance"].(map[string]any)["method"] != "hash" {
		t.Fatalf("route balance: %v", rt)
	}

	code, out = f.do("POST", "/api/v1/t/shop/apps/php-shop/ingress/drain", map[string]any{"opId": op(), "drainSeconds": 60})
	if opState(t, code, out) != "applied" {
		t.Fatalf("drain: %d %v", code, out)
	}
	_, app = f.do("GET", "/api/v1/t/shop/apps/php-shop/ingress", nil)
	if inst := app["instance"].(map[string]any); inst["drainRevision"] != float64(1) || inst["drainDeadline"] == nil || inst["draining"] != true {
		t.Fatalf("drained: %v", inst)
	}
	// the revision defaults to the record's: undrain is its second change
	code, out = f.do("DELETE", "/api/v1/t/shop/apps/php-shop/ingress/drain", map[string]any{"opId": op()})
	if opState(t, code, out) != "applied" {
		t.Fatalf("undrain: %d %v", code, out)
	}
	_, h := f.do("GET", "/api/v1/ingress/history", nil)
	var acts []string
	for _, it := range h["items"].([]any) {
		acts = append(acts, it.(map[string]any)["action"].(string))
	}
	if s := strings.Join(acts, ","); !strings.HasPrefix(s, "undrain-ingress,drain-ingress,set-ingress-balance,set-node-gateways") {
		t.Fatalf("history: %s", s)
	}
	if first := h["items"].([]any)[3].(map[string]any); first["by"] != "admin" || first["request"] == "" || first["detail"] == nil {
		t.Fatalf("history row: %v", first)
	}
	if code, _ := f.do("GET", "/api/v1/ingress/history?app=php-shop", nil); code != 400 {
		t.Fatalf("app without tenant: %d", code)
	}
}
