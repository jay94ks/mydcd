// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"testing"
)

func TestRegistries(t *testing.T) {
	f, fake := newFakeFixture(t)
	n := 0
	op := func() string { n++; return fmt.Sprintf("ab12c3d4-0000-4000-8000-%012d", n) }
	row := func(tenant, id string) map[string]any {
		code, out := f.do("GET", "/api/v1/t/"+tenant+"/registries", nil)
		if code != 200 {
			t.Fatalf("list: %d %v", code, out)
		}
		for _, it := range out["items"].([]any) {
			if r := it.(map[string]any); r["id"] == id {
				return r
			}
		}
		return nil
	}
	fakeLogin(t, f, "alice")
	if r := row("shop", "builtin"); r["status"] != "serving" || r["node"] != "node-b" || r["limits"].(map[string]any)["maxRequests"] != float64(64) {
		t.Fatalf("seed: %v", r)
	}

	fakeLogin(t, f, "admin")
	put := func(body map[string]any) (int, map[string]any) {
		body["opId"] = op()
		return f.do("PUT", "/api/v1/t/payments/registries/private", body)
	}
	if code, out := put(map[string]any{"volume": "ledger-data"}); code != 422 {
		t.Fatalf("missing fields: %d %v", code, out)
	}
	if code, out := put(map[string]any{"volume": "ledger-data", "authority": "bad host"}); code != 422 {
		t.Fatalf("bad authority: %d %v", code, out)
	}
	if code, out := put(map[string]any{"volume": "ledger-data", "authority": "reg.payments.example.com:5443"}); opState(t, code, out) != "applied" {
		t.Fatalf("create: %d %v", code, out)
	}
	r := row("payments", "private")
	if r["status"] != "pending" || r["node"] != "node-c" || r["address"] != "0.0.0.0:5443" || r["revision"] != float64(1) || r["volume"] != "ledger-data" {
		t.Fatalf("created: %v", r)
	}
	fake.ObserveRegistry("payments", "private", true)
	if r = row("payments", "private"); r["status"] != "serving" {
		t.Fatalf("observed: %v", r)
	}
	lim := r["limits"].(map[string]any)
	lim["maxRequests"] = 8
	if code, out := put(map[string]any{"limits": lim}); opState(t, code, out) != "applied" {
		t.Fatalf("edit: %d %v", code, out)
	}
	if r = row("payments", "private"); r["status"] != "pending" || r["limits"].(map[string]any)["maxRequests"] != float64(8) || r["endpoint"] != "reg.payments.example.com:5443" {
		t.Fatalf("edited: %v", r)
	}
	if code, out := put(map[string]any{"volume": "other"}); code != 422 {
		t.Fatalf("volume change: %d %v", code, out)
	}
	if code, out := put(map[string]any{"expected": 1}); opState(t, code, out) != "failed" {
		t.Fatalf("stale: %d %v", code, out)
	}
	act := func(verb string) (int, map[string]any) {
		return f.do("POST", "/api/v1/t/payments/registries/private/"+verb, map[string]any{"opId": op()})
	}
	if code, out := act("delete"); code != 409 {
		t.Fatalf("delete running: %d %v", code, out)
	}
	if code, out := act("stop"); opState(t, code, out) != "applied" {
		t.Fatalf("stop: %d %v", code, out)
	}
	if r = row("payments", "private"); r["status"] != "stopped" {
		t.Fatalf("stopped: %v", r)
	}
	if code, out := act("start"); opState(t, code, out) != "applied" {
		t.Fatalf("start: %d %v", code, out)
	}
	if code, out := act("stop"); opState(t, code, out) != "applied" {
		t.Fatalf("stop again: %d %v", code, out)
	}
	if code, out := act("delete"); opState(t, code, out) != "applied" {
		t.Fatalf("delete: %d %v", code, out)
	}
	if r = row("payments", "private"); r["status"] != "deleted" {
		t.Fatalf("deleted: %v", r)
	}
	if code, out := act("start"); code != 404 {
		t.Fatalf("start deleted: %d %v", code, out)
	}
	if code, out := put(map[string]any{}); code != 409 {
		t.Fatalf("reuse deleted ID: %d %v", code, out)
	}

	bobLogin(t, f) // a reader: sfcd refuses
	if code, out := f.do("POST", "/api/v1/t/shop/registries/builtin/stop", map[string]any{"opId": op()}); code != 403 && opState(t, code, out) != "failed" {
		t.Fatalf("bob: %d %v", code, out)
	}
}
