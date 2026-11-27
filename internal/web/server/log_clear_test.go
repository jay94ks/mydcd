// SPDX-License-Identifier: Apache-2.0

package server

import (
	"testing"

	"github.com/jay94ks/seafield/internal/web/sfc"
)

// UI-3C log clearing: every server clears its own log store; a server that
// is down keeps its logs until the same request is sent again; a viewer is
// refused by each server.
func TestLogClear(t *testing.T) {
	f, fake := newFakeFixture(t)
	fakeLogin(t, f, "alice")
	stored := func(q string) map[string]map[string]any {
		t.Helper()
		code, out := f.do("GET", "/api/v1/t/shop/logs/stored?"+q, nil)
		if code != 200 {
			t.Fatalf("stored %s: %d %v", q, code, out)
		}
		rows := map[string]map[string]any{}
		for _, n := range out["nodes"].([]any) {
			n := n.(map[string]any)
			for _, l := range n["logs"].([]any) {
				l := l.(map[string]any)
				rows[l["key"].(string)] = l
			}
		}
		return rows
	}
	before := stored("app=php-shop")
	if len(before) == 0 {
		t.Fatal("no stored logs")
	}
	var lines float64
	for _, l := range before {
		lines += l["lines"].(float64)
		if l["container"] == "" || l["service"] == "" {
			t.Fatalf("row %v", l)
		}
	}
	if lines == 0 {
		t.Fatal("no lines stored")
	}

	fake.SetLogStoreDown("node-b", true)
	code, out := f.do("POST", "/api/v1/t/shop/logs/clear", map[string]any{"app": "php-shop"})
	if code != 200 || out["total"].(float64) < 2 || out["cleared"] != out["total"].(float64)-1 {
		t.Fatalf("clear: %d %v", code, out)
	}
	codes := map[string]string{}
	for _, n := range out["nodes"].([]any) {
		n := n.(map[string]any)
		codes[n["node"].(string)] = n["code"].(string)
	}
	if codes["node-b"] != "unreachable" || codes["node-a"] != "ok" || codes["node-d"] != "" {
		t.Fatalf("codes %v", codes)
	}
	fake.SetLogStoreDown("node-b", false)
	if code, out := f.do("POST", "/api/v1/t/shop/logs/clear", map[string]any{"app": "php-shop"}); code != 200 || out["cleared"] != out["total"] {
		t.Fatalf("clear again: %d %v", code, out)
	}
	for k, l := range stored("app=php-shop") {
		if l["lines"].(float64) != 0 {
			t.Fatalf("%s still has lines: %v", k, l)
		}
	}
	if code, out := f.do("GET", "/api/v1/t/shop/logs/stored?app=php-shop&node=node-zz", nil); code != 404 {
		t.Fatalf("unknown node: %d %v", code, out)
	}

	// a bad selection
	for _, body := range []map[string]any{{}, {"app": "php-shop", "standalone": "x"}, {"standalone": "x", "service": "web"}} {
		if code, out := f.do("POST", "/api/v1/t/shop/logs/clear", body); code != 400 {
			t.Fatalf("selection %v: %d %v", body, code, out)
		}
	}
	if code, _ := f.do("POST", "/api/v1/t/shop/apps/php-shop/logs-clear", map[string]any{}); code != 404 && code != 405 {
		t.Fatalf("old route still answers: %d", code)
	}

	// a viewer reads the list, and every server refuses the clear
	if code, out := keyLogin(f, "bob", sfc.FixtureKey("bob")); code != 200 {
		t.Fatalf("bob: %d %v", code, out)
	}
	if rows := stored("app=php-shop&service=web"); len(rows) == 0 {
		t.Fatal("viewer list")
	}
	code, out = f.do("POST", "/api/v1/t/shop/logs/clear", map[string]any{"app": "php-shop", "service": "web"})
	if code != 200 || out["cleared"] != 0.0 {
		t.Fatalf("viewer clear: %d %v", code, out)
	}
}
