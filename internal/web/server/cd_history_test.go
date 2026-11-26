// SPDX-License-Identifier: Apache-2.0

package server

import "testing"

func TestCDHistory(t *testing.T) {
	f, _ := newFakeFixture(t)
	fakeLogin(t, f, "alice")
	code, out := f.do("GET", "/api/v1/t/shop/apps/php-shop/cd/history", nil)
	items, _ := out["items"].([]any)
	if code != 200 || len(items) != 2 || items[0].(map[string]any)["result"] != "candidate" || items[1].(map[string]any)["result"] != "succeeded" {
		t.Fatalf("history: %d %v", code, out)
	}
	code, ch := f.do("GET", "/api/v1/t/shop/apps/php-shop/cd/changes", nil)
	svcs, _ := ch["services"].([]any)
	if code != 200 || ch["count"] != float64(1) || len(svcs) != 1 {
		t.Fatalf("changes: %d %v", code, ch)
	}
	svc := svcs[0].(map[string]any)
	field := svc["fields"].([]any)[0].(map[string]any)
	q := ""
	for _, p := range field["path"].([]any) {
		q += "&path=" + p.(string)
	}
	code, v := f.do("GET", "/api/v1/t/shop/apps/php-shop/cd/values?"+q[1:], nil)
	if code != 200 || v["gitRunning"] == v["gitCandidate"] || v["gitRunning"] != field["before"] || v["gitCandidate"] != field["after"] || v["overridden"] != false {
		t.Fatalf("values: %d %v (change %v)", code, v, field)
	}
	if code, out := f.do("GET", "/api/v1/t/shop/apps/php-shop/cd/values?path=services&path=web&path=ports", nil); code != 422 {
		t.Fatalf("bad path: %d %v", code, out)
	}
	if code, out := f.do("GET", "/api/v1/t/shop/apps/shop-worker/cd/history", nil); code != 422 {
		t.Fatalf("not cd: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/t/shop/apps/php-shop/cd/sync", map[string]any{"opId": "c4d2c3d4-0000-4000-8000-000000000001"}); opState(t, code, out) != "applied" {
		t.Fatalf("sync: %d %v", code, out)
	}
	_, out = f.do("GET", "/api/v1/t/shop/apps/php-shop/cd/history", nil)
	if r := out["items"].([]any)[0].(map[string]any); r["result"] != "succeeded" || r["operation"] == nil {
		t.Fatalf("after sync: %v", out)
	}
	if _, ch = f.do("GET", "/api/v1/t/shop/apps/php-shop/cd/changes", nil); ch["count"] != float64(0) || len(ch["services"].([]any)) != 0 {
		t.Fatalf("changes after sync: %v", ch)
	}
}
