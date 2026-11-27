// SPDX-License-Identifier: Apache-2.0

package server

import "testing"

func TestImageTrust(t *testing.T) {
	f, _ := newFakeFixture(t)
	fakeLogin(t, f, "alice")
	get := func() map[string]any {
		code, out := f.do("GET", "/api/v1/t/shop/image-trust", nil)
		if code != 200 {
			t.Fatalf("get: %d %v", code, out)
		}
		return out
	}
	rule := func(v map[string]any, registry, repo string) map[string]any {
		for _, r := range v["rules"].([]any) {
			if m := r.(map[string]any); m["registry"] == registry && m["repository"] == repo {
				return m
			}
		}
		return nil
	}
	v := get()
	b := rule(v, "registry.sfc.local", "**")
	if b == nil || b["origin"] != "builtin" || b["pull"] != "registry-credential" || len(b["uses"].([]any)) < 2 {
		t.Fatalf("builtin rule: %v", v)
	}
	my := rule(v, "docker.io", "library/mysql")
	if my == nil || my["origin"] != "direct" || my["only"] != float64(1) || my["uses"].([]any)[0].(map[string]any)["service"] != "db" {
		t.Fatalf("mysql rule: %v", my)
	}
	rev := v["revision"].(float64)

	// drop mysql: php-shop/db would lose its only source
	drop := []map[string]any{{"registry": "docker.io", "repository": "library/mysql"}}
	code, out := f.do("POST", "/api/v1/t/shop/image-trust/preview", map[string]any{"remove": drop})
	if aff, _ := out["affected"].([]any); code != 200 || len(aff) != 1 || aff[0].(map[string]any)["app"] != "php-shop" {
		t.Fatalf("preview: %d %v", code, out)
	}
	if code, out := f.do("PATCH", "/api/v1/t/shop/image-trust", map[string]any{"opId": "7a12c3d4-0000-4000-8000-000000000001", "add": []map[string]any{{"registry": "Bad Host", "repository": "x"}}}); code != 422 {
		t.Fatalf("bad rule: %d %v", code, out)
	}
	if code, out := f.do("PATCH", "/api/v1/t/shop/image-trust", map[string]any{"opId": "7a12c3d4-0000-4000-8000-000000000005"}); code != 422 {
		t.Fatalf("empty change: %d %v", code, out)
	}
	if code, out := f.do("PATCH", "/api/v1/t/shop/image-trust", map[string]any{"opId": "7a12c3d4-0000-4000-8000-000000000002", "remove": drop, "expected": rev - 1}); opState(t, code, out) != "failed" {
		t.Fatalf("stale: %d %v", code, out)
	}
	if code, out := f.do("PATCH", "/api/v1/t/shop/image-trust", map[string]any{"opId": "7a12c3d4-0000-4000-8000-000000000003", "remove": drop}); opState(t, code, out) != "applied" {
		t.Fatalf("remove: %d %v", code, out)
	}
	v = get()
	if rule(v, "docker.io", "library/mysql") != nil || v["revision"] == rev || len(v["untrusted"].([]any)) != 1 {
		t.Fatalf("after: %v", v)
	}
	// the same delta again was made from an older list: CAS fails
	if code, out := f.do("PATCH", "/api/v1/t/shop/image-trust", map[string]any{"opId": "7a12c3d4-0000-4000-8000-000000000006", "remove": drop}); opState(t, code, out) != "failed" {
		t.Fatalf("remove again: %d %v", code, out)
	}
	if code, out := f.do("PATCH", "/api/v1/t/shop/image-trust", map[string]any{"opId": "7a12c3d4-0000-4000-8000-000000000007", "add": drop}); opState(t, code, out) != "applied" || rule(get(), "docker.io", "library/mysql") == nil {
		t.Fatalf("add back: %d %v", code, out)
	}

	bobLogin(t, f) // a reader sees the list, sfcd refuses the change
	get()
	if code, out := f.do("PATCH", "/api/v1/t/shop/image-trust", map[string]any{"opId": "7a12c3d4-0000-4000-8000-000000000004", "remove": drop}); code != 403 && opState(t, code, out) != "failed" {
		t.Fatalf("bob: %d %v", code, out)
	}
}
