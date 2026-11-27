// SPDX-License-Identifier: Apache-2.0

package server

import "testing"

func TestImageResolve(t *testing.T) {
	f, fake := newFakeFixture(t)
	fakeLogin(t, f, "alice")
	res := func(ref string) (int, map[string]any) {
		return f.do("POST", "/api/v1/t/shop/images/resolve", map[string]any{"ref": ref})
	}
	code, out := res("mysql:8.4")
	if code != 200 || out["ref"] != "docker.io/library/mysql:8.4" || out["registryKind"] != "unknown" || out["registry"] != "docker.io" || out["trusted"] != true ||
		len(out["platforms"].([]any)) != 2 || out["platforms"].([]any)[0].(map[string]any)["platform"] == nil || out["pinned"] == "" || out["code"] != nil {
		t.Fatalf("mysql: %d %v", code, out)
	}
	code, out = res("registry.sfc.local/shop/php-shop:1.4.2")
	if code != 200 || out["registryKind"] != "builtin" || out["source"] == nil || out["code"] != nil || out["digest"] == nil {
		t.Fatalf("builtin: %d %v", code, out)
	}
	if code, out := res("registry.sfc.local/shop/php-shop:nope"); code != 200 || out["code"] != "not-found" || out["digest"] != nil {
		t.Fatalf("builtin missing tag: %d %v", code, out)
	}
	code, out = res("registry.example.com/shop/cron:1")
	if code != 200 || out["registryKind"] != "external" || out["source"] != "example" || out["code"] != nil {
		t.Fatalf("external: %d %v", code, out)
	}
	fake.SetRegistryLoginResult("registry.example.com", "unauthorized")
	if _, out := res("registry.example.com/shop/cron:1"); out["code"] != "unauthorized" || out["digest"] != nil {
		t.Fatalf("external refused: %v", out)
	}
	code, out = res("nginx")
	if code != 200 || out["code"] != "untrusted" || out["trusted"] != false || out["reason"] == nil || len(out["rules"].([]any)) == 0 || out["digest"] != nil {
		t.Fatalf("untrusted: %d %v", code, out)
	}
	if code, out := res("Bad Ref"); code != 422 || errCode(out) != "invalid-ref" {
		t.Fatalf("invalid: %d %v", code, out)
	}
	if code, out := res(" "); code != 422 || errCode(out) != "invalid-ref" {
		t.Fatalf("empty: %d %v", code, out)
	}
	if code, _ := f.do("POST", "/api/v1/t/elsewhere/images/resolve", map[string]any{"ref": "mysql:8.4"}); code != 403 && code != 404 {
		t.Fatalf("other tenant: %d", code)
	}
}
