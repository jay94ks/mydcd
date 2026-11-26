// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"testing"
)

func TestCD(t *testing.T) {
	f, _ := newFakeFixture(t)
	fakeLogin(t, f, "alice")
	n := 0
	op := func() string { n++; return fmt.Sprintf("cdc2c3d4-0000-4000-8000-%012d", n) }
	cd := func() map[string]any {
		code, out := f.do("GET", "/api/v1/t/shop/apps/php-shop/cd", nil)
		if code != 200 {
			t.Fatalf("cd: %d %v", code, out)
		}
		return out["cd"].(map[string]any)
	}
	c := cd()
	if c["running"] != "a1b2c3d" || c["candidate"] != "e4f5a6b" || c["sync"] != "OutOfSync" || c["policyRevision"] != float64(1) || c["policy"] == nil {
		t.Fatalf("status: %v", c)
	}
	rev := c["revision"].(float64)
	if code, out := f.do("GET", "/api/v1/t/shop/apps/nope/cd", nil); code != 404 {
		t.Fatalf("not cd: %d %v", code, out)
	}
	// a stale expected: strict CAS fails in mydcd
	if code, out := f.do("POST", "/api/v1/t/shop/apps/php-shop/cd/replan", map[string]any{"opId": op(), "expected": rev - 1}); opState(t, code, out) != "failed" {
		t.Fatalf("stale: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/t/shop/apps/php-shop/cd/sync", map[string]any{"opId": op(), "candidate": "00"}); code != 409 {
		t.Fatalf("candidate changed: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/t/shop/apps/php-shop/cd/pause", map[string]any{"opId": op()}); opState(t, code, out) != "applied" {
		t.Fatalf("pause: %d %v", code, out)
	}
	if c = cd(); c["paused"] != true || c["effectiveSync"] != "Paused" {
		t.Fatalf("paused: %v", c)
	}
	if code, out := f.do("POST", "/api/v1/t/shop/apps/php-shop/cd/resume", map[string]any{"opId": op()}); opState(t, code, out) != "applied" {
		t.Fatalf("resume: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/t/shop/apps/php-shop/cd/sync", map[string]any{"opId": op(), "candidate": cd()["candidateDigest"]}); opState(t, code, out) != "applied" {
		t.Fatalf("sync: %d %v", code, out)
	}
	if c = cd(); c["running"] != "e4f5a6b" || c["sync"] != "InSync" {
		t.Fatalf("synced: %v", c)
	}
	if code, out := f.do("POST", "/api/v1/t/shop/apps/php-shop/cd/sync", map[string]any{"opId": op(), "operation": "Bad"}); code != 422 {
		t.Fatalf("bad operation: %d %v", code, out)
	}

	// policy round trip
	p := c["policy"].(map[string]any)
	p["sync"].(map[string]any)["mode"] = "manual"
	p["source"].(map[string]any)["credential"] = "deploy-key"
	if code, out := f.do("PUT", "/api/v1/t/shop/apps/php-shop/cd/policy", map[string]any{"opId": op(), "policy": p}); opState(t, code, out) != "applied" {
		t.Fatalf("configure: %d %v", code, out)
	}
	if c = cd(); c["mode"] != "manual" || c["policyRevision"] != float64(2) || c["policy"].(map[string]any)["source"].(map[string]any)["credential"] != "deploy-key" {
		t.Fatalf("configured: %v", c)
	}
	if code, out := f.do("PUT", "/api/v1/t/shop/apps/php-shop/cd/policy", map[string]any{"opId": op(), "policy": map[string]any{"bogus": 1}}); code != 422 {
		t.Fatalf("bad policy: %d %v", code, out)
	}

	// field overrides
	path := "?path=services&path=web&path=image"
	if code, out := f.do("GET", "/api/v1/t/shop/apps/php-shop/cd/field?path=services&path=web&path=ports", nil); code != 422 {
		t.Fatalf("bad path: %d %v", code, out)
	}
	code, out := f.do("GET", "/api/v1/t/shop/apps/php-shop/cd/field"+path, nil)
	if code != 200 || out["override"] != nil || len(out["target"].(string)) != 64 {
		t.Fatalf("field: %d %v", code, out)
	}
	field := []string{"services", "web", "image"}
	if code, out := f.do("DELETE", "/api/v1/t/shop/apps/php-shop/cd/overrides", map[string]any{"opId": op(), "path": field}); code != 409 {
		t.Fatalf("release none: %d %v", code, out)
	}
	if code, out := f.do("PUT", "/api/v1/t/shop/apps/php-shop/cd/overrides", map[string]any{"opId": op(), "path": field, "value": "nginx:1.27"}); opState(t, code, out) != "applied" {
		t.Fatalf("override: %d %v", code, out)
	}
	if _, out := f.do("GET", "/api/v1/t/shop/apps/php-shop/cd/field"+path, nil); out["override"] == nil {
		t.Fatalf("overridden: %v", out)
	}
	if c = cd(); c["overrideCount"] != float64(1) {
		t.Fatalf("count: %v", c)
	}
	if code, out := f.do("PUT", "/api/v1/t/shop/apps/php-shop/cd/overrides", map[string]any{"opId": op(), "path": field, "value": "nginx:1.28"}); opState(t, code, out) != "applied" {
		t.Fatalf("override again: %d %v", code, out)
	}
	if code, out := f.do("DELETE", "/api/v1/t/shop/apps/php-shop/cd/overrides", map[string]any{"opId": op(), "path": field}); opState(t, code, out) != "applied" {
		t.Fatalf("release: %d %v", code, out)
	}
	if c = cd(); c["overrideCount"] != nil {
		t.Fatalf("released: %v", c)
	}

	bobLogin(t, f) // a reader: mydcd refuses the change
	if code, out := f.do("POST", "/api/v1/t/shop/apps/php-shop/cd/replan", map[string]any{"opId": op()}); code != 403 && opState(t, code, out) != "failed" {
		t.Fatalf("bob: %d %v", code, out)
	}
}
