// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"strings"
	"testing"
)

func TestRegistryCredential(t *testing.T) {
	f, _ := newFakeFixture(t)
	fakeLogin(t, f, "alice")
	path := "/api/v1/t/shop/registries/builtin/credential"
	code, out := f.do("POST", path, map[string]any{"repository": "shop/web", "access": "push,pull"})
	if code != 200 || out["username"] != "alice" || out["authority"] != "registry.mydc.local" || out["expiresAt"] == "" ||
		!strings.HasPrefix(out["token"].(string), "mydc-fake-registry-login.") || len(out["access"].([]any)) != 2 {
		t.Fatalf("credential: %d %v", code, out)
	}
	for _, bad := range []map[string]any{{"repository": "", "access": "pull"}, {"repository": "shop/web", "access": "delete"}, {"repository": "**", "access": "pull"}} {
		if code, out := f.do("POST", path, bad); code != 422 {
			t.Fatalf("bad %v: %d %v", bad, code, out)
		}
	}
	// the token is in no stored op or journal
	if _, ops := f.do("GET", "/api/v1/ops", nil); strings.Contains(fmt.Sprint(ops), "mydc-fake-registry-login") {
		t.Fatalf("token in ops: %v", ops)
	}
	assertNowhere(t, f, out["token"].(string)) // not in any stored op (bbolt) either
	// stopped registry: mydcd refuses
	if code, out := f.do("POST", "/api/v1/t/shop/registries/builtin/stop", map[string]any{"opId": "9e12c3d4-0000-4000-8000-000000000001"}); opState(t, code, out) != "applied" {
		t.Fatalf("stop: %d %v", code, out)
	}
	if code, out := f.do("POST", path, map[string]any{"repository": "shop/web"}); code != 403 {
		t.Fatalf("stopped: %d %v", code, out)
	}
	bobLogin(t, f)
	if code, out := f.do("POST", "/api/v1/t/shop/registries/builtin/credential", map[string]any{"repository": "shop/web"}); code != 403 {
		t.Fatalf("bob: %d %v", code, out)
	}
}
