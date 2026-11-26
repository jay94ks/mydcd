// SPDX-License-Identifier: Apache-2.0

package server

import "testing"

func TestCDProbe(t *testing.T) {
	f, _ := newFakeFixture(t)
	fakeLogin(t, f, "alice")
	const p = "/api/v1/t/shop/apps/php-shop/cd/probe"
	code, out := f.do("POST", p, map[string]any{"repository": "https://git.example.com/shop/app.git", "branch": "main", "path": "app.yaml"})
	if code != 200 || out["commit"] == "" || out["size"] == nil {
		t.Fatalf("probe: %d %v", code, out)
	}
	for _, c := range []struct {
		body map[string]any
		code int
		err  string
	}{
		{map[string]any{"repository": "https://git.example.com/shop/private.git", "branch": "main", "path": "app.yaml"}, 422, "auth-failed"},
		{map[string]any{"repository": "https://git.example.com/shop/app.git", "branch": "dev", "path": "app.yaml"}, 422, "no-branch"},
		{map[string]any{"repository": "https://git.example.com/shop/app.git", "branch": "main", "path": "nope.yaml"}, 422, "no-file"},
	} {
		if code, out := f.do("POST", p, c.body); code != c.code || errCode(out) != c.err {
			t.Fatalf("%v: %d %v", c.body, code, out)
		}
	}
	if code, out := f.do("POST", p, map[string]any{"repository": "https://git.example.com/shop/private.git", "branch": "main", "path": "app.yaml", "credential": "git-deploy"}); code != 200 {
		t.Fatalf("with credential: %d %v", code, out)
	}
	// alice only views payments
	if code, _ := f.do("POST", "/api/v1/t/payments/apps/payments-api/cd/probe", map[string]any{"repository": "https://git.example.com/shop/app.git", "branch": "main", "path": "app.yaml"}); code != 403 {
		t.Fatalf("viewer: %d", code)
	}
}
