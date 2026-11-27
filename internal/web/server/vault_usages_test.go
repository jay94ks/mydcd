// SPDX-License-Identifier: Apache-2.0

package server

import (
	"strings"
	"testing"
)

func TestVaultUsages(t *testing.T) {
	f, _ := newFakeFixture(t)
	fakeLogin(t, f, "alice")
	_, out := f.do("GET", "/api/v1/t/shop/apps/php-shop/source", nil)
	doc := strings.Replace(out["yaml"].(string), "      node: node-b\n", "      node: node-b\n      secrets_from: [mysql]\n", 1)
	if code, out := f.do("POST", "/api/v1/t/shop/apps/deploy", map[string]any{"opId": "fab2c3d4-0000-4000-8000-000000000001", "yaml": doc}); opState(t, code, out) != "applied" {
		t.Fatalf("deploy: %d %v", code, out)
	}
	for _, q := range []string{"?id=mysql", ""} { // the object, then the whole realm
		code, out := f.do("GET", "/api/v1/t/shop/vault/usages"+q, nil)
		items, _ := out["items"].([]any)
		if code != 200 || len(items) != 1 {
			t.Fatalf("usages%s: %d %v", q, code, out)
		}
		u := items[0].(map[string]any)
		if u["app"] != "php-shop" || u["service"] != "db" || u["node"] != "node-b" || u["id"] == "" || u["live"] != true || u["secrets"].([]any)[0] != "mysql" {
			t.Fatalf("row: %v", u)
		}
	}
	if code, out := f.do("GET", "/api/v1/t/shop/vault/usages?id=nope", nil); code != 404 {
		t.Fatalf("unknown: %d %v", code, out)
	}
	if code, out := f.do("GET", "/api/v1/vault/usages", nil); code != 400 {
		t.Fatalf("cluster without id: %d %v", code, out)
	}
	bobLogin(t, f) // a reader: sfcd refuses
	if code, out := f.do("GET", "/api/v1/t/shop/vault/usages?id=mysql", nil); code != 403 {
		t.Fatalf("bob: %d %v", code, out)
	}
}
