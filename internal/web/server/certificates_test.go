// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/web/sfc"
)

func certRow(t *testing.T, items []any, name, state string) map[string]any {
	t.Helper()
	for _, it := range items {
		row := it.(map[string]any)
		if row["state"] == state && row["names"].([]any)[0] == name {
			return row
		}
	}
	t.Fatalf("no %s row for %s: %v", state, name, items)
	return nil
}

func TestCertificates(t *testing.T) {
	f, _ := newFakeFixture(t)
	fakeLogin(t, f, "alice")
	if code, _ := f.do("GET", "/api/v1/certificates", nil); code != 403 {
		t.Fatalf("alice list: %d", code)
	}
	fakeLogin(t, f, "admin")
	code, out := f.do("GET", "/api/v1/certificates", nil)
	if code != 200 || out["store"] != true {
		t.Fatalf("list: %d %v", code, out)
	}
	items := out["items"].([]any)
	if len(items) != 4 {
		t.Fatalf("items: %v", items)
	}
	shop := certRow(t, items, "shop.example.com", "linked")
	old := certRow(t, items, "shop.example.com", "pending-destroy")
	partner := certRow(t, items, "old.partner.example.net", "unlinked")
	if shop["keyType"] != "ecdsa-p256" || len(shop["links"].([]any)) != 2 || !strings.Contains(shop["serial"].(string), ":") {
		t.Fatalf("shop row: %v", shop)
	}
	if len(old["links"].([]any)) != 0 || len(partner["links"].([]any)) != 0 {
		t.Fatalf("unlinked rows: %v %v", old, partner)
	}
	if _, out := f.do("GET", "/api/v1/certificates?state=pending-destroy", nil); len(out["items"].([]any)) != 1 {
		t.Fatalf("state filter: %v", out)
	}
	if _, out := f.do("GET", "/api/v1/certificates?host=api.payments.example.com", nil); len(out["items"].([]any)) != 1 {
		t.Fatalf("host filter: %v", out)
	}

	// detail by ID prefix: chain subjects and the servers serving each link
	shopID := shop["id"].(string)
	code, out = f.do("GET", "/api/v1/certificates/"+shopID[:12], nil)
	if code != 200 || out["id"] != shopID || len(out["chain"].([]any)) == 0 {
		t.Fatalf("detail: %d %v", code, out)
	}
	for _, l := range out["links"].([]any) {
		if l := l.(map[string]any); l["host"] == "shop.example.com" && len(l["servedBy"].([]any)) == 0 {
			t.Fatalf("servedBy: %v", out["links"])
		}
	}
	if code, _ := f.do("GET", "/api/v1/certificates/"+shopID[:12]+"/chain", nil); code != 200 {
		t.Fatalf("chain: %d", code)
	}
	if code, _ := f.do("GET", "/api/v1/certificates/000000000000", nil); code != 404 {
		t.Fatalf("missing: %d", code)
	}
	if code, _ := f.do("GET", "/api/v1/certificates/abc", nil); code == 200 {
		t.Fatal("short prefix answered")
	}

	// delete: a linked certificate is refused with its links
	code, out = f.do("DELETE", "/api/v1/certificates/"+shopID, nil)
	if code != 409 || out["error"].(map[string]any)["code"] != "linked" || len(out["links"].([]any)) != 2 {
		t.Fatalf("delete linked: %d %v", code, out)
	}
	if code, out := f.do("DELETE", "/api/v1/certificates/"+old["id"].(string), nil); code != 204 {
		t.Fatalf("delete pending: %d %v", code, out)
	}
	// disable drops every link; then it can be deleted
	code, out = f.do("POST", "/api/v1/certificates/"+shopID+"/disable", nil)
	if code != 200 || out["unlinkedHosts"] != float64(2) {
		t.Fatalf("disable: %d %v", code, out)
	}
	if code, _ := f.do("POST", "/api/v1/certificates/"+shopID+"/disable", nil); code != 409 {
		t.Fatalf("disable again: %d", code)
	}
	if code, out := f.do("DELETE", "/api/v1/certificates/"+shopID, nil); code != 204 {
		t.Fatalf("delete disabled: %d %v", code, out)
	}

	// check and put
	now := time.Now()
	chain, key, err := sfc.NewTestCertificate([]string{"files.shop.example.com"}, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	_, otherKey, _ := sfc.NewTestCertificate([]string{"x.example.com"}, now.Add(-time.Hour), now.Add(time.Hour))
	oldChain, oldKey, _ := sfc.NewTestCertificate([]string{"old.example.com"}, now.Add(-48*time.Hour), now.Add(-time.Hour))
	code, out = f.do("POST", "/api/v1/certificates/check", map[string]any{"chain": string(chain)})
	if code != 200 || out["names"].([]any)[0] != "files.shop.example.com" || len(out["links"].([]any)) != 1 || out["invalid"] != nil {
		t.Fatalf("check: %d %v", code, out)
	}
	if _, out := f.do("POST", "/api/v1/certificates/check", map[string]any{"chain": string(oldChain)}); out["invalid"] != "expired" {
		t.Fatalf("check expired: %v", out)
	}
	if code, _ := f.do("POST", "/api/v1/certificates/check", map[string]any{"chain": "nope"}); code != 422 {
		t.Fatalf("check bad: %d", code)
	}
	for _, bad := range []struct {
		chain, key, code string
	}{
		{"nope", string(key), "invalid-chain"},
		{string(chain), "nope", "invalid-key"},
		{string(chain), string(otherKey), "mismatch"},
		{string(oldChain), string(oldKey), "not-valid-now"},
	} {
		code, out := f.do("POST", "/api/v1/certificates", map[string]any{"chain": bad.chain, "key": bad.key})
		if code != 422 || out["error"].(map[string]any)["code"] != bad.code {
			t.Fatalf("%s: %d %v", bad.code, code, out)
		}
		if strings.Contains(mustString(out), "PRIVATE KEY") {
			t.Fatalf("key echoed: %v", out)
		}
	}
	body := map[string]any{"chain": string(chain), "key": string(key)}
	code, out = f.do("POST", "/api/v1/certificates", body)
	if code != 201 || out["created"] != true || len(out["links"].([]any)) != 1 {
		t.Fatalf("put: %d %v", code, out)
	}
	id := out["id"]
	if code, again := f.do("POST", "/api/v1/certificates", body); code != 200 || again["created"] != false || again["id"] != id {
		t.Fatalf("put again: %d %v", code, again)
	}

	// the key is nowhere in the web store
	_, sess := f.do("GET", "/api/v1/auth/session", nil)
	ops, err := f.store.ListOps(sess["user"].(map[string]any)["id"].(string), "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) == 0 {
		t.Fatal("no ops stored")
	}
	for _, o := range ops {
		if bytes.Contains(o.Signed, key) || bytes.Contains(o.Signed, []byte("PRIVATE KEY")) {
			t.Fatalf("op %s holds the key", o.ID)
		}
	}
}
