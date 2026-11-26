// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"strings"
	"testing"
)

func TestCDGroupApproval(t *testing.T) {
	f, fake := newFakeFixture(t)
	fakeLogin(t, f, "alice")
	fake.SetGroupPassword("shop", "shop-db", "open-sesame")
	_, out := f.do("GET", "/api/v1/t/shop/apps/php-shop/source", nil)
	doc := strings.Replace(out["yaml"].(string), "      node: node-b\n", "      node: node-b\n      secrets_from: [group/shop-db]\n", 1)
	// deploy the app with the Group first (approved), so its CD candidate uses it
	opID := fmt.Sprintf("e9b2c3d4-0000-4000-8000-%012d", 2)
	f.do("POST", "/api/v1/t/shop/apps/deploy", map[string]any{"opId": opID, "yaml": doc})
	if code, out := f.do("POST", "/api/v1/t/shop/apps/deploy/"+opID+"/approve", map[string]any{"group": "shop-db", "password": "open-sesame"}); code != 200 {
		t.Fatalf("deploy approve: %d %v", code, out)
	}
	_, out = f.do("GET", "/api/v1/t/shop/apps", nil)
	var cand string
	for _, it := range out["items"].([]any) {
		if a := it.(map[string]any); a["app"] == "php-shop" {
			cand, _ = a["cd"].(map[string]any)["candidateDigest"].(string)
		}
	}
	if len(cand) != 64 {
		t.Fatalf("candidate digest: %v", out)
	}
	base := "/api/v1/t/shop/apps/php-shop/cd/"
	code, out := f.do("GET", base+"approvals?candidate="+cand, nil)
	ap, _ := out["approvals"].([]any)
	if code != 200 || len(ap) != 1 || ap[0].(map[string]any)["state"] != "required" {
		t.Fatalf("cd approvals: %d %v", code, out)
	}
	if code, out := f.do("GET", base+"approvals", nil); code != 422 {
		t.Fatalf("no selection: %d %v", code, out)
	}
	if code, out := f.do("POST", base+"approvals", map[string]any{"candidate": cand, "group": "shop-db", "password": "nope"}); code != 403 || errCode(out) != "approval-denied" {
		t.Fatalf("wrong: %d %v", code, out)
	}
	code, out = f.do("POST", base+"approvals", map[string]any{"candidate": cand, "group": "shop-db", "password": "open-sesame"})
	if code != 200 || out["approvals"].([]any)[0].(map[string]any)["state"] != "approved" {
		t.Fatalf("approve: %d %v", code, out)
	}
	if !fake.GroupApproved("shop", "shop-db", "cd-shop-php-shop/"+cand) {
		t.Fatal("fake approval missing")
	}
	if _, out := f.do("GET", base+"approvals?candidate="+cand, nil); out["approvals"].([]any)[0].(map[string]any)["state"] != "approved" {
		t.Fatalf("after: %v", out)
	}
	if code, out := f.do("POST", base+"approvals", map[string]any{"candidate": cand, "group": "shop-db", "password": "open-sesame"}); code != 409 || errCode(out) != "already-approved" {
		t.Fatalf("twice: %d %v", code, out)
	}
	assertNowhere(t, f, "open-sesame")
	// only the registrant approves
	fakeLogin(t, f, "admin")
	if code, _ := f.do("GET", base+"approvals?candidate="+cand, nil); code != 403 {
		t.Fatalf("other user: %d", code)
	}
}
