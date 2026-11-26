// SPDX-License-Identifier: Apache-2.0

package server

import (
	"testing"
)

// f4e1a7e: a build whose context mounts a protected Group's Secret waits
// with its original unsent until the requester approves the Group.
func TestBuildSecretApproval(t *testing.T) {
	f, fake := newFakeFixture(t)
	fakeLogin(t, f, "alice")
	fake.SetGroupPassword("shop", "shop-db", "open-sesame") // worker mounts shop/mysql
	op := opSeq("ab47bbbb")
	opID := op()
	code, out := f.do("POST", "/api/v1/t/shop/build-contexts/worker/build", map[string]any{"opId": opID})
	o := out["op"].(map[string]any)
	ap, _ := o["approvals"].([]any)
	if code != 202 || o["state"] != "running" || o["errorCode"] != "approval-required" || len(ap) != 1 || ap[0].(map[string]any)["group"] != "shop-db" {
		t.Fatalf("start: %d %v", code, out)
	}
	if fake.GroupApproved("shop", "shop-db", o["requestId"].(string)) {
		t.Fatal("approved before the password")
	}
	// the same opId again still waits; resume is refused; the list shows it
	if code, out := f.do("POST", "/api/v1/t/shop/build-contexts/worker/build", map[string]any{"opId": opID}); code != 202 || out["op"].(map[string]any)["errorCode"] != "approval-required" {
		t.Fatalf("again: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/ops/"+opID+"/resume", nil); code != 409 || errCode(out) != "approval-required" {
		t.Fatalf("resume: %d %v", code, out)
	}
	_, out = f.do("GET", "/api/v1/t/shop/vault/approvals", nil)
	items := out["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["kind"] != "build" || items[0].(map[string]any)["context"] != "worker" || items[0].(map[string]any)["build"] != "build-"+opID {
		t.Fatalf("list: %v", out)
	}
	base := "/api/v1/t/shop/build-approvals/" + opID + "/approve"
	if code, out := f.do("POST", base, map[string]any{"group": "shop-db", "password": "wrong"}); code != 403 || errCode(out) != "approval-denied" {
		t.Fatalf("wrong password: %d %v", code, out)
	}
	if code, out := f.do("POST", base, map[string]any{"group": "other", "password": "x"}); code != 409 || errCode(out) != "not-required" {
		t.Fatalf("other group: %d %v", code, out)
	}
	code, out = f.do("POST", base, map[string]any{"group": "shop-db", "password": "open-sesame"})
	o = out["op"].(map[string]any)
	if code != 200 || o["state"] != "applied" || o["errorCode"] != nil {
		t.Fatalf("approve: %d %v", code, out)
	}
	if !fake.GroupApproved("shop", "shop-db", o["requestId"].(string)) {
		t.Fatal("approval not kept")
	}
	assertNowhere(t, f, "open-sesame")
	assertNowhere(t, f, "wrong")
	if _, out := f.do("GET", "/api/v1/t/shop/vault/approvals", nil); len(out["items"].([]any)) != 0 {
		t.Fatalf("list after: %v", out)
	}
	if code, _ := f.do("POST", base, map[string]any{"group": "shop-db", "password": "open-sesame"}); code != 409 {
		t.Fatalf("after done: %d", code)
	}
	// an unprotected Group: the build is sent at once
	fake.SetGroupPassword("shop", "shop-db", "")
	if code, out := f.do("POST", "/api/v1/t/shop/build-contexts/worker/build", map[string]any{"opId": op()}); opState(t, code, out) != "applied" {
		t.Fatalf("open: %d %v", code, out)
	}
}
