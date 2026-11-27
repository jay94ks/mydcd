// SPDX-License-Identifier: Apache-2.0

package server

import (
	"testing"

	"github.com/jay94ks/seafield/internal/web/sfc"
)

func TestOwnLoginsScreen(t *testing.T) {
	f, _ := newFakeFixture(t)
	_, out := f.do("POST", "/api/v1/auth/credential/challenge", map[string]any{"username": "alice", "method": "password"})
	if code, _ := f.do("POST", "/api/v1/auth/credential/login", map[string]any{"ticketId": out["ticketId"], "secret": "wrong"}); code == 200 {
		t.Fatal("wrong password accepted")
	}
	fakeLogin(t, f, "alice")
	code, v := f.do("GET", "/api/v1/me/logins", nil)
	items, _ := v["items"].([]any)
	if code != 200 || len(items) != 2 || v["budgetMax"].(float64) != 5 || len(v["missing"].([]any)) != 0 {
		t.Fatalf("logins: %d %v", code, v)
	}
	ok, failed := items[0].(map[string]any), items[1].(map[string]any)
	// the browser's own address and user agent are kept beside the record
	if ok["ok"] != true || ok["method"] != "password" || ok["session"] == "" || ok["expiresAt"] == "" || ok["address"] != "127.0.0.1" || ok["client"] == "" || ok["node"] != "node-a" {
		t.Fatalf("success row: %v", ok)
	}
	if failed["ok"] != false || failed["reason"] != "denied" || failed["count"].(float64) != 1 {
		t.Fatalf("failure row: %v", failed)
	}
	// another user sees only their own
	bobLogin(t, f)
	_, v = f.do("GET", "/api/v1/me/logins", nil)
	items = v["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["method"] != string(sfc.MethodPrivateKey) {
		t.Fatalf("bob: %v", v)
	}
	if code, _ := f.do("GET", "/api/v1/me/logins?after=bad", nil); code == 200 {
		t.Fatal("bad cursor accepted")
	}
}

func TestOwnSessionsScreen(t *testing.T) {
	f, _ := newFakeFixture(t)
	op := opSeq("5e55e000")
	fakeLogin(t, f, "alice")
	fakeLogin(t, f, "alice")
	code, v := f.do("GET", "/api/v1/me/sessions", nil)
	items, _ := v["items"].([]any)
	if code != 200 || len(items) != 2 {
		t.Fatalf("sessions: %d %v", code, v)
	}
	current, other := items[0].(map[string]any), items[1].(map[string]any)
	if current["current"] != true || other["current"] != false || other["expiresAt"] == "" || other["method"] != "password" {
		t.Fatalf("rows: %v", items)
	}
	if code, out := f.do("DELETE", "/api/v1/me/sessions/"+current["id"].(string), map[string]any{"opId": op()}); code != 422 {
		t.Fatalf("current session ended here: %d %v", code, out)
	}
	if code, out := f.do("DELETE", "/api/v1/me/sessions/"+other["id"].(string), map[string]any{"opId": op()}); opState(t, code, out) != "applied" {
		t.Fatalf("revoke: %d %v", code, out)
	}
	_, v = f.do("GET", "/api/v1/me/sessions", nil)
	if items = v["items"].([]any); len(items) != 1 || items[0].(map[string]any)["current"] != true {
		t.Fatalf("after revoke: %v", v)
	}
}
