// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func vpsRow(t *testing.T, out map[string]any, name string) map[string]any {
	t.Helper()
	for _, it := range out["servers"].([]any) {
		if r := it.(map[string]any); r["name"] == name {
			return r
		}
	}
	t.Fatalf("no server %s in %v", name, out["servers"])
	return nil
}

func TestVPSManagement(t *testing.T) {
	f, fake := newFakeFixture(t)
	op := opSeq("ab12cdef")
	fakeLogin(t, f, "alice")
	if code, _ := f.do("GET", "/api/v1/system/vps", nil); code != 403 {
		t.Fatalf("alice reads VPS: %d", code)
	}
	fakeLogin(t, f, "admin")
	fake.SetClock(func() time.Time { return time.Unix(1795600000, 0) })
	code, out := f.do("GET", "/api/v1/system/vps", nil)
	if code != 200 || out["revision"].(float64) != 1 || len(out["accounts"].([]any)) != 1 || out["status"] == nil {
		t.Fatalf("read: %d %v", code, out)
	}
	if a := out["accounts"].([]any)[0].(map[string]any); a["keyHint"] != "3F2A" || a["overageKRWPerGB"].(float64) != 10 {
		t.Fatalf("account row: %v", a)
	}
	if r := vpsRow(t, out, "vps-seoul-3"); r["capAction"] != "notify" || r["phase"] != "creating" {
		t.Fatalf("notify row: %v", r)
	}
	if r := vpsRow(t, out, "vps-seoul-1"); r["capAction"] != "stop" || r["build"] != nil {
		t.Fatalf("stop row: %v", r)
	}
	if st := out["status"].(map[string]any); st["leader"] != "node-a" || !strings.Contains(fmt.Sprint(st["servers"]), "judgeable:true") {
		t.Fatalf("status: %v", st)
	}
	if code, out := f.do("GET", "/api/v1/system/vps/accounts/main/offer?zone=KR1", nil); code != 200 || len(out["flavors"].([]any)) != 2 {
		t.Fatalf("offer: %d %v", code, out)
	}
	if code, _ := f.do("GET", "/api/v1/system/vps/accounts/other/offer", nil); code == 200 {
		t.Fatal("offer of an unknown account")
	}

	// The capped server starts only after the cap is raised above the
	// recorded projection (₩31,400).
	if code, out := f.do("POST", "/api/v1/system/vps/servers/vps-busan-1/start", map[string]any{"opId": op()}); opState(t, code, out) == "applied" {
		t.Fatalf("capped start under the projection: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/system/vps/servers/vps-busan-1/cap", map[string]any{"opId": op(), "capKRW": 20000}); code != 409 {
		t.Fatalf("same cap: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/system/vps/servers/vps-busan-1/cap", map[string]any{"opId": op(), "capAction": "never"}); code != 422 {
		t.Fatalf("bad cap action: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/system/vps/servers/vps-busan-1/cap", map[string]any{"opId": op(), "capKRW": 35000, "capAction": "notify"}); opState(t, code, out) != "applied" {
		t.Fatalf("raise cap: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/system/vps/servers/vps-busan-1/start", map[string]any{"opId": op()}); opState(t, code, out) != "applied" {
		t.Fatalf("start: %d %v", code, out)
	}
	_, out = f.do("GET", "/api/v1/system/vps", nil)
	if r := vpsRow(t, out, "vps-busan-1"); r["phase"] != "starting" || r["capKRW"].(float64) != 35000 || r["capAction"] != "notify" || out["revision"].(float64) != 3 {
		t.Fatalf("after start: %v %v", r, out["revision"])
	}

	// stop: only running; the DNS wait is bounded.
	if code, out := f.do("POST", "/api/v1/system/vps/servers/vps-busan-1/stop", map[string]any{"opId": op()}); code != 409 {
		t.Fatalf("stop a starting server: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/system/vps/servers/vps-seoul-1/stop", map[string]any{"opId": op(), "dnsWaitSeconds": 7200}); code != 422 {
		t.Fatalf("long wait: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/system/vps/servers/vps-seoul-1/stop", map[string]any{"opId": op(), "expected": 1}); opState(t, code, out) == "applied" {
		t.Fatalf("stale expected: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/system/vps/servers/vps-seoul-1/stop", map[string]any{"opId": op(), "dnsWaitSeconds": 60}); opState(t, code, out) != "applied" {
		t.Fatalf("stop: %d %v", code, out)
	}
	_, out = f.do("GET", "/api/v1/system/vps", nil)
	if r := vpsRow(t, out, "vps-seoul-1"); r["phase"] != "stopping" || r["stopAfter"].(float64) != 1795600060 {
		t.Fatalf("after stop: %v", r)
	}

	// create, then delete.
	create := map[string]any{"opId": op(), "name": "vps-seoul-4", "account": "main", "zone": "KR1", "image": "ubuntu-2404", "flavor": "ss1-c2m4", "script": "sfc-enroll", "capKRW": 30000}
	if code, out := f.do("POST", "/api/v1/system/vps/servers", create); opState(t, code, out) != "applied" {
		t.Fatalf("create: %d %v", code, out)
	}
	create["opId"] = op()
	if code, out := f.do("POST", "/api/v1/system/vps/servers", create); code != 409 {
		t.Fatalf("create again: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/system/vps/servers", map[string]any{"opId": op(), "name": "vps-x", "account": "main", "zone": "KR1", "image": "ubuntu-2404", "flavor": "f", "capKRW": 0}); code != 422 {
		t.Fatalf("zero cap: %d %v", code, out)
	}
	_, out = f.do("GET", "/api/v1/system/vps", nil)
	if r := vpsRow(t, out, "vps-seoul-4"); r["phase"] != "creating" || r["port"].(float64) != 7443 || r["createdBy"] != "u-admin" {
		t.Fatalf("created: %v", r)
	}
	if code, out := f.do("DELETE", "/api/v1/system/vps/servers/vps-seoul-4", map[string]any{"opId": op()}); opState(t, code, out) != "applied" {
		t.Fatalf("delete: %d %v", code, out)
	}
	if code, out := f.do("DELETE", "/api/v1/system/vps/servers/vps-seoul-4", map[string]any{"opId": op()}); code != 409 {
		t.Fatalf("delete again: %d %v", code, out)
	}
	if code, out := f.do("DELETE", "/api/v1/system/vps/servers/nope", map[string]any{"opId": op()}); code != 404 {
		t.Fatalf("delete unknown: %d %v", code, out)
	}
}

func TestVPSAccounts(t *testing.T) {
	f, _ := newFakeFixture(t)
	op := opSeq("ab13cdef")
	fakeLogin(t, f, "admin")
	if code, out := f.do("POST", "/api/v1/system/vps/accounts", map[string]any{"opId": op(), "name": "main", "vendor": "iwinv", "accessKey": "AK1", "secretKey": "s"}); code != 409 {
		t.Fatalf("existing account: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/system/vps/accounts", map[string]any{"opId": op(), "name": "test", "vendor": "other", "accessKey": "AK1", "secretKey": "s"}); code != 422 {
		t.Fatalf("unknown vendor: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/system/vps/accounts", map[string]any{"opId": op(), "name": "test", "vendor": "iwinv", "accessKey": "AK1", "secretKey": "rejected"}); code < 400 {
		t.Fatalf("sealing refused: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/system/vps/accounts", map[string]any{"opId": op(), "name": "test", "vendor": "iwinv", "accessKey": "AKIDXYZ9", "secretKey": "s3cret", "trafficPrice": 12}); opState(t, code, out) != "applied" {
		t.Fatalf("add: %d %v", code, out)
	}
	// the web store keeps neither key.
	ops, err := f.store.ListOps("u-admin", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range ops {
		if raw, _ := json.Marshal(o); strings.Contains(string(raw), "s3cret") || strings.Contains(string(raw), "AKIDXYZ9") {
			t.Fatalf("a provider key is in a stored op: %s", raw)
		}
	}
	_, out := f.do("GET", "/api/v1/system/vps", nil)
	if !strings.Contains(fmt.Sprint(out["accounts"]), "keyHint:XYZ9") || !strings.Contains(fmt.Sprint(out["accounts"]), "overageKRWPerGB:12") {
		t.Fatalf("added account: %v", out["accounts"])
	}
	if code, out := f.do("PATCH", "/api/v1/system/vps/accounts/test", map[string]any{"opId": op()}); code != 422 {
		t.Fatalf("empty set: %d %v", code, out)
	}
	if code, out := f.do("PATCH", "/api/v1/system/vps/accounts/test", map[string]any{"opId": op(), "trafficPrice": 12}); code != 409 {
		t.Fatalf("unchanged set: %d %v", code, out)
	}
	if code, out := f.do("PATCH", "/api/v1/system/vps/accounts/test", map[string]any{"opId": op(), "sshKeyId": "key-1"}); opState(t, code, out) != "applied" {
		t.Fatalf("set ssh key: %d %v", code, out)
	}
	if _, out := f.do("GET", "/api/v1/system/vps", nil); !strings.Contains(fmt.Sprint(out["accounts"]), "sshKeyID:key-1") {
		t.Fatalf("ssh key ID not set: %v", out["accounts"])
	}
	if code, out := f.do("POST", "/api/v1/system/vps/accounts/test/rotate-key", map[string]any{"opId": op(), "accessKey": "AKNEW777", "secretKey": "t"}); opState(t, code, out) != "applied" {
		t.Fatalf("rotate: %d %v", code, out)
	}
	_, out = f.do("GET", "/api/v1/system/vps", nil)
	if s := fmt.Sprint(out["accounts"]); !strings.Contains(s, "keyHint:W777") || strings.Contains(s, "sshKeyID:key-1") {
		t.Fatalf("rotated account keeps the old SSH key ID: %v", s)
	}
	if code, out := f.do("DELETE", "/api/v1/system/vps/accounts/main", map[string]any{"opId": op()}); code != 409 {
		t.Fatalf("remove an account in use: %d %v", code, out)
	}
	if code, out := f.do("DELETE", "/api/v1/system/vps/accounts/test", map[string]any{"opId": op()}); opState(t, code, out) != "applied" {
		t.Fatalf("remove: %d %v", code, out)
	}
}
