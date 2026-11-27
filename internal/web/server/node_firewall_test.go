// SPDX-License-Identifier: Apache-2.0

package server

import "testing"

// The 방화벽 설정 tab: show, a delta change at the read revision, a stale
// revision refused with the current one, an opId replayed, the log, and a
// server whose node.yaml does not allow control.
func TestFakeNodeFirewall(t *testing.T) {
	f, fake := newFakeFixture(t)
	_, out := f.do("POST", "/api/v1/auth/credential/challenge", map[string]any{"username": "admin", "method": "password"})
	if code, out := f.do("POST", "/api/v1/auth/credential/login", map[string]any{"ticketId": out["ticketId"], "secret": "admin"}); code != 200 {
		t.Fatalf("login: %d %v", code, out)
	}
	code, out := f.do("GET", "/api/v1/nodes/node-a/firewall", nil)
	fw, _ := out["firewall"].(map[string]any)
	if code != 200 || fw == nil || fw["managed"] != true || fw["policy"] != "inherit" || fw["effective"] != "return" || fw["revision"] != float64(0) || len(fw["locked"].([]any)) == 0 {
		t.Fatalf("show: %d %v", code, out)
	}
	add := map[string]any{"opId": "fw-1", "revision": 0, "add": []any{map[string]any{"action": "allow", "proto": "tcp", "ports": "443", "from": []any{}}}}
	code, out = f.do("POST", "/api/v1/nodes/node-a/firewall", add)
	change, _ := out["change"].(map[string]any)
	if code != 200 || out["code"] != nil || change == nil || change["to"] != float64(1) || change["added"].([]any)[0] != "r1" {
		t.Fatalf("add: %d %v", code, out)
	}
	if code, again := f.do("POST", "/api/v1/nodes/node-a/firewall", add); code != 200 || again["change"] == nil {
		t.Fatalf("replay: %d %v", code, again)
	}
	code, out = f.do("POST", "/api/v1/nodes/node-a/firewall", map[string]any{"opId": "fw-2", "revision": 0, "policy": "drop"})
	if code != 200 || out["code"] != "revision" || out["firewall"].(map[string]any)["revision"] != float64(1) {
		t.Fatalf("stale revision: %d %v", code, out)
	}
	code, out = f.do("POST", "/api/v1/nodes/node-a/firewall", map[string]any{"opId": "fw-3", "revision": 1, "add": []any{map[string]any{"action": "allow", "proto": "tcp", "ports": "443"}}})
	if code != 200 || out["code"] != "duplicate" {
		t.Fatalf("duplicate: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/nodes/node-a/firewall", map[string]any{"opId": "fw-4", "revision": 1}); code != 422 {
		t.Fatalf("empty change: %d %v", code, out)
	}
	code, out = f.do("GET", "/api/v1/nodes/node-a/firewall/log", nil)
	if code != 200 || len(out["log"].([]any)) != 1 {
		t.Fatalf("log: %d %v", code, out)
	}
	fake.SetFirewallManaged("node-b", false)
	code, out = f.do("GET", "/api/v1/nodes/node-b/firewall", nil)
	if code != 200 || out["firewall"].(map[string]any)["managed"] != false {
		t.Fatalf("unmanaged show: %d %v", code, out)
	}
	code, out = f.do("POST", "/api/v1/nodes/node-b/firewall", map[string]any{"opId": "fw-5", "revision": 0, "policy": "drop"})
	if code != 200 || out["code"] != "not-managed" {
		t.Fatalf("unmanaged change: %d %v", code, out)
	}
}
