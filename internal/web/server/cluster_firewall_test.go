// SPDX-License-Identifier: Apache-2.0

package server

import "testing"

// The cluster firewall: read, a signed delta at the read revision, a
// required rule that partly overrides a server rule, and the server view
// showing the cluster layer and the policy in force.
func TestFakeClusterFirewall(t *testing.T) {
	f, _ := newFakeFixture(t)
	fakeLogin(t, f, "admin")
	code, out := f.do("GET", "/api/v1/firewall", nil)
	if code != 200 || out["policy"] != "return" || out["revision"] != float64(0) || len(out["rules"].([]any)) != 0 {
		t.Fatalf("show: %d %v", code, out)
	}
	ssh := map[string]any{"action": "allow", "proto": "tcp", "ports": "22", "from": []any{"192.168.1.0/24"}, "required": true}
	change := map[string]any{"opId": "c7b2c3d4-0000-4000-8000-000000000001", "revision": 0, "add": []any{ssh}, "policy": "drop"}
	if code, out := f.do("POST", "/api/v1/firewall", change); opState(t, code, out) != "applied" {
		t.Fatalf("change: %d %v", code, out)
	}
	code, out = f.do("GET", "/api/v1/firewall", nil)
	rules := out["rules"].([]any)
	if code != 200 || out["policy"] != "drop" || out["revision"] != float64(1) || len(rules) != 1 || rules[0].(map[string]any)["id"] != "c1" || rules[0].(map[string]any)["required"] != true {
		t.Fatalf("after: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/firewall", map[string]any{"opId": "c7b2c3d4-0000-4000-8000-000000000002", "revision": 1, "policy": "inherit"}); code != 422 {
		t.Fatalf("cluster inherit: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/firewall", map[string]any{"opId": "c7b2c3d4-0000-4000-8000-000000000003", "revision": 0, "policy": "return"}); opState(t, code, out) == "applied" {
		t.Fatalf("stale revision applied: %d %v", code, out)
	}
	deny := map[string]any{"opId": "fw-1", "revision": 0, "add": []any{map[string]any{"action": "deny", "proto": "any", "from": []any{"192.168.1.7/32"}}}}
	if code, out := f.do("POST", "/api/v1/nodes/node-a/firewall", deny); code != 200 || out["code"] != nil {
		t.Fatalf("server deny: %d %v", code, out)
	}
	code, out = f.do("GET", "/api/v1/nodes/node-a/firewall", nil)
	fw := out["firewall"].(map[string]any)
	cluster, _ := fw["cluster"].(map[string]any)
	if code != 200 || fw["effective"] != "drop" || cluster == nil || cluster["revision"] != float64(1) || len(fw["shadowed"].([]any)) != 1 || fw["shadowed"].([]any)[0] != "r1" {
		t.Fatalf("server view: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/nodes/node-a/firewall", map[string]any{"opId": "fw-2", "revision": 1, "add": []any{map[string]any{"action": "allow", "proto": "tcp", "ports": "1", "required": true}}}); code != 200 || out["code"] != "invalid" {
		t.Fatalf("server required: %d %v", code, out)
	}
}
