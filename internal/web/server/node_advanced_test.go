// SPDX-License-Identifier: Apache-2.0

package server

import (
	"strings"
	"testing"
)

// Force remove of a server that stopped answering (the fake can mark one
// unreachable; the other server actions run on real mydcd:
// TestRealServerNodeLifecycle).
func TestNodeAdvancedRoutes(t *testing.T) {
	f, fake := newFakeFixture(t)
	op := opSeq("ad510000")
	node := func(id string) map[string]any {
		_, out := f.do("GET", "/api/v1/nodes", nil)
		for _, it := range out["items"].([]any) {
			if m := it.(map[string]any); m["id"] == id {
				return m
			}
		}
		return nil
	}
	fakeLogin(t, f, "admin")

	// node-c goes once it stops answering.
	fake.SetNodeStatus("node-c", "unreachable")
	code, fp := f.do("GET", "/api/v1/nodes/node-c/force-remove-plan", nil)
	if code != 200 || fp["code"] != nil || fp["forceable"] != true || fp["volumes"] == nil || fp["probe"] == nil {
		t.Fatalf("force plan node-c: %d %v", code, fp)
	}
	if code, out := f.do("POST", "/api/v1/nodes/node-c/force-remove", map[string]any{"opId": op(), "plan": strings.Repeat("ab", 32), "operation": fp["operation"]}); code != 409 || errCode(out) != "plan-changed" {
		t.Fatalf("stale force plan: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/nodes/node-c/force-remove", map[string]any{"opId": op(), "plan": fp["plan"], "operation": fp["operation"]}); opState(t, code, out) != "applied" || node("node-c")["phase"] != "removed" && node("node-c") != nil {
		t.Fatalf("force remove: %d %v", code, out)
	}
}
