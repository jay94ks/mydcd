// SPDX-License-Identifier: Apache-2.0

package server

import (
	"strings"
	"testing"
)

// A second compaction while one runs is refused (the rest of the
// compaction screens run on real sfcd: TestRealServerNodeViews).
func TestRaftCompact(t *testing.T) {
	f, fake := newFakeFixture(t)
	fakeLogin(t, f, "admin")
	_, out := f.do("GET", "/api/v1/raft/compact/plan?mode=minimal", nil)
	preview := out["plan"].(string)
	fake.HoldCompaction(true)
	code, out := f.do("POST", "/api/v1/raft/compact", map[string]any{"opId": opA, "nodes": []string{}, "mode": "minimal", "serial": true, "plan": preview})
	if code != 200 || out["op"].(map[string]any)["state"] != "applied" {
		t.Fatalf("compact: %d %v", code, out)
	}
	_, out = f.do("GET", "/api/v1/raft/compact", nil)
	if last := out["last"].(map[string]any); last["state"] != "running" {
		t.Fatalf("running: %v", last)
	}
	if code, out := f.do("POST", "/api/v1/raft/compact", map[string]any{"opId": opB, "nodes": []string{}, "mode": "keep", "serial": false}); code != 409 || out["error"].(map[string]any)["code"] != "in-progress" {
		t.Fatalf("second: %d %v", code, out)
	}
	fake.HoldCompaction(false)
	_, out = f.do("GET", "/api/v1/raft/compact", nil)
	if s := mustString(out["last"]); !strings.Contains(s, `"state":"done"`) || strings.Contains(s, `"state":"running"`) {
		t.Fatalf("done: %s", s)
	}
}
