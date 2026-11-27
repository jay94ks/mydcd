// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/web/sfc"
)

// A propose-auto MCP tool runs on its own under its limits; past them it
// asks a person, whose approval calls it once.
func TestIncidentMCPCandidates(t *testing.T) {
	f, fake, clock := incidentFixture(t)
	m := newMCPFake(t, f)
	ctx := context.Background()
	fakeLogin(t, f, "admin")
	makeAutomation(t, f, "sfc-autofix", "a1b2c3d4-0000-4000-8000-0000000000e8", true, true)
	if code, out := f.do("PUT", "/api/v1/incidents/policy", map[string]any{"revision": 0, "level": "auto-low", "ratePerHour": 5,
		"approvers": map[string]any{"label": "관리자", "deadlineMinutes": 30}, "quiet": []string{}, "newAppDefault": "suggest",
		"actions": map[string]any{"cordon-node": "human"}}); code != 200 {
		t.Fatalf("policy: %d %v", code, out)
	}
	code, srv := f.do("POST", "/api/v1/system/mcp", map[string]any{"name": "grafana", "url": m.URL + "/mcp", "auth": map[string]any{"kind": "bearer", "token": "tok-secret-1234"},
		"users": map[string]any{"tenants": []string{}}})
	if code != 201 {
		t.Fatalf("mcp: %d %v", code, srv)
	}
	if code, out := f.do("PUT", "/api/v1/system/mcp/grafana", map[string]any{"revision": srv["revision"], "tools": map[string]any{
		"create_silence": map[string]any{"incident": "propose-auto", "auto": map[string]any{"floor": "low", "perIncident": 1, "perDay": 1,
			"revert": map[string]any{"tool": "delete_silence"}, "signals": []string{"node-unreachable"},
			"inputs": map[string]any{"duration": map[string]any{"kind": "fixed", "value": "1h"}, "matchers": map[string]any{"kind": "template", "value": "node={node}"},
				"comment": map[string]any{"kind": "incident", "value": "id"}}}}}}); code != 200 {
		t.Fatalf("tools: %d %v", code, out)
	}
	calls := func() []string {
		m.mu.Lock()
		defer m.mu.Unlock()
		return append([]string(nil), m.calls...)
	}

	fake.AddEvent(sfc.FixtureEvent{Time: clock.Load(), Scope: "cluster", Node: "node-c", Kind: "node-unreachable", Target: "node-c"})
	f.srv.watchOnce(ctx)
	row := findIncident(t, f, "node-unreachable")
	if row == nil || decisionOf(row) != "auto" || row["mitigation"] != "묵음" {
		t.Fatalf("auto: %v", row)
	}
	id := row["id"].(string)
	if c := calls(); len(c) != 1 || c[0] != `create_silence {"comment":"`+id+`","duration":"1h","matchers":"node=node-c"}` {
		t.Fatalf("calls: %v", c)
	}
	_, det := f.do("GET", "/api/v1/incidents/"+id, nil)
	if fmt.Sprint(det["mcpCalls"]) != "map[grafana:1]" || !strings.Contains(fmt.Sprint(det["timeline"]), "자동 실행 (MCP mcp.grafana.create_silence)") || strings.Contains(fmt.Sprint(det), "metrics up") {
		t.Fatalf("detail: %v", det)
	}

	// The day's one run is used: the next incident asks a person.
	clock.Add(1)
	fake.AddEvent(sfc.FixtureEvent{Time: clock.Load(), Scope: "cluster", Node: "node-b", Kind: "node-unreachable", Target: "node-b"})
	f.srv.watchOnce(ctx)
	var next map[string]any
	_, list := f.do("GET", "/api/v1/incidents?limit=200", nil)
	for _, it := range list["items"].([]any) {
		if x := it.(map[string]any); x["node"] == "node-b" {
			next = x
		}
	}
	if next == nil || decisionOf(next) != "pending" || !strings.Contains(fmt.Sprint(next["decision"]), "하루 한도(1번)") {
		t.Fatalf("limit: %v", next)
	}
	_, det = f.do("GET", "/api/v1/incidents/"+next["id"].(string), nil)
	ap := det["approval"].(map[string]any)
	if ap["action"] != "mcp.grafana.create_silence" {
		t.Fatalf("approval: %v", ap)
	}
	opID := "a1b2c3d4-0000-4000-8000-0000000000f1"
	for i := 0; i < 2; i++ { // the repeat answers from the record
		code, out := f.do("POST", "/api/v1/incidents/"+next["id"].(string)+"/approve", map[string]any{"opId": opID, "basisHash": ap["basisHash"]})
		if raw, _ := json.Marshal(out); code != 200 || string(raw) != `{"mcp":{"ok":true,"server":"grafana","tool":"create_silence"}}` {
			t.Fatalf("approve %d: %d %s", i, code, raw)
		}
	}
	if c := calls(); len(c) != 2 || !strings.Contains(c[1], "node=node-b") {
		t.Fatalf("calls after approval: %v", c)
	}
	if code, out := f.do("POST", "/api/v1/incidents/"+next["id"].(string)+"/approve", map[string]any{"opId": "a1b2c3d4-0000-4000-8000-0000000000f2", "basisHash": ap["basisHash"]}); code != 409 {
		t.Fatalf("second approval: %d %v", code, out)
	}
}
