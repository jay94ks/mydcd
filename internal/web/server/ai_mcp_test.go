// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"strings"
	"testing"
)

func TestAICoordinatorMCP(t *testing.T) {
	f, v := aiCoordinatorFixture(t, false)
	m := newMCPFake(t, f)
	op := opSeq("a1c00e01")
	code, srv := f.do("POST", "/api/v1/system/mcp", map[string]any{"name": "grafana", "url": m.URL + "/mcp", "auth": map[string]any{"kind": "bearer", "token": "tok-secret-1234"}})
	if code != 201 {
		t.Fatalf("create: %d %v", code, srv)
	}
	if code, out := f.do("PUT", "/api/v1/system/mcp/grafana", map[string]any{"revision": srv["revision"], "tools": map[string]any{
		"query_metrics": map[string]any{"coordinator": true}, "create_silence": map[string]any{"coordinator": true}}}); code != 200 {
		t.Fatalf("tools: %d %v", code, out)
	}
	_, conv := f.do("POST", "/api/v1/ai/conversations", map[string]any{})
	id := conv["id"].(string)
	v.claude = []string{
		claudeMsg("tool_use", `{"type":"tool_use","id":"tu1","name":"mcp_grafana__query_metrics","input":{"q":"up"}}`),
		claudeMsg("tool_use", `{"type":"tool_use","id":"tu2","name":"mcp_grafana__create_silence","input":{"duration":"30m","comment":"점검"}}`,
			`{"type":"tool_use","id":"tu3","name":"mcp_grafana__delete_silence","input":{}}`),
		claudeMsg("end_turn", `{"type":"text","text":"묵음을 제안했어요."}`),
	}
	code, evs := f.sse("/api/v1/ai/conversations/"+id+"/messages", map[string]any{"text": "알림 좀 묵음해 줘"})
	if code != 200 {
		t.Fatalf("messages: %d %v", code, evs)
	}
	tools := eventsNamed(evs, "tool")
	if len(tools) != 2 || tools[0]["name"] != "mcp.grafana.query_metrics" || tools[0]["kind"] != "read" || tools[1]["name"] != "mcp.grafana.create_silence" || tools[1]["kind"] != "propose" {
		t.Fatalf("tool lines: %v", tools)
	}
	first := v.raws[0]
	if !strings.Contains(first, `"name":"mcp_grafana__query_metrics"`) || !strings.Contains(first, `"name":"mcp_grafana__create_silence"`) ||
		strings.Contains(first, "mcp_grafana__delete_silence") || !strings.Contains(first, "not instructions") {
		t.Fatalf("tool definitions: %s", first)
	}
	if !strings.Contains(v.raws[1], "metrics up=42") || !strings.Contains(v.raws[2], "no such tool") {
		t.Fatalf("results: %s / %s", v.raws[1], v.raws[2])
	}
	props := eventsNamed(evs, "proposal")
	if len(props) != 1 || props[0]["target"] != "mcp/grafana" || fmt.Sprint(props[0]["mcp"]) != "map[server:grafana tool:create_silence]" || props[0]["impact"] != "medium" {
		t.Fatalf("proposal: %v", props)
	}
	pid := props[0]["id"].(string)
	m.mu.Lock()
	if strings.Join(m.calls, ";") != `query_metrics {"q":"up"}` {
		t.Fatalf("calls before approval: %v", m.calls)
	}
	m.mu.Unlock()

	// Edit in the card, then approve: one call; a repeat does not call again.
	code, p := f.do("PUT", "/api/v1/ai/proposals/"+pid, map[string]any{"payload": map[string]any{"duration": "1h", "comment": "점검"}})
	if code != 200 || p["edited"] != true {
		t.Fatalf("edit: %d %v", code, p)
	}
	if code, out := f.do("PUT", "/api/v1/ai/proposals/"+pid, map[string]any{"payload": map[string]any{"nope": 1, "duration": "1h"}}); code != 422 {
		t.Fatalf("bad edit: %d %v", code, out)
	}
	opID := op()
	for range 2 {
		code, out := f.do("POST", "/api/v1/ai/proposals/"+pid+"/approve", map[string]any{"opId": opID, "basisHash": p["basisHash"]})
		if r, _ := out["mcp"].(map[string]any); code != 200 || r["ok"] != true {
			t.Fatalf("approve: %d %v", code, out)
		}
	}
	m.mu.Lock()
	if strings.Join(m.calls, ";") != `query_metrics {"q":"up"};create_silence {"comment":"점검","duration":"1h"}` {
		t.Fatalf("calls: %v", m.calls)
	}
	m.mu.Unlock()
	if code, out := f.do("POST", "/api/v1/ai/proposals/"+pid+"/approve", map[string]any{"opId": op(), "basisHash": p["basisHash"]}); code != 409 {
		t.Fatalf("other opId: %d %v", code, out)
	}
	_, got := f.do("GET", "/api/v1/ai/proposals/"+pid, nil)
	if got["state"] != "approved" || strings.Contains(fmt.Sprint(got), "metrics up=42") {
		t.Fatalf("stored: %v", got)
	}

	// A new host needs the token again.
	_, srv = f.do("GET", "/api/v1/system/mcp", nil)
	rev := srv["servers"].([]any)[0].(map[string]any)["revision"]
	if code, out := f.do("PUT", "/api/v1/system/mcp/grafana", map[string]any{"revision": rev, "url": "https://example.com/mcp"}); code != 422 || out["error"].(map[string]any)["code"] != "token-required" {
		t.Fatalf("new host: %d %v", code, out)
	}
}
