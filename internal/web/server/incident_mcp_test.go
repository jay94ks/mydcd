// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/web/mydc"
)

func TestIncidentMCPDiagnose(t *testing.T) {
	f, fake, clock := incidentFixture(t)
	v := newScriptVendor(t)
	f.srv.opt.AI = v.endpoints()
	m := newMCPFake(t, f)
	ctx := context.Background()
	fakeLogin(t, f, "admin")
	for p, k := range map[string]string{"claude": testClaudeKey, "openai": testOpenAIKey} {
		if code, out := f.do("PUT", "/api/v1/system/ai/keys/"+p, map[string]any{"key": k}); code != 200 {
			t.Fatalf("key %s: %d %v", p, code, out)
		}
	}
	setAIRoles(t, f, []string{})
	makeAutomation(t, f, "mydc-autofix", "a1b2c3d4-0000-4000-8000-0000000000e7", true, true)
	if code, out := f.do("PUT", "/api/v1/incidents/policy", map[string]any{"revision": 0, "level": "suggest", "ratePerHour": 5,
		"approvers": map[string]any{"label": "관리자", "deadlineMinutes": 30}, "quiet": []string{}, "newAppDefault": "suggest"}); code != 200 {
		t.Fatalf("policy: %d %v", code, out)
	}
	code, srv := f.do("POST", "/api/v1/system/mcp", map[string]any{"name": "grafana", "url": m.URL + "/mcp", "auth": map[string]any{"kind": "bearer", "token": "tok-secret-1234"},
		"users": map[string]any{"tenants": []string{"shop"}}})
	if code != 201 {
		t.Fatalf("mcp: %d %v", code, srv)
	}
	if code, out := f.do("PUT", "/api/v1/system/mcp/grafana", map[string]any{"revision": srv["revision"], "tools": map[string]any{
		"query_metrics": map[string]any{"incident": "diagnose", "auto": map[string]any{"inputs": map[string]any{"q": map[string]any{"kind": "template", "value": `up{app="{app}"}`}}}},
		// A propose tool is not called by the diagnosis.
		"delete_silence": map[string]any{"incident": "propose-approve"}}}); code != 200 {
		t.Fatalf("tools: %d %v", code, out)
	}
	v.claude = []string{claudeText(`{"hypothesis":"지표가 떨어졌어요","candidates":[{"action":"restart-task","note":"다시 시작"}]}`)}
	v.openai = []string{openaiText(`{"level":"low","reversible":true,"blast_radius":1,"data_risk":"none","confidence":0.9,"reasons":[]}`)}
	now := clock.Load()
	for i := int64(3); i > 0; i-- {
		fake.AddEvent(mydc.FixtureEvent{Time: now - i*30, Scope: "app", Tenant: "shop", App: "php-shop", Node: "node-a", Kind: "task-restarted", Target: "shop/php-shop/web/1"})
	}
	f.srv.watchOnce(ctx)
	row := findIncident(t, f, "task-restarted")
	if row == nil {
		t.Fatal("no incident")
	}
	m.mu.Lock()
	calls := strings.Join(m.calls, ";")
	m.mu.Unlock()
	if calls != `query_metrics {"q":"up{app=\"php-shop\"}"}` {
		t.Fatalf("calls: %s", calls)
	}
	if len(v.raws) == 0 || !strings.Contains(v.raws[0], "\\u003cmcp-results\\u003e") || !strings.Contains(v.raws[0], "metrics up") || strings.Contains(v.raws[1], "metrics up") {
		t.Fatalf("diagnosis input: %v", v.raws)
	}
	_, det := f.do("GET", "/api/v1/incidents/"+row["id"].(string), nil)
	if fmt.Sprint(det["mcpCalls"]) != "map[grafana:1]" || !strings.Contains(fmt.Sprint(det["timeline"]), "mcp.grafana.query_metrics") || strings.Contains(fmt.Sprint(det), "metrics up") {
		t.Fatalf("detail: %v", det)
	}

}
