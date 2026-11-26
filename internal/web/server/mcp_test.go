// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/web/store"
)

// mcpFake is a Streamable HTTP MCP server: JSON answers, tools/list page 1
// as an SSE stream with a server notification first.
type mcpFake struct {
	*httptest.Server
	mu      sync.Mutex
	tools   []map[string]any
	methods []string
	bad     []string // requests without the session or version headers
	calls   []string // tools/call name and arguments
}

func newMCPFake(t *testing.T, f *fixture) *mcpFake {
	m := &mcpFake{}
	m.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok-secret-1234" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"secret":"do not keep"}`)
			return
		}
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		var q struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params map[string]any  `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&q)
		m.mu.Lock()
		defer m.mu.Unlock()
		m.methods = append(m.methods, q.Method)
		if q.Method != "initialize" && (r.Header.Get("Mcp-Session-Id") != "sess-1" || r.Header.Get("MCP-Protocol-Version") != mcpProtocol) {
			m.bad = append(m.bad, q.Method)
		}
		answer := func(result any) []byte {
			b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": result})
			return b
		}
		switch q.Method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "sess-1")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(answer(map[string]any{"protocolVersion": mcpProtocol, "capabilities": map[string]any{"tools": map[string]any{}},
				"serverInfo": map[string]any{"name": "grafana-mcp", "version": "0.9"}}))
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			if q.Params["cursor"] == "p2" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(answer(map[string]any{"tools": m.tools[1:]}))
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = fmt.Fprintf(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{}}\n\n")
			_, _ = fmt.Fprintf(w, "data: %s\n\n", answer(map[string]any{"tools": m.tools[:1], "nextCursor": "p2"}))
		case "tools/call":
			raw, _ := json.Marshal(q.Params["arguments"])
			m.calls = append(m.calls, fmt.Sprint(q.Params["name"])+" "+string(raw))
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(answer(map[string]any{"content": []any{map[string]any{"type": "text", "text": "metrics up=42"}}, "isError": q.Params["name"] == "delete_silence"}))
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`+string(q.ID)+`,"error":{"code":-32601,"message":"no"}}`)
		}
	}))
	t.Cleanup(m.Close)
	pool := x509.NewCertPool()
	pool.AddCert(m.Certificate())
	f.srv.opt.WebhookTLS = &tls.Config{RootCAs: pool}
	f.srv.opt.WebhookAllowAddr = func(a netip.Addr) bool { return a.IsLoopback() }
	m.tools = []map[string]any{
		{"name": "query_metrics", "description": "질의", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"q": map[string]any{"type": "string"}}},
			"annotations": map[string]any{"readOnlyHint": true}},
		{"name": "create_silence", "title": "묵음", "description": "알림 묵음 만들기", "inputSchema": map[string]any{"type": "object",
			"properties": map[string]any{"matchers": map[string]any{"type": "string"}, "duration": map[string]any{"type": "string", "description": "기간"}, "comment": map[string]any{"type": "string"}},
			"required":   []any{"duration"}}},
		{"name": "delete_silence", "description": "묵음 지우기", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"id": map[string]any{"type": "string"}}}},
		{"name": "bad name!", "description": "건너뜀"},
	}
	return m
}

func toolOf(srv map[string]any, name string) map[string]any {
	for _, x := range srv["tools"].([]any) {
		if t := x.(map[string]any); t["name"] == name {
			return t
		}
	}
	return nil
}

func TestMCPServers(t *testing.T) {
	f, _, _ := incidentFixture(t)
	m := newMCPFake(t, f)
	fakeLogin(t, f, "alice")
	if code, _ := f.do("GET", "/api/v1/system/mcp", nil); code != 403 {
		t.Fatalf("alice: %d", code)
	}
	fakeLogin(t, f, "admin")
	add := func(url, token string) (int, map[string]any) {
		return f.do("POST", "/api/v1/system/mcp", map[string]any{"name": "grafana", "url": url, "auth": map[string]any{"kind": "bearer", "token": token}})
	}
	if code, out := add("http://example.com/mcp", "tok-secret-1234"); code != 422 || out["error"].(map[string]any)["code"] != "invalid" {
		t.Fatalf("http: %d %v", code, out)
	}
	code, out := add(m.URL+"/mcp", "wrong-token-xx")
	if e, _ := out["error"].(map[string]any); code != 422 || e["code"] != "mcp-connect" || e["error"] != "401 Unauthorized" || strings.Contains(fmt.Sprint(out), "do not keep") {
		t.Fatalf("bad token: %d %v", code, out)
	}
	if _, err := f.srv.opt.Store.GetMCPServer("grafana"); err == nil {
		t.Fatal("saved after a failed connect")
	}
	code, srv := add(m.URL+"/mcp", "tok-secret-1234")
	if code != 201 || srv["state"] != "ok" || fmt.Sprint(srv["auth"]) != "map[kind:bearer last4:1234 set:true]" || fmt.Sprint(srv["info"]) != "map[serverName:grafana-mcp version:0.9]" ||
		len(srv["tools"].([]any)) != 3 || srv["enabled"] != true {
		t.Fatalf("create: %d %v", code, srv)
	}
	if cs := toolOf(srv, "create_silence"); cs["kind"] != "change" || cs["incident"] != "off" || cs["tenants"] != "all" || cs["new"] != false || cs["title"] != "묵음" ||
		fmt.Sprint(cs["args"]) != "[map[description:기간 name:duration required:true type:string] map[name:comment type:string] map[name:matchers type:string]]" {
		t.Fatalf("tool: %v", cs)
	}
	if q := toolOf(srv, "query_metrics"); q["kind"] != "read" || q["readOnlyHint"] != true {
		t.Fatalf("read tool: %v", q)
	}
	m.mu.Lock()
	if len(m.bad) > 0 || strings.Join(m.methods, ",") != "initialize,notifications/initialized,tools/list,tools/list" {
		t.Fatalf("protocol: %v bad %v", m.methods, m.bad)
	}
	m.mu.Unlock()
	if tok, err := f.srv.opt.Seal.Get(mcpTokenKey("grafana")); err != nil || string(tok) != "tok-secret-1234" {
		t.Fatalf("sealed: %q %v", tok, err)
	}
	row, _ := f.srv.opt.Store.GetMCPServer("grafana")
	if raw, _ := json.Marshal(row); strings.Contains(string(raw), "tok-secret") {
		t.Fatal("token in the store")
	}
	if code, _ := add(m.URL+"/mcp", "tok-secret-1234"); code != 409 {
		t.Fatalf("again: %d", code)
	}

	put := func(rev any, tools map[string]any) (int, map[string]any) {
		return f.do("PUT", "/api/v1/system/mcp/grafana", map[string]any{"revision": rev, "tools": tools})
	}
	rev := srv["revision"]
	errCode := func(out map[string]any) any { e, _ := out["error"].(map[string]any); return e["code"] }
	if code, out := put(rev, map[string]any{"create_silence": map[string]any{"kind": "read"}}); code != 422 || errCode(out) != "kind" {
		t.Fatalf("lower kind: %d %v", code, out)
	}
	if code, out := put(rev, map[string]any{"create_silence": map[string]any{"incident": "diagnose"}}); code != 422 || errCode(out) != "invalid" {
		t.Fatalf("diagnose change: %d %v", code, out)
	}
	if code, out := put(rev, map[string]any{"create_silence": map[string]any{"incident": "propose-auto"}}); code != 422 || errCode(out) != "auto-incomplete" ||
		len(out["error"].(map[string]any)["missing"].([]any)) != 4 {
		t.Fatalf("incomplete: %d %v", code, out)
	}
	full := map[string]any{"floor": "low", "perIncident": 1, "perDay": 10, "revert": map[string]any{"tool": "delete_silence"}, "signals": []string{"5xx 급증"},
		"inputs": map[string]any{"duration": map[string]any{"kind": "max", "value": "60m"}, "matchers": map[string]any{"kind": "incident", "value": "app"},
			"comment": map[string]any{"kind": "template", "value": "MyDC 사건 {id} 자동 묵음"}}}
	irr := map[string]any{"floor": "low", "perIncident": 1, "perDay": 10, "revert": map[string]any{"irreversible": true}, "inputs": full["inputs"]}
	if code, out := put(rev, map[string]any{"create_silence": map[string]any{"incident": "propose-auto", "auto": irr}}); code != 422 || errCode(out) != "auto-incomplete" {
		t.Fatalf("irreversible low: %d %v", code, out)
	}
	code, srv = put(rev, map[string]any{"create_silence": map[string]any{"incident": "propose-auto", "auto": full, "coordinator": true, "tenants": []string{"shop"}},
		"query_metrics": map[string]any{"incident": "diagnose", "coordinator": true}})
	if cs := toolOf(srv, "create_silence"); code != 200 || cs["incident"] != "propose-auto" || fmt.Sprint(cs["tenants"]) != "[shop]" || cs["coordinator"] != true {
		t.Fatalf("propose-auto: %d %v", code, srv)
	}
	if code, _ := put(rev, map[string]any{}); code != 409 {
		t.Fatalf("stale: %d", code)
	}

	// Refresh: a new tool comes in off and marked new; a gone one leaves;
	// administrators are told.
	m.mu.Lock()
	m.tools = append(m.tools[:3], map[string]any{"name": "run_query_v2", "description": "새 질의", "annotations": map[string]any{"readOnlyHint": true}})
	m.tools = m.tools[1:] // query_metrics is gone
	m.mu.Unlock()
	code, srv = f.do("POST", "/api/v1/system/mcp/grafana/refresh", nil)
	if nt := toolOf(srv, "run_query_v2"); code != 200 || nt == nil || nt["new"] != true || nt["incident"] != "off" || nt["coordinator"] != false ||
		toolOf(srv, "query_metrics") != nil || srv["catalogRevision"] != float64(2) || toolOf(srv, "create_silence")["incident"] != "propose-auto" {
		t.Fatalf("refresh: %d %v", code, srv)
	}
	_, ns := f.do("GET", "/api/v1/notifications", nil)
	if s := fmt.Sprint(ns); !strings.Contains(s, "mcp-tools-changed") || !strings.Contains(s, "run_query_v2") {
		t.Fatalf("notice: %v", s)
	}

	// A failing server: the error is kept, the catalog stays.
	f.srv.opt.WebhookAllowAddr = func(netip.Addr) bool { return false }
	code, out = f.do("POST", "/api/v1/system/mcp/grafana/refresh", nil)
	row, _ = f.srv.opt.Store.GetMCPServer("grafana")
	if code != 422 || errCode(out) != "mcp-connect" || row.State != "error" || !strings.Contains(row.Error, "not allowed") || len(row.Tools) != 3 {
		t.Fatalf("failing: %d %v %+v", code, out, row)
	}
	f.srv.opt.WebhookAllowAddr = func(a netip.Addr) bool { return a.IsLoopback() }

	// Guidelines name servers their scope may use.
	_, srv = f.do("GET", "/api/v1/system/mcp", nil)
	rev = srv["servers"].([]any)[0].(map[string]any)["revision"]
	fakeLogin(t, f, "alice")
	if code, out := guidePut(f, "app/shop/php-shop", 0, "지침", map[string]any{"mcpServers": []string{"grafana"}}); code != 422 {
		t.Fatalf("not for shop yet: %d %v", code, out)
	}
	fakeLogin(t, f, "admin")
	if code, out := f.do("PUT", "/api/v1/system/mcp/grafana", map[string]any{"revision": rev, "users": map[string]any{"tenants": []string{"shop"}}}); code != 200 {
		t.Fatalf("users: %d %v", code, out)
	}
	// Dry run on a past incident: nothing is called.
	in := &store.Incident{ID: "inc-test1", Scope: "app", Tenant: "shop", App: "php-shop", Signal: "probe-failed", Title: "상태 검사 연속 실패", State: "closed",
		LastSignal: time.Now(), Timeline: []store.IncidentEntry{}}
	if err := f.srv.opt.Store.PutIncident(in); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	before := len(m.methods)
	m.mu.Unlock()
	code, res := f.do("POST", "/api/v1/system/mcp/grafana/tools/create_silence/test", map[string]any{"incident": "inc-test1"})
	if s := fmt.Sprint(res["steps"]); code != 200 || !strings.Contains(s, "duration 최대 60m") || !strings.Contains(s, "matchers php-shop") ||
		!strings.Contains(s, "comment MyDC 사건 inc-test1 자동 묵음") || res["result"] != "승인 요청을 만들었을 것 · 실제 호출 안 함" {
		t.Fatalf("test: %d %v", code, res)
	}
	m.mu.Lock()
	if len(m.methods) != before {
		t.Fatal("the dry run called the server")
	}
	m.mu.Unlock()

	fakeLogin(t, f, "alice")
	if code, out := guidePut(f, "app/shop/php-shop", 0, "지침", map[string]any{"mcpServers": []string{"grafana"}}); code != 200 {
		t.Fatalf("guide: %d %v", code, out)
	}
	_, g := f.do("GET", "/api/v1/guides/app/shop/php-shop", nil)
	if s := fmt.Sprint(g["choices"].(map[string]any)["mcpServers"]); !strings.Contains(s, "name:grafana") || !strings.Contains(s, "도구 3개 (읽기 1 · 바꾸기 2)") {
		t.Fatalf("choices: %v", s)
	}

	// Delete: confirm the name; guidelines drop it, the token is gone.
	fakeLogin(t, f, "admin")
	_, srv = f.do("GET", "/api/v1/system/mcp", nil)
	if s := srv["servers"].([]any)[0].(map[string]any); fmt.Sprint(s["usedBy"]) != "[app/shop/php-shop]" {
		t.Fatalf("usedBy: %v", s["usedBy"])
	}
	if code, _ := f.do("DELETE", "/api/v1/system/mcp/grafana", map[string]any{"confirmName": "x"}); code != 422 {
		t.Fatalf("confirm: %d", code)
	}
	if code, _ := f.do("DELETE", "/api/v1/system/mcp/grafana", map[string]any{"confirmName": "grafana"}); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if _, err := f.srv.opt.Seal.Get(mcpTokenKey("grafana")); err == nil {
		t.Fatal("token kept")
	}
	fakeLogin(t, f, "alice")
	_, g = f.do("GET", "/api/v1/guides/app/shop/php-shop", nil)
	if s := fmt.Sprint(g["fields"].(map[string]any)["mcpServers"]); s != "[]" {
		t.Fatalf("guide after delete: %v", s)
	}
}
