// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/web/ai"
	"github.com/jay94ks/mydcd/internal/web/seal"
)

const (
	testClaudeKey = "sk-ant-test-0123456789abcd"
	testOpenAIKey = "sk-openai-test-0123456789wxyz"
)

// aiVendors is a stand-in for the Claude and OpenAI APIs.
type aiVendors struct {
	srv          *httptest.Server
	claudeFails  bool // /v1/messages answers 500
	claudeCalls  int
	openaiCalls  int
	seenBadKeys  bool
	lastSystemOK bool
}

func newAIVendors(t *testing.T) *aiVendors {
	v := &aiVendors{}
	v.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-Api-Key")
		if key == "" {
			key = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}
		if key != testClaudeKey && key != testOpenAIKey {
			v.seenBadKeys = true
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/claude/v1/models":
			_, _ = io.WriteString(w, `{"data":[
				{"type":"model","id":"claude-opus-5-5","display_name":"Claude Opus 5.5","created_at":"2026-10-01T00:00:00Z"},
				{"type":"model","id":"claude-haiku-5-5","display_name":"Claude Haiku 5.5","created_at":"2026-09-01T00:00:00Z"}],"has_more":false}`)
		case "/claude/v1/messages":
			v.claudeCalls++
			if v.claudeFails {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = io.WriteString(w, `{"type":"error","error":{"type":"api_error","message":"overloaded"}}`)
				return
			}
			_, _ = io.WriteString(w, `{"id":"m","type":"message","role":"assistant","model":"claude-haiku-5-5","content":[{"type":"text","text":"요약"}],
				"stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":3000,"cache_creation_input_tokens":0}}`)
		case "/openai/models":
			_, _ = io.WriteString(w, `{"object":"list","data":[
				{"id":"gpt-6","object":"model","created":1790000000,"owned_by":"openai"},
				{"id":"gpt-6-mini","object":"model","created":1789000000,"owned_by":"openai"},
				{"id":"text-embedding-4","object":"model","created":1795000000,"owned_by":"openai"}]}`)
		case "/openai/responses":
			v.openaiCalls++
			_, _ = io.WriteString(w, `{"id":"r","object":"response","created_at":1,"status":"completed","model":"gpt-6-mini",
				"output":[{"type":"message","id":"o","role":"assistant","status":"completed","content":[{"type":"output_text","text":"summary","annotations":[]}]}],
				"usage":{"input_tokens":2000,"output_tokens":4,"total_tokens":2004,"input_tokens_details":{"cached_tokens":1024,"cache_write_tokens":0},"output_tokens_details":{"reasoning_tokens":0}}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(v.srv.Close)
	return v
}

func (v *aiVendors) endpoints() ai.Endpoints {
	return ai.Endpoints{ClaudeURL: v.srv.URL + "/claude/", OpenAIURL: v.srv.URL + "/openai/", Retries: -1}
}

func TestAISettings(t *testing.T) {
	f, _ := newFakeFixture(t)
	vendors := newAIVendors(t)
	var logs bytes.Buffer
	f.srv.log = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	f.srv.opt.AI = vendors.endpoints()
	fakeLogin(t, f, "alice")
	if code, out := f.do("GET", "/api/v1/system/ai", nil); code != 403 {
		t.Fatalf("manager: %d %v", code, out)
	}
	fakeLogin(t, f, "admin")
	code, v := f.do("GET", "/api/v1/system/ai", nil)
	roles := v["roles"].(map[string]any)
	if code != 200 || v["sealReady"] != false || roles["coordinator"].(map[string]any)["mainMissing"] != true || v["limits"].(map[string]any)["toolCallsPerConversation"] != 40.0 {
		t.Fatalf("defaults: %d %v", code, v)
	}
	if code, out := f.do("PUT", "/api/v1/system/ai/keys/claude", map[string]any{"key": testClaudeKey}); code != 503 || errCode(out) != "seal-unavailable" {
		t.Fatalf("no seal: %d %v", code, out)
	}
	sealDir := t.TempDir()
	box, err := seal.Open(sealDir, make([]byte, seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.opt.Seal = box

	// A key the vendor refuses is not kept.
	code, out := f.do("PUT", "/api/v1/system/ai/keys/claude", map[string]any{"key": "sk-ant-wrong-key-000000"})
	if code != 422 || errCode(out) != "key-rejected" || out["error"].(map[string]any)["detail"] != "auth" {
		t.Fatalf("bad key: %d %v", code, out)
	}
	if _, err := box.Get("ai-key-claude"); err == nil {
		t.Fatal("a refused key was sealed")
	}
	if code, out := f.do("PUT", "/api/v1/system/ai/keys/gemini", map[string]any{"key": testClaudeKey}); code != 404 {
		t.Fatalf("unknown provider: %d %v", code, out)
	}
	code, out = f.do("PUT", "/api/v1/system/ai/keys/claude", map[string]any{"key": testClaudeKey})
	if code != 200 || out["configured"] != true || out["last4"] != "abcd" || out["models"] != 2.0 || out["setBy"] != "admin" {
		t.Fatalf("claude key: %d %v", code, out)
	}
	code, out = f.do("PUT", "/api/v1/system/ai/keys/openai", map[string]any{"key": testOpenAIKey})
	if code != 200 || out["models"] != 2.0 || out["modelsTotal"] != 3.0 {
		t.Fatalf("openai key: %d %v", code, out)
	}
	if _, out := f.do("GET", "/api/v1/system/ai/models/openai", nil); len(out["items"].([]any)) != 2 {
		t.Fatalf("models: %v", out)
	}
	if _, out := f.do("GET", "/api/v1/system/ai/models/openai?all=1", nil); len(out["items"].([]any)) != 3 {
		t.Fatalf("all models: %v", out)
	}

	_, v = f.do("GET", "/api/v1/system/ai", nil)
	if v["roles"].(map[string]any)["coordinator"].(map[string]any)["mainMissing"] != false {
		t.Fatalf("coordinator after key: %v", v["roles"])
	}
	rev := v["revision"]
	role := func(main, fb map[string]any, effort string) map[string]any {
		return map[string]any{"main": main, "fallback": fb, "effort": effort, "thinking": "auto", "maxOutputTokens": 4000, "stream": false}
	}
	claudeHaiku := map[string]any{"provider": "claude", "model": "claude-haiku-5-5"}
	gptMini := map[string]any{"provider": "openai", "model": "gpt-6-mini"}
	limits := map[string]any{"dailyTokensPerUser": 0, "toolCallsPerConversation": 0, "tokensPerConversation": 1000000, "compaction": map[string]any{"enabled": false, "triggerTokens": 150000}}
	data := map[string]any{"maskSecretLikeEnv": true, "logTailLines": 200, "excludeTenants": []string{"payments"}}
	body := map[string]any{"revision": rev, "roles": map[string]any{"simple": role(claudeHaiku, gptMini, "low")}, "data": data, "limits": limits}
	if code, out := f.do("PUT", "/api/v1/system/ai/settings", body); code != 422 || errCode(out) != "unlimited-needs-compaction" {
		t.Fatalf("unlimited: %d %v", code, out)
	}
	limits["compaction"] = map[string]any{"enabled": true, "triggerTokens": 150000}
	body["roles"] = map[string]any{"simple": role(map[string]any{"provider": "openai", "model": "text-embedding-5"}, nil, "low")}
	if code, out := f.do("PUT", "/api/v1/system/ai/settings", body); code != 422 || errCode(out) != "model-not-in-catalog" {
		t.Fatalf("unknown model: %d %v", code, out)
	}
	body["roles"] = map[string]any{"simple": role(claudeHaiku, gptMini, "low")}
	body["revision"] = 99
	if code, out := f.do("PUT", "/api/v1/system/ai/settings", body); code != 409 || errCode(out) != "revision-changed" {
		t.Fatalf("stale revision: %d %v", code, out)
	}
	body["revision"] = rev
	code, v = f.do("PUT", "/api/v1/system/ai/settings", body)
	simple := v["roles"].(map[string]any)["simple"].(map[string]any)
	if code != 200 || simple["fallbackMissing"] != false || simple["sameProvider"] != false || v["data"].(map[string]any)["excludeTenants"].([]any)[0] != "payments" {
		t.Fatalf("settings: %d %v", code, v)
	}

	// Gateway: main answers with cache reads; when Claude fails, the
	// fallback answers and the audit says so.
	ctx := context.Background()
	call := aiCall{Role: roleSimple, User: "u-admin", Username: "admin"}
	res, err := f.srv.aiGenerate(ctx, call, ai.Request{System: "고정 지시", Messages: []ai.Message{{Role: "user", Text: "요약해"}}})
	if err != nil || res.Fallback || res.Text != "요약" || res.Model.Model != "claude-haiku-5-5" {
		t.Fatalf("main: %v %+v", err, res)
	}
	vendors.claudeFails = true
	res, err = f.srv.aiGenerate(ctx, call, ai.Request{System: "고정 지시", Messages: []ai.Message{{Role: "user", Text: "요약해"}}})
	if err != nil || !res.Fallback || res.Model.Provider != "openai" || res.Switched != "unavailable" {
		t.Fatalf("fallback: %v %+v", err, res)
	}
	code, u := f.do("GET", "/api/v1/system/ai/usage?days=1", nil)
	if hr := u["roles"].(map[string]any)["simple"].(map[string]any)["hitRate"].(float64); code != 200 || hr <= 0.5 || len(u["items"].([]any)) != 2 {
		t.Fatalf("usage: %d %v", code, u)
	}
	code, au := f.do("GET", "/api/v1/system/ai/audit?limit=2", nil)
	if code != 200 || au["total"].(float64) < 5 || len(au["items"].([]any)) != 2 || au["cursor"] == nil {
		t.Fatalf("audit: %d %v", code, au)
	}
	first := au["items"].([]any)[0].(map[string]any)
	if first["kind"] != "fallback" || first["provider"] != "openai" {
		t.Fatalf("newest audit row: %v", first)
	}
	if _, au2 := f.do("GET", "/api/v1/system/ai/audit?limit=2&cursor="+au["cursor"].(string), nil); au2["items"].([]any)[0].(map[string]any)["id"] == first["id"] {
		t.Fatalf("page 2 repeats: %v", au2)
	}

	// The keys are in the sealed files only: not in web.db, a response or a log.
	assertKeyNowhere := func(k string) {
		t.Helper()
		var db bytes.Buffer
		if _, err := f.store.Backup(func(int64) io.Writer { return &db }); err != nil {
			t.Fatal(err)
		}
		_, all := f.do("GET", "/api/v1/system/ai", nil)
		if bytes.Contains(db.Bytes(), []byte(k)) || strings.Contains(logs.String(), k) || strings.Contains(fmt.Sprint(all), k) {
			t.Fatalf("key %s leaked", k[:8])
		}
	}
	assertKeyNowhere(testClaudeKey)
	assertKeyNowhere(testOpenAIKey)
	entries, _ := os.ReadDir(sealDir)
	for _, e := range entries {
		raw, _ := os.ReadFile(filepath.Join(sealDir, e.Name()))
		if bytes.Contains(raw, []byte(testClaudeKey)) {
			t.Fatal("sealed file holds the plain key")
		}
	}

	if code, out := f.do("DELETE", "/api/v1/system/ai/audit", map[string]any{"before": time.Now().Add(time.Hour).Format(time.RFC3339)}); code != 200 || out["deleted"].(float64) < 5 {
		t.Fatalf("audit delete: %d %v", code, out)
	}
	if code, _ := f.do("DELETE", "/api/v1/system/ai/keys/claude", nil); code != 204 {
		t.Fatalf("delete key: %d", code)
	}
	_, v = f.do("GET", "/api/v1/system/ai", nil)
	if s := v["roles"].(map[string]any)["simple"].(map[string]any); s["mainMissing"] != true || s["fallbackMissing"] != false {
		t.Fatalf("after delete: %v", s)
	}
	if _, err := box.Get("ai-key-claude"); err == nil {
		t.Fatal("deleted key still sealed")
	}
}
