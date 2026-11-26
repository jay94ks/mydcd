// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/jay94ks/mydcd/internal/web/ai"
	"github.com/jay94ks/mydcd/internal/web/seal"
)

// scriptVendor answers model calls from a queue and keeps the requests.
type scriptVendor struct {
	srv    *httptest.Server
	mu     sync.Mutex
	claude []string // response bodies; "stream:<text>" streams a text answer
	openai []string
	reqs   []map[string]any
	raws   []string
}

func newScriptVendor(t *testing.T) *scriptVendor {
	v := &scriptVendor{}
	v.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/claude/v1/models":
			_, _ = io.WriteString(w, `{"data":[{"type":"model","id":"claude-opus-5-5","display_name":"Claude Opus 5.5","created_at":"2026-10-01T00:00:00Z"}],"has_more":false}`)
			return
		case "/openai/models":
			_, _ = io.WriteString(w, `{"object":"list","data":[{"id":"gpt-6","object":"model","created":1790000000,"owned_by":"openai"}]}`)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		var req map[string]any
		_ = json.Unmarshal(raw, &req)
		v.mu.Lock()
		v.reqs, v.raws = append(v.reqs, req), append(v.raws, string(raw))
		var next string
		q := &v.claude
		if r.URL.Path == "/openai/responses" {
			q = &v.openai
		}
		if len(*q) == 0 {
			v.mu.Unlock()
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `{"type":"error","error":{"type":"api_error","message":"script ended"}}`)
			return
		}
		next, *q = (*q)[0], (*q)[1:]
		v.mu.Unlock()
		if text, ok := strings.CutPrefix(next, "stream:"); ok {
			w.Header().Set("Content-Type", "text/event-stream")
			ev := func(name, data string) { fmt.Fprintf(w, "event: %s\ndata: %s\n\n", name, data) }
			ev("message_start", `{"type":"message_start","message":{"id":"ms","type":"message","role":"assistant","model":"claude-opus-5-5","content":[],"stop_reason":null,"usage":{"input_tokens":7,"output_tokens":0,"cache_read_input_tokens":4000}}}`)
			ev("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`)
			for _, part := range strings.SplitAfter(text, " ") {
				b, _ := json.Marshal(part)
				ev("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":`+string(b)+`}}`)
			}
			ev("content_block_stop", `{"type":"content_block_stop","index":0}`)
			ev("message_delta", `{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":3}}`)
			ev("message_stop", `{"type":"message_stop"}`)
			return
		}
		_, _ = io.WriteString(w, next)
	}))
	t.Cleanup(v.srv.Close)
	return v
}

func (v *scriptVendor) endpoints() ai.Endpoints {
	return ai.Endpoints{ClaudeURL: v.srv.URL + "/claude/", OpenAIURL: v.srv.URL + "/openai/", Retries: -1}
}

func claudeMsg(stop string, content ...string) string {
	return `{"id":"m","type":"message","role":"assistant","model":"claude-opus-5-5","content":[` + strings.Join(content, ",") +
		`],"stop_reason":"` + stop + `","usage":{"input_tokens":20,"output_tokens":10,"cache_read_input_tokens":5000,"cache_creation_input_tokens":0}}`
}

type sseEvent struct {
	name string
	data map[string]any
}

func (f *fixture) sse(path string, body any) (int, []sseEvent) {
	f.t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", f.http.URL+path, bytes.NewReader(raw))
	req.Header.Set("X-MyDC-Web", "1")
	resp, err := f.hc.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out []sseEvent
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	var name string
	for sc.Scan() {
		line := sc.Text()
		if n, ok := strings.CutPrefix(line, "event: "); ok {
			name = n
		} else if d, ok := strings.CutPrefix(line, "data: "); ok {
			var m map[string]any
			_ = json.Unmarshal([]byte(d), &m)
			out = append(out, sseEvent{name, m})
		}
	}
	return resp.StatusCode, out
}

func eventsNamed(evs []sseEvent, name string) []map[string]any {
	var out []map[string]any
	for _, e := range evs {
		if e.name == name {
			out = append(out, e.data)
		}
	}
	return out
}

// aiCoordinatorFixture logs in admin with both keys set and the
// coordinator on Claude (main) and OpenAI (fallback).
func aiCoordinatorFixture(t *testing.T, stream bool) (*fixture, *scriptVendor) {
	f, _ := newFakeFixture(t)
	v := newScriptVendor(t)
	f.srv.opt.AI = v.endpoints()
	box, err := seal.Open(t.TempDir(), make([]byte, seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	f.srv.opt.Seal = box
	fakeLogin(t, f, "admin")
	for p, k := range map[string]string{"claude": testClaudeKey, "openai": testOpenAIKey} {
		if code, out := f.do("PUT", "/api/v1/system/ai/keys/"+p, map[string]any{"key": k}); code != 200 {
			t.Fatalf("key %s: %d %v", p, code, out)
		}
	}
	_, cur := f.do("GET", "/api/v1/system/ai", nil)
	role := map[string]any{"main": map[string]any{"provider": "claude", "model": "claude-opus-5-5"}, "fallback": map[string]any{"provider": "openai", "model": "gpt-6"},
		"effort": "high", "thinking": "auto", "maxOutputTokens": 8000, "stream": stream}
	body := map[string]any{"revision": cur["revision"], "roles": map[string]any{"coordinator": role},
		"data":   map[string]any{"maskSecretLikeEnv": true, "logTailLines": 200, "excludeTenants": []string{}},
		"limits": map[string]any{"dailyTokensPerUser": 0, "toolCallsPerConversation": 10, "tokensPerConversation": 0, "compaction": map[string]any{"enabled": true, "triggerTokens": 150000}}}
	if code, out := f.do("PUT", "/api/v1/system/ai/settings", body); code != 200 {
		t.Fatalf("settings: %d %v", code, out)
	}
	return f, v
}

func TestAICoordinatorClaude(t *testing.T) {
	f, v := aiCoordinatorFixture(t, false)
	op := opSeq("a1c00001")
	if code, out := f.do("POST", "/api/v1/ai/conversations", map[string]any{"chips": []map[string]string{{"kind": "Bad Kind"}}}); code != 422 {
		t.Fatalf("bad chip: %d %v", code, out)
	}
	code, conv := f.do("POST", "/api/v1/ai/conversations", map[string]any{"chips": []map[string]string{{"kind": "incident", "id": "inc-0412"}}})
	if code != 201 || conv["title"] != "새 대화" || len(conv["chips"].([]any)) != 1 {
		t.Fatalf("create: %d %v", code, conv)
	}
	id := conv["id"].(string)
	v.claude = []string{
		claudeMsg("tool_use",
			`{"type":"server_tool_use","id":"srv1","name":"tool_search_tool_bm25","input":{"query":"servers"}}`,
			`{"type":"tool_search_tool_result","tool_use_id":"srv1","content":{"type":"tool_search_tool_search_result","tool_references":[{"type":"tool_reference","tool_name":"nodes_list"},{"type":"tool_reference","tool_name":"node_cordon"}]}}`,
			`{"type":"text","text":"서버 목록을 볼게요. "}`,
			`{"type":"tool_use","id":"tu1","name":"nodes_list","input":{}}`),
		claudeMsg("tool_use",
			`{"type":"tool_use","id":"tu2","name":"node_cordon","input":{"node":"node-a","reason":"디스크 경보","api_token":"x"}}`,
			`{"type":"tool_use","id":"tu3","name":"node_cordon","input":{"node":"node-a","reason":"디스크 경보"}}`),
		claudeMsg("end_turn", `{"type":"text","text":"node-a에 새 배치를 막는 제안을 만들었어요."}`),
	}
	code, evs := f.sse("/api/v1/ai/conversations/"+id+"/messages", map[string]any{"text": "node-a 디스크가 가득 찼어", "context": map[string]any{"screen": "서버", "path": "/nodes/node-a", "selection": map[string]any{"incident": "inc-1"}}, "chips": []map[string]string{{"kind": "app", "tenant": "shop", "app": "php-shop"}}})
	if code != 200 {
		t.Fatalf("messages: %d %v", code, evs)
	}
	tools := eventsNamed(evs, "tool")
	if len(tools) != 3 || tools[0]["kind"] != "find" || tools[1]["name"] != "nodes_list" || tools[1]["kind"] != "read" || tools[2]["kind"] != "propose" {
		t.Fatalf("tool lines: %v", tools)
	}
	props := eventsNamed(evs, "proposal")
	if len(props) != 1 || props[0]["target"] != "node/node-a" || props[0]["state"] != "pending" || props[0]["impact"] != "low" {
		t.Fatalf("proposal: %v", props)
	}
	if args := tools[2]["args"].(map[string]any); args["node"] != "node-a" || args["reason"] != "디스크 경보" {
		t.Fatalf("args: %v", args)
	}
	done := eventsNamed(evs, "done")
	if len(done) != 1 || len(eventsNamed(evs, "error")) != 0 || done[0]["usage"].(map[string]any)["cacheReadTokens"] != 15000.0 {
		t.Fatalf("done: %v", evs)
	}

	// The requests: tool search plus deferred catalog, a 1-hour cached
	// system prompt, the same prefix on every step, results returned.
	if len(v.reqs) != 3 {
		t.Fatalf("calls: %d", len(v.reqs))
	}
	first := v.reqs[0]
	ts := first["tools"].([]any)
	if ts[0].(map[string]any)["type"] != "tool_search_tool_bm25_20251119" {
		t.Fatalf("first tool: %v", ts[0])
	}
	deferred, core := 0, 0
	for _, x := range ts[1:] {
		if x.(map[string]any)["defer_loading"] == true {
			deferred++
		} else {
			core++
		}
	}
	if core != 4 || deferred != len(aiCatalog)-4 {
		t.Fatalf("core %d deferred %d", core, deferred)
	}
	sys := first["system"].([]any)[0].(map[string]any)
	if sys["cache_control"].(map[string]any)["ttl"] != "1h" || strings.Contains(sys["text"].(string), "admin") {
		t.Fatalf("system: %v", sys)
	}
	prefix := func(raw string) string {
		var m map[string]json.RawMessage
		_ = json.Unmarshal([]byte(raw), &m)
		return string(m["tools"]) + string(m["system"])
	}
	if prefix(v.raws[0]) != prefix(v.raws[1]) || prefix(v.raws[1]) != prefix(v.raws[2]) {
		t.Fatal("the cached prefix moved between steps")
	}
	if !strings.Contains(v.raws[1], `"tool_use_id":"tu1"`) || !strings.Contains(v.raws[1], "node-a") || !strings.Contains(v.raws[0], `\u003ccontext\u003e`) {
		t.Fatalf("second request lacks the tool result or context: %s", v.raws[1])
	}
	if !strings.Contains(v.raws[0], `selection: {\"incident\":\"inc-1\"}`) {
		t.Fatalf("selection: %s", v.raws[0])
	}
	if !strings.Contains(v.raws[0], `attached: {\"app\":\"php-shop\",\"kind\":\"app\",\"tenant\":\"shop\"}`) {
		t.Fatalf("chips not sent: %s", v.raws[0])
	}
	// tu2 had an argument outside the schema: an error result, no proposal.
	if !strings.Contains(v.raws[2], `unknown argument \"api_token\"`) {
		t.Fatalf("schema check: %s", v.raws[2])
	}

	// Stored: the visible text and lines, never tool results.
	code, c := f.do("GET", "/api/v1/ai/conversations/"+id, nil)
	msgs := c["messages"].([]any)
	if code != 200 || len(msgs) != 2 || c["title"] != "node-a 디스크가 가득 찼어" || c["chips"].([]any)[0].(map[string]any)["kind"] != "app" || msgs[0].(map[string]any)["chips"] == nil {
		t.Fatalf("conversation: %d %v", code, c)
	}
	am := msgs[1].(map[string]any)
	if am["role"] != "assistant" || am["model"] != "Claude Opus 5.5" || !strings.Contains(am["text"].(string), "제안을 만들었어요") || len(am["tools"].([]any)) != 3 || len(am["proposals"].([]any)) != 1 {
		t.Fatalf("assistant message: %v", am)
	}
	raw, _ := json.Marshal(c)
	if strings.Contains(string(raw), "voter") || strings.Contains(string(raw), "tool_result") {
		t.Fatalf("tool results were stored: %s", raw)
	}
	if code, _ := f.do("PATCH", "/api/v1/ai/conversations/"+id, map[string]any{"chips": nil}); code != 204 {
		t.Fatalf("chips off: %d", code)
	}
	if _, c := f.do("GET", "/api/v1/ai/conversations/"+id, nil); len(c["chips"].([]any)) != 0 || c["title"] != "node-a 디스크가 가득 찼어" {
		t.Fatalf("after chips off: %v", c)
	}
	_, list := f.do("GET", "/api/v1/ai/conversations", nil)
	if items := list["items"].([]any); len(items) != 1 || items[0].(map[string]any)["pendingProposals"] != 1.0 {
		t.Fatalf("list: %v", list)
	}

	// Approve: the basis must match, then the route runs on admin's session.
	pid := props[0]["id"].(string)
	if code, out := f.do("POST", "/api/v1/ai/proposals/"+pid+"/approve", map[string]any{"opId": op(), "basisHash": "00"}); code != 409 || errCode(out) != "proposal-changed" {
		t.Fatalf("stale basis: %d %v", code, out)
	}
	_, p := f.do("GET", "/api/v1/ai/proposals/"+pid, nil)
	opID := op()
	code, out := f.do("POST", "/api/v1/ai/proposals/"+pid+"/approve", map[string]any{"opId": opID, "basisHash": p["basisHash"]})
	if opState(t, code, out) != "applied" {
		t.Fatalf("approve: %d %v", code, out)
	}
	if _, o := f.do("GET", "/api/v1/ops/"+opID, nil); o["op"].(map[string]any)["action"] != "cordon-node" {
		t.Fatalf("op: %v", o)
	}
	if code, out := f.do("POST", "/api/v1/ai/proposals/"+pid+"/approve", map[string]any{"opId": opID, "basisHash": p["basisHash"]}); opState(t, code, out) != "applied" {
		t.Fatalf("repeat approve: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/ai/proposals/"+pid+"/reject", map[string]any{"reason": "x"}); code != 409 || errCode(out) != "proposal-approved" {
		t.Fatalf("reject approved: %d %v", code, out)
	}
	if _, p := f.do("GET", "/api/v1/ai/proposals/"+pid, nil); p["state"] != "approved" || p["op"] != opID || p["decidedBy"] != "admin" {
		t.Fatalf("approved proposal: %v", p)
	}

	// The next turn tells the model, then streams nothing more (stop flow).
	v.claude = []string{claudeMsg("end_turn", `{"type":"text","text":"적용됐어요."}`)}
	if code, evs := f.sse("/api/v1/ai/conversations/"+id+"/messages", map[string]any{"text": "됐어?"}); code != 200 || len(eventsNamed(evs, "done")) != 1 {
		t.Fatalf("turn 2: %d %v", code, evs)
	}
	last := v.raws[len(v.raws)-1]
	if !strings.Contains(last, "approved by the person") || !strings.Contains(last, `"tool_use_id":"tu1"`) {
		t.Fatalf("turn 2 request lacks the decision or the warm transcript: %s", last)
	}

	// Audit and export.
	_, au := f.do("GET", "/api/v1/system/ai/audit?limit=50", nil)
	found := false
	for _, it := range au["items"].([]any) {
		if it.(map[string]any)["kind"] == "proposal-approved" {
			found = true
		}
	}
	if !found {
		t.Fatalf("audit: %v", au)
	}
	req, _ := http.NewRequest("GET", f.http.URL+"/api/v1/ai/conversations/"+id+"/export?format=md", nil)
	resp, err := f.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	md, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(md), "# node-a 디스크가 가득 찼어") || !strings.Contains(string(md), "제안 작업 "+pid) {
		t.Fatalf("export: %s", md)
	}

	// Another person cannot see it; deleting takes the proposals along.
	fakeLogin(t, f, "alice")
	if code, _ := f.do("GET", "/api/v1/ai/conversations/"+id, nil); code != 404 {
		t.Fatalf("other user: %d", code)
	}
	if code, _ := f.do("GET", "/api/v1/ai/proposals/"+pid, nil); code != 404 {
		t.Fatalf("other user proposal: %d", code)
	}
	fakeLogin(t, f, "admin")
	if code, _ := f.do("DELETE", "/api/v1/ai/conversations/"+id, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if code, _ := f.do("GET", "/api/v1/ai/proposals/"+pid, nil); code != 404 {
		t.Fatalf("proposal after delete: %d", code)
	}
}

func TestAICoordinatorEditRejectAndFallback(t *testing.T) {
	f, v := aiCoordinatorFixture(t, false)
	op := opSeq("a1c00002")
	_, conv := f.do("POST", "/api/v1/ai/conversations", map[string]any{"title": "점검"})
	id := conv["id"].(string)
	// Claude fails at once: the turn moves to OpenAI, which finds a tool,
	// proposes through call_tool, then answers.
	v.claude = nil
	v.openai = []string{
		`{"id":"r1","object":"response","created_at":1,"status":"completed","model":"gpt-6","output":[
			{"type":"function_call","id":"fc1","call_id":"c1","name":"find_tools","arguments":"{\"query\":\"cordon server\"}","status":"completed"}],
			"usage":{"input_tokens":3000,"output_tokens":5,"total_tokens":3005,"input_tokens_details":{"cached_tokens":2048,"cache_write_tokens":0},"output_tokens_details":{"reasoning_tokens":0}}}`,
		`{"id":"r2","object":"response","created_at":1,"status":"completed","model":"gpt-6","output":[
			{"type":"function_call","id":"fc2","call_id":"c2","name":"call_tool","arguments":"{\"name\":\"node_cordon\",\"args\":{\"node\":\"node-b\"}}","status":"completed"}],
			"usage":{"input_tokens":3100,"output_tokens":5,"total_tokens":3105,"input_tokens_details":{"cached_tokens":2048,"cache_write_tokens":0},"output_tokens_details":{"reasoning_tokens":0}}}`,
		`{"id":"r3","object":"response","created_at":1,"status":"completed","model":"gpt-6","output":[
			{"type":"message","id":"o","role":"assistant","status":"completed","content":[{"type":"output_text","text":"제안했어요","annotations":[]}]}],
			"usage":{"input_tokens":3200,"output_tokens":4,"total_tokens":3204,"input_tokens_details":{"cached_tokens":2048,"cache_write_tokens":0},"output_tokens_details":{"reasoning_tokens":0}}}`,
	}
	code, evs := f.sse("/api/v1/ai/conversations/"+id+"/messages", map[string]any{"text": "node-b 막아줘"})
	if code != 200 || len(eventsNamed(evs, "error")) != 0 {
		t.Fatalf("fallback turn: %d %v", code, evs)
	}
	tools := eventsNamed(evs, "tool")
	if len(tools) != 2 || tools[0]["kind"] != "find" || !strings.Contains(tools[0]["summary"].(string), "node_cordon") || tools[1]["kind"] != "propose" {
		t.Fatalf("tools: %v", tools)
	}
	or := v.reqs[len(v.reqs)-1]
	if or["prompt_cache_key"] != "mydc-coordinator-v1" || or["store"] != false || len(or["tools"].([]any)) != 3 {
		t.Fatalf("openai request: %v", or)
	}
	if !strings.Contains(v.raws[len(v.raws)-2], `"call_id":"c1"`) {
		t.Fatalf("find_tools output not sent back: %s", v.raws[len(v.raws)-2])
	}
	_, c := f.do("GET", "/api/v1/ai/conversations/"+id, nil)
	if am := c["messages"].([]any)[1].(map[string]any); am["fallback"] != true || am["model"] != "gpt-6" {
		t.Fatalf("fallback message: %v", am)
	}
	pid := eventsNamed(evs, "proposal")[0]["id"].(string)

	// Edit in the card: arguments checked again, target fixed.
	if code, out := f.do("PUT", "/api/v1/ai/proposals/"+pid, map[string]any{"payload": map[string]any{"node": "node-a"}}); code != 422 || errCode(out) != "target-changed" {
		t.Fatalf("retarget: %d %v", code, out)
	}
	if code, out := f.do("PUT", "/api/v1/ai/proposals/"+pid, map[string]any{"payload": map[string]any{"node": "node-b", "reason": 3}}); code != 422 {
		t.Fatalf("bad type: %d %v", code, out)
	}
	_, before := f.do("GET", "/api/v1/ai/proposals/"+pid, nil)
	code, ed := f.do("PUT", "/api/v1/ai/proposals/"+pid, map[string]any{"payload": map[string]any{"node": "node-b", "reason": "점검"}})
	if code != 200 || ed["edited"] != true || ed["basisHash"] == before["basisHash"] {
		t.Fatalf("edit: %d %v", code, ed)
	}
	if code, out := f.do("POST", "/api/v1/ai/proposals/"+pid+"/reject", map[string]any{"reason": "지금은 안 돼"}); code != 204 {
		t.Fatalf("reject: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/ai/proposals/"+pid+"/approve", map[string]any{"opId": op(), "basisHash": ed["basisHash"]}); code != 409 || errCode(out) != "proposal-rejected" {
		t.Fatalf("approve rejected: %d %v", code, out)
	}
	// The conversation stays on the fallback; the model hears both.
	v.openai = []string{`{"id":"r4","object":"response","created_at":1,"status":"completed","model":"gpt-6","output":[
		{"type":"message","id":"o","role":"assistant","status":"completed","content":[{"type":"output_text","text":"알겠어요","annotations":[]}]}],
		"usage":{"input_tokens":10,"output_tokens":2,"total_tokens":12,"input_tokens_details":{"cached_tokens":0,"cache_write_tokens":0},"output_tokens_details":{"reasoning_tokens":0}}}`}
	n := len(v.reqs)
	if code, evs := f.sse("/api/v1/ai/conversations/"+id+"/messages", map[string]any{"text": "그럼 내일 해"}); code != 200 || len(eventsNamed(evs, "done")) != 1 {
		t.Fatalf("turn 2: %d %v", code, evs)
	}
	if len(v.reqs) != n+1 || !strings.Contains(v.raws[n], "edited by the person") || !strings.Contains(v.raws[n], "지금은 안 돼") {
		t.Fatalf("turn 2 request: %s", v.raws[n])
	}
}

func TestAICoordinatorStreamAndLimits(t *testing.T) {
	f, v := aiCoordinatorFixture(t, true)
	_, conv := f.do("POST", "/api/v1/ai/conversations", map[string]any{})
	id := conv["id"].(string)
	v.claude = []string{"stream:안녕하세요 무엇을 도와드릴까요"}
	code, evs := f.sse("/api/v1/ai/conversations/"+id+"/messages", map[string]any{"text": "안녕"})
	deltas := eventsNamed(evs, "delta")
	if code != 200 || len(deltas) != 3 || deltas[0]["text"] != "안녕하세요 " {
		t.Fatalf("stream: %d %v", code, evs)
	}
	if v.reqs[0]["stream"] != true {
		t.Fatalf("not streamed: %v", v.reqs[0])
	}
	if code, out := f.do("POST", "/api/v1/ai/conversations/"+id+"/messages", map[string]any{"text": ""}); code != 422 {
		t.Fatalf("empty: %d %v", code, out)
	}
	if code, _ := f.do("POST", "/api/v1/ai/conversations/c-nope/messages", map[string]any{"text": "x"}); code != 404 {
		t.Fatalf("missing: %d", code)
	}
	// Every provider failing is an error event, and the question stays.
	v.claude = nil
	code, evs = f.sse("/api/v1/ai/conversations/"+id+"/messages", map[string]any{"text": "다시"})
	if e := eventsNamed(evs, "error"); code != 200 || len(e) != 1 || e[0]["code"] != "ai-unavailable" {
		t.Fatalf("failure: %d %v", code, evs)
	}
	_, c := f.do("GET", "/api/v1/ai/conversations/"+id, nil)
	if msgs := c["messages"].([]any); len(msgs) != 3 || msgs[2].(map[string]any)["text"] != "다시" {
		t.Fatalf("after failure: %v", msgs)
	}
	if code, _ := f.do("DELETE", "/api/v1/ai/conversations", nil); code != 204 {
		t.Fatalf("delete all: %d", code)
	}
	if _, l := f.do("GET", "/api/v1/ai/conversations", nil); len(l["items"].([]any)) != 0 {
		t.Fatalf("after delete all: %v", l)
	}
}

func TestAIMasking(t *testing.T) {
	src := `{"yaml":"services:\n  web:\n    env:\n      DB_PASSWORD: hunter22\n      MODE: prod\n    command: run --pass hunter22\n","password":"p4ssw0rd","keys":["a","b"],"note":"p4ssw0rd again"}`
	out := maskResult([]byte(src), true, nil)
	if strings.Contains(out, "hunter22") || strings.Contains(out, "p4ssw0rd") || !strings.Contains(out, "«가림: DB_PASSWORD»") || !strings.Contains(out, "MODE: prod") || !strings.Contains(out, `"keys":["a","b"]`) {
		t.Fatalf("mask: %s", out)
	}
	ex := newAIExcluder([]string{"payments"})
	ev := maskResult([]byte(`{"items":[{"tenant":"payments","text":"x"},{"tenant":"shop","text":"payments app down, payments-net ok"}],"rows":[{"id":"payments"},{"id":"shop"}]}`), true, ex)
	if strings.Contains(ev, "payments") || !strings.Contains(ev, aiExcludedName+"-net") || strings.Count(ev, "shop") != 2 {
		t.Fatalf("exclude: %s", ev)
	}
	args := maskArgs(map[string]any{"token": "abc", "node": "node-a", "long": strings.Repeat("가", 300)})
	if args["token"] != aiMasked || args["node"] != "node-a" || len([]rune(args["long"])) != aiArgMax+1 {
		t.Fatalf("args: %v", args)
	}
	d, _ := aiToolByName("app_source")
	if _, err := d.check(json.RawMessage(`{"t":"../x","app":"a"}`)); err == nil {
		t.Fatal("path traversal accepted")
	}
	a, err := d.check(json.RawMessage(`{"t":"shop","app":"php-shop","version":3}`))
	if err != nil || a.path != "/api/v1/t/shop/apps/php-shop/source" || a.query.Get("version") != "3" {
		t.Fatalf("check: %v %+v", err, a)
	}
}

// Excluded workspaces reach the vendor nowhere: not by path, not by a
// tenant query, not inside multi-workspace results, not in the question.
func TestAICoordinatorExcludedTenant(t *testing.T) {
	f, v := aiCoordinatorFixture(t, false)
	_, cur := f.do("GET", "/api/v1/system/ai", nil)
	data := cur["data"].(map[string]any)
	data["excludeTenants"] = []string{"payments"}
	if code, out := f.do("PUT", "/api/v1/system/ai/settings", map[string]any{"revision": cur["revision"], "data": data, "limits": cur["limits"]}); code != 200 {
		t.Fatalf("settings: %d %v", code, out)
	}
	// The workspace list does name it.
	if _, ts := f.do("GET", "/api/v1/tenants", nil); !strings.Contains(fmt.Sprint(ts), "payments") {
		t.Fatalf("fixture: %v", ts)
	}
	_, conv := f.do("POST", "/api/v1/ai/conversations", map[string]any{"chips": []map[string]string{{"kind": "app", "tenant": "payments", "app": "pay"}}})
	id := conv["id"].(string)
	use := func(id, name, input string) string {
		return `{"type":"tool_use","id":"` + id + `","name":"` + name + `","input":` + input + `}`
	}
	v.claude = []string{
		claudeMsg("tool_use", use("a", "tenants_list", `{}`), use("b", "events_list", `{}`), use("c", "node_tasks", `{"node":"node-a"}`),
			use("d", "dashboard_get", `{}`), use("e", "nodes_summary", `{"tenant":"payments"}`), use("g", "apps_list", `{"t":"payments"}`)),
		claudeMsg("end_turn", `{"type":"text","text":"끝"}`),
	}
	code, evs := f.sse("/api/v1/ai/conversations/"+id+"/messages", map[string]any{"text": "payments 작업 공간 앱 상태 알려 줘",
		"context": map[string]any{"screen": "앱", "path": "/t/payments/apps/pay", "selection": "payments/pay"}})
	if code != 200 || len(eventsNamed(evs, "done")) != 1 {
		t.Fatalf("turn: %d %v", code, evs)
	}
	for i, raw := range v.raws {
		// The scripted model's own calls name it; nothing else may.
		raw = strings.NewReplacer(`"tenant":"payments"`, "", `"t":"payments"`, "").Replace(raw)
		if strings.Contains(raw, "payments") {
			at := strings.Index(raw, "payments")
			t.Fatalf("request %d names the excluded workspace: …%s…", i, raw[max(0, at-200):min(len(raw), at+100)])
		}
		// Nor what is inside it: the app from the chip, path and selection.
		if strings.Contains(raw, "/pay") || strings.Contains(raw, `\"pay\"`) {
			t.Fatalf("request %d names an app of the excluded workspace: %s", i, raw)
		}
	}
	if !strings.Contains(v.raws[1], aiExcludedText) || !strings.Contains(v.raws[1], `\"id\":\"shop\"`) {
		t.Fatalf("results: %s", v.raws[1])
	}
}
