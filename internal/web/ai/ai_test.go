// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeVendors serves the Claude and OpenAI paths the adapters use and
// records the request bodies.
type fakeVendors struct {
	srv    *httptest.Server
	bodies map[string][]map[string]any
	status int
	keys   []string
}

func newFakeVendors(t *testing.T) *fakeVendors {
	f := &fakeVendors{bodies: map[string][]map[string]any{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if k := r.Header.Get("X-Api-Key"); k != "" {
			f.keys = append(f.keys, k)
		}
		if k := r.Header.Get("Authorization"); k != "" {
			f.keys = append(f.keys, strings.TrimPrefix(k, "Bearer "))
		}
		if f.status != 0 {
			w.WriteHeader(f.status)
			_, _ = io.WriteString(w, `{"type":"error","error":{"type":"authentication_error","message":"bad key"}}`)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		f.bodies[r.URL.Path] = append(f.bodies[r.URL.Path], body)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/claude/v1/models":
			_, _ = io.WriteString(w, `{"data":[
				{"type":"model","id":"claude-haiku-5-5","display_name":"Claude Haiku 5.5","created_at":"2026-09-01T00:00:00Z"},
				{"type":"model","id":"claude-opus-5-5","display_name":"Claude Opus 5.5","created_at":"2026-10-01T00:00:00Z"}],
				"has_more":false,"first_id":"a","last_id":"b"}`)
		case "/claude/v1/messages":
			stop := "end_turn"
			if strings.Contains(string(raw), "decline me") {
				stop = "refusal"
			}
			_, _ = io.WriteString(w, `{"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-5-5",
				"content":[{"type":"text","text":"안녕"}],"stop_reason":"`+stop+`",
				"usage":{"input_tokens":12,"output_tokens":3,"cache_read_input_tokens":4000,"cache_creation_input_tokens":0}}`)
		case "/openai/models":
			_, _ = io.WriteString(w, `{"object":"list","data":[
				{"id":"gpt-6","object":"model","created":1790000000,"owned_by":"openai"},
				{"id":"text-embedding-4","object":"model","created":1795000000,"owned_by":"openai"}]}`)
		case "/openai/responses":
			_, _ = io.WriteString(w, `{"id":"resp_1","object":"response","created_at":1,"status":"completed","model":"gpt-6",
				"output":[{"type":"message","id":"m1","role":"assistant","status":"completed",
				"content":[{"type":"output_text","text":"hello","annotations":[]}]}],
				"usage":{"input_tokens":5000,"output_tokens":7,"total_tokens":5007,
				"input_tokens_details":{"cached_tokens":4096,"cache_write_tokens":0},"output_tokens_details":{"reasoning_tokens":0}}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeVendors) ep() Endpoints {
	return Endpoints{ClaudeURL: f.srv.URL + "/claude/", OpenAIURL: f.srv.URL + "/openai/", Retries: -1}
}

func TestListModels(t *testing.T) {
	f := newFakeVendors(t)
	ctx := context.Background()
	ms, err := ListModels(ctx, f.ep(), Claude, "sk-ant-test", nil)
	if err != nil || len(ms) != 2 || ms[0].ID != "claude-opus-5-5" || ms[0].DisplayName != "Claude Opus 5.5" {
		t.Fatalf("claude: %v %+v", err, ms)
	}
	hide, err := HideRules(DefaultHidden)
	if err != nil {
		t.Fatal(err)
	}
	ms, err = ListModels(ctx, f.ep(), OpenAI, "sk-test", hide)
	if err != nil || len(ms) != 2 || ms[0].ID != "text-embedding-4" || !ms[0].Hidden || ms[1].Hidden {
		t.Fatalf("openai: %v %+v", err, ms)
	}
	f.status = http.StatusUnauthorized
	if _, err := ListModels(ctx, f.ep(), Claude, "bad", nil); !errors.Is(err, ErrAuth) {
		t.Fatalf("auth: %v", err)
	}
	f.status = http.StatusTooManyRequests
	if _, err := ListModels(ctx, f.ep(), OpenAI, "bad", nil); Class(err) != ErrRateLimited {
		t.Fatalf("rate: %v", err)
	}
	f.status = http.StatusBadGateway
	if _, err := ListModels(ctx, f.ep(), OpenAI, "bad", nil); Class(err) != ErrUnavailable {
		t.Fatalf("5xx: %v", err)
	}
}

// The fixed prefix is cached: Claude gets a 1-hour breakpoint on the
// system prompt and the automatic one; OpenAI gets prompt_cache_key and
// no stored response. Two calls send byte-identical prefixes.
func TestGeneratePromptCaching(t *testing.T) {
	f := newFakeVendors(t)
	ctx := context.Background()
	req := Request{Model: "claude-opus-5-5", System: "너는 Seafield Cluster 도우미다.", Messages: []Message{{Role: "user", Text: "안녕"}}, CacheKey: "sfc-simple-v1"}
	out, err := Generate(ctx, f.ep(), Claude, "sk-ant-test", req)
	if err != nil || out.Text != "안녕" || out.Usage.CacheRead != 4000 || out.Usage.Input != 12 {
		t.Fatalf("claude: %v %+v", err, out)
	}
	req.Messages = append(req.Messages, Message{Role: "assistant", Text: "안녕"}, Message{Role: "user", Text: "또"})
	if _, err := Generate(ctx, f.ep(), Claude, "sk-ant-test", req); err != nil {
		t.Fatal(err)
	}
	bs := f.bodies["/claude/v1/messages"]
	sys, _ := json.Marshal(bs[0]["system"])
	sys2, _ := json.Marshal(bs[1]["system"])
	if string(sys) != string(sys2) || !strings.Contains(string(sys), `"ttl":"1h"`) || bs[0]["cache_control"] == nil {
		t.Fatalf("claude cache: %s / %v", sys, bs[0]["cache_control"])
	}
	if oc, _ := bs[0]["output_config"].(map[string]any); oc["effort"] != "medium" {
		t.Fatalf("effort: %v", bs[0]["output_config"])
	}

	req.Model = "gpt-6"
	out, err = Generate(ctx, f.ep(), OpenAI, "sk-test", req)
	if err != nil || out.Text != "hello" || out.Usage.CacheRead != 4096 || out.Usage.Input != 904 {
		t.Fatalf("openai: %v %+v", err, out)
	}
	ob := f.bodies["/openai/responses"][0]
	if ob["prompt_cache_key"] != "sfc-simple-v1" || ob["store"] != false || ob["instructions"] != req.System {
		t.Fatalf("openai body: %v", ob)
	}

	req.Model, req.Messages = "claude-opus-5-5", []Message{{Role: "user", Text: "decline me"}}
	if _, err := Generate(ctx, f.ep(), Claude, "sk-ant-test", req); !errors.Is(err, ErrRefused) {
		t.Fatalf("refusal: %v", err)
	}
	for _, k := range f.keys {
		if k != "sk-ant-test" && k != "sk-test" && k != "bad" {
			t.Fatalf("unexpected key sent: %q", k)
		}
	}
}
