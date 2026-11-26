// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var testTools = []Tool{
	{Name: "nodes_list", Description: "List cluster servers", Schema: map[string]any{"type": "object", "properties": map[string]any{}}, Core: true},
	{Name: "node_cordon", Description: "Stop new placements on a server", Schema: map[string]any{"type": "object", "properties": map[string]any{"node": map[string]any{"type": "string"}}}},
}

func TestFindTools(t *testing.T) {
	got := FindTools(testTools, "cordon server", 8)
	if len(got) != 2 || got[0].Name != "node_cordon" {
		t.Fatalf("find: %+v", got)
	}
	if len(FindTools(testTools, "volume", 8)) != 0 {
		t.Fatal("unrelated match")
	}
}

// The OpenAI stream: describe_tool is answered here, call_tool comes back
// as a call, deltas arrive as they stream.
func TestChatOpenAIStream(t *testing.T) {
	var bodies []map[string]any
	step := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var b map[string]any
		_ = json.Unmarshal(raw, &b)
		bodies = append(bodies, b)
		w.Header().Set("Content-Type", "text/event-stream")
		usage := `"usage":{"input_tokens":100,"output_tokens":5,"total_tokens":105,"input_tokens_details":{"cached_tokens":64,"cache_write_tokens":0},"output_tokens_details":{"reasoning_tokens":0}}`
		var output string
		switch step {
		case 0:
			output = `[{"type":"function_call","id":"f1","call_id":"c1","name":"describe_tool","arguments":"{\"name\":\"node_cordon\"}","status":"completed"}]`
		case 1:
			fmt.Fprint(w, "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"막을게요\",\"sequence_number\":1,\"item_id\":\"o\",\"output_index\":0,\"content_index\":0}\n\n")
			output = `[{"type":"message","id":"o","role":"assistant","status":"completed","content":[{"type":"output_text","text":"막을게요","annotations":[]}]},
				{"type":"function_call","id":"f2","call_id":"c2","name":"call_tool","arguments":"{\"name\":\"node_cordon\",\"args\":{\"node\":\"node-a\"}}","status":"completed"}]`
		default:
			output = `[{"type":"message","id":"o2","role":"assistant","status":"completed","content":[{"type":"output_text","text":"끝","annotations":[]}]}]`
		}
		step++
		resp := `{"id":"r","object":"response","created_at":1,"status":"completed","model":"gpt-6","output":` + output + `,` + usage + `}`
		fmt.Fprintf(w, "event: response.completed\ndata: {\"type\":\"response.completed\",\"sequence_number\":2,\"response\":%s}\n\n", strings.Join(strings.Fields(resp), " "))
	}))
	defer srv.Close()
	ep := Endpoints{OpenAIURL: srv.URL + "/", Retries: -1}
	c := NewChat(OpenAI, "gpt-6", []Message{{Role: "user", Text: "전에 물었어"}, {Role: "assistant", Text: "네"}})
	c.User("node-a 막아", "<context>now</context>")
	req := ChatRequest{System: "fixed", Tools: testTools, CacheKey: "mydc-coordinator-v1", Stream: true}
	var deltas []string
	st, err := c.Next(context.Background(), ep, "k", req, func(d string) { deltas = append(deltas, d) })
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Calls) != 1 || st.Calls[0].Name != "node_cordon" || string(st.Calls[0].Input) != `{"node":"node-a"}` || st.Text != "막을게요" || len(deltas) != 1 || !c.Open() {
		t.Fatalf("step: %+v deltas %v", st, deltas)
	}
	if st.Usage.CacheRead != 128 || st.Usage.Input != 72 {
		t.Fatalf("usage over two rounds: %+v", st.Usage)
	}
	if _, err := c.Next(context.Background(), ep, "k", req, nil); err == nil {
		t.Fatal("next with open calls")
	}
	c.Results([]ToolResult{{ID: "c2", Text: "proposal p-1"}})
	st, err = c.Next(context.Background(), ep, "k", req, nil)
	if err != nil || st.Text != "끝" {
		t.Fatalf("final: %v %+v", err, st)
	}
	second, _ := json.Marshal(bodies[1]["input"])
	if !strings.Contains(string(second), `"call_id":"c1"`) || !strings.Contains(string(second), "input_schema") {
		t.Fatalf("describe_tool output not sent: %s", second)
	}
	third, _ := json.Marshal(bodies[2]["input"])
	if !strings.Contains(string(third), `"output":"proposal p-1"`) || bodies[2]["prompt_cache_key"] != "mydc-coordinator-v1" || bodies[2]["store"] != false {
		t.Fatalf("third request: %s %v", third, bodies[2])
	}
	if inc, _ := json.Marshal(bodies[2]["include"]); !strings.Contains(string(inc), "reasoning.encrypted_content") {
		t.Fatalf("include: %s", inc)
	}
	// The history prefix is unchanged between requests (append-only).
	first, _ := json.Marshal(bodies[0]["input"])
	if !strings.HasPrefix(string(second), strings.TrimSuffix(string(first), "]")) || !strings.HasPrefix(string(third), strings.TrimSuffix(string(second), "]")) {
		t.Fatalf("history moved:\n%s\n%s\n%s", first, second, third)
	}
}
