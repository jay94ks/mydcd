// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/openai/openai-go/v3"
	ooption "github.com/openai/openai-go/v3/option"
	"github.com/openai/openai-go/v3/responses"
	"github.com/openai/openai-go/v3/shared"
)

// Tool use (W2.2). The catalog is fixed per prompt version and sorted by
// name so the request prefix stays byte-equal across users and turns.
//
//   - Claude: the core tools are loaded, the rest are declared with
//     defer_loading and found by the server-side BM25 tool search; found
//     definitions are appended by the API, so the cached prefix holds.
//   - OpenAI: a changing tool list would break its prefix cache, so the
//     model gets three fixed meta tools (find_tools, describe_tool,
//     call_tool). The first two are answered here from the same catalog;
//     call_tool comes back to the caller as an ordinary ToolCall.
//
// A Chat keeps the provider-native transcript append-only (thinking
// blocks, tool calls, tool results), as the vendors' preserved reasoning
// and prompt caches need. It lives in memory only: the caller stores the
// visible text, and a Chat rebuilt from that text (NewChat) is a fresh
// transcript with no replayed reasoning.

// Tool is one catalog entry as the model sees it.
type Tool struct {
	Name        string
	Description string
	// Schema is the JSON Schema of the input (an object with
	// additionalProperties false).
	Schema map[string]any
	// Core tools are always loaded on Claude; the rest are searched.
	Core bool
}

// ToolCall is one call the caller runs.
type ToolCall struct {
	ID    string
	Name  string
	Input json.RawMessage
}

// ToolResult answers one ToolCall.
type ToolResult struct {
	ID      string
	Text    string
	IsError bool
}

// Found is one tool search the model ran (shown as a "found" activity line).
type Found struct {
	Query string
	Names []string
}

// ChatRequest is the fixed part of every step of a conversation.
type ChatRequest struct {
	System      string
	Tools       []Tool
	MaxTokens   int64
	Effort      string
	ThinkingOff bool
	CacheKey    string
	Stream      bool
}

// Step is one model answer.
type Step struct {
	Text  string
	Calls []ToolCall
	Found []Found
	Usage Usage
}

// Chat is one conversation's native transcript on one provider and model.
type Chat struct {
	Provider Provider
	Model    string
	claude   []anthropic.MessageParam
	openai   []json.RawMessage
	// pending holds the outputs of meta calls answered here, sent with the
	// caller's results.
	pending []json.RawMessage
	// open is true while tool calls wait for results.
	open bool
}

// NewChat starts a transcript from the visible history (user and
// assistant text only).
func NewChat(p Provider, model string, history []Message) *Chat {
	c := &Chat{Provider: p, Model: model}
	for _, m := range history {
		if m.Role == "assistant" {
			c.addAssistantText(m.Text)
		} else {
			c.User(m.Text)
		}
	}
	return c
}

// Open reports tool calls waiting for results (no new user text then).
func (c *Chat) Open() bool { return c.open }

// User appends a user message. Several texts in one call become one
// message (the question first, then this turn's screen context).
func (c *Chat) User(texts ...string) {
	switch c.Provider {
	case Claude:
		var blocks []anthropic.ContentBlockParamUnion
		for _, t := range texts {
			if t != "" {
				blocks = append(blocks, anthropic.NewTextBlock(t))
			}
		}
		if n := len(c.claude); n > 0 && c.claude[n-1].OfUser != nil {
			// Two user messages in a row (a stopped turn): merge.
			c.claude[n-1].OfUser.Content = append(c.claude[n-1].OfUser.Content, blocks...)
			return
		}
		c.claude = append(c.claude, anthropic.NewUserMessage(blocks...))
	case OpenAI:
		for _, t := range texts {
			if t != "" {
				c.openai = append(c.openai, mustJSON(map[string]any{"role": "user", "content": t}))
			}
		}
	}
}

func (c *Chat) addAssistantText(t string) {
	switch c.Provider {
	case Claude:
		c.claude = append(c.claude, anthropic.NewAssistantMessage(anthropic.NewTextBlock(t)))
	case OpenAI:
		c.openai = append(c.openai, mustJSON(map[string]any{"role": "assistant", "content": t}))
	}
}

// Results answers the open calls (every one of them, in one message).
func (c *Chat) Results(rs []ToolResult) {
	switch c.Provider {
	case Claude:
		var blocks []anthropic.ContentBlockParamUnion
		for _, r := range rs {
			blocks = append(blocks, anthropic.NewToolResultBlock(r.ID, r.Text, r.IsError))
		}
		c.claude = append(c.claude, anthropic.NewUserMessage(blocks...))
	case OpenAI:
		c.openai = append(c.openai, c.pending...)
		c.pending = nil
		for _, r := range rs {
			out := r.Text
			if r.IsError {
				out = "error: " + out
			}
			c.openai = append(c.openai, mustJSON(map[string]any{"type": "function_call_output", "call_id": r.ID, "output": out}))
		}
	}
	c.open = false
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// Next runs one step. onDelta (may be nil) gets answer text as it streams.
// On error the transcript is unchanged except for the user text already
// added, so the caller may retry or move to another model.
func (c *Chat) Next(ctx context.Context, ep Endpoints, key string, req ChatRequest, onDelta func(string)) (Step, error) {
	if c.open {
		return Step{}, &classed{ErrInvalid, errors.New("tool calls are waiting for results")}
	}
	switch c.Provider {
	case Claude:
		return c.nextClaude(ctx, ep, key, req, onDelta)
	case OpenAI:
		return c.nextOpenAI(ctx, ep, key, req, onDelta)
	}
	return Step{}, &classed{ErrInvalid, errors.New("unknown provider")}
}

func sortedTools(ts []Tool) []Tool {
	out := append([]Tool(nil), ts...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func schemaParam(s map[string]any) anthropic.ToolInputSchemaParam {
	p := anthropic.ToolInputSchemaParam{ExtraFields: map[string]any{}}
	for k, v := range s {
		switch k {
		case "type":
		case "properties":
			p.Properties = v
		case "required":
			if r, ok := v.([]string); ok {
				p.Required = r
			} else {
				p.ExtraFields[k] = v
			}
		default:
			p.ExtraFields[k] = v
		}
	}
	return p
}

func claudeTools(ts []Tool) []anthropic.ToolUnionParam {
	out := []anthropic.ToolUnionParam{{OfToolSearchToolBm25_20251119: &anthropic.ToolSearchToolBm25_20251119Param{
		Type: "tool_search_tool_bm25_20251119",
	}}}
	for _, t := range sortedTools(ts) {
		tp := &anthropic.ToolParam{
			Name:        t.Name,
			Description: anthropic.String(t.Description),
			InputSchema: schemaParam(t.Schema),
		}
		if !t.Core {
			tp.DeferLoading = anthropic.Bool(true)
		}
		out = append(out, anthropic.ToolUnionParam{OfTool: tp})
	}
	return out
}

func (c *Chat) nextClaude(ctx context.Context, ep Endpoints, key string, req ChatRequest, onDelta func(string)) (Step, error) {
	cl := ep.claude(key)
	r := Request{MaxTokens: req.MaxTokens, Effort: req.Effort, ThinkingOff: req.ThinkingOff}
	params := anthropic.MessageNewParams{
		Model:        anthropic.Model(c.Model),
		MaxTokens:    r.maxTokens(),
		Messages:     c.claude,
		CacheControl: anthropic.NewCacheControlEphemeralParam(),
		OutputConfig: anthropic.OutputConfigParam{Effort: anthropic.OutputConfigEffort(r.effort())},
	}
	if len(req.Tools) > 0 {
		params.Tools = claudeTools(req.Tools)
	}
	if req.System != "" {
		params.System = []anthropic.TextBlockParam{{
			Text:         req.System,
			CacheControl: anthropic.CacheControlEphemeralParam{TTL: anthropic.CacheControlEphemeralTTLTTL1h},
		}}
	}
	var msg anthropic.Message
	if req.Stream {
		st := cl.Messages.NewStreaming(ctx, params)
		for st.Next() {
			ev := st.Current()
			if err := msg.Accumulate(ev); err != nil {
				st.Close()
				return Step{}, classify(err)
			}
			if ev.Type == "content_block_delta" && ev.Delta.Type == "text_delta" && onDelta != nil {
				onDelta(ev.Delta.Text)
			}
		}
		if err := st.Err(); err != nil {
			return Step{}, classify(err)
		}
	} else {
		m, err := cl.Messages.New(ctx, params)
		if err != nil {
			return Step{}, classify(err)
		}
		msg = *m
		if onDelta != nil {
			for _, b := range msg.Content {
				if t, ok := b.AsAny().(anthropic.TextBlock); ok {
					onDelta(t.Text)
				}
			}
		}
	}
	out := Step{Usage: Usage{
		Input: msg.Usage.InputTokens, Output: msg.Usage.OutputTokens,
		CacheRead: msg.Usage.CacheReadInputTokens, CacheWrite: msg.Usage.CacheCreationInputTokens,
	}}
	if msg.StopReason == anthropic.StopReasonRefusal {
		// A refused answer is not kept: the fallback model starts over.
		return out, &classed{ErrRefused, errors.New("the model declined")}
	}
	var text strings.Builder
	queries := map[string]int{}
	for _, b := range msg.Content {
		switch v := b.AsAny().(type) {
		case anthropic.TextBlock:
			text.WriteString(v.Text)
		case anthropic.ToolUseBlock:
			out.Calls = append(out.Calls, ToolCall{ID: v.ID, Name: v.Name, Input: json.RawMessage(v.JSON.Input.Raw())})
		case anthropic.ServerToolUseBlock:
			q := ""
			if m, ok := v.Input.(map[string]any); ok {
				q, _ = m["query"].(string)
			}
			queries[v.ID] = len(out.Found)
			out.Found = append(out.Found, Found{Query: q})
		case anthropic.ToolSearchToolResultBlock:
			if i, ok := queries[v.ToolUseID]; ok {
				for _, ref := range v.Content.ToolReferences {
					out.Found[i].Names = append(out.Found[i].Names, ref.ToolName)
				}
			}
		}
	}
	out.Text = text.String()
	c.claude = append(c.claude, msg.ToParam())
	c.open = len(out.Calls) > 0
	return out, nil
}

// The OpenAI meta tools.
const (
	metaFind     = "find_tools"
	metaDescribe = "describe_tool"
	metaCall     = "call_tool"
)

func openAITools() []responses.ToolUnionParam {
	fn := func(name, desc string, props map[string]any, req []string) responses.ToolUnionParam {
		return responses.ToolUnionParam{OfFunction: &responses.FunctionToolParam{
			Name:        name,
			Description: openai.String(desc),
			Parameters:  map[string]any{"type": "object", "properties": props, "required": req, "additionalProperties": false},
			Strict:      openai.Bool(false),
		}}
	}
	return []responses.ToolUnionParam{
		fn(metaCall, "Run one catalog tool by name with its arguments. Changing tools only create a proposal for the user to approve.",
			map[string]any{"name": map[string]any{"type": "string"}, "args": map[string]any{"type": "object"}}, []string{"name", "args"}),
		fn(metaDescribe, "Return a catalog tool's input schema.",
			map[string]any{"name": map[string]any{"type": "string"}}, []string{"name"}),
		fn(metaFind, "Search the tool catalog. Returns matching tool names and one-line descriptions.",
			map[string]any{"query": map[string]any{"type": "string"}}, []string{"query"}),
	}
}

// FindTools is the catalog search behind find_tools: tools whose name or
// description hold the most query words, best first, at most limit.
func FindTools(ts []Tool, query string, limit int) []Tool {
	words := strings.Fields(strings.ToLower(strings.NewReplacer(".", " ", "_", " ", "-", " ").Replace(query)))
	type hit struct {
		t     Tool
		score int
	}
	var hits []hit
	for _, t := range sortedTools(ts) {
		hay := strings.ToLower(strings.NewReplacer(".", " ", "_", " ").Replace(t.Name) + " " + t.Description)
		n := 0
		for _, w := range words {
			if strings.Contains(hay, w) {
				n++
			}
		}
		if n > 0 {
			hits = append(hits, hit{t, n})
		}
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].score > hits[j].score })
	var out []Tool
	for i := 0; i < len(hits) && i < limit; i++ {
		out = append(out, hits[i].t)
	}
	return out
}

// maxMetaRounds caps find/describe-only rounds inside one step.
const maxMetaRounds = 8

func (c *Chat) nextOpenAI(ctx context.Context, ep Endpoints, key string, req ChatRequest, onDelta func(string)) (Step, error) {
	var out Step
	start := len(c.openai)
	for round := 0; ; round++ {
		resp, err := c.openAIOnce(ctx, ep, key, req, onDelta)
		if err != nil {
			c.openai, c.pending = c.openai[:start], nil
			return out, err
		}
		u := resp.Usage
		cached, written := u.InputTokensDetails.CachedTokens, u.InputTokensDetails.CacheWriteTokens
		out.Usage = out.Usage.Add(Usage{Input: max(0, u.InputTokens-cached-written), Output: u.OutputTokens, CacheRead: cached, CacheWrite: written})
		for _, item := range resp.Output {
			for _, part := range item.Content {
				if part.Type == "refusal" {
					c.openai, c.pending = c.openai[:start], nil
					return out, &classed{ErrRefused, errors.New("the model declined")}
				}
			}
		}
		out.Text += resp.OutputText()
		var meta []json.RawMessage
		for _, item := range resp.Output {
			c.openai = append(c.openai, json.RawMessage(item.RawJSON()))
			if item.Type != "function_call" {
				continue
			}
			fc := item.AsFunctionCall()
			var args struct {
				Query string          `json:"query"`
				Name  string          `json:"name"`
				Args  json.RawMessage `json:"args"`
			}
			_ = json.Unmarshal([]byte(fc.Arguments), &args)
			switch fc.Name {
			case metaFind:
				found := FindTools(req.Tools, args.Query, 8)
				f := Found{Query: args.Query}
				var rows []map[string]string
				for _, t := range found {
					f.Names = append(f.Names, t.Name)
					rows = append(rows, map[string]string{"name": t.Name, "description": t.Description})
				}
				out.Found = append(out.Found, f)
				meta = append(meta, mustJSON(map[string]any{"type": "function_call_output", "call_id": fc.CallID, "output": string(mustJSON(rows))}))
			case metaDescribe:
				res := fmt.Sprintf("error: no tool %q", args.Name)
				for _, t := range req.Tools {
					if t.Name == args.Name {
						res = string(mustJSON(map[string]any{"name": t.Name, "description": t.Description, "input_schema": t.Schema}))
					}
				}
				meta = append(meta, mustJSON(map[string]any{"type": "function_call_output", "call_id": fc.CallID, "output": res}))
			case metaCall:
				in := args.Args
				if len(in) == 0 {
					in = json.RawMessage("{}")
				}
				out.Calls = append(out.Calls, ToolCall{ID: fc.CallID, Name: args.Name, Input: in})
			default:
				meta = append(meta, mustJSON(map[string]any{"type": "function_call_output", "call_id": fc.CallID, "output": "error: call catalog tools through call_tool"}))
			}
		}
		if len(out.Calls) > 0 {
			c.pending, c.open = meta, true
			return out, nil
		}
		if len(meta) == 0 || round+1 >= maxMetaRounds {
			c.openai = append(c.openai, meta...)
			return out, nil
		}
		c.openai = append(c.openai, meta...)
	}
}

func (c *Chat) openAIOnce(ctx context.Context, ep Endpoints, key string, req ChatRequest, onDelta func(string)) (*responses.Response, error) {
	cl := ep.openai(key)
	r := Request{MaxTokens: req.MaxTokens, Effort: req.Effort, ThinkingOff: req.ThinkingOff}
	params := responses.ResponseNewParams{
		Model:           shared.ResponsesModel(c.Model),
		MaxOutputTokens: openai.Int(r.maxTokens()),
		Reasoning:       shared.ReasoningParam{Effort: shared.ReasoningEffort(r.effort())},
		Store:           openai.Bool(false),
		// Reasoning goes back encrypted, since nothing is stored there.
		Include: []responses.ResponseIncludable{responses.ResponseIncludableReasoningEncryptedContent},
	}
	if len(req.Tools) > 0 {
		params.Tools = openAITools()
	}
	if req.System != "" {
		params.Instructions = openai.String(req.System)
	}
	if req.CacheKey != "" {
		params.PromptCacheKey = openai.String(req.CacheKey)
	}
	input := ooption.WithJSONSet("input", c.openai)
	if !req.Stream {
		resp, err := cl.Responses.New(ctx, params, input)
		if err != nil {
			return nil, classify(err)
		}
		if onDelta != nil && resp.OutputText() != "" {
			onDelta(resp.OutputText())
		}
		return resp, nil
	}
	st := cl.Responses.NewStreaming(ctx, params, input)
	defer st.Close()
	var final *responses.Response
	for st.Next() {
		ev := st.Current()
		switch ev.Type {
		case "response.output_text.delta":
			if onDelta != nil {
				onDelta(ev.Delta)
			}
		case "response.completed", "response.incomplete":
			r := ev.Response
			final = &r
		case "response.failed":
			return nil, &classed{ErrUnavailable, errors.New("response failed")}
		}
	}
	if err := st.Err(); err != nil {
		return nil, classify(err)
	}
	if final == nil {
		return nil, &classed{ErrUnavailable, errors.New("stream ended early")}
	}
	return final, nil
}

// Summary is the simple compaction: the same model writes one message
// that replaces the transcript. keep says what the summary must hold.
func (c *Chat) Summary(ctx context.Context, ep Endpoints, key string, req ChatRequest, keep string) (string, Usage, error) {
	if c.open {
		return "", Usage{}, &classed{ErrInvalid, errors.New("tool calls are waiting for results")}
	}
	tmp := &Chat{Provider: c.Provider, Model: c.Model, claude: append([]anthropic.MessageParam(nil), c.claude...), openai: append([]json.RawMessage(nil), c.openai...)}
	tmp.User(keep)
	r := req
	r.Stream = false
	st, err := tmp.Next(ctx, ep, key, r, nil)
	return st.Text, st.Usage, err
}
