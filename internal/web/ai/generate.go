// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"errors"
	"strings"

	"github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/responses"
	"github.com/openai/openai-go/v3/shared"
)

// Message is one conversation turn.
type Message struct {
	Role string // "user" or "assistant"
	Text string
}

// Request is one model call. System is the fixed, cached prefix: it must
// not carry dates, user names or the current screen (those go in the
// messages), or the cache breaks.
type Request struct {
	Model     string
	System    string
	Messages  []Message
	MaxTokens int64
	// Effort: low / medium / high ("" = medium). Thinking off is the lowest
	// effort the model accepts: current Claude models refuse a disabled
	// thinking setting, so off means effort low on both providers.
	Effort      string
	ThinkingOff bool
	// CacheKey is OpenAI's prompt_cache_key (per role and prompt version,
	// e.g. "mydc-simple-v1"); Claude ignores it.
	CacheKey string
}

// Usage counts tokens. Input excludes the cached ones on both providers
// (OpenAI reports them inside input_tokens; they are taken out here).
type Usage struct {
	Input      int64 `json:"inputTokens"`
	Output     int64 `json:"outputTokens"`
	CacheRead  int64 `json:"cacheReadTokens"`
	CacheWrite int64 `json:"cacheWriteTokens"`
}

// Add sums two usages.
func (u Usage) Add(v Usage) Usage {
	return Usage{u.Input + v.Input, u.Output + v.Output, u.CacheRead + v.CacheRead, u.CacheWrite + v.CacheWrite}
}

// Response is the model's answer.
type Response struct {
	Text  string
	Usage Usage
}

func (r Request) effort() string {
	if r.ThinkingOff {
		return "low"
	}
	switch r.Effort {
	case "low", "medium", "high":
		return r.Effort
	}
	return "medium"
}

func (r Request) maxTokens() int64 {
	if r.MaxTokens > 0 {
		return r.MaxTokens
	}
	return 16000
}

// Generate makes one call. A refusal is ErrRefused (with the usage spent).
func Generate(ctx context.Context, ep Endpoints, p Provider, key string, req Request) (Response, error) {
	if req.Model == "" || len(req.Messages) == 0 {
		return Response{}, &classed{ErrInvalid, errors.New("model and messages are required")}
	}
	switch p {
	case Claude:
		return generateClaude(ctx, ep, key, req)
	case OpenAI:
		return generateOpenAI(ctx, ep, key, req)
	}
	return Response{}, &classed{ErrInvalid, errors.New("unknown provider")}
}

func generateClaude(ctx context.Context, ep Endpoints, key string, req Request) (Response, error) {
	c := ep.claude(key)
	params := anthropic.MessageNewParams{
		Model:     anthropic.Model(req.Model),
		MaxTokens: req.maxTokens(),
		// The conversation end: automatic breakpoint on the last block.
		CacheControl: anthropic.NewCacheControlEphemeralParam(),
		OutputConfig: anthropic.OutputConfigParam{Effort: anthropic.OutputConfigEffort(req.effort())},
	}
	if req.System != "" {
		// The fixed prefix (tools + system): 1-hour breakpoint, since people
		// pause minutes between questions.
		params.System = []anthropic.TextBlockParam{{
			Text:         req.System,
			CacheControl: anthropic.CacheControlEphemeralParam{TTL: anthropic.CacheControlEphemeralTTLTTL1h},
		}}
	}
	for _, m := range req.Messages {
		block := anthropic.NewTextBlock(m.Text)
		if m.Role == "assistant" {
			params.Messages = append(params.Messages, anthropic.NewAssistantMessage(block))
		} else {
			params.Messages = append(params.Messages, anthropic.NewUserMessage(block))
		}
	}
	msg, err := c.Messages.New(ctx, params)
	if err != nil {
		return Response{}, classify(err)
	}
	out := Response{Usage: Usage{
		Input: msg.Usage.InputTokens, Output: msg.Usage.OutputTokens,
		CacheRead: msg.Usage.CacheReadInputTokens, CacheWrite: msg.Usage.CacheCreationInputTokens,
	}}
	var b strings.Builder
	for _, block := range msg.Content {
		if t, ok := block.AsAny().(anthropic.TextBlock); ok {
			b.WriteString(t.Text)
		}
	}
	out.Text = b.String()
	if msg.StopReason == anthropic.StopReasonRefusal {
		return out, &classed{ErrRefused, errors.New("the model declined")}
	}
	return out, nil
}

func generateOpenAI(ctx context.Context, ep Endpoints, key string, req Request) (Response, error) {
	c := ep.openai(key)
	var input responses.ResponseInputParam
	for _, m := range req.Messages {
		role := responses.EasyInputMessageRoleUser
		if m.Role == "assistant" {
			role = responses.EasyInputMessageRoleAssistant
		}
		input = append(input, responses.ResponseInputItemParamOfMessage(m.Text, role))
	}
	params := responses.ResponseNewParams{
		Model:           shared.ResponsesModel(req.Model),
		Input:           responses.ResponseNewParamsInputUnion{OfInputItemList: input},
		MaxOutputTokens: openai.Int(req.maxTokens()),
		Reasoning:       shared.ReasoningParam{Effort: shared.ReasoningEffort(req.effort())},
		// Nothing is kept at the vendor beyond the call.
		Store: openai.Bool(false),
	}
	if req.System != "" {
		params.Instructions = openai.String(req.System)
	}
	if req.CacheKey != "" {
		params.PromptCacheKey = openai.String(req.CacheKey)
	}
	resp, err := c.Responses.New(ctx, params)
	if err != nil {
		return Response{}, classify(err)
	}
	u := resp.Usage
	cached, written := u.InputTokensDetails.CachedTokens, u.InputTokensDetails.CacheWriteTokens
	out := Response{Text: resp.OutputText(), Usage: Usage{
		Input: max(0, u.InputTokens-cached-written), Output: u.OutputTokens, CacheRead: cached, CacheWrite: written,
	}}
	for _, item := range resp.Output {
		for _, part := range item.Content {
			if part.Type == "refusal" {
				return out, &classed{ErrRefused, errors.New("the model declined")}
			}
		}
	}
	return out, nil
}
