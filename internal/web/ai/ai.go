// SPDX-License-Identifier: Apache-2.0

// Package ai is mydc-web's AI gateway (W2.1): the Claude and OpenAI
// adapters behind one small interface (messages + usage with cache
// counts), the provider model catalog, and the error classes the AI
// settings screen shows. It holds no keys: the caller opens the sealed key
// and passes it in for each call, and nothing here logs or stores it.
//
// Prompt caching: the system prompt is the fixed prefix. Claude caches it
// with an explicit 1-hour breakpoint and the conversation end with the
// automatic breakpoint; OpenAI caches long equal prefixes itself and gets
// a fixed prompt_cache_key per role so equal prefixes land together.
package ai

import (
	"context"
	"errors"
	"net"
	"net/http"
	"regexp"
	"sort"
	"time"

	"github.com/anthropics/anthropic-sdk-go/v2"
	aoption "github.com/anthropics/anthropic-sdk-go/v2/option"
	"github.com/openai/openai-go/v3"
	ooption "github.com/openai/openai-go/v3/option"
)

// Provider names an AI vendor.
type Provider string

const (
	Claude Provider = "claude"
	OpenAI Provider = "openai"
)

// Providers lists the known providers in display order.
var Providers = []Provider{Claude, OpenAI}

// Valid reports a known provider.
func (p Provider) Valid() bool { return p == Claude || p == OpenAI }

// Error classes of a failed call (the settings screen's detail codes).
var (
	ErrAuth        = errors.New("auth")         // key missing, wrong or revoked
	ErrRateLimited = errors.New("rate-limited") // 429
	ErrUnavailable = errors.New("unavailable")  // timeout, 5xx, network
	ErrInvalid     = errors.New("invalid")      // 400/404: the request or model
	ErrRefused     = errors.New("refused")      // the model declined (stop reason refusal)
)

// Class maps an error to one of the classes above (ErrUnavailable when it
// is none of them).
func Class(err error) error {
	for _, c := range []error{ErrAuth, ErrRateLimited, ErrUnavailable, ErrInvalid, ErrRefused} {
		if errors.Is(err, c) {
			return c
		}
	}
	return ErrUnavailable
}

type classed struct {
	class error
	err   error
}

func (e *classed) Error() string { return e.class.Error() + ": " + e.err.Error() }
func (e *classed) Unwrap() []error {
	return []error{e.class, e.err}
}

func classify(err error) error {
	if err == nil {
		return nil
	}
	status := 0
	var ae *anthropic.Error
	var oe *openai.Error
	switch {
	case errors.As(err, &ae):
		status = ae.StatusCode
	case errors.As(err, &oe):
		status = oe.StatusCode
	}
	var ne net.Error
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return &classed{ErrAuth, err}
	case status == http.StatusTooManyRequests:
		return &classed{ErrRateLimited, err}
	case status == http.StatusBadRequest || status == http.StatusNotFound || status == http.StatusUnprocessableEntity:
		return &classed{ErrInvalid, err}
	case status >= 500, errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne):
		return &classed{ErrUnavailable, err}
	}
	return &classed{ErrUnavailable, err}
}

// Endpoints overrides where the adapters go (tests, a proxy). Empty values
// are the vendors' public APIs.
type Endpoints struct {
	ClaudeURL  string
	OpenAIURL  string
	HTTPClient *http.Client
	// Retries is the SDK retry count for 429/5xx (default 2; -1 for none).
	Retries int
}

func (e Endpoints) retries() int {
	switch {
	case e.Retries < 0:
		return 0
	case e.Retries == 0:
		return 2
	}
	return e.Retries
}

func (e Endpoints) claude(key string) anthropic.Client {
	opts := []aoption.RequestOption{aoption.WithAPIKey(key), aoption.WithMaxRetries(e.retries())}
	if e.ClaudeURL != "" {
		opts = append(opts, aoption.WithBaseURL(e.ClaudeURL))
	}
	if e.HTTPClient != nil {
		opts = append(opts, aoption.WithHTTPClient(e.HTTPClient))
	}
	return anthropic.NewClient(opts...)
}

func (e Endpoints) openai(key string) openai.Client {
	opts := []ooption.RequestOption{ooption.WithAPIKey(key), ooption.WithMaxRetries(e.retries())}
	if e.OpenAIURL != "" {
		opts = append(opts, ooption.WithBaseURL(e.OpenAIURL))
	}
	if e.HTTPClient != nil {
		opts = append(opts, ooption.WithHTTPClient(e.HTTPClient))
	}
	return openai.NewClient(opts...)
}

// Model is one catalog entry.
type Model struct {
	ID          string    `json:"id"`
	DisplayName string    `json:"displayName,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	Hidden      bool      `json:"hidden"`
}

// DefaultHidden are the OpenAI model ID patterns that cannot chat
// (embeddings, speech, images, moderation, …). The web settings file can
// replace them.
var DefaultHidden = []string{
	`embedding`, `^tts-`, `whisper`, `transcribe`, `-tts`, `audio`, `realtime`,
	`^dall-e`, `^gpt-image`, `image`, `moderation`, `^babbage`, `^davinci`,
	`search`, `^sora`, `^codex-mini`, `computer-use`,
}

// HideRules compiles hide patterns (invalid ones are an error).
func HideRules(patterns []string) ([]*regexp.Regexp, error) {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, err
		}
		out = append(out, re)
	}
	return out, nil
}

// ListModels reads the provider's model catalog with key (the connection
// test), newest first. OpenAI rows matching hide are marked Hidden.
func ListModels(ctx context.Context, ep Endpoints, p Provider, key string, hide []*regexp.Regexp) ([]Model, error) {
	var out []Model
	switch p {
	case Claude:
		c := ep.claude(key)
		it := c.Models.ListAutoPaging(ctx, anthropic.ModelListParams{})
		for it.Next() {
			m := it.Current()
			out = append(out, Model{ID: m.ID, DisplayName: m.DisplayName, CreatedAt: m.CreatedAt.UTC()})
		}
		if err := it.Err(); err != nil {
			return nil, classify(err)
		}
	case OpenAI:
		c := ep.openai(key)
		it := c.Models.ListAutoPaging(ctx)
		for it.Next() {
			m := it.Current()
			row := Model{ID: m.ID, CreatedAt: time.Unix(m.Created, 0).UTC()}
			for _, re := range hide {
				if re.MatchString(m.ID) {
					row.Hidden = true
					break
				}
			}
			out = append(out, row)
		}
		if err := it.Err(); err != nil {
			return nil, classify(err)
		}
	default:
		return nil, &classed{ErrInvalid, errors.New("unknown provider")}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}
