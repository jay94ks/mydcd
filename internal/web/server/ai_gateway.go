// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"

	"github.com/jay94ks/seafield/internal/web/ai"
	"github.com/jay94ks/seafield/internal/web/store"
)

// The AI gateway call every role uses (coordinator, diagnosis, impact,
// simple): role settings, the daily budget, main → fallback, and the
// usage and audit rows. Prompt text and answers are not recorded.

var (
	errAIRoleOff  = errors.New("ai-role-unavailable") // neither model usable
	errAIBudget   = errors.New("ai-budget-exceeded")  // the user's daily tokens are spent
	errAIBothFail = errors.New("ai-unavailable")      // main and fallback failed
)

// aiCall says who calls and how.
type aiCall struct {
	Role     string
	User     string // user ID ("" for the automation account)
	Username string
	// UseFallback keeps a conversation on the fallback once it switched
	// (switching back mid-way breaks the cache and the context).
	UseFallback bool
}

// aiResult is the answer with which model gave it.
type aiResult struct {
	ai.Response
	Model    store.AIModelRef
	Fallback bool
	// Switched is why the main was skipped ("" when it answered).
	Switched string
}

// aiDailyUsed sums the user's tokens today.
func (s *Server) aiDailyUsed(user string) int64 {
	rows, err := s.opt.Store.ListAIUsage(s.now().UTC().Format("2006-01-02"))
	if err != nil {
		s.log.Error("ai usage", "err", err)
		return 0
	}
	var n int64
	for _, u := range rows {
		if u.User == user {
			n += u.Input + u.Output + u.CacheRead + u.CacheWrite
		}
	}
	return n
}

// aiGenerate runs req for call.Role. Model, effort and output cap come
// from the role settings; req.CacheKey defaults to sfc-<role>-v1.
func (s *Server) aiGenerate(ctx context.Context, call aiCall, req ai.Request) (aiResult, error) {
	c := s.aiConfig()
	role := c.Roles[call.Role]
	cats := s.aiCatalogs()
	if lim := c.Limits.DailyTokensPerUser; lim > 0 && call.User != "" && s.aiDailyUsed(call.User) >= lim {
		return aiResult{}, errAIBudget
	}
	req.Effort, req.ThinkingOff = role.Effort, role.Thinking == "off"
	if req.MaxTokens == 0 {
		req.MaxTokens = role.MaxOutputTokens
	}
	if req.CacheKey == "" {
		req.CacheKey = "sfc-" + call.Role + "-v1"
	}
	tries, switched := aiTries(c, cats, role, call.UseFallback)
	if len(tries) == 0 {
		return aiResult{}, errAIRoleOff
	}
	var lastErr error
	for _, t := range tries {
		key, err := s.aiKey(ai.Provider(t.ref.Provider))
		if err != nil {
			lastErr, switched = err, "key-unavailable"
			continue
		}
		req.Model = t.ref.Model
		resp, err := ai.Generate(ctx, s.opt.AI, ai.Provider(t.ref.Provider), key, req)
		s.aiRecord(call, *t.ref, t.fallback, switched, resp.Usage, err)
		if err == nil {
			return aiResult{Response: resp, Model: *t.ref, Fallback: t.fallback, Switched: switched}, nil
		}
		if ctx.Err() != nil {
			return aiResult{}, ctx.Err()
		}
		lastErr, switched = err, ai.Class(err).Error()
	}
	s.log.Warn("ai call failed", "role", call.Role, "class", ai.Class(lastErr).Error())
	return aiResult{}, errors.Join(errAIBothFail, lastErr)
}

// aiTry is one model to try.
type aiTry struct {
	ref      *store.AIModelRef
	fallback bool
}

// aiTries lists the usable models of a role in order (main, then
// fallback) and why the main is skipped ("" when it is first).
func aiTries(c *store.AIConfig, cats map[ai.Provider]*store.AICatalog, role store.AIRole, useFallback bool) ([]aiTry, string) {
	var tries []aiTry
	switched := ""
	if !useFallback {
		if aiModelUsable(c, cats, role.Main) {
			tries = append(tries, aiTry{role.Main, false})
		} else {
			switched = "main-missing"
		}
	} else {
		switched = "sticky"
	}
	if aiModelUsable(c, cats, role.Fallback) {
		tries = append(tries, aiTry{role.Fallback, true})
	}
	return tries, switched
}

// aiRecord adds the usage row and the audit row of one request.
func (s *Server) aiRecord(call aiCall, ref store.AIModelRef, fallback bool, switched string, u ai.Usage, err error) {
	if uerr := s.opt.Store.AddAIUsage(store.AIUsage{
		Day: s.now().UTC().Format("2006-01-02"), Role: call.Role, Provider: ref.Provider, Model: ref.Model, Fallback: fallback, User: call.User,
		Requests: 1, Input: u.Input, Output: u.Output, CacheRead: u.CacheRead, CacheWrite: u.CacheWrite,
	}); uerr != nil {
		s.log.Error("ai usage", "err", uerr)
	}
	e := store.AIAudit{ID: randomID(12), At: s.now(), User: call.User, Username: call.Username, Kind: "request", Role: call.Role,
		Provider: ref.Provider, Model: ref.Model, Fallback: fallback, Tokens: u.Input + u.Output + u.CacheWrite, CacheRead: u.CacheRead}
	if fallback {
		e.Kind, e.Reason = "fallback", switched
	}
	if err != nil {
		e.Reason = ai.Class(err).Error()
	}
	if aerr := s.opt.Store.AppendAIAudit(&e); aerr != nil {
		s.log.Error("ai audit", "err", aerr)
	}
}
