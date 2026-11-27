// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/jay94ks/seafield/internal/web/ai"
	"github.com/jay94ks/seafield/internal/web/seal"
	"github.com/jay94ks/seafield/internal/web/store"
)

// AI settings (UI-B7, W2.1, system admin). The Claude and OpenAI API keys
// are sealed files ("ai-key-<provider>"); bbolt keeps their last four
// characters, the model catalog read with them, the role settings, daily
// usage and the AI audit. A key is stored only after it read the catalog
// (the connection test), is never sent back, and never logged.

// AI roles.
const (
	roleCoordinator = "coordinator"
	roleDiagnosis   = "diagnosis"
	roleImpact      = "impact"
	roleSimple      = "simple"
)

var aiRoles = []string{roleCoordinator, roleDiagnosis, roleImpact, roleSimple}

func aiKeyName(p ai.Provider) string { return "ai-key-" + string(p) }

// defaultAIConfig: Claude models by default (the plan's table); the impact
// role has no main until a second provider is chosen (it should differ
// from diagnosis). A role whose provider has no key shows mainMissing.
func defaultAIConfig() *store.AIConfig {
	ref := func(m string) *store.AIModelRef { return &store.AIModelRef{Provider: string(ai.Claude), Model: m} }
	return &store.AIConfig{
		Roles: map[string]store.AIRole{
			roleCoordinator: {Main: ref("claude-opus-5-5"), Effort: "high", Thinking: "auto", MaxOutputTokens: 32000, Stream: true},
			roleDiagnosis:   {Main: ref("claude-opus-5-5"), Effort: "high", Thinking: "auto", MaxOutputTokens: 16000},
			roleImpact:      {Effort: "medium", Thinking: "auto", MaxOutputTokens: 4000},
			roleSimple:      {Main: ref("claude-haiku-5-5"), Effort: "low", Thinking: "off", MaxOutputTokens: 1024},
		},
		Data:   store.AIData{MaskSecretLikeEnv: true, LogTailLines: 200, ExcludeTenants: []string{}},
		Limits: store.AILimits{DailyTokensPerUser: 2_000_000, ToolCallsPerConversation: 40, TokensPerConversation: 1_000_000, Compaction: store.AICompaction{TriggerTokens: 150_000}},
	}
}

func (s *Server) aiConfig() *store.AIConfig {
	c, err := s.opt.Store.GetAIConfig()
	if err != nil {
		s.log.Error("ai config", "err", err)
	}
	if c == nil {
		return defaultAIConfig()
	}
	def := defaultAIConfig()
	for _, r := range aiRoles {
		if _, ok := c.Roles[r]; !ok {
			if c.Roles == nil {
				c.Roles = map[string]store.AIRole{}
			}
			c.Roles[r] = def.Roles[r]
		}
	}
	if c.Data.ExcludeTenants == nil {
		c.Data.ExcludeTenants = []string{}
	}
	return c
}

func (s *Server) aiHide() []*regexp.Regexp {
	pats := s.opt.AIHideModels
	if pats == nil {
		pats = ai.DefaultHidden
	}
	re, err := ai.HideRules(pats)
	if err != nil {
		s.log.Error("ai hide rules", "err", err)
		re, _ = ai.HideRules(ai.DefaultHidden)
	}
	return re
}

type aiProviderView struct {
	Provider    string `json:"provider"`
	Configured  bool   `json:"configured"`
	Last4       string `json:"last4,omitempty"`
	SetBy       string `json:"setBy,omitempty"`
	SetAt       string `json:"setAt,omitempty"`
	CatalogAt   string `json:"catalogAt,omitempty"`
	Models      int    `json:"models"`
	ModelsTotal int    `json:"modelsTotal"`
	Error       string `json:"error,omitempty"`
}

type aiRoleView struct {
	Main            *store.AIModelRef `json:"main"`
	Fallback        *store.AIModelRef `json:"fallback"`
	MainMissing     bool              `json:"mainMissing"`
	FallbackMissing bool              `json:"fallbackMissing"`
	SameProvider    bool              `json:"sameProvider"`
	Effort          string            `json:"effort"`
	Thinking        string            `json:"thinking"`
	MaxOutputTokens int64             `json:"maxOutputTokens"`
	Stream          bool              `json:"stream"`
}

type aiView struct {
	SealReady bool                  `json:"sealReady"`
	Revision  uint64                `json:"revision"`
	Providers []aiProviderView      `json:"providers"`
	Roles     map[string]aiRoleView `json:"roles"`
	Data      store.AIData          `json:"data"`
	Limits    store.AILimits        `json:"limits"`
}

// aiCatalogs reads both catalogs.
func (s *Server) aiCatalogs() map[ai.Provider]*store.AICatalog {
	out := map[ai.Provider]*store.AICatalog{}
	for _, p := range ai.Providers {
		c, err := s.opt.Store.GetAICatalog(string(p))
		if err != nil {
			s.log.Error("ai catalog", "provider", p, "err", err)
		}
		if c != nil {
			out[p] = c
		}
	}
	return out
}

// aiModelUsable: the provider has a key and its catalog lists the model.
func aiModelUsable(c *store.AIConfig, cats map[ai.Provider]*store.AICatalog, ref *store.AIModelRef) bool {
	if ref == nil || c.Providers[ref.Provider] == nil {
		return false
	}
	cat := cats[ai.Provider(ref.Provider)]
	if cat == nil {
		return false
	}
	return slices.ContainsFunc(cat.Models, func(m store.AIModel) bool { return m.ID == ref.Model })
}

func (s *Server) aiView() aiView {
	c := s.aiConfig()
	cats := s.aiCatalogs()
	v := aiView{SealReady: s.opt.Seal.Ready(), Revision: c.Revision, Roles: map[string]aiRoleView{}, Data: c.Data, Limits: c.Limits}
	for _, p := range ai.Providers {
		row := aiProviderView{Provider: string(p)}
		if pr := c.Providers[string(p)]; pr != nil {
			row.Configured, row.Last4, row.SetBy, row.SetAt, row.Error = true, pr.Last4, pr.SetBy, rfc3339(pr.SetAt), pr.Error
			if !pr.CatalogAt.IsZero() {
				row.CatalogAt = rfc3339(pr.CatalogAt)
			}
		}
		if cat := cats[p]; cat != nil {
			row.ModelsTotal = len(cat.Models)
			for _, m := range cat.Models {
				if !m.Hidden {
					row.Models++
				}
			}
		}
		v.Providers = append(v.Providers, row)
	}
	for _, name := range aiRoles {
		r := c.Roles[name]
		v.Roles[name] = aiRoleView{
			Main: r.Main, Fallback: r.Fallback,
			MainMissing: !aiModelUsable(c, cats, r.Main), FallbackMissing: r.Fallback != nil && !aiModelUsable(c, cats, r.Fallback),
			SameProvider: r.Main != nil && r.Fallback != nil && r.Main.Provider == r.Fallback.Provider,
			Effort:       r.Effort, Thinking: r.Thinking, MaxOutputTokens: r.MaxOutputTokens, Stream: r.Stream,
		}
	}
	return v
}

func (s *Server) aiAudit(ws *webSession, e store.AIAudit) {
	e.ID, e.At = randomID(12), s.now()
	if ws != nil {
		e.User, e.Username = ws.user.ID, ws.user.Username
	}
	if err := s.opt.Store.AppendAIAudit(&e); err != nil {
		s.log.Error("ai audit", "err", err, "kind", e.Kind)
	}
}

func aiProviderOf(w http.ResponseWriter, r *http.Request) (ai.Provider, bool) {
	p := ai.Provider(r.PathValue("provider"))
	if !p.Valid() {
		writeError(w, http.StatusNotFound, "not-found", "provider: claude or openai")
		return "", false
	}
	return p, true
}

func (s *Server) aiCtx(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), 30*time.Second)
}

// GET /system/ai → aiView.
func (s *Server) handleGetAI(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if !s.requireAdmin(w, r, ws) {
		return
	}
	writeJSON(w, http.StatusOK, s.aiView())
}

func writeKeyRejected(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": map[string]string{
		"code": "key-rejected", "message": "the key could not read the provider's model catalog", "detail": ai.Class(err).Error(),
	}})
}

func validAPIKey(k string) bool {
	if len(k) < 8 || len(k) > 512 {
		return false
	}
	for _, r := range k {
		if r > unicode.MaxASCII || unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func toStoreModels(ms []ai.Model) []store.AIModel {
	out := make([]store.AIModel, len(ms))
	for i, m := range ms {
		out[i] = store.AIModel{ID: m.ID, DisplayName: m.DisplayName, CreatedAt: m.CreatedAt, Hidden: m.Hidden}
	}
	return out
}

// PUT /system/ai/keys/{provider} {key}: read the catalog with the key (the
// connection test); on success seal the key and keep the catalog.
func (s *Server) handlePutAIKey(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Key string `json:"key"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	p, ok := aiProviderOf(w, r)
	if !ok || !s.requireAdmin(w, r, ws) {
		return
	}
	req.Key = strings.TrimSpace(req.Key)
	if !validAPIKey(req.Key) {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "key: 8..512 printable ASCII characters")
		return
	}
	if !s.opt.Seal.Ready() {
		writeError(w, http.StatusServiceUnavailable, "seal-unavailable", "API keys are sealed with the web's seal key, which is not ready")
		return
	}
	ctx, cancel := s.aiCtx(r)
	defer cancel()
	models, err := ai.ListModels(ctx, s.opt.AI, p, req.Key, s.aiHide())
	if err != nil {
		s.log.Warn("ai key test", "provider", p, "class", ai.Class(err).Error())
		writeKeyRejected(w, err)
		return
	}
	if err := s.opt.Seal.Put(aiKeyName(p), []byte(req.Key)); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "could not seal the key")
		return
	}
	now := s.now()
	if err := s.opt.Store.PutAICatalog(string(p), &store.AICatalog{Provider: string(p), FetchedAt: now, Models: toStoreModels(models)}); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	last4 := req.Key[len(req.Key)-4:]
	var before any
	if _, err := s.opt.Store.UpdateAIConfig(func(cur *store.AIConfig) (*store.AIConfig, error) {
		c := cur
		if c == nil {
			c = defaultAIConfig()
		}
		if c.Providers == nil {
			c.Providers = map[string]*store.AIProvider{}
		}
		if old := c.Providers[string(p)]; old != nil {
			before = map[string]string{"last4": old.Last4}
		}
		c.Providers[string(p)] = &store.AIProvider{Last4: last4, SetByID: ws.user.ID, SetBy: ws.user.Username, SetAt: now, CatalogAt: now}
		return c, nil
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(ws, "", "ai", "key", string(p), before, map[string]string{"last4": last4})
	s.aiAudit(ws, store.AIAudit{Kind: "key-set", Provider: string(p)})
	writeJSON(w, http.StatusOK, s.aiProviderRow(p))
}

func (s *Server) aiProviderRow(p ai.Provider) aiProviderView {
	for _, row := range s.aiView().Providers {
		if row.Provider == string(p) {
			return row
		}
	}
	return aiProviderView{Provider: string(p)}
}

// DELETE /system/ai/keys/{provider} → 204. Roles on it show as missing.
func (s *Server) handleDeleteAIKey(w http.ResponseWriter, r *http.Request, ws *webSession) {
	p, ok := aiProviderOf(w, r)
	if !ok || !s.requireAdmin(w, r, ws) {
		return
	}
	if err := s.opt.Seal.Delete(aiKeyName(p)); err != nil && !errors.Is(err, seal.ErrNotFound) {
		writeError(w, http.StatusInternalServerError, "internal", "could not remove the sealed key")
		return
	}
	_ = s.opt.Store.PutAICatalog(string(p), nil)
	var before any
	if _, err := s.opt.Store.UpdateAIConfig(func(cur *store.AIConfig) (*store.AIConfig, error) {
		c := cur
		if c == nil {
			c = defaultAIConfig()
		}
		if old := c.Providers[string(p)]; old != nil {
			before = map[string]string{"last4": old.Last4}
			delete(c.Providers, string(p))
		}
		return c, nil
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if before != nil {
		s.audit(ws, "", "ai", "key-delete", string(p), before, nil)
		s.aiAudit(ws, store.AIAudit{Kind: "key-deleted", Provider: string(p)})
	}
	w.WriteHeader(http.StatusNoContent)
}

// aiKey opens a provider's sealed key.
func (s *Server) aiKey(p ai.Provider) (string, error) {
	raw, err := s.opt.Seal.Get(aiKeyName(p))
	if err != nil {
		return "", err
	}
	defer clear(raw)
	return string(raw), nil
}

// refreshAICatalog reads a provider's catalog again with its sealed key. A
// failure keeps the old list and records the class.
func (s *Server) refreshAICatalog(ctx context.Context, p ai.Provider) error {
	key, err := s.aiKey(p)
	if err != nil {
		return err
	}
	models, err := ai.ListModels(ctx, s.opt.AI, p, key, s.aiHide())
	now := s.now()
	if err == nil {
		err = s.opt.Store.PutAICatalog(string(p), &store.AICatalog{Provider: string(p), FetchedAt: now, Models: toStoreModels(models)})
	}
	class := ""
	if err != nil {
		class = ai.Class(err).Error()
		s.log.Warn("ai catalog refresh", "provider", p, "class", class)
	}
	_, uerr := s.opt.Store.UpdateAIConfig(func(cur *store.AIConfig) (*store.AIConfig, error) {
		c := cur
		if c == nil {
			c = defaultAIConfig()
		}
		if pr := c.Providers[string(p)]; pr != nil {
			pr.Error = class
			if class == "" {
				pr.CatalogAt = now
			}
		}
		return c, nil
	})
	if err == nil {
		err = uerr
	}
	return err
}

// POST /system/ai/models/{provider}/refresh → provider row.
func (s *Server) handleRefreshAIModels(w http.ResponseWriter, r *http.Request, ws *webSession) {
	p, ok := aiProviderOf(w, r)
	if !ok || !s.requireAdmin(w, r, ws) {
		return
	}
	if s.aiConfig().Providers[string(p)] == nil {
		writeError(w, http.StatusConflict, "not-configured", "connect the provider's key first")
		return
	}
	ctx, cancel := s.aiCtx(r)
	defer cancel()
	if err := s.refreshAICatalog(ctx, p); errors.Is(err, seal.ErrUnavailable) {
		writeError(w, http.StatusServiceUnavailable, "seal-unavailable", "the seal key is not ready")
		return
	}
	writeJSON(w, http.StatusOK, s.aiProviderRow(p))
}

// GET /system/ai/models/{provider}?all=1 → {provider, fetchedAt, items}.
func (s *Server) handleGetAIModels(w http.ResponseWriter, r *http.Request, ws *webSession) {
	p, ok := aiProviderOf(w, r)
	if !ok || !s.requireAdmin(w, r, ws) {
		return
	}
	cat, err := s.opt.Store.GetAICatalog(string(p))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	out := map[string]any{"provider": p, "items": []store.AIModel{}}
	if cat != nil {
		all := r.URL.Query().Get("all") == "1"
		items := []store.AIModel{}
		for _, m := range cat.Models {
			if all || !m.Hidden {
				items = append(items, m)
			}
		}
		out["fetchedAt"], out["items"] = rfc3339(cat.FetchedAt), items
	}
	writeJSON(w, http.StatusOK, out)
}

type aiRoleInput struct {
	Main            *store.AIModelRef `json:"main"`
	Fallback        *store.AIModelRef `json:"fallback"`
	Effort          string            `json:"effort"`
	Thinking        string            `json:"thinking"`
	MaxOutputTokens int64             `json:"maxOutputTokens"`
	Stream          bool              `json:"stream"`
}

// PUT /system/ai/settings {revision, roles, data, limits} → aiView.
func (s *Server) handlePutAISettings(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Revision uint64                 `json:"revision"`
		Roles    map[string]aiRoleInput `json:"roles"`
		Data     store.AIData           `json:"data"`
		Limits   store.AILimits         `json:"limits"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !s.requireAdmin(w, r, ws) {
		return
	}
	cats := s.aiCatalogs()
	bad := func(code, msg string) { writeError(w, http.StatusUnprocessableEntity, code, msg) }
	for name, ri := range req.Roles {
		if !slices.Contains(aiRoles, name) {
			bad("invalid", "roles: coordinator, diagnosis, impact, simple")
			return
		}
		if ri.Effort != "low" && ri.Effort != "medium" && ri.Effort != "high" {
			bad("invalid", name+".effort: low, medium or high")
			return
		}
		if ri.Thinking != "auto" && ri.Thinking != "off" {
			bad("invalid", name+".thinking: auto or off")
			return
		}
		if ri.MaxOutputTokens < 256 || ri.MaxOutputTokens > 128000 {
			bad("invalid", name+".maxOutputTokens: 256..128000")
			return
		}
	}
	d := req.Data
	if d.LogTailLines < 0 || d.LogTailLines > 200 || len(d.ExcludeTenants) > 1000 {
		bad("invalid", "data.logTailLines: 0..200")
		return
	}
	if d.ExcludeTenants == nil {
		d.ExcludeTenants = []string{}
	}
	l := req.Limits
	if l.DailyTokensPerUser < 0 || l.ToolCallsPerConversation < 0 || l.TokensPerConversation < 0 || l.ToolCallsPerConversation > 1000 {
		bad("invalid", "limits: 0 (unlimited) or more; tool calls at most 1000")
		return
	}
	if !l.Compaction.Enabled && (l.ToolCallsPerConversation == 0 || l.TokensPerConversation == 0) {
		bad("unlimited-needs-compaction", "per-conversation limits can be unlimited only with automatic compaction")
		return
	}
	if l.Compaction.TriggerTokens == 0 {
		l.Compaction.TriggerTokens = 150_000
	}
	if l.Compaction.TriggerTokens < 50_000 || l.Compaction.TriggerTokens > 900_000 {
		bad("invalid", "limits.compaction.triggerTokens: 50000..900000")
		return
	}
	var before *store.AIConfig
	next, err := s.opt.Store.UpdateAIConfig(func(cur *store.AIConfig) (*store.AIConfig, error) {
		c := cur
		rev := uint64(0)
		if c == nil {
			c = defaultAIConfig()
		} else {
			rev = c.Revision
			cp := *c
			before = &cp
		}
		if req.Revision != rev {
			return nil, errRevisionChanged
		}
		roles := map[string]store.AIRole{}
		for k, v := range c.Roles {
			roles[k] = v
		}
		for name, ri := range req.Roles {
			for _, ref := range []*store.AIModelRef{ri.Main, ri.Fallback} {
				if ref != nil && !aiModelUsable(c, cats, ref) {
					return nil, &httpErr{http.StatusUnprocessableEntity, "model-not-in-catalog", name + ": " + ref.Provider + "/" + ref.Model + " is not in a connected provider's catalog"}
				}
			}
			roles[name] = store.AIRole{Main: ri.Main, Fallback: ri.Fallback, Effort: ri.Effort, Thinking: ri.Thinking, MaxOutputTokens: ri.MaxOutputTokens, Stream: ri.Stream}
		}
		out := *c
		out.Roles, out.Data, out.Limits = roles, d, l
		return &out, nil
	})
	var he *httpErr
	switch {
	case errors.Is(err, errRevisionChanged):
		writeError(w, http.StatusConflict, "revision-changed", "someone changed the AI settings; read them again")
		return
	case errors.As(err, &he):
		writeError(w, he.status, he.code, he.msg)
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	var prev any
	if before != nil {
		prev = map[string]any{"roles": before.Roles, "data": before.Data, "limits": before.Limits}
	}
	s.audit(ws, "", "ai", "settings", "ai", prev, map[string]any{"roles": next.Roles, "data": next.Data, "limits": next.Limits})
	s.aiAudit(ws, store.AIAudit{Kind: "settings"})
	writeJSON(w, http.StatusOK, s.aiView())
}

var errRevisionChanged = errors.New("revision changed")

// GET /system/ai/usage?days=7 → {items, roles: {role: {hitRate}}}: daily
// counters summed over users, and each role's cache hit rate over the
// period (cache reads / all input tokens).
func (s *Server) handleGetAIUsage(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if !s.requireAdmin(w, r, ws) {
		return
	}
	days := 7
	if v := r.URL.Query().Get("days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 90 {
			writeError(w, http.StatusUnprocessableEntity, "invalid", "days: 1..90")
			return
		}
		days = n
	}
	since := s.now().UTC().AddDate(0, 0, -(days - 1)).Format("2006-01-02")
	rows, err := s.opt.Store.ListAIUsage(since)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	type k struct {
		day, role, provider, model string
		fallback                   bool
	}
	sum := map[k]*store.AIUsage{}
	var keys []k
	type rate struct{ read, all int64 }
	rates := map[string]*rate{}
	for _, u := range rows {
		kk := k{u.Day, u.Role, u.Provider, u.Model, u.Fallback}
		cur := sum[kk]
		if cur == nil {
			cur = &store.AIUsage{Day: u.Day, Role: u.Role, Provider: u.Provider, Model: u.Model, Fallback: u.Fallback}
			sum[kk] = cur
			keys = append(keys, kk)
		}
		cur.Requests += u.Requests
		cur.Input += u.Input
		cur.Output += u.Output
		cur.CacheRead += u.CacheRead
		cur.CacheWrite += u.CacheWrite
		rt := rates[u.Role]
		if rt == nil {
			rt = &rate{}
			rates[u.Role] = rt
		}
		rt.read += u.CacheRead
		rt.all += u.Input + u.CacheRead + u.CacheWrite
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.day != b.day {
			return a.day > b.day
		}
		return a.role+a.provider+a.model < b.role+b.provider+b.model
	})
	items := make([]*store.AIUsage, 0, len(keys))
	for _, kk := range keys {
		items = append(items, sum[kk])
	}
	roles := map[string]map[string]float64{}
	for _, name := range aiRoles {
		hr := 0.0
		if rt := rates[name]; rt != nil && rt.all > 0 {
			hr = float64(rt.read) / float64(rt.all)
		}
		roles[name] = map[string]float64{"hitRate": hr}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "roles": roles})
}

// GET /system/ai/audit?cursor=&limit= → {items, cursor?, total}.
func (s *Server) handleGetAIAudit(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if !s.requireAdmin(w, r, ws) {
		return
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			writeError(w, http.StatusUnprocessableEntity, "invalid", "limit: 1..500")
			return
		}
		limit = n
	}
	rows, next, total, err := s.opt.Store.ListAIAudit(r.URL.Query().Get("cursor"), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if rows == nil {
		rows = []*store.AIAudit{}
	}
	out := map[string]any{"items": camel{rows}, "total": total}
	if next != "" {
		out["cursor"] = next
	}
	writeJSON(w, http.StatusOK, out)
}

// DELETE /system/ai/audit {before} → {deleted}.
func (s *Server) handleDeleteAIAudit(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Before time.Time `json:"before"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !s.requireAdmin(w, r, ws) {
		return
	}
	if req.Before.IsZero() {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "before: an RFC 3339 time")
		return
	}
	n, err := s.opt.Store.DeleteAIAuditBefore(req.Before)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(ws, "", "ai", "audit-delete", "ai-audit", nil, map[string]any{"before": rfc3339(req.Before), "deleted": n})
	writeJSON(w, http.StatusOK, map[string]int{"deleted": n})
}

// aiCatalogTick reads a connected provider's catalog again once a day (and
// on start), so the role combo boxes and the 'not in the list' marks stay
// current.
func (s *Server) aiCatalogTick(ctx context.Context) {
	if !s.opt.Seal.Ready() {
		return
	}
	c := s.aiConfig()
	for _, p := range ai.Providers {
		pr := c.Providers[string(p)]
		if pr == nil || s.now().Sub(pr.CatalogAt) < 24*time.Hour {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		_ = s.refreshAICatalog(cctx, p)
		cancel()
	}
}
