// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jay94ks/mydcd/internal/web/mydc"
	"github.com/jay94ks/mydcd/internal/web/store"
)

// MCP servers (W2.3a, UI-B9): system administrators connect remote tool
// servers (bearer or no auth; OAuth later) and say per tool where it may be
// used. All mydc-web: the catalog is the web's own data, the token sits in
// the seal box, tool answers are never stored.

var (
	mcpNameRE     = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)
	mcpToolNameRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

func mcpTokenKey(name string) string { return "mcp-token-" + name }

var mcpIncidentUses = []string{"off", "diagnose", "notify", "propose-approve", "propose-auto"}

type mcpAuthReq struct {
	Kind  string  `json:"kind"`
	Token *string `json:"token,omitempty"`
}

func writeErrorWith(w http.ResponseWriter, status int, code, msg string, extra map[string]any) {
	e := map[string]any{"code": code, "message": msg}
	for k, v := range extra {
		e[k] = v
	}
	writeJSON(w, status, map[string]any{"error": e})
}

func writeMCPConnect(w http.ResponseWriter, err error) {
	msg := "connect failed"
	var me *mcpError
	if errors.As(err, &me) {
		msg = me.msg
	}
	writeErrorWith(w, http.StatusUnprocessableEntity, "mcp-connect", "the MCP server could not be reached (the answer body is not stored)", map[string]any{"error": msg})
}

// mcpCatalog connects and lists the tools.
func (s *Server) mcpCatalog(ctx context.Context, rawURL, token string) (*store.MCPInfo, []mcpListedTool, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*mcpTimeout)
	defer cancel()
	c, info, err := s.mcpDial(ctx, rawURL, token)
	if err != nil {
		return nil, nil, err
	}
	defer c.close()
	tools, err := c.listTools(ctx)
	if err != nil {
		return nil, nil, err
	}
	return &store.MCPInfo{ServerName: info.Name, Version: info.Version}, tools, nil
}

// mcpArgs lists inputSchema's properties, required first, then by name.
func mcpArgs(schema map[string]any) []store.MCPArg {
	props, _ := schema["properties"].(map[string]any)
	req := map[string]bool{}
	if rs, ok := schema["required"].([]any); ok {
		for _, r := range rs {
			if n, ok := r.(string); ok {
				req[n] = true
			}
		}
	}
	out := []store.MCPArg{}
	for name, p := range props {
		if utf8.RuneCountInString(name) > 64 {
			continue
		}
		a := store.MCPArg{Name: name, Required: req[name]}
		if m, ok := p.(map[string]any); ok {
			if t, ok := m["type"].(string); ok {
				a.Type = oneLine(t, 32)
			}
			if d, ok := m["description"].(string); ok {
				a.Description = oneLine(d, 300)
			}
		}
		out = append(out, a)
		if len(out) == 64 {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Required != out[j].Required {
			return out[i].Required
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// mergeTools brings the listed tools into the stored catalog: known tools
// keep their settings, new ones come in off (marked new when fresh is
// false), gone ones are dropped. A tool that stops being read-only stops
// being a read tool. changed: added or removed names.
func mergeTools(cur []*store.MCPTool, listed []mcpListedTool, fresh bool) (out []*store.MCPTool, added, removed []string, changed bool) {
	byName := map[string]*store.MCPTool{}
	for _, t := range cur {
		byName[t.Name] = t
	}
	seen := map[string]bool{}
	for _, l := range listed {
		if !mcpToolNameRE.MatchString(l.Name) || seen[l.Name] {
			continue
		}
		seen[l.Name] = true
		title := l.Title
		if title == "" {
			title = l.Annotations.Title
		}
		desc := strings.TrimSpace(l.Description)
		if utf8.RuneCountInString(desc) > mcpToolDescMax {
			desc = string([]rune(desc)[:mcpToolDescMax])
		}
		schema := l.InputSchema
		if raw, err := json.Marshal(schema); err != nil || len(raw) > 16<<10 {
			schema = nil
		}
		t := byName[l.Name]
		if t == nil {
			t = &store.MCPTool{Name: l.Name, Kind: "change", Incident: "off", AllTenants: true, New: !fresh}
			if l.Annotations.ReadOnlyHint {
				t.Kind = "read"
			}
			added = append(added, l.Name)
		} else {
			cp := *t
			t = &cp
			if t.Description != desc || t.ReadOnlyHint != l.Annotations.ReadOnlyHint {
				changed = true
			}
		}
		t.Title, t.Description, t.ReadOnlyHint, t.Schema, t.Args = oneLine(title, 100), desc, l.Annotations.ReadOnlyHint, schema, mcpArgs(l.InputSchema)
		if !t.ReadOnlyHint && t.Kind == "read" {
			t.Kind = "change"
			if t.Incident == "diagnose" {
				t.Incident = "off"
			}
		}
		out = append(out, t)
	}
	for _, t := range cur {
		if !seen[t.Name] {
			removed = append(removed, t.Name)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, added, removed, changed || len(added) > 0 || len(removed) > 0
}

// mcpUsedBy: the guideline scopes that name the server.
func (s *Server) mcpUsedBy(name string) []string {
	out := []string{}
	gs, _ := s.opt.Store.ListGuides()
	for _, g := range gs {
		if slices.Contains(g.Fields.MCPServers, name) {
			out = append(out, g.Scope)
		}
	}
	sort.Strings(out)
	return out
}

func (s *Server) mcpView(m *store.MCPServer) map[string]any {
	auth := map[string]any{"kind": m.Auth, "set": m.Auth == "bearer" || m.Auth == "oauth"}
	if m.Auth == "oauth" {
		if !m.TokenExpiresAt.IsZero() {
			auth["expiresAt"] = rfc3339(m.TokenExpiresAt)
		}
		if m.NeedsLogin {
			auth["needsLogin"] = true
		}
	}
	if m.TokenLast4 != "" {
		auth["last4"] = m.TokenLast4
	}
	tools := []map[string]any{}
	for _, t := range m.Tools {
		v := map[string]any{"name": t.Name, "description": t.Description, "readOnlyHint": t.ReadOnlyHint, "args": t.Args, "kind": t.Kind,
			"coordinator": t.Coordinator, "incident": t.Incident, "new": t.New}
		if t.Args == nil {
			v["args"] = []store.MCPArg{}
		}
		if t.Title != "" {
			v["title"] = t.Title
		}
		if t.AllTenants {
			v["tenants"] = "all"
		} else {
			v["tenants"] = append([]string{}, t.Tenants...)
		}
		if t.Auto != nil {
			v["auto"] = t.Auto
		}
		if t.Hint != "" {
			v["hint"] = t.Hint
		}
		tools = append(tools, v)
	}
	v := map[string]any{"name": m.Name, "url": m.URL, "auth": auth, "enabled": m.Enabled, "state": m.State, "catalogRevision": m.CatalogRevision,
		"tools": tools, "users": map[string]any{"systemAdmins": true, "tenants": append([]string{}, m.Users.Tenants...)},
		"usedBy": s.mcpUsedBy(m.Name), "createdBy": m.CreatedBy, "createdAt": rfc3339(m.CreatedAt), "revision": m.Revision}
	if m.Error != "" {
		v["error"] = m.Error
	}
	if !m.CheckedAt.IsZero() {
		v["checkedAt"] = rfc3339(m.CheckedAt)
	}
	if m.Info != nil {
		v["info"] = m.Info
	}
	return v
}

// GET /system/mcp
func (s *Server) handleListMCP(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if !s.requireAdmin(w, r, ws) {
		return
	}
	all, err := s.opt.Store.ListMCPServers()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	out := []map[string]any{}
	for _, m := range all {
		out = append(out, s.mcpView(m))
	}
	writeJSON(w, http.StatusOK, map[string]any{"servers": out})
}

func checkMCPAuth(a *mcpAuthReq, had bool) string {
	switch a.Kind {
	case "oauth":
		return "auth.kind: oauth is set up with POST /system/mcp or …/oauth/login"
	case "none":
		if a.Token != nil {
			return "auth.token: only with bearer"
		}
	case "bearer":
		if a.Token == nil && !had {
			return "auth.token: required for bearer"
		}
		if a.Token != nil && !validToken(*a.Token) {
			return "auth.token: 1 to 512 printable characters"
		}
	default:
		return "auth.kind: bearer, oauth or none"
	}
	return ""
}

func checkMCPUsers(u *store.MCPUsers) string {
	if len(u.Tenants) > 100 {
		return "users.tenants: at most 100"
	}
	for _, t := range u.Tenants {
		if !safeParamRE.MatchString(t) {
			return "users.tenants: " + oneLine(t, 64) + " is not a workspace name"
		}
	}
	slices.Sort(u.Tenants)
	u.Tenants = slices.Compact(u.Tenants)
	return ""
}

// POST /system/mcp {name, url, auth:{kind, token?}, users?}
func (s *Server) handleCreateMCP(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Name  string          `json:"name"`
		URL   string          `json:"url"`
		Auth  mcpAuthReq      `json:"auth"`
		Users *store.MCPUsers `json:"users,omitempty"`
	}
	if !readJSON(w, r, &req) || !s.requireAdmin(w, r, ws) {
		return
	}
	users := store.MCPUsers{Tenants: []string{}}
	if req.Users != nil {
		users = *req.Users
	}
	msg := ""
	oauth := req.Auth.Kind == "oauth"
	switch {
	case oauth && req.Auth.Token != nil:
		msg = "auth.token: not with oauth"
	case !mcpNameRE.MatchString(req.Name):
		msg = "name: a lowercase letter, then lowercase letters, digits and -, at most 31"
	case s.checkWebhookURL(req.URL) != "":
		msg = s.checkWebhookURL(req.URL)
	case !oauth && checkMCPAuth(&req.Auth, false) != "":
		msg = checkMCPAuth(&req.Auth, false)
	default:
		msg = checkMCPUsers(&users)
	}
	if msg != "" {
		writeError(w, http.StatusUnprocessableEntity, "invalid", msg)
		return
	}
	if _, err := s.opt.Store.GetMCPServer(req.Name); err == nil {
		writeError(w, http.StatusConflict, "exists", "an MCP server with this name exists")
		return
	}
	if oauth {
		// Nothing is stored until the callback brings a token.
		l, err := s.mcpOAuthStart(r.Context(), r, ws, req.Name, req.URL, users, false)
		if err != nil {
			writeMCPConnect(w, err)
			return
		}
		s.audit(ws, "", "mcp", "oauth-login-start", req.Name, nil, map[string]any{"url": req.URL})
		s.writeOAuthLogin(w, http.StatusAccepted, l)
		return
	}
	token := ""
	if req.Auth.Token != nil {
		token = *req.Auth.Token
	}
	info, listed, err := s.mcpCatalog(r.Context(), req.URL, token)
	if err != nil {
		writeMCPConnect(w, err)
		return
	}
	tools, _, _, _ := mergeTools(nil, listed, true)
	m := &store.MCPServer{Name: req.Name, URL: req.URL, Auth: req.Auth.Kind, TokenLast4: last4(token), Enabled: true, State: "ok", CheckedAt: s.now(),
		Info: info, Users: users, Tools: tools, CatalogRevision: 1, CreatedBy: ws.user.Username, CreatedAt: s.now()}
	if m.Tools == nil {
		m.Tools = []*store.MCPTool{}
	}
	_ = s.opt.Seal.Delete(mcpTokenKey(m.Name))
	if token != "" {
		if err := s.opt.Seal.Put(mcpTokenKey(m.Name), []byte(token)); err != nil {
			writeError(w, http.StatusInternalServerError, "internal", "could not seal the token")
			return
		}
	}
	if err := s.opt.Store.CreateMCPServer(m); errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "exists", "an MCP server with this name exists")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(ws, "", "mcp", "create", m.Name, nil, map[string]any{"url": m.URL, "auth": m.Auth, "tools": len(m.Tools)})
	writeJSON(w, http.StatusCreated, s.mcpView(m))
}

type mcpToolPatch struct {
	Kind        *string         `json:"kind,omitempty"`
	Coordinator *bool           `json:"coordinator,omitempty"`
	Incident    *string         `json:"incident,omitempty"`
	Tenants     json.RawMessage `json:"tenants,omitempty"`
	Auto        *store.MCPAuto  `json:"auto,omitempty"`
	Hint        *string         `json:"hint,omitempty"`
}

// autoMissing: what a propose-auto tool still lacks (the screen shows the
// same list).
func autoMissing(t *store.MCPTool, a *store.MCPAuto) []string {
	if a == nil {
		return []string{"영향 등급 하한", "입력 제한", "한도", "되돌리기"}
	}
	var out []string
	if a.Floor == "" {
		out = append(out, "영향 등급 하한")
	}
	if len(t.Args) == 0 || slices.ContainsFunc(t.Args, func(x store.MCPArg) bool { _, ok := a.Inputs[x.Name]; return !ok }) {
		out = append(out, "입력 제한")
	}
	if a.PerIncident < 1 || a.PerDay < 1 {
		out = append(out, "한도")
	}
	if a.Revert.Tool == "" && !a.Revert.Irreversible {
		out = append(out, "되돌리기")
	}
	if a.Revert.Irreversible && a.Floor == impactLow {
		out = append(out, "되돌릴 수 없으면 하한 보통 이상")
	}
	return out
}

// checkAuto validates the shape of auto ("" = fine; completeness is
// autoMissing's).
func checkAuto(m *store.MCPServer, t *store.MCPTool, a *store.MCPAuto) string {
	if a.Floor != "" && a.Floor != impactLow && a.Floor != impactMedium && a.Floor != impactHigh {
		return "auto.floor: low, medium or high"
	}
	if len(a.Inputs) > 64 {
		return "auto.inputs: at most 64"
	}
	for n, in := range a.Inputs {
		if !slices.ContainsFunc(t.Args, func(x store.MCPArg) bool { return x.Name == n }) {
			return "auto.inputs: " + oneLine(n, 64) + " is not an argument of the tool"
		}
		switch in.Kind {
		case "max", "incident", "template", "fixed":
		default:
			return "auto.inputs." + n + ": kind max, incident, template or fixed"
		}
		if utf8.RuneCountInString(in.Value) > 500 || strings.ContainsAny(in.Value, "\r\n") {
			return "auto.inputs." + n + ": value at most 500 characters on one line"
		}
		if in.Kind == "incident" && !slices.Contains(mcpIncidentFields, in.Value) {
			return "auto.inputs." + n + ": incident value one of " + strings.Join(mcpIncidentFields, ", ")
		}
	}
	if a.PerIncident < 0 || a.PerIncident > 10 || a.PerDay < 0 || a.PerDay > 100 {
		return "auto: perIncident 1 to 10, perDay 1 to 100"
	}
	if a.Revert.Tool != "" && a.Revert.Irreversible {
		return "auto.revert: a tool or irreversible, not both"
	}
	if a.Revert.Tool != "" && (a.Revert.Tool == t.Name || m.Tool(a.Revert.Tool) == nil) {
		return "auto.revert.tool: another tool of this server"
	}
	if len(a.Signals) > 16 {
		return "auto.signals: at most 16"
	}
	for _, sg := range a.Signals {
		if sg == "" || utf8.RuneCountInString(sg) > 64 {
			return "auto.signals: 1 to 64 characters each"
		}
	}
	return ""
}

// mcpIncidentFields: what an "incident" input may fill from.
var mcpIncidentFields = []string{"id", "tenant", "app", "node", "target", "signal", "title"}

// applyToolPatch changes t in place (code, message on failure).
func applyToolPatch(m *store.MCPServer, t *store.MCPTool, p mcpToolPatch) (string, string, map[string]any) {
	if p.Kind != nil {
		switch *p.Kind {
		case "read", "change", "notify":
		default:
			return "invalid", "kind: read, change or notify", nil
		}
		if *p.Kind == "read" && !t.ReadOnlyHint {
			return "kind", "kind: a tool the server does not mark read-only cannot be a read tool", nil
		}
		t.Kind = *p.Kind
	}
	if p.Coordinator != nil {
		t.Coordinator = *p.Coordinator
	}
	if p.Incident != nil {
		if !slices.Contains(mcpIncidentUses, *p.Incident) {
			return "invalid", "incident: " + strings.Join(mcpIncidentUses, ", "), nil
		}
		t.Incident = *p.Incident
	}
	if len(p.Tenants) > 0 {
		var all string
		var list []string
		if json.Unmarshal(p.Tenants, &all) == nil && all == "all" {
			t.AllTenants, t.Tenants = true, nil
		} else if json.Unmarshal(p.Tenants, &list) == nil {
			u := store.MCPUsers{Tenants: list}
			if msg := checkMCPUsers(&u); msg != "" {
				return "invalid", strings.Replace(msg, "users.tenants", "tenants", 1), nil
			}
			t.AllTenants, t.Tenants = false, u.Tenants
		} else {
			return "invalid", `tenants: "all" or a list of workspaces`, nil
		}
	}
	if p.Auto != nil {
		if msg := checkAuto(m, t, p.Auto); msg != "" {
			return "invalid", msg, nil
		}
		t.Auto = p.Auto
	}
	if p.Hint != nil {
		if utf8.RuneCountInString(*p.Hint) > 500 {
			return "invalid", "hint: at most 500 characters", nil
		}
		t.Hint = strings.TrimSpace(*p.Hint)
	}
	switch {
	case t.Incident == "diagnose" && t.Kind != "read":
		return "invalid", "incident: diagnose is for read tools", nil
	case t.Incident == "notify" && t.Kind == "read":
		return "invalid", "incident: notify is for change or notify tools", nil
	case strings.HasPrefix(t.Incident, "propose-") && t.Kind == "read":
		return "invalid", "incident: proposals are for change or notify tools", nil
	}
	if t.Incident == "propose-auto" {
		if miss := autoMissing(t, t.Auto); len(miss) > 0 {
			return "auto-incomplete", "빠진 것: " + strings.Join(miss, ", "), map[string]any{"missing": miss}
		}
	}
	t.New = false
	return "", "", nil
}

func (s *Server) loadMCP(w http.ResponseWriter, r *http.Request, ws *webSession) (*store.MCPServer, bool) {
	if !s.requireAdmin(w, r, ws) {
		return nil, false
	}
	m, err := s.opt.Store.GetMCPServer(r.PathValue("name"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not-found", "no such MCP server")
		return nil, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return nil, false
	}
	return m, true
}

func (s *Server) mcpToken(m *store.MCPServer) (string, error) {
	if m.Auth == "oauth" {
		return s.mcpOAuthToken(m)
	}
	if m.Auth != "bearer" {
		return "", nil
	}
	b, err := s.opt.Seal.Get(mcpTokenKey(m.Name))
	if err != nil {
		return "", mcpErrorf("the sealed token could not be read; enter it again")
	}
	return string(b), nil
}

// PUT /system/mcp/{name} {revision, url?, auth?, users?, enabled?, tools?}
func (s *Server) handlePutMCP(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Revision uint64                  `json:"revision"`
		URL      *string                 `json:"url,omitempty"`
		Auth     *mcpAuthReq             `json:"auth,omitempty"`
		Users    *store.MCPUsers         `json:"users,omitempty"`
		Enabled  *bool                   `json:"enabled,omitempty"`
		Tools    map[string]mcpToolPatch `json:"tools,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	cur, ok := s.loadMCP(w, r, ws)
	if !ok {
		return
	}
	if req.Revision != cur.Revision {
		writeError(w, http.StatusConflict, "stale", "the MCP server changed; read it again")
		return
	}
	if req.URL != nil {
		if msg := s.checkWebhookURL(*req.URL); msg != "" {
			writeError(w, http.StatusUnprocessableEntity, "invalid", msg)
			return
		}
	}
	if req.Auth != nil {
		if msg := checkMCPAuth(req.Auth, cur.Auth == "bearer"); msg != "" {
			writeError(w, http.StatusUnprocessableEntity, "invalid", msg)
			return
		}
	}
	if req.URL != nil && cur.Auth == "bearer" && hostOf(*req.URL) != hostOf(cur.URL) && (req.Auth == nil || req.Auth.Kind == "bearer" && req.Auth.Token == nil) {
		// The sealed token was given for the old host only.
		writeError(w, http.StatusUnprocessableEntity, "token-required", "auth.token: enter the token again for a new host")
		return
	}
	if req.URL != nil && cur.Auth == "oauth" && (req.Auth == nil || req.Auth.Kind == "oauth") && *req.URL != cur.URL {
		// The token was issued for the old address (resource) only.
		writeError(w, http.StatusUnprocessableEntity, "login-required", "url: an OAuth server is moved by connecting it again")
		return
	}
	if req.Users != nil {
		if msg := checkMCPUsers(req.Users); msg != "" {
			writeError(w, http.StatusUnprocessableEntity, "invalid", msg)
			return
		}
	}
	if len(req.Tools) > mcpMaxTools {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "tools: too many")
		return
	}
	// A new address or token is tried first, and the catalog read again.
	var info *store.MCPInfo
	var listed []mcpListedTool
	token, newToken := "", false
	reconnect := (req.URL != nil && *req.URL != cur.URL) || req.Auth != nil
	if reconnect {
		u := cur.URL
		if req.URL != nil {
			u = *req.URL
		}
		var err error
		switch {
		case req.Auth != nil && req.Auth.Token != nil:
			token, newToken = *req.Auth.Token, true
		case req.Auth != nil && req.Auth.Kind == "none":
		default:
			if token, err = s.mcpToken(cur); err != nil {
				writeMCPConnect(w, err)
				return
			}
		}
		if info, listed, err = s.mcpCatalog(r.Context(), u, token); err != nil {
			writeMCPConnect(w, err)
			return
		}
	}
	var code, msg string
	var extra map[string]any
	var added, removed []string
	m, err := s.opt.Store.UpdateMCPServer(cur.Name, req.Revision, func(m *store.MCPServer) error {
		if reconnect {
			if req.URL != nil {
				m.URL = *req.URL
			}
			if req.Auth != nil {
				m.Auth = req.Auth.Kind
				m.TokenExpiresAt, m.NeedsLogin = time.Time{}, false
				if m.Auth == "none" {
					m.TokenLast4 = ""
				} else if newToken {
					m.TokenLast4 = last4(token)
				}
			}
			var changed bool
			m.Tools, added, removed, changed = mergeTools(m.Tools, listed, false)
			if changed {
				m.CatalogRevision++
			}
			m.Info, m.State, m.Error, m.CheckedAt = info, "ok", "", s.now()
		}
		if req.Users != nil {
			m.Users = *req.Users
		}
		if req.Enabled != nil {
			m.Enabled = *req.Enabled
		}
		names := make([]string, 0, len(req.Tools))
		for n := range req.Tools {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			t := m.Tool(n)
			if t == nil {
				code, msg = "invalid", "tools: no such tool "+oneLine(n, 64)
				return errMCPReject
			}
			if code, msg, extra = applyToolPatch(m, t, req.Tools[n]); code != "" {
				msg = n + ": " + msg
				return errMCPReject
			}
		}
		// A revert tool that went away, or a change that left propose-auto
		// incomplete, is checked on the whole catalog.
		for _, t := range m.Tools {
			if t.Incident == "propose-auto" {
				if t.Auto != nil && t.Auto.Revert.Tool != "" && m.Tool(t.Auto.Revert.Tool) == nil {
					t.Incident = "propose-approve"
				}
			}
		}
		return nil
	})
	if errors.Is(err, errMCPReject) {
		writeErrorWith(w, http.StatusUnprocessableEntity, code, msg, extra)
		return
	}
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "stale", "the MCP server changed; read it again")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if req.Auth != nil {
		if cur.Auth == "oauth" && m.Auth != "oauth" {
			_ = s.opt.Seal.Delete(mcpOAuthKey(m.Name))
		}
		if req.Auth.Kind == "none" {
			_ = s.opt.Seal.Delete(mcpTokenKey(m.Name))
		} else if newToken {
			if err := s.opt.Seal.Put(mcpTokenKey(m.Name), []byte(token)); err != nil {
				writeError(w, http.StatusInternalServerError, "internal", "could not seal the token")
				return
			}
		}
	}
	s.audit(ws, "", "mcp", "update", m.Name, nil, map[string]any{"url": m.URL, "auth": m.Auth, "enabled": m.Enabled, "tools": len(req.Tools), "tokenChanged": newToken})
	if len(added) > 0 || len(removed) > 0 {
		s.notifyMCPTools(r.Context(), ws, m, added, removed)
	}
	writeJSON(w, http.StatusOK, s.mcpView(m))
}

var errMCPReject = errors.New("mcp: rejected")

// POST /system/mcp/{name}/refresh
func (s *Server) handleRefreshMCP(w http.ResponseWriter, r *http.Request, ws *webSession) {
	cur, ok := s.loadMCP(w, r, ws)
	if !ok {
		return
	}
	token, err := s.mcpToken(cur)
	var info *store.MCPInfo
	var listed []mcpListedTool
	if err == nil {
		info, listed, err = s.mcpCatalog(r.Context(), cur.URL, token)
	}
	var added, removed []string
	m, uerr := s.opt.Store.UpdateMCPServer(cur.Name, 0, func(m *store.MCPServer) error {
		m.CheckedAt = s.now()
		if err != nil {
			m.State, m.Error = "error", fmt.Sprint(err)
			var me *mcpError
			if errors.As(err, &me) {
				m.Error = me.msg
			}
			return nil
		}
		var changed bool
		m.Tools, added, removed, changed = mergeTools(m.Tools, listed, false)
		if changed {
			m.CatalogRevision++
		}
		m.Info, m.State, m.Error = info, "ok", ""
		return nil
	})
	if uerr != nil {
		writeError(w, http.StatusInternalServerError, "internal", uerr.Error())
		return
	}
	if err != nil {
		writeMCPConnect(w, err)
		return
	}
	if len(added) > 0 || len(removed) > 0 {
		s.notifyMCPTools(r.Context(), ws, m, added, removed)
	}
	writeJSON(w, http.StatusOK, s.mcpView(m))
}

// notifyMCPTools tells the system administrators that the catalog changed
// (new tools come in off).
func (s *Server) notifyMCPTools(ctx context.Context, ws *webSession, m *store.MCPServer, added, removed []string) {
	var users []string
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err := ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		after := ""
		for range incidentMaxPages {
			p, err := c.Users(ctx, after)
			if err != nil {
				return err
			}
			for _, u := range p.Items {
				if u.SystemAdmin && u.Enabled {
					users = append(users, u.ID)
				}
			}
			if p.Next == "" {
				return nil
			}
			after = p.Next
		}
		return nil
	})
	if err != nil {
		s.log.Warn("mcp notify", "err", err)
		users = []string{ws.user.ID}
	}
	var parts []string
	if len(added) > 0 {
		parts = append(parts, fmt.Sprintf("새 도구 %d개(꺼진 채): %s", len(added), strings.Join(added, ", ")))
	}
	if len(removed) > 0 {
		parts = append(parts, fmt.Sprintf("없어진 도구 %d개: %s", len(removed), strings.Join(removed, ", ")))
	}
	for _, u := range users {
		s.notify(&store.Notification{User: u, Kind: NotifyMCPToolsChanged, Severity: "info", Title: "MCP 서버 " + m.Name + "의 도구가 바뀌었어요",
			Body: oneLine(strings.Join(parts, " · "), 500), Link: "/system/ai/mcp", Action: len(added) > 0})
	}
}

// DELETE /system/mcp/{name} {confirmName}
func (s *Server) handleDeleteMCP(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		ConfirmName string `json:"confirmName"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	m, ok := s.loadMCP(w, r, ws)
	if !ok {
		return
	}
	if req.ConfirmName != m.Name {
		writeError(w, http.StatusUnprocessableEntity, "confirm-name", "type the server's name to delete it")
		return
	}
	used := s.mcpUsedBy(m.Name)
	if err := s.opt.Store.DeleteMCPServer(m.Name); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	_ = s.opt.Seal.Delete(mcpTokenKey(m.Name))
	_ = s.opt.Seal.Delete(mcpOAuthKey(m.Name))
	s.mcpOAuth.mu.Lock()
	if l := s.mcpOAuth.logins[m.Name]; l != nil {
		delete(s.mcpOAuth.byState, l.state)
		delete(s.mcpOAuth.logins, m.Name)
	}
	s.mcpOAuth.mu.Unlock()
	s.audit(ws, "", "mcp", "delete", m.Name, nil, map[string]any{"usedBy": used})
	w.WriteHeader(http.StatusNoContent)
}

// mcpUsable: the server may be used for tenant ("" = cluster scope, system
// administrators).
func mcpUsable(m *store.MCPServer, tenant string) bool {
	return tenant == "" || slices.Contains(m.Users.Tenants, tenant)
}

// mcpToolFor: the tool may be used for an incident of tenant.
func mcpToolFor(m *store.MCPServer, t *store.MCPTool, tenant string) bool {
	return m.Enabled && mcpUsable(m, tenant) && (t.AllTenants || tenant == "" || slices.Contains(t.Tenants, tenant))
}

// mcpFill is what an input would get for an incident (dry run).
func mcpFill(in *store.Incident, x store.MCPInput) string {
	switch x.Kind {
	case "fixed":
		return x.Value
	case "max":
		return "최대 " + x.Value
	case "incident":
		return incidentField(in, x.Value)
	}
	out := x.Value
	for _, f := range mcpIncidentFields {
		out = strings.ReplaceAll(out, "{"+f+"}", incidentField(in, f))
	}
	return out
}

func incidentField(in *store.Incident, f string) string {
	switch f {
	case "id":
		return in.ID
	case "tenant":
		return in.Tenant
	case "app":
		return in.App
	case "node":
		return in.Node
	case "target":
		return in.Target
	case "signal":
		return in.Signal
	case "title":
		return in.Title
	}
	return ""
}

var impactWords = map[string]string{impactLow: "낮음", impactMedium: "보통", impactHigh: "높음"}

// POST /system/mcp/{name}/tools/{tool}/test {incident}: what incident
// response would have done with the tool for a past incident. The tool is
// not called.
func (s *Server) handleTestMCPTool(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Incident string `json:"incident"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	m, ok := s.loadMCP(w, r, ws)
	if !ok {
		return
	}
	t := m.Tool(r.PathValue("tool"))
	if t == nil {
		writeError(w, http.StatusNotFound, "not-found", "no such tool")
		return
	}
	in, err := s.opt.Store.GetIncident(req.Incident)
	if req.Incident == "" || errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "incident: no such incident")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	name := "mcp." + m.Name + "." + t.Name
	steps := []map[string]any{{"label": in.ID + " 불러옴", "detail": in.Title}}
	result := ""
	switch {
	case t.Incident == "off":
		result = "이 도구는 장애 대응에 쓰지 않았을 것"
	case !mcpToolFor(m, t, in.Tenant):
		steps = append(steps, map[string]any{"label": "쓸 범위", "detail": "이 사건의 작업 공간에는 쓸 수 없음"})
		result = "이 도구는 쓰지 않았을 것"
	case t.Incident == "diagnose":
		steps = append(steps, map[string]any{"label": "진단 A", "detail": name + "을(를) 읽어 진단에 씀"})
		result = "진단에서 읽었을 것 · 실제 호출 안 함"
	case t.Incident == "notify":
		steps = append(steps, map[string]any{"label": "알림", "detail": name + "(으)로 사건 요약을 보냄"})
		result = "알림을 보냈을 것 · 실제 호출 안 함"
	default:
		var args []string
		if t.Auto != nil {
			for _, a := range t.Args {
				if x, ok := t.Auto.Inputs[a.Name]; ok {
					args = append(args, a.Name+" "+mcpFill(in, x))
				}
			}
		}
		steps = append(steps, map[string]any{"label": "진단 A", "detail": strings.TrimSpace(name + " 제안 " + strings.Join(args, " · "))})
		floor := impactMedium
		if t.Auto != nil && t.Auto.Floor != "" {
			floor = t.Auto.Floor
		}
		steps = append(steps, map[string]any{"label": "영향 평가 B", "detail": fmt.Sprintf("하한 %s (규칙·영향 평가가 더 높게 볼 수 있음)", impactWords[floor])})
		auto := t.Incident == "propose-auto" && floor == impactLow
		if auto {
			cluster, err := s.clusterPolicy()
			level := incidentOff
			if err == nil {
				level = effectiveClusterLevel(cluster)
				if in.Scope == "app" {
					if p, err := s.appPolicy(in.Tenant, in.App, cluster); err == nil && levelRank(p.Level) < levelRank(level) {
						level = p.Level
					}
				}
			}
			if level != incidentAutoLow {
				steps = append(steps, map[string]any{"label": "정책", "detail": "자동 실행 수준이 아님"})
				auto = false
			}
		}
		if auto {
			result = "자동 실행했을 것 · 실제 호출 안 함"
		} else {
			result = "승인 요청을 만들었을 것 · 실제 호출 안 함"
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"steps": steps, "result": result})
}

// mcpChoices: the servers a guideline scope may name (tenant "" = cluster).
func (s *Server) mcpChoices(tenant string) []map[string]any {
	out := []map[string]any{}
	all, _ := s.opt.Store.ListMCPServers()
	for _, m := range all {
		if !mcpUsable(m, tenant) {
			continue
		}
		read, change := 0, 0
		for _, t := range m.Tools {
			if t.Kind == "read" {
				read++
			} else {
				change++
			}
		}
		state := m.State
		if !m.Enabled {
			state = "off"
		}
		out = append(out, map[string]any{"name": m.Name, "summary": fmt.Sprintf("도구 %d개 (읽기 %d · 바꾸기 %d)", len(m.Tools), read, change), "state": state})
	}
	return out
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Host)
}
