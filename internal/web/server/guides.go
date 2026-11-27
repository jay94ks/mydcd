// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/jay94ks/seafield/internal/web/ai"
	"github.com/jay94ks/seafield/internal/web/sfc"
	"github.com/jay94ks/seafield/internal/web/store"
)

// Incident response guidelines (W2.3a, UI-BA). Cluster guidelines are the
// system administrators', workspace and app guidelines the workspace
// managers'. They go to diagnosis and the coordinator as people's
// instructions, but the code keeps their limits: they cannot add actions,
// lower grades or lift what a higher scope ruled out, and the impact
// assessment only gets the fields that raise or block.

const guideTextMax = 4000

// guideScope is a parsed scope.
type guideScope struct {
	Scope, Tenant, App string
}

func (g guideScope) kind() string {
	switch {
	case g.App != "":
		return "app"
	case g.Tenant != "":
		return "tenant"
	}
	return "cluster"
}

func scopeOf(r *http.Request) guideScope {
	t, app := r.PathValue("t"), r.PathValue("app")
	switch {
	case app != "":
		return guideScope{"app/" + t + "/" + app, t, app}
	case t != "":
		return guideScope{"tenant/" + t, t, ""}
	}
	return guideScope{Scope: "cluster"}
}

// upper lists the scopes above g, highest first.
func (g guideScope) upper() []guideScope {
	switch g.kind() {
	case "app":
		return []guideScope{{Scope: "cluster"}, {"tenant/" + g.Tenant, g.Tenant, ""}}
	case "tenant":
		return []guideScope{{Scope: "cluster"}}
	}
	return nil
}

// guideStack is the scopes an incident uses: cluster, then the workspace
// and the app for an app incident.
func guideStack(in *store.Incident) []guideScope {
	if in.Scope != "app" {
		return []guideScope{{Scope: "cluster"}}
	}
	return []guideScope{{Scope: "cluster"}, {"tenant/" + in.Tenant, in.Tenant, ""}, {"app/" + in.Tenant + "/" + in.App, in.Tenant, in.App}}
}

// canGuide: read (manage=false) or change a scope, as sfcd says.
func (a incidentAccess) canGuide(g guideScope, manage bool) bool {
	if g.Tenant == "" {
		return a.admin
	}
	role := a.roles[g.Tenant]
	return role != "" && (!manage || role == sfc.RoleManager)
}

func (s *Server) guideAccess(w http.ResponseWriter, r *http.Request, ws *webSession, g guideScope, manage bool) bool {
	if g.Tenant != "" && (!safeParamRE.MatchString(g.Tenant) || g.App != "" && !safeParamRE.MatchString(g.App)) {
		writeError(w, http.StatusNotFound, "not-found", "no such scope")
		return false
	}
	acc, err := s.incidentAccessOf(r, ws)
	if err != nil {
		s.writeBackendError(w, ws, err)
		return false
	}
	if !acc.canGuide(g, false) {
		writeError(w, http.StatusNotFound, "not-found", "no such scope")
		return false
	}
	if manage && !acc.canGuide(g, true) {
		writeError(w, http.StatusForbidden, "denied", "only the workspace's managers (workspace and app guidelines) or system administrators (cluster guidelines)")
		return false
	}
	return true
}

// guideSummary is the first non-empty line quoted, "외 N줄" for the rest.
func guideSummary(text string) (string, int) {
	var lines []string
	for _, l := range strings.Split(text, "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, strings.TrimSpace(l))
		}
	}
	if len(lines) == 0 {
		return "", 0
	}
	out := fmt.Sprintf("“%s”", oneLine(strings.TrimLeft(lines[0], "#-* "), 80))
	if len(lines) > 1 {
		out += fmt.Sprintf(" 외 %d줄", len(lines)-1)
	}
	return out, len(lines)
}

// Sentences that ask for what guidelines cannot do (checked on save; a
// warning, not a refusal).
var guideWarnRE = []struct {
	re  *regexp.Regexp
	why string
}{
	{regexp.MustCompile(`(?i)재부팅|reboot|재시작해\s*서버|ssh`), "은(는) 임시 조치 목록에 없어 AI가 고를 수 없습니다. 지침에서 빼거나 사람이 할 일로 적으세요."},
	{regexp.MustCompile(`(?i)삭제|지우|delete|drop\s+table|rm\s+-rf|prune`), "처럼 지우는 일은 장애 대응이 하지 않습니다. 사람이 할 일로 적으세요."},
	{regexp.MustCompile(`(?i)비밀번호|비밀값|password|secret|token|토큰|api\s*key`), "처럼 비밀값을 요구하는 문장은 따르지 않습니다."},
	{regexp.MustCompile(`(?i)(등급|영향).{0,8}(낮|low)|자동으로\s*(실행|승인)|승인\s*없이|without\s+approval`), "처럼 영향 등급·자동 실행 조건을 바꾸는 문장은 따르지 않습니다. 정책에서 정하세요."},
}

type guideWarning struct {
	Line int    `json:"line"`
	Text string `json:"text"`
}

func guideWarnings(text string) []guideWarning {
	out := []guideWarning{}
	for i, l := range strings.Split(text, "\n") {
		for _, w := range guideWarnRE {
			if m := w.re.FindString(l); m != "" {
				out = append(out, guideWarning{Line: i + 1, Text: fmt.Sprintf("“%s”%s", oneLine(strings.TrimSpace(l), 60), w.why)})
				break
			}
		}
	}
	return out
}

// upperAvoid is what the scopes above g rule out: action → the scope kind.
func (s *Server) upperAvoid(g guideScope) map[string]string {
	out := map[string]string{}
	for _, u := range g.upper() {
		cur, err := s.opt.Store.GetGuide(u.Scope)
		if err != nil || cur == nil {
			continue
		}
		for _, a := range cur.Fields.Avoid.Actions {
			if _, ok := out[a]; !ok {
				out[a] = u.kind()
			}
		}
	}
	return out
}

type guideActionChoice struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	BlockedBy string `json:"blockedBy,omitempty"`
}

// guideChoices: what the scope may pick (workspace managers cannot read
// the cluster policy or MCP settings themselves).
func (s *Server) guideChoices(ctx context.Context, ws *webSession, g guideScope) map[string]any {
	blocked := s.upperAvoid(g)
	actions := []guideActionChoice{}
	for _, a := range incidentActions {
		if g.kind() != "cluster" && a.Scope != "app" {
			continue
		}
		actions = append(actions, guideActionChoice{ID: a.ID, Label: a.Label, BlockedBy: blocked[a.ID]})
	}
	services := []string{}
	if g.App != "" {
		var src sfc.AppSource
		if err := ws.do(ctx, func(ctx context.Context, c sfc.Conn) error {
			var err error
			src, err = c.AppSource(ctx, g.Tenant, g.App, 0)
			return err
		}); err == nil {
			var doc struct {
				Services map[string]any `yaml:"services"`
			}
			if yaml.Unmarshal(src.Document, &doc) == nil {
				for name := range doc.Services {
					services = append(services, name)
				}
				slices.Sort(services)
			}
		}
	}
	return map[string]any{"actions": actions, "services": services, "mcpServers": s.mcpChoices(g.Tenant)}
}

func emptyGuide(g guideScope) *store.Guide {
	return &store.Guide{Scope: g.Scope, Tenant: g.Tenant, App: g.App, Deliver: store.GuideTo{Diagnose: true, Coordinator: true}}
}

func normFields(f *store.GuideFields) {
	for _, p := range []*[]string{&f.Prefer, &f.Avoid.Actions, &f.Avoid.Services, &f.MCPServers, &f.Notify, &f.Critical} {
		if *p == nil {
			*p = []string{}
		}
	}
}

func (s *Server) guideView(ctx context.Context, ws *webSession, g guideScope, cur *store.Guide) map[string]any {
	if cur == nil {
		cur = emptyGuide(g)
	}
	normFields(&cur.Fields)
	sum, lines := guideSummary(cur.Text)
	v := map[string]any{"scope": g.Scope, "version": cur.Version, "revision": cur.Version, "text": cur.Text, "fields": cur.Fields, "deliver": cur.Deliver,
		"warnings": guideWarnings(cur.Text), "summary": sum, "lines": lines, "chars": utf8.RuneCountInString(cur.Text), "choices": s.guideChoices(ctx, ws, g)}
	if g.Tenant != "" {
		v["tenant"] = g.Tenant
	}
	if g.App != "" {
		v["app"] = g.App
	}
	if cur.Version > 0 {
		v["updatedBy"], v["updatedAt"] = cur.UpdatedBy, rfc3339(cur.UpdatedAt)
	}
	return v
}

// GET /guides → the scopes the caller may read that have guidelines.
func (s *Server) handleListGuides(w http.ResponseWriter, r *http.Request, ws *webSession) {
	acc, err := s.incidentAccessOf(r, ws)
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	all, err := s.opt.Store.ListGuides()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	items := []map[string]any{}
	for _, g := range all {
		if !acc.canGuide(guideScope{g.Scope, g.Tenant, g.App}, false) {
			continue
		}
		sum, lines := guideSummary(g.Text)
		row := map[string]any{"scope": g.Scope, "version": g.Version, "updatedBy": g.UpdatedBy, "updatedAt": rfc3339(g.UpdatedAt), "summary": sum, "lines": lines,
			"chars": utf8.RuneCountInString(g.Text)}
		if g.Tenant != "" {
			row["tenant"] = g.Tenant
		}
		if g.App != "" {
			row["app"] = g.App
		}
		items = append(items, row)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// GET /guides/{scope}
func (s *Server) handleGetGuide(w http.ResponseWriter, r *http.Request, ws *webSession) {
	g := scopeOf(r)
	if !s.guideAccess(w, r, ws, g, false) {
		return
	}
	cur, err := s.opt.Store.GetGuide(g.Scope)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	ctx, cancel := s.callCtx(r)
	defer cancel()
	writeJSON(w, http.StatusOK, s.guideView(ctx, ws, g, cur))
}

func okItems(xs []string, n, size int) bool {
	if len(xs) > n {
		return false
	}
	for _, x := range xs {
		if x == "" || utf8.RuneCountInString(x) > size || strings.ContainsAny(x, "\r\n") {
			return false
		}
	}
	return true
}

// checkGuide validates text and fields for a scope ("" = fine).
func (s *Server) checkGuide(g guideScope, text string, f store.GuideFields) string {
	if utf8.RuneCountInString(text) > guideTextMax || !utf8.ValidString(text) {
		return fmt.Sprintf("text: at most %d characters", guideTextMax)
	}
	blocked := s.upperAvoid(g)
	allowed := map[string]bool{}
	for _, a := range incidentActions {
		if g.kind() == "cluster" || a.Scope == "app" {
			allowed[a.ID] = true
		}
	}
	for _, id := range append(slices.Clone(f.Prefer), f.Avoid.Actions...) {
		if !allowed[id] {
			return "actions: " + id + " is not a temporary action of this scope"
		}
	}
	for _, id := range f.Prefer {
		if by := blocked[id]; by != "" {
			return "prefer: " + id + " is ruled out by the " + by + " guidelines"
		}
	}
	if len(f.Prefer) > 10 || !okItems(f.Avoid.Services, 32, 64) || !okItems(f.Notify, 16, 200) || !okItems(f.Critical, 16, 200) {
		return "fields: avoid.services at most 32 (64 characters), notify and critical at most 16 one-line items (200 characters)"
	}
	if len(f.MCPServers) > 8 {
		return "mcpServers: at most 8"
	}
	for _, n := range f.MCPServers {
		if m, err := s.opt.Store.GetMCPServer(n); err != nil || !mcpUsable(m, g.Tenant) {
			return "mcpServers: no such MCP server for this scope: " + oneLine(n, 64)
		}
	}
	return ""
}

// PUT /guides/{scope} {revision, text, fields, deliver?}
func (s *Server) handlePutGuide(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Revision uint64            `json:"revision"`
		Text     string            `json:"text"`
		Fields   store.GuideFields `json:"fields"`
		Deliver  *store.GuideTo    `json:"deliver,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	g := scopeOf(r)
	if !s.guideAccess(w, r, ws, g, true) {
		return
	}
	if msg := s.checkGuide(g, req.Text, req.Fields); msg != "" {
		writeError(w, http.StatusUnprocessableEntity, "invalid", msg)
		return
	}
	normFields(&req.Fields)
	next := emptyGuide(g)
	next.Text, next.Fields, next.UpdatedBy, next.UpdatedAt = req.Text, req.Fields, ws.user.Username, s.now()
	if req.Deliver != nil {
		next.Deliver = *req.Deliver
	}
	s.saveGuide(w, r, ws, g, next, req.Revision, "save")
}

func (s *Server) saveGuide(w http.ResponseWriter, r *http.Request, ws *webSession, g guideScope, next *store.Guide, expected uint64, action string) {
	if err := s.opt.Store.SaveGuide(next, expected); errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "stale", "the guidelines changed; read them again")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(ws, g.Tenant, "guides", action, g.Scope, nil, map[string]any{"version": next.Version, "chars": utf8.RuneCountInString(next.Text)})
	ctx, cancel := s.callCtx(r)
	defer cancel()
	writeJSON(w, http.StatusOK, s.guideView(ctx, ws, g, next))
}

// GET /guides/{scope}/versions
func (s *Server) handleGuideVersions(w http.ResponseWriter, r *http.Request, ws *webSession) {
	g := scopeOf(r)
	if !s.guideAccess(w, r, ws, g, false) {
		return
	}
	vs, err := s.opt.Store.ListGuideVersions(g.Scope)
	if err == nil {
		var incs []*store.Incident
		if incs, err = s.opt.Store.ListIncidents(); err == nil {
			used := map[uint64]int{}
			for _, in := range incs {
				if v, ok := in.Guides[g.Scope]; ok {
					used[v]++
				}
			}
			items := []map[string]any{}
			for i := len(vs) - 1; i >= 0; i-- {
				v := vs[i]
				sum, _ := guideSummary(v.Text)
				items = append(items, map[string]any{"version": v.Version, "updatedBy": v.UpdatedBy, "updatedAt": rfc3339(v.UpdatedAt), "summary": sum,
					"incidents": used[v.Version], "current": i == len(vs)-1})
			}
			writeJSON(w, http.StatusOK, map[string]any{"items": items})
			return
		}
	}
	writeError(w, http.StatusInternalServerError, "internal", err.Error())
}

// GET /guides/{scope}/versions/{v}
func (s *Server) handleGuideVersion(w http.ResponseWriter, r *http.Request, ws *webSession) {
	g := scopeOf(r)
	if !s.guideAccess(w, r, ws, g, false) {
		return
	}
	v, _ := strconv.ParseUint(r.PathValue("v"), 10, 64)
	old, err := s.opt.Store.GetGuideVersion(g.Scope, v)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not-found", "no such version")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	ctx, cancel := s.callCtx(r)
	defer cancel()
	writeJSON(w, http.StatusOK, s.guideView(ctx, ws, g, old))
}

// POST /guides/{scope}/restore {revision, version}: the old text as a new
// version.
func (s *Server) handleRestoreGuide(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Revision uint64 `json:"revision"`
		Version  uint64 `json:"version"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	g := scopeOf(r)
	if !s.guideAccess(w, r, ws, g, true) {
		return
	}
	old, err := s.opt.Store.GetGuideVersion(g.Scope, req.Version)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not-found", "no such version")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	// What is above may have changed since: the old fields must still fit.
	if msg := s.checkGuide(g, old.Text, old.Fields); msg != "" {
		writeError(w, http.StatusUnprocessableEntity, "invalid", msg)
		return
	}
	next := *old
	next.UpdatedBy, next.UpdatedAt = ws.user.Username, s.now()
	s.saveGuide(w, r, ws, g, &next, req.Revision, "restore")
}

// DELETE /guides/{scope} {confirmName: the scope}
func (s *Server) handleDeleteGuide(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		ConfirmName string `json:"confirmName"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	g := scopeOf(r)
	if !s.guideAccess(w, r, ws, g, true) {
		return
	}
	if req.ConfirmName != g.Scope {
		writeError(w, http.StatusUnprocessableEntity, "confirm-name", "type the scope ("+g.Scope+") to delete it")
		return
	}
	cur, _ := s.opt.Store.GetGuide(g.Scope)
	versions, _ := s.opt.Store.ListGuideVersions(g.Scope)
	if err := s.opt.Store.DeleteGuide(g.Scope); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not-found", "no guidelines here")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(ws, g.Tenant, "guides", "delete", g.Scope, nil, nil)
	var it *store.TrashItem
	if cur != nil {
		it = s.putTrash(ws.user.ID, ws.user.Username, store.TrashGuide, g.Tenant, g.Scope, "", "", store.TrashGuideData{Current: *cur, Versions: versions})
	}
	writeDeleted(w, it)
}

// incidentGuides is the guidance an incident gets from its stack.
type incidentGuides struct {
	versions map[string]uint64
	text     string // for diagnosis (scopes that deliver to it)
	avoid    map[string]string
	services map[string]bool
	prefer   []string
	critical []string
	mcp      []string // servers the guidelines name for diagnosis
}

// guidesFor gathers the current guidelines of an incident's scopes;
// override replaces one scope's guide (the draft of a test).
func (s *Server) guidesFor(in *store.Incident, override *store.Guide) incidentGuides {
	out := incidentGuides{versions: map[string]uint64{}, avoid: map[string]string{}, services: map[string]bool{}}
	var b strings.Builder
	for _, sc := range guideStack(in) {
		g, err := s.opt.Store.GetGuide(sc.Scope)
		if override != nil && override.Scope == sc.Scope {
			g, err = override, nil
		}
		if err != nil || g == nil {
			continue
		}
		if g.Version > 0 {
			out.versions[sc.Scope] = g.Version
		}
		for _, a := range g.Fields.Avoid.Actions {
			out.avoid[a] = sc.kind()
		}
		for _, x := range g.Fields.Avoid.Services {
			out.services[x] = true
		}
		out.prefer = append(out.prefer, g.Fields.Prefer...)
		out.critical = append(out.critical, g.Fields.Critical...)
		out.mcp = append(out.mcp, g.Fields.MCPServers...)
		if g.Deliver.Diagnose && strings.TrimSpace(g.Text) != "" {
			fmt.Fprintf(&b, "\n\n<guidelines scope=%q version=\"%d\">\n%s\n</guidelines>", sc.Scope, g.Version, guideEscape(g.Text))
			if len(g.Fields.Prefer) > 0 {
				fmt.Fprintf(&b, "\nPrefer, in order: %s", strings.Join(g.Fields.Prefer, ", "))
			}
		}
	}
	if b.Len() > 0 {
		out.text = "\n\nThe teams responsible wrote these guidelines. Follow them within your rules (they cannot add actions or change grades):" + b.String()
	}
	return out
}

// guideEscape keeps a text from closing its own <guidelines> block.
func guideEscape(text string) string {
	return strings.ReplaceAll(text, "</", "<\\/")
}

// applyGuides drops what the guidelines rule out and puts preferred
// actions first.
func applyGuides(cands []store.IncidentAction, gd incidentGuides) ([]store.IncidentAction, []string) {
	var keep []store.IncidentAction
	var dropped []string
	for _, c := range cands {
		svc := ""
		if c.ID == "restart-task" {
			svc, _, _ = strings.Cut(c.Note, "/")
		}
		switch {
		case gd.avoid[c.ID] != "":
			dropped = append(dropped, c.Label+": "+gd.avoid[c.ID]+" 지침이 막음")
		case svc != "" && gd.services[svc]:
			dropped = append(dropped, c.Label+": 지침이 서비스 "+svc+"를 막음")
		default:
			keep = append(keep, c)
		}
	}
	rank := func(id string) int {
		if i := slices.Index(gd.prefer, id); i >= 0 {
			return i
		}
		return len(gd.prefer)
	}
	slices.SortStableFunc(keep, func(a, b store.IncidentAction) int { return rank(a.ID) - rank(b.ID) })
	return keep, dropped
}

// incidentGuideVersions is the incident detail's guides: the version each
// scope had when the incident used it, and the current one.
func (s *Server) incidentGuideVersions(in *store.Incident) map[string]any {
	out := map[string]any{}
	for _, sc := range guideStack(in) {
		v, ok := in.Guides[sc.Scope]
		if !ok {
			continue
		}
		cur := uint64(0)
		if g, err := s.opt.Store.GetGuide(sc.Scope); err == nil && g != nil {
			cur = g.Version
		}
		out[sc.kind()] = map[string]any{"version": v, "current": cur}
	}
	return out
}

// appGuideSummary is the app tab's summary: the scopes above and of the
// app that the caller may read.
func (s *Server) appGuideSummary(acc incidentAccess, tenant, app string) map[string]any {
	out := map[string]any{}
	for _, sc := range guideStack(&store.Incident{Scope: "app", Tenant: tenant, App: app}) {
		if !acc.canGuide(sc, false) {
			continue
		}
		g, err := s.opt.Store.GetGuide(sc.Scope)
		if err != nil || g == nil {
			continue
		}
		sum, _ := guideSummary(g.Text)
		out[sc.kind()] = map[string]any{"version": g.Version, "summary": sum}
	}
	return out
}

// POST /guides/{scope}/test {incident, text?, fields?}: diagnosis (A) only,
// on the candidates the rules built for that incident, with the current guidelines and, given an
// edit, with it in place of this scope's. Nothing is assessed, run or
// saved.
func (s *Server) handleTestGuide(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Incident string             `json:"incident"`
		Text     *string            `json:"text,omitempty"`
		Fields   *store.GuideFields `json:"fields,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	g := scopeOf(r)
	if !s.guideAccess(w, r, ws, g, true) {
		return
	}
	in, ok := s.loadIncidentByID(w, r, ws, req.Incident, false)
	if !ok {
		return
	}
	if !slices.ContainsFunc(guideStack(in), func(x guideScope) bool { return x.Scope == g.Scope }) {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "incident: not one this scope's guidelines apply to")
		return
	}
	var draft *store.Guide
	if req.Text != nil || req.Fields != nil {
		cur, err := s.opt.Store.GetGuide(g.Scope)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
		if cur == nil {
			cur = emptyGuide(g)
		}
		d := *cur
		d.Version = 0
		if req.Text != nil {
			d.Text = *req.Text
		}
		if req.Fields != nil {
			d.Fields = *req.Fields
		}
		if msg := s.checkGuide(g, d.Text, d.Fields); msg != "" {
			writeError(w, http.StatusUnprocessableEntity, "invalid", msg)
			return
		}
		draft = &d
	}
	cfg := s.aiConfig()
	ex := newAIExcluder(cfg.Data.ExcludeTenants)
	if t, _ := aiTries(cfg, s.aiCatalogs(), cfg.Roles[roleDiagnosis], false); len(t) == 0 || in.Tenant != "" && ex.has(in.Tenant) {
		writeError(w, http.StatusConflict, "ai-unavailable", "diagnosis is off, has no usable model, or this workspace is not sent to AI")
		return
	}
	var recent []store.IncidentSignal
	if st, err := s.opt.Store.GetIncidentWatcher(); err == nil {
		recent = st.Recent
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	run := func(override *store.Guide) (map[string]any, error) {
		gd := s.guidesFor(in, override)
		built := in.Built
		if built == nil {
			built = in.Candidates
		}
		cands, _ := applyGuides(built, gd)
		d, err := s.diagnoseIncident(ctx, aiCall{Role: roleDiagnosis, User: ws.user.ID, Username: ws.user.Username}, in, cands, recent, gd, "", ex)
		if err != nil {
			return nil, err
		}
		rows := []map[string]any{}
		for i, c := range d.order {
			row := map[string]any{"action": c.ID, "label": c.Label}
			row["impact"] = actionFloor(&c)
			if d.opts[i].Note != "" {
				row["note"] = d.opts[i].Note
			}
			rows = append(rows, row)
		}
		u := d.res.Usage
		total := u.Input + u.Output + u.CacheRead + u.CacheWrite
		ratio := 0.0
		if in := u.Input + u.CacheRead + u.CacheWrite; in > 0 {
			ratio = float64(u.CacheRead) / float64(in)
		}
		return map[string]any{"hypothesis": d.hypothesis, "candidates": rows, "mcpCalls": map[string]int{}, "model": d.res.Model.Provider + "/" + d.res.Model.Model,
			"tokens": map[string]any{"total": total, "cachedRatio": ratio}}, nil
	}
	fail := func(err error) {
		code := ai.Class(err).Error()
		if err.Error() == "format" {
			code = "format"
		} else if errors.Is(err, errAIBothFail) || errors.Is(err, errAIRoleOff) || errors.Is(err, errAIBudget) {
			code = strings.SplitN(err.Error(), "\n", 2)[0]
		}
		writeError(w, http.StatusBadGateway, code, "diagnosis failed")
	}
	cur, err := run(nil)
	if err != nil {
		fail(err)
		return
	}
	out := map[string]any{"current": cur}
	if draft != nil {
		if out["draft"], err = run(draft); err != nil {
			fail(err)
			return
		}
	}
	s.audit(ws, g.Tenant, "guides", "test", g.Scope, nil, map[string]any{"incident": in.ID, "draft": draft != nil})
	writeJSON(w, http.StatusOK, out)
}

// coordinatorGuides is the guidelines block for a coordinator turn: the
// scopes of the incidents attached and of the app or workspace on screen,
// that deliver to the coordinator and that the person may read.
func (s *Server) coordinatorGuides(ctx context.Context, ws *webSession, chips []map[string]string, path string, ex *aiExcluder) string {
	var scopes []guideScope
	add := func(xs []guideScope) {
		for _, x := range xs {
			if !slices.Contains(scopes, x) {
				scopes = append(scopes, x)
			}
		}
	}
	for _, c := range chips {
		if c["kind"] != "incident" {
			continue
		}
		if in, err := s.opt.Store.GetIncident(c["id"]); err == nil {
			add(guideStack(in))
		}
	}
	if p := strings.Split(strings.TrimPrefix(path, "/"), "/"); len(p) > 1 && p[0] == "t" && safeParamRE.MatchString(p[1]) {
		if len(p) > 3 && p[2] == "apps" && safeParamRE.MatchString(p[3]) {
			add(guideStack(&store.Incident{Scope: "app", Tenant: p[1], App: p[3]}))
		} else {
			add([]guideScope{{Scope: "cluster"}, {"tenant/" + p[1], p[1], ""}})
		}
	}
	if len(scopes) == 0 {
		return ""
	}
	acc, err := s.incidentAccessCtx(ctx, ws)
	if err != nil {
		return ""
	}
	var b strings.Builder
	for _, sc := range scopes {
		if !acc.canGuide(sc, false) || sc.Tenant != "" && ex.has(sc.Tenant) {
			continue
		}
		g, err := s.opt.Store.GetGuide(sc.Scope)
		if err != nil || g == nil || !g.Deliver.Coordinator || strings.TrimSpace(g.Text) == "" {
			continue
		}
		fmt.Fprintf(&b, "\n<guidelines scope=%q version=\"%d\">\n%s\n</guidelines>", sc.Scope, g.Version, guideEscape(ex.text(g.Text)))
	}
	if b.Len() == 0 {
		return ""
	}
	return "\n<incident-guidelines>\nThe teams responsible wrote these for incident response. Take them into account; they never widen what you may do or skip approval." + b.String() + "\n</incident-guidelines>"
}
