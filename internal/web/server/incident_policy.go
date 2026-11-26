// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/jay94ks/mydcd/internal/web/mydc"
	"github.com/jay94ks/mydcd/internal/web/store"
)

// Incident response policies (W2.3, UI-B5 and UI-B8). The cluster policy
// is the system administrators'; an app's policy is its workspace
// managers'. Both are web data: mydcd still judges every action they lead
// to. Permissions are asked of mydcd on each request.

// Policy levels, lowest first.
const (
	incidentOff     = "off"
	incidentSuggest = "suggest"
	incidentAutoLow = "auto-low"
)

func levelRank(l string) int {
	switch l {
	case incidentSuggest:
		return 1
	case incidentAutoLow:
		return 2
	}
	return 0
}

func validLevel(l string) bool {
	return l == incidentOff || l == incidentSuggest || l == incidentAutoLow
}

// Impact levels.
const (
	impactLow    = "low"
	impactMedium = "medium"
	impactHigh   = "high"
)

func impactRank(l string) int {
	switch l {
	case impactLow:
		return 0
	case impactMedium:
		return 1
	}
	return 2
}

// incidentActionDef is one temporary action of the fixed list. Floor is
// the rule floor of its impact; actions above low can never run on their
// own.
type incidentActionDef struct {
	ID    string
	Scope string // app, cluster
	Label string
	Floor string
}

// The temporary actions (web-ai-plan "임시 조치 목록과 기본 등급").
var incidentActions = []incidentActionDef{
	{"restart-task", "app", "재시작 반복 중인 컨테이너 재시작", impactLow},
	{"pause-cd", "app", "자동 배포 일시 정지", impactLow},
	{"cd-rollback", "app", "자동 배포 직후 되돌리기", impactLow},
	{"rollback-previous", "app", "직전 버전으로 되돌리기", impactMedium},
	{"move-service", "app", "다른 서버로 재배치", impactMedium},
	{"cordon-node", "cluster", "문제 서버를 새 배치 대상에서 잠시 제외", impactLow},
	{"reconnect-tunnel", "cluster", "서버 간 망(터널) 다시 연결", impactLow},
	{"restart-registry", "cluster", "이미지 저장소 다시 시작", impactLow},
	{"prune-images", "cluster", "서버 이미지 캐시 정리", impactMedium},
	{"drain-node", "cluster", "서버 비우기", impactHigh},
}

func incidentActionByID(id string) *incidentActionDef {
	for i := range incidentActions {
		if incidentActions[i].ID == id {
			return &incidentActions[i]
		}
	}
	return nil
}

// Per-action settings.
const (
	actionAllow    = "allow"    // may run on its own when low
	actionApproval = "approval" // always asks a person
	actionHuman    = "human"    // never proposed; people act themselves
)

func defaultActionSetting(a incidentActionDef) string {
	switch a.Floor {
	case impactLow:
		return actionAllow
	case impactMedium:
		return actionApproval
	}
	return actionHuman
}

// clusterPolicy is the stored cluster policy with defaults filled in.
func (s *Server) clusterPolicy() (*store.IncidentPolicy, error) {
	p, err := s.opt.Store.GetIncidentPolicy()
	if err != nil {
		return nil, err
	}
	return fillClusterPolicy(p), nil
}

func fillClusterPolicy(p *store.IncidentPolicy) *store.IncidentPolicy {
	if p == nil {
		p = &store.IncidentPolicy{Level: incidentOff, NewAppDefault: incidentSuggest}
	}
	if p.RatePerHour == 0 {
		p.RatePerHour = 5
	}
	if p.Approvers.DeadlineMinutes == 0 {
		p.Approvers.DeadlineMinutes = 30
	}
	if p.Approvers.To == "" {
		p.Approvers.To = approversSystemAndTenant
	}
	if p.Approvers.Label == "" {
		p.Approvers.Label = approversLabel(p.Approvers.To, -1)
	}
	if p.Quiet == nil {
		p.Quiet = []string{}
	}
	if p.NewAppDefault == "" {
		p.NewAppDefault = incidentSuggest
	}
	if p.Actions == nil {
		p.Actions = map[string]string{}
	}
	for _, a := range incidentActions {
		if p.Actions[a.ID] == "" {
			p.Actions[a.ID] = defaultActionSetting(a)
		}
	}
	return p
}

// effectiveClusterLevel is the cluster level as it acts now (stopped = off
// for running on its own; detection and proposals go on).
func effectiveClusterLevel(p *store.IncidentPolicy) string {
	if p.Stopped && p.Level == incidentAutoLow {
		return incidentSuggest
	}
	return p.Level
}

// appPolicy is one app's stored policy with defaults filled in.
func (s *Server) appPolicy(tenant, app string, cluster *store.IncidentPolicy) (*store.AppIncidentPolicy, error) {
	p, err := s.opt.Store.GetAppIncidentPolicy(tenant, app)
	if err != nil {
		return nil, err
	}
	if p == nil {
		p = &store.AppIncidentPolicy{Tenant: tenant, App: app, Level: cluster.NewAppDefault}
	}
	if p.RatePerHour == 0 {
		p.RatePerHour = 2
	}
	if p.CDRollback.WindowMinutes == 0 {
		p.CDRollback.WindowMinutes = 30
	}
	if p.Quiet == nil {
		p.Quiet = []string{}
	}
	if p.Actions == nil {
		p.Actions = map[string]bool{}
	}
	for _, a := range appActionsAvailable(cluster) {
		if _, ok := p.Actions[a.ID]; !ok {
			p.Actions[a.ID] = true
		}
	}
	return p, nil
}

// appActionsAvailable: the app actions the cluster policy leaves to apps.
func appActionsAvailable(cluster *store.IncidentPolicy) []incidentActionDef {
	var out []incidentActionDef
	for _, a := range incidentActions {
		if a.Scope == "app" && cluster.Actions[a.ID] != actionHuman {
			out = append(out, a)
		}
	}
	return out
}

type policyActionView struct {
	ID    string `json:"id"`
	Scope string `json:"scope"`
	Label string `json:"label"`
	Floor string `json:"floor"`
	Auto  string `json:"auto"`
}

func actionViews(defs []incidentActionDef, cluster *store.IncidentPolicy) []policyActionView {
	out := make([]policyActionView, 0, len(defs))
	for _, a := range defs {
		out = append(out, policyActionView{ID: a.ID, Scope: a.Scope, Label: a.Label, Floor: a.Floor, Auto: cluster.Actions[a.ID]})
	}
	return out
}

const (
	approversSystem          = "system-admins"
	approversSystemAndTenant = "system-and-tenant-admins"
)

// approversLabel names who is asked; admins < 0 when the count is unknown.
func approversLabel(to string, admins int) string {
	who := "시스템 관리자"
	if admins >= 0 {
		who = fmt.Sprintf("시스템 관리자 %d명", admins)
	}
	if to == approversSystemAndTenant {
		return who + " + 그 앱의 작업 공간 관리자"
	}
	return who
}

// systemAdminCount reads how many enabled system administrators mydcd has,
// as ws (-1 when it cannot be read).
func (s *Server) systemAdminCount(ctx context.Context, ws *webSession) int {
	n := 0
	err := ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		after := ""
		for range incidentMaxPages {
			p, err := c.Users(ctx, after)
			if err != nil {
				return err
			}
			for _, u := range p.Items {
				if u.SystemAdmin && u.Enabled {
					n++
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
		return -1
	}
	return n
}

func (s *Server) clusterPolicyView(p *store.IncidentPolicy) (map[string]any, error) {
	apps, err := s.opt.Store.ListAppIncidentPolicies()
	if err != nil {
		return nil, err
	}
	rows := make([]map[string]any, 0, len(apps))
	for _, a := range apps {
		quiet := a.Quiet
		if quiet == nil {
			quiet = []string{}
		}
		rows = append(rows, map[string]any{"tenant": a.Tenant, "app": a.App, "level": a.Level, "ratePerHour": a.RatePerHour, "quiet": quiet, "cdRollback": a.CDRollback})
	}
	auto := map[string]any{"configured": false}
	if a := s.automationRow(); a != nil {
		auto = map[string]any{"configured": true, "username": a.Username}
	}
	out := map[string]any{
		"level": p.Level, "stopped": p.Stopped, "ratePerHour": p.RatePerHour, "approvers": p.Approvers, "quiet": p.Quiet,
		"newAppDefault": p.NewAppDefault, "actions": actionViews(incidentActions, p),
		"apps": rows, "revision": p.Revision, "automation": auto,
	}
	for k, v := range s.decideState("cluster", "", "") {
		out[k] = v
	}
	return out, nil
}

// GET /incidents/policy (system admin).
func (s *Server) handleGetIncidentPolicy(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if !s.requireAdmin(w, r, ws) {
		return
	}
	p, err := s.clusterPolicy()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.writeClusterPolicy(w, r, ws, p)
}

func (s *Server) writeClusterPolicy(w http.ResponseWriter, r *http.Request, ws *webSession, p *store.IncidentPolicy) {
	v, err := s.clusterPolicyView(p)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	ctx, cancel := s.callCtx(r)
	defer cancel()
	n := s.systemAdminCount(ctx, ws)
	ap := p.Approvers
	ap.Label = approversLabel(ap.To, n)
	v["approvers"] = ap
	opts := []map[string]string{}
	for _, to := range []string{approversSystem, approversSystemAndTenant} {
		opts = append(opts, map[string]string{"to": to, "label": approversLabel(to, n)})
	}
	v["approverOptions"] = opts
	writeJSON(w, http.StatusOK, v)
}

var quietRE = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]-([01][0-9]|2[0-3]):[0-5][0-9]$`)

func validQuiet(q []string) bool {
	if len(q) > 8 {
		return false
	}
	for _, x := range q {
		if !quietRE.MatchString(x) {
			return false
		}
	}
	return true
}

// PUT /incidents/policy {revision, level, ratePerHour, approvers, quiet,
// newAppDefault, actions?} (system admin).
func (s *Server) handlePutIncidentPolicy(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Revision      uint64                  `json:"revision"`
		Level         string                  `json:"level"`
		RatePerHour   int                     `json:"ratePerHour"`
		Approvers     store.IncidentApprovers `json:"approvers"`
		Quiet         []string                `json:"quiet"`
		NewAppDefault string                  `json:"newAppDefault"`
		Actions       map[string]string       `json:"actions,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !s.requireAdmin(w, r, ws) {
		return
	}
	switch {
	case !validLevel(req.Level) || !validLevel(req.NewAppDefault):
		writeError(w, http.StatusUnprocessableEntity, "invalid", "level, newAppDefault: off, suggest or auto-low")
		return
	case req.RatePerHour < 1 || req.RatePerHour > 30:
		writeError(w, http.StatusUnprocessableEntity, "invalid", "ratePerHour: 1 to 30")
		return
	case req.Approvers.DeadlineMinutes < 5 || req.Approvers.DeadlineMinutes > 240:
		writeError(w, http.StatusUnprocessableEntity, "invalid", "approvers: deadlineMinutes 5 to 240")
		return
	case req.Approvers.To != "" && req.Approvers.To != approversSystem && req.Approvers.To != approversSystemAndTenant:
		writeError(w, http.StatusUnprocessableEntity, "invalid", "approvers.to: system-admins or system-and-tenant-admins")
		return
	case !validQuiet(req.Quiet):
		writeError(w, http.StatusUnprocessableEntity, "invalid", `quiet: at most 8 "HH:MM-HH:MM" ranges`)
		return
	}
	for id, v := range req.Actions {
		a := incidentActionByID(id)
		if a == nil || (v != actionAllow && v != actionApproval && v != actionHuman) {
			writeError(w, http.StatusUnprocessableEntity, "invalid", "actions: a known action id → allow, approval or human")
			return
		}
		if v == actionAllow && a.Floor != impactLow {
			writeError(w, http.StatusUnprocessableEntity, "floor", a.ID+": only low-impact actions may run on their own")
			return
		}
	}
	if req.Level != incidentOff && s.automationRow() == nil {
		writeError(w, http.StatusUnprocessableEntity, "automation-missing", "set up the automation account first (system › automation)")
		return
	}
	if req.Approvers.To == "" {
		req.Approvers.To = approversSystemAndTenant
	}
	{
		ctx, cancel := s.callCtx(r)
		req.Approvers.Label = approversLabel(req.Approvers.To, s.systemAdminCount(ctx, ws))
		cancel()
	}
	var before *store.IncidentPolicy
	p, err := s.opt.Store.UpdateIncidentPolicy(func(cur *store.IncidentPolicy) (*store.IncidentPolicy, error) {
		cur = fillClusterPolicy(cur)
		if cur.Revision != req.Revision {
			return nil, errStale
		}
		b := *cur
		before = &b
		next := *cur
		next.Level, next.RatePerHour, next.Approvers, next.Quiet, next.NewAppDefault = req.Level, req.RatePerHour, req.Approvers, req.Quiet, req.NewAppDefault
		if next.Quiet == nil {
			next.Quiet = []string{}
		}
		next.Actions = map[string]string{}
		for k, v := range cur.Actions {
			next.Actions[k] = v
		}
		for k, v := range req.Actions {
			next.Actions[k] = v
		}
		next.UpdatedBy, next.UpdatedAt = ws.user.Username, s.now()
		return &next, nil
	})
	if errors.Is(err, errStale) {
		writeError(w, http.StatusConflict, "stale", "the policy changed; read it again")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(ws, "", "incidents", "policy", "cluster", before, p)
	s.writeClusterPolicy(w, r, ws, fillClusterPolicy(p))
}

var errStale = errors.New("stale")

// POST /incidents/stop, /incidents/resume (system admin): nothing runs on
// its own while stopped.
func (s *Server) handleIncidentStop(stop bool) func(http.ResponseWriter, *http.Request, *webSession) {
	return func(w http.ResponseWriter, r *http.Request, ws *webSession) {
		if !s.requireAdmin(w, r, ws) {
			return
		}
		p, err := s.opt.Store.UpdateIncidentPolicy(func(cur *store.IncidentPolicy) (*store.IncidentPolicy, error) {
			cur = fillClusterPolicy(cur)
			cur.Stopped, cur.UpdatedBy, cur.UpdatedAt = stop, ws.user.Username, s.now()
			return cur, nil
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
		action := "resume"
		if stop {
			action = "stop"
		}
		s.audit(ws, "", "incidents", action, "cluster", nil, map[string]any{"stopped": stop})
		s.writeClusterPolicy(w, r, ws, fillClusterPolicy(p))
	}
}

func (s *Server) appPolicyView(p *store.AppIncidentPolicy, cluster *store.IncidentPolicy) map[string]any {
	avail := appActionsAvailable(cluster)
	actions := map[string]bool{}
	for _, a := range avail {
		actions[a.ID] = p.Actions[a.ID]
	}
	out := map[string]any{
		"level": p.Level, "ratePerHour": p.RatePerHour, "quiet": p.Quiet, "cdRollback": p.CDRollback, "actions": actions,
		"revision": p.Revision, "approvers": cluster.Approvers.Label,
		"available": actionViews(avail, cluster), "clusterLevel": effectiveClusterLevel(cluster),
	}
	for k, v := range s.decideState("app", p.Tenant, p.App) {
		out[k] = v
	}
	return out
}

// GET /t/{t}/apps/{app}/incident (workspace members).
func (s *Server) handleGetAppIncident(w http.ResponseWriter, r *http.Request, ws *webSession) {
	tenant, app := r.PathValue("t"), r.PathValue("app")
	if !s.requireRole(w, r, ws, tenant, false) {
		return
	}
	cluster, err := s.clusterPolicy()
	if err == nil {
		var p *store.AppIncidentPolicy
		if p, err = s.appPolicy(tenant, app, cluster); err == nil {
			acc, err := s.incidentAccessOf(r, ws)
			if err != nil {
				s.writeBackendError(w, ws, err)
				return
			}
			v := s.appPolicyView(p, cluster)
			v["guides"] = s.appGuideSummary(acc, tenant, app)
			writeJSON(w, http.StatusOK, v)
			return
		}
	}
	writeError(w, http.StatusInternalServerError, "internal", err.Error())
}

// PUT /t/{t}/apps/{app}/incident {revision, level, ratePerHour, quiet,
// cdRollback, actions} (workspace managers).
func (s *Server) handlePutAppIncident(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Revision    uint64                 `json:"revision"`
		Level       string                 `json:"level"`
		RatePerHour int                    `json:"ratePerHour"`
		Quiet       []string               `json:"quiet"`
		CDRollback  store.CDRollbackPolicy `json:"cdRollback"`
		Actions     map[string]bool        `json:"actions"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant, app := r.PathValue("t"), r.PathValue("app")
	if !s.requireRole(w, r, ws, tenant, true) {
		return
	}
	cluster, err := s.clusterPolicy()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	avail := map[string]bool{}
	for _, a := range appActionsAvailable(cluster) {
		avail[a.ID] = true
	}
	switch {
	case !validLevel(req.Level):
		writeError(w, http.StatusUnprocessableEntity, "invalid", "level: off, suggest or auto-low")
		return
	case req.RatePerHour < 1 || req.RatePerHour > 10:
		writeError(w, http.StatusUnprocessableEntity, "invalid", "ratePerHour: 1 to 10")
		return
	case !validQuiet(req.Quiet):
		writeError(w, http.StatusUnprocessableEntity, "invalid", `quiet: at most 8 "HH:MM-HH:MM" ranges`)
		return
	case req.CDRollback.WindowMinutes < 5 || req.CDRollback.WindowMinutes > 120:
		writeError(w, http.StatusUnprocessableEntity, "invalid", "cdRollback.windowMinutes: 5 to 120")
		return
	}
	for id := range req.Actions {
		if !avail[id] {
			writeError(w, http.StatusUnprocessableEntity, "invalid", "actions: "+id+" is not an app action the cluster allows")
			return
		}
	}
	// The app must exist (and be readable) in mydcd.
	ctx, cancel := s.callCtx(r)
	defer cancel()
	err = ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		rev, err := s.appRevision(ctx, c, tenant, app)
		if err == nil && rev == 0 {
			err = &httpErr{http.StatusNotFound, "not-found", "no such app"}
		}
		return err
	})
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	var before *store.AppIncidentPolicy
	p, err := s.opt.Store.UpdateAppIncidentPolicy(tenant, app, func(cur *store.AppIncidentPolicy) (*store.AppIncidentPolicy, error) {
		rev := uint64(0)
		if cur != nil {
			rev = cur.Revision
			b := *cur
			before = &b
		}
		if rev != req.Revision {
			return nil, errStale
		}
		next := &store.AppIncidentPolicy{Level: req.Level, RatePerHour: req.RatePerHour, Quiet: req.Quiet, CDRollback: req.CDRollback,
			Actions: req.Actions, UpdatedBy: ws.user.Username, UpdatedAt: s.now(), Revision: rev}
		if cur != nil {
			next.Migrations = cur.Migrations
		}
		if next.Quiet == nil {
			next.Quiet = []string{}
		}
		return next, nil
	})
	if errors.Is(err, errStale) {
		writeError(w, http.StatusConflict, "stale", "the app's policy changed; read it again")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(ws, tenant, "incidents", "app-policy", app, before, p)
	if p, err = s.appPolicy(tenant, app, cluster); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.appPolicyView(p, cluster))
}

type incidentVersionView struct {
	Version   uint64 `json:"version"`
	Summary   string `json:"summary"`
	By        string `json:"by"`
	CD        bool   `json:"cd"`
	At        string `json:"at"`
	Migration bool   `json:"migration"`
	// Auto: what the version changed that keeps it from rolling back on
	// its own (data stores, networks, secrets, health scripts).
	Auto string `json:"auto,omitempty"`
}

// GET /t/{t}/apps/{app}/incident/versions (workspace members): the app's
// versions from mydcd with the web's "data migration" marks.
func (s *Server) handleAppIncidentVersions(w http.ResponseWriter, r *http.Request, ws *webSession) {
	tenant, app := r.PathValue("t"), r.PathValue("app")
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var page mydc.Page[mydc.AppRevision]
	docs := map[uint64][]byte{}
	err := ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		var err error
		if page, err = c.AppRevisions(ctx, tenant, app, ""); err != nil {
			return err
		}
		// The newest versions' documents, to mark what they changed.
		vs := page.Items
		if len(vs) > 20 {
			vs = vs[len(vs)-20:]
		}
		for _, v := range vs {
			if src, err := c.AppSource(ctx, tenant, app, v.Version); err == nil {
				docs[v.Version] = src.Document
			}
		}
		return nil
	})
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	p, err := s.opt.Store.GetAppIncidentPolicy(tenant, app)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	items := make([]incidentVersionView, 0, len(page.Items))
	var prev []byte
	for _, v := range page.Items {
		row := versionView(v, p)
		if doc, ok := docs[v.Version]; ok {
			row.Auto = versionAuto(doc, prev)
			prev = doc
		} else {
			prev = nil
		}
		items = append(items, row)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func versionView(v mydc.AppRevision, p *store.AppIncidentPolicy) incidentVersionView {
	out := incidentVersionView{Version: v.Version, Summary: v.Operation, By: v.Submitter, CD: v.Kind == "cd", At: rfc3339(time.Unix(v.AcceptedAt, 0))}
	if p != nil {
		out.Migration = p.Migrations[v.Version]
	}
	return out
}

// PUT /t/{t}/apps/{app}/incident/versions/{v} {migration} (workspace
// managers): mark a version as carrying a data migration, which keeps it
// out of rolling back on its own.
func (s *Server) handlePutAppIncidentVersion(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Migration bool `json:"migration"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant, app := r.PathValue("t"), r.PathValue("app")
	version, err := strconv.ParseUint(r.PathValue("v"), 10, 64)
	if err != nil || version == 0 {
		writeError(w, http.StatusBadRequest, "bad-request", "version: a positive number")
		return
	}
	if !s.requireRole(w, r, ws, tenant, true) {
		return
	}
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var found *mydc.AppRevision
	err = ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		after := ""
		for {
			page, err := c.AppRevisions(ctx, tenant, app, after)
			if err != nil {
				return err
			}
			for i := range page.Items {
				if page.Items[i].Version == version {
					found = &page.Items[i]
					return nil
				}
			}
			if page.Next == "" {
				return nil
			}
			after = page.Next
		}
	})
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	if found == nil {
		writeError(w, http.StatusNotFound, "not-found", "no such version")
		return
	}
	cluster, err := s.clusterPolicy()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	p, err := s.opt.Store.UpdateAppIncidentPolicy(tenant, app, func(cur *store.AppIncidentPolicy) (*store.AppIncidentPolicy, error) {
		if cur == nil {
			cur = &store.AppIncidentPolicy{Level: cluster.NewAppDefault}
		}
		if cur.Migrations == nil {
			cur.Migrations = map[uint64]bool{}
		}
		if req.Migration {
			cur.Migrations[version] = true
		} else {
			delete(cur.Migrations, version)
		}
		return cur, nil
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(ws, tenant, "incidents", "version-migration", app+"@"+strconv.FormatUint(version, 10), nil, map[string]any{"migration": req.Migration})
	writeJSON(w, http.StatusOK, versionView(*found, p))
}
