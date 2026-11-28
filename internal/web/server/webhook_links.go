// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/web/sfc"
	"github.com/jay94ks/seafield/internal/web/store"
)

// Webhook links (W2.3b): where a webhook is used. incident and ingress
// links carry event names; cd links (UI-44) the kind of check and how to
// wait (devel: /mnt/project-files/w2/cd-webhooks-contract.md).

var webhookEvents = map[string][]string{
	"incident": {"opened", "approval-required", "auto-run", "approved", "rejected", "expired", "recovered", "closed"},
	"cd": {"candidate-created", "approval-required", "approved", "rejected", "sync-started", "sync-succeeded", "sync-failed",
		"drift-detected", "paused", "resumed", "rolled-back"},
	"ingress": {"down", "tls-rejects", "source-rejects", "recovered", "certificate-expiring", "limit-90", "error-rate", "latency", "no-backends", "probe-failed", "cert", "blocked", "balance-fallback"},
}

// Ingress links (UI-5A/5B): a gateway link (system administrator) takes the
// gateway events, an app or route link (workspace manager) the route ones.
var (
	// recovered on a gateway link is the same as recover: true.
	ingressGatewayEvents = []string{"down", "tls-rejects", "source-rejects", "error-rate", "blocked", "recovered", "certificate-expiring", "limit-90"}
	ingressRouteEvents   = []string{"error-rate", "latency", "no-backends", "probe-failed", "cert", "blocked", "balance-fallback"}
)

type webhookLinkReq struct {
	Revision     uint64                 `json:"revision"`
	Point        string                 `json:"point"`
	Scope        store.WebhookLinkScope `json:"scope"`
	Events       []string               `json:"events"`
	Webhook      string                 `json:"webhook"`
	Kind         string                 `json:"kind,omitempty"`
	WaitSeconds  int                    `json:"waitSeconds,omitempty"`
	OnTimeout    string                 `json:"onTimeout,omitempty"`
	When         string                 `json:"when,omitempty"`
	OnFail       string                 `json:"onFail,omitempty"`
	OpenIncident *bool                  `json:"openIncident,omitempty"`
	Threshold    float64                `json:"threshold,omitempty"`
	Minutes      int                    `json:"minutes,omitempty"`
	Recover      bool                   `json:"recover,omitempty"`
	Group        bool                   `json:"group,omitempty"`
}

// linkManage: who may change links of a scope.
func linkManage(acc incidentAccess, sc store.WebhookLinkScope) bool {
	if sc.Tenant == "" {
		return acc.admin
	}
	return acc.webhook(sc.Tenant, true)
}

func linkRead(acc incidentAccess, sc store.WebhookLinkScope) bool {
	if sc.Tenant == "" {
		return acc.admin
	}
	return acc.webhook(sc.Tenant, false)
}

// checkLink fills defaults and validates l against its webhook ("" = fine).
func checkLink(l *store.WebhookLink, h *store.Webhook, openIncident *bool) string {
	sc := l.Scope
	switch {
	case webhookEvents[l.Point] == nil:
		return "point: incident, cd or ingress"
	case sc.Tenant != "" && !safeParamRE.MatchString(sc.Tenant), sc.App != "" && (!safeParamRE.MatchString(sc.App) || sc.Tenant == ""):
		return "scope: tenant, and app inside it"
	case (sc.Gateway != "" || sc.Route != "") && l.Point != "ingress":
		return "scope: gateway and route are for ingress links only"
	case sc.Route != "" && (sc.App == "" || !safeParamRE.MatchString(sc.Route)):
		return "scope.route: a route of the app"
	case h.Tenant != "" && h.Tenant != sc.Tenant:
		return "webhook: a workspace webhook links inside its workspace only"
	}
	for _, e := range l.Events {
		if !slices.Contains(webhookEvents[l.Point], e) {
			return "events: " + e + " is not an event of " + l.Point
		}
	}
	if l.Point != "ingress" {
		l.Threshold, l.Minutes, l.Recover, l.Group = 0, 0, false, false
	} else if msg := checkIngressLink(l, h); msg != "" {
		return msg
	}
	if l.Point != "cd" {
		l.Kind, l.WaitSeconds, l.OnTimeout, l.When, l.OnFail, l.OpenIncident = "", 0, "", "", "", false
		if h.Role == "notify" && len(l.Events) == 0 {
			return "events: pick at least one"
		}
		if h.Role == "decide" {
			if l.Point != "incident" {
				return "webhook: decide webhooks answer incidents and CD checks only"
			}
			l.Events = []string{}
		}
		return ""
	}
	if sc.App == "" {
		return "scope: CD links are per app"
	}
	switch l.Kind {
	case "pre-sync", "post-sync":
		if h.Role != "decide" {
			return "role: CD checks need a decide webhook"
		}
		lo, def, hi := 5, 60, 600 // post-sync: how long to wait for healthy
		if l.Kind == "pre-sync" {
			lo, def, hi = 5, 10, 30 // the answer
		}
		if l.WaitSeconds == 0 {
			l.WaitSeconds = def
		}
		if l.WaitSeconds < lo || l.WaitSeconds > hi {
			return fmt.Sprintf("waitSeconds: %d..%d for %s", lo, hi, l.Kind)
		}
		l.Events = []string{}
	case "notify":
		if h.Role != "notify" {
			return "role: CD notices need a notify webhook"
		}
		if len(l.Events) == 0 {
			return "events: pick at least one"
		}
		l.WaitSeconds, l.OnTimeout, l.When, l.OnFail = 0, "", "", ""
	default:
		return "kind: pre-sync, post-sync or notify"
	}
	switch l.Kind {
	case "pre-sync":
		if l.OnTimeout == "" {
			l.OnTimeout = "hold"
		}
		if l.OnTimeout != "hold" && l.OnTimeout != "pass" && l.OnTimeout != "reject" {
			return "onTimeout: hold, pass or reject"
		}
		l.When, l.OnFail, l.OpenIncident = "", "", false
	case "post-sync":
		if l.OnTimeout == "" {
			l.OnTimeout = "pass"
		}
		if l.When == "" {
			l.When = "healthy"
		}
		if l.OnFail == "" {
			l.OnFail = "pause"
		}
		switch {
		case l.OnTimeout != "pass" && l.OnTimeout != "fail":
			return "onTimeout: pass or fail"
		case l.When != "synced" && l.When != "healthy":
			return "when: synced or healthy"
		case l.OnFail != "pause" && l.OnFail != "pause-rollback":
			return "onFail: pause or pause-rollback"
		}
		l.OpenIncident = openIncident == nil || *openIncident
	}
	return ""
}

// checkIngressLink: the scope is a gateway or an app (and maybe a route),
// its events fit it, and the condition is one of error-rate or latency.
func checkIngressLink(l *store.WebhookLink, h *store.Webhook) string {
	sc := l.Scope
	allowed := ingressRouteEvents
	switch {
	case sc.Gateway != "":
		if sc.Tenant != "" || sc.Gateway != sfc.GatewayExternal && sc.Gateway != sfc.GatewayLocal {
			return "scope.gateway: external or local, without a workspace"
		}
		allowed = ingressGatewayEvents
	case sc.App == "":
		return "scope: a gateway, or an app (and a route of it)"
	}
	for _, e := range l.Events {
		if !slices.Contains(allowed, e) {
			return "events: " + e + " is not an event of this scope"
		}
	}
	rate, lat := slices.Contains(l.Events, "error-rate"), slices.Contains(l.Events, "latency")
	switch {
	case l.Minutes < 0 || l.Minutes > 60:
		return "minutes: 0..60"
	case l.Threshold < 0:
		return "threshold: not negative"
	case (l.Threshold != 0 || l.Minutes != 0) && !rate && !lat:
		return "threshold, minutes: for error-rate or latency"
	case l.Threshold != 0 && rate && lat:
		return "threshold: link error-rate and latency separately"
	case rate && l.Threshold > 100:
		return "threshold: percent of 5xx, 0..100"
	}
	return ""
}

// ingressCondition is the link's condition in words in lang ("" without
// one).
func ingressCondition(lang string, l *store.WebhookLink) string {
	if l.Point != "ingress" || l.Threshold == 0 && l.Minutes == 0 {
		return ""
	}
	what, unit := ph("ingress-cond.5xx"), "%"
	if slices.Contains(l.Events, "latency") {
		what, unit = ph("ingress-cond.latency"), "ms"
	}
	cond := with(ph("ingress-cond.threshold"), "what", what)
	if l.Threshold != 0 {
		cond = with(ph("ingress-cond.value", "value", fmt.Sprintf("%g", l.Threshold), "unit", unit), "what", what)
	}
	if l.Minutes != 0 {
		cond = with(ph("ingress-cond.minutes", "minutes", fmt.Sprint(l.Minutes)), "cond", cond)
	}
	return render(lang, cond)
}

// lastLinkDelivery: the newest delivery sent for link id ({at, status?,
// error?}, nil when none).
func (s *Server) lastLinkDelivery(webhook, id string) map[string]any {
	ds, _ := s.opt.Store.ListWebhookDeliveries(webhook)
	for _, d := range ds {
		if d.Link != id {
			continue
		}
		v := map[string]any{"at": rfc3339(d.At)}
		if d.Status != 0 {
			v["status"] = d.Status
		}
		if d.Error != "" {
			v["error"] = d.Error
		}
		return v
	}
	return nil
}

func (s *Server) linkView(ctx context.Context, lang string, ws *webSession, l *store.WebhookLink, role string) map[string]any {
	raw, _ := json.Marshal(l)
	var v map[string]any
	_ = json.Unmarshal(raw, &v)
	delete(v, "createdBy")
	v["createdBy"], v["role"] = l.CreatedBy, role
	if c := ingressCondition(lang, l); c != "" {
		v["condition"] = c
	}
	if last := s.lastLinkDelivery(l.Webhook, l.ID); last != nil {
		v["last"] = last
	}
	if l.Kind == "pre-sync" && ws != nil {
		v["approver"] = s.cdApproverState(ctx, ws, l.Scope.Tenant, l.Scope.App)
	}
	return v
}

// cdApproverState: the automation account and whether sfcd lists it as an
// approver of the app.
func (s *Server) cdApproverState(ctx context.Context, ws *webSession, tenant, app string) map[string]any {
	a := s.automationRow()
	out := map[string]any{"scope": "ApproveCD " + tenant + "/" + app, "state": "missing"}
	if a == nil {
		return out
	}
	out["account"] = a.Username
	var users []string
	if err := ws.do(ctx, func(ctx context.Context, c sfc.Conn) error {
		_, cd, err := cdRow(ctx, c, tenant, app)
		if err == nil {
			users = cd.Approvers
		}
		return err
	}); err == nil {
		out["state"] = "denied"
		if slices.Contains(users, a.UserID) {
			out["state"] = "ok"
		}
	}
	return out
}

// GET /webhook-links?point=&tenant=&app=
func (s *Server) handleListWebhookLinks(w http.ResponseWriter, r *http.Request, ws *webSession) {
	acc, err := s.incidentAccessOf(r, ws)
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	all, err := s.opt.Store.ListWebhookLinks()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	q := r.URL.Query()
	ctx, cancel := s.callCtx(r)
	defer cancel()
	items := []map[string]any{}
	lang := s.requestLang(r, ws)
	for _, l := range all {
		if !linkRead(acc, l.Scope) || q.Get("point") != "" && l.Point != q.Get("point") || q.Get("tenant") != "" && l.Scope.Tenant != q.Get("tenant") ||
			q.Get("app") != "" && l.Scope.App != q.Get("app") {
			continue
		}
		role := ""
		if h, err := s.opt.Store.GetWebhook(l.Webhook); err == nil {
			role = h.Role
		}
		items = append(items, s.linkView(ctx, lang, ws, l, role))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// POST /webhook-links, PUT /webhook-links/{id}
func (s *Server) handlePutWebhookLink(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req webhookLinkReq
	if !readJSON(w, r, &req) {
		return
	}
	acc, err := s.incidentAccessOf(r, ws)
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	id := r.PathValue("id")
	var cur *store.WebhookLink
	if id != "" {
		if cur, err = s.opt.Store.GetWebhookLink(id); err != nil || !linkManage(acc, cur.Scope) {
			writeError(w, http.StatusNotFound, "not-found", "no such link")
			return
		}
		if req.Point != "" && req.Point != cur.Point || req.Scope != (store.WebhookLinkScope{}) && req.Scope != cur.Scope {
			writeError(w, http.StatusUnprocessableEntity, "immutable", "point and scope cannot change; make a new link")
			return
		}
		req.Point, req.Scope = cur.Point, cur.Scope
	}
	if !linkManage(acc, req.Scope) {
		writeError(w, http.StatusForbidden, "denied", "cluster links need a system administrator; workspace links its managers")
		return
	}
	h, err := s.opt.Store.GetWebhook(req.Webhook)
	if err != nil || !acc.webhook(h.Tenant, true) {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "webhook: no such webhook")
		return
	}
	l := &store.WebhookLink{ID: id, Point: req.Point, Scope: req.Scope, Events: req.Events, Webhook: req.Webhook, Kind: req.Kind, WaitSeconds: req.WaitSeconds,
		OnTimeout: req.OnTimeout, When: req.When, OnFail: req.OnFail, Threshold: req.Threshold, Minutes: req.Minutes, Recover: req.Recover, Group: req.Group, CreatedBy: ws.user.Username, CreatedAt: s.now()}
	if l.Events == nil {
		l.Events = []string{}
	}
	if cur != nil {
		l.CreatedBy, l.CreatedAt = cur.CreatedBy, cur.CreatedAt
	} else {
		l.ID = "wl-" + strings.ToLower(randomID(8))
	}
	if msg := checkLink(l, h, req.OpenIncident); msg != "" {
		code := "invalid"
		if strings.HasPrefix(msg, "role:") {
			code = "role"
		}
		writeError(w, http.StatusUnprocessableEntity, code, msg)
		return
	}
	all, _ := s.opt.Store.ListWebhookLinks()
	for _, x := range all {
		if x.ID != l.ID && x.Point == "cd" && x.Scope == l.Scope && (l.Kind == "pre-sync" || l.Kind == "post-sync") && x.Kind == l.Kind {
			writeError(w, http.StatusConflict, "exists", "this app already has a "+l.Kind+" check")
			return
		}
		if x.ID != l.ID && x.Point == "incident" && x.Scope == l.Scope && h.Role == "decide" && s.webhookRole(x.Webhook) == "decide" {
			writeError(w, http.StatusConflict, "exists", "this scope already has a decide webhook")
			return
		}
	}
	ctx, cancel := s.callCtx(r)
	defer cancel()
	if l.Kind == "pre-sync" {
		if code := s.preSyncReady(ctx, ws, l); code != "" {
			writeError(w, http.StatusUnprocessableEntity, "cd-mode", text(s.requestLang(r, ws), code, nil))
			return
		}
	}
	expected := uint64(0)
	if cur != nil {
		expected = req.Revision
	}
	if err := s.opt.Store.PutWebhookLink(l, expected); errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "stale", "the link changed; read it again")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if l.Kind == "pre-sync" && (cur == nil || cur.Kind != "pre-sync") {
		s.cdApprover(ctx, ws, l.Scope.Tenant, l.Scope.App, true)
	}
	if cur != nil && cur.Kind == "pre-sync" && l.Kind != "pre-sync" {
		s.cdApprover(ctx, ws, l.Scope.Tenant, l.Scope.App, false)
	}
	s.audit(ws, l.Scope.Tenant, "webhooks", "link", l.ID, nil, map[string]any{"point": l.Point, "webhook": l.Webhook, "kind": l.Kind})
	status := http.StatusOK
	if cur == nil {
		status = http.StatusCreated
	}
	writeJSON(w, status, s.linkView(ctx, s.requestLang(r, ws), ws, l, h.Role))
}

func (s *Server) webhookRole(name string) string {
	if h, err := s.opt.Store.GetWebhook(name); err == nil {
		return h.Role
	}
	return ""
}

// preSyncReady: the app's CD waits for approval ("" = fine, else the
// text code of what to change).
func (s *Server) preSyncReady(ctx context.Context, ws *webSession, l *store.WebhookLink) string {
	var cd *sfc.AppCD
	err := ws.do(ctx, func(ctx context.Context, c sfc.Conn) error {
		var err error
		_, cd, err = cdRow(ctx, c, l.Scope.Tenant, l.Scope.App)
		return err
	})
	if err != nil {
		return "cd-link.needs-cd"
	}
	if cd.Mode != "manual" {
		return "cd-link.needs-manual"
	}
	return ""
}

// cdApprover makes the automation account an approver of the app's CD
// candidates (or drops it), as the person saving the link (sfcd judges
// it). sfcd takes the user ID, which the web learns from the account's
// login; before any login it logs in once to learn it.
func (s *Server) cdApprover(ctx context.Context, ws *webSession, tenant, app string, grant bool) {
	a := s.automationRow()
	if a == nil {
		return
	}
	if a.UserID == "" {
		as, err := s.automationLogin(ctx, "cd-approver")
		if err != nil {
			s.log.Warn("cd approver", "tenant", tenant, "app", app, "grant", grant, "err", automationErrorCode(err))
			return
		}
		as.conn.Close()
		if a = s.automationRow(); a == nil || a.UserID == "" {
			return
		}
	}
	route := routeAppCDApproverAdd
	if !grant {
		route = routeAppCDApproverDel
	}
	body, _ := json.Marshal(map[string]any{"opId": newOpID(), "userId": a.UserID})
	method, path := routePath(route, "t", tenant, "app", app)
	if status, out := s.dispatchWith(ctx, ws, method, path, nil, body, map[string]string{"X-SFC-Reason": "webhook-pre-sync"}); status >= 400 {
		s.log.Warn("cd approver", "tenant", tenant, "app", app, "grant", grant, "status", status, "body", string(out))
	}
}

// DELETE /webhook-links/{id}
func (s *Server) handleDeleteWebhookLink(w http.ResponseWriter, r *http.Request, ws *webSession) {
	acc, err := s.incidentAccessOf(r, ws)
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	l, err := s.opt.Store.GetWebhookLink(r.PathValue("id"))
	if err != nil || !linkManage(acc, l.Scope) {
		writeError(w, http.StatusNotFound, "not-found", "no such link")
		return
	}
	if err := s.opt.Store.DeleteWebhookLink(l.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if l.Kind == "pre-sync" {
		ctx, cancel := s.callCtx(r)
		defer cancel()
		s.cdApprover(ctx, ws, l.Scope.Tenant, l.Scope.App, false)
	}
	s.audit(ws, l.Scope.Tenant, "webhooks", "unlink", l.ID, nil, map[string]any{"point": l.Point, "webhook": l.Webhook})
	w.WriteHeader(http.StatusNoContent)
}

// linksFor: the enabled links of a point whose scope covers tenant/app
// (cluster links cover everything).
func (s *Server) linksFor(point, tenant, app string) []*store.WebhookLink {
	all, err := s.opt.Store.ListWebhookLinks()
	if err != nil {
		return nil
	}
	var out []*store.WebhookLink
	for _, l := range all {
		if l.Point != point || l.Scope.Tenant != "" && l.Scope.Tenant != tenant || l.Scope.App != "" && l.Scope.App != app {
			continue
		}
		out = append(out, l)
	}
	return out
}
