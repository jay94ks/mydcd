// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/jay94ks/mydcd/internal/web/mydc"
	"github.com/jay94ks/mydcd/internal/web/store"
)

// Incidents (W2.3, UI-B3·B4): what the watcher opened and decided. Who
// may see an incident is asked of mydcd on each request: cluster incidents
// are the system administrators', app incidents belong to whoever has a
// role in the workspace. Approving sends the action as the approver.

// Decision kinds.
const (
	decisionNone     = "none"
	decisionAuto     = "auto"
	decisionPending  = "pending"
	decisionApproved = "approved"
	decisionRejected = "rejected"
	decisionExpired  = "expired"
)

// Incident states.
const (
	incidentOpen       = "open"
	incidentMitigating = "mitigating"
	incidentRecovered  = "recovered"
	incidentClosed     = "closed"
)

// incidentAccess is what the caller may see, from mydcd.
type incidentAccess struct {
	admin bool
	roles map[string]mydc.Role
}

func (s *Server) incidentAccessOf(r *http.Request, ws *webSession) (incidentAccess, error) {
	ctx, cancel := s.callCtx(r)
	defer cancel()
	return s.incidentAccessCtx(ctx, ws)
}

func (s *Server) incidentAccessCtx(ctx context.Context, ws *webSession) (incidentAccess, error) {
	out := incidentAccess{roles: map[string]mydc.Role{}}
	err := ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		who, err := c.Whoami(ctx)
		if err != nil {
			return err
		}
		out.admin = who.User.SystemAdmin
		ts, err := c.Tenants(ctx)
		for _, t := range ts {
			out.roles[t.ID] = t.Role
		}
		return err
	})
	return out, err
}

// can: see (manage=false) or decide and delete (manage=true).
func (a incidentAccess) can(in *store.Incident, manage bool) bool {
	if in.Scope == "cluster" {
		return a.admin
	}
	role := a.roles[in.Tenant]
	return role != "" && (!manage || role == mydc.RoleManager)
}

type incidentDecisionView struct {
	Kind      string `json:"kind"`
	By        string `json:"by,omitempty"`
	ExpiresAt string `json:"expiresAt,omitempty"`
	Note      string `json:"note,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

type incidentRow struct {
	ID         string               `json:"id"`
	Scope      string               `json:"scope"`
	Tenant     string               `json:"tenant,omitempty"`
	App        string               `json:"app,omitempty"`
	Node       string               `json:"node,omitempty"`
	Signal     string               `json:"signal"`
	Mitigation string               `json:"mitigation"`
	Impact     string               `json:"impact"`
	Decision   incidentDecisionView `json:"decision"`
	State      string               `json:"state"`
	At         string               `json:"at"`
	Fallback   bool                 `json:"fallback,omitempty"`
}

// decisionNow is the decision as it stands now: a pending one past its
// deadline reads as expired before the watcher records it.
func (s *Server) decisionNow(in *store.Incident) store.IncidentDecision {
	d := in.Decision
	if d.Kind == decisionPending && !d.ExpiresAt.IsZero() && !s.now().Before(d.ExpiresAt) {
		d.Kind = decisionExpired
	}
	return d
}

func (s *Server) incidentRowOf(in *store.Incident) incidentRow {
	d := s.decisionNow(in)
	dv := incidentDecisionView{Kind: d.Kind, By: d.By, Note: d.Note, Reason: d.Reason}
	if d.Kind == decisionPending {
		dv.ExpiresAt = rfc3339(d.ExpiresAt)
	}
	mit := ""
	if a := chosenAction(in); a != nil {
		mit = a.Label
	} else if a := incidentActionByID(in.Mitigation); a != nil {
		mit = a.Label
	}
	impact := in.Impact
	if impact == "" {
		impact = impactHigh
	}
	return incidentRow{ID: in.ID, Scope: in.Scope, Tenant: in.Tenant, App: in.App, Node: in.Node, Signal: in.Signal, Mitigation: mit,
		Impact: impact, Decision: dv, State: in.State, At: rfc3339(in.At), Fallback: in.Fallback}
}

// GET /incidents?scope=&decision=&state=&tenant=&app=&q=&cursor=&limit=
func (s *Server) handleListIncidents(w http.ResponseWriter, r *http.Request, ws *webSession) {
	acc, err := s.incidentAccessOf(r, ws)
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	all, err := s.opt.Store.ListIncidents()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	limit = min(limit, 200)
	cursor := q.Get("cursor")
	text := strings.ToLower(q.Get("q"))
	items := []incidentRow{}
	total, pending, next := 0, 0, ""
	past := cursor == ""
	for _, in := range all {
		if !acc.can(in, false) {
			continue
		}
		row := s.incidentRowOf(in)
		if row.Decision.Kind == decisionPending {
			pending++
		}
		if v := q.Get("scope"); v != "" && v != in.Scope ||
			q.Get("decision") != "" && q.Get("decision") != row.Decision.Kind ||
			q.Get("state") != "" && q.Get("state") != in.State ||
			q.Get("tenant") != "" && q.Get("tenant") != in.Tenant ||
			q.Get("app") != "" && q.Get("app") != in.App ||
			text != "" && !strings.Contains(strings.ToLower(in.Title+" "+in.Target+" "+in.Signal), text) {
			continue
		}
		total++
		if !past {
			past = in.ID == cursor
			continue
		}
		if len(items) == limit {
			if next == "" {
				next = items[len(items)-1].ID
			}
			continue
		}
		items = append(items, row)
	}
	out := map[string]any{"items": items, "total": total, "pending": pending, "level": nil, "stopped": false, "watcher": s.watcherView()}
	if next != "" {
		out["cursor"] = next
	}
	if acc.admin {
		p, err := s.clusterPolicy()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
		out["level"], out["stopped"] = p.Level, p.Stopped
		if p.Stopped {
			out["level"] = incidentOff
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) watcherView() map[string]any {
	st, err := s.opt.Store.GetIncidentWatcher()
	if err != nil || st.State == "" {
		return map[string]any{"state": "stopped"}
	}
	v := map[string]any{"state": st.State}
	if !st.At.IsZero() {
		v["at"] = rfc3339(st.At)
	}
	if st.Error != "" {
		v["error"] = st.Error
	}
	return v
}

// loadIncident reads one incident the caller may see (404 otherwise, the
// same answer for "none" and "not yours").
func (s *Server) loadIncident(w http.ResponseWriter, r *http.Request, ws *webSession, manage bool) (*store.Incident, bool) {
	return s.loadIncidentByID(w, r, ws, r.PathValue("id"), manage)
}

func (s *Server) loadIncidentByID(w http.ResponseWriter, r *http.Request, ws *webSession, id string, manage bool) (*store.Incident, bool) {
	in, err := s.opt.Store.GetIncident(id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not-found", "no such incident")
		return nil, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return nil, false
	}
	acc, err := s.incidentAccessOf(r, ws)
	if err != nil {
		s.writeBackendError(w, ws, err)
		return nil, false
	}
	if !acc.can(in, false) {
		writeError(w, http.StatusNotFound, "not-found", "no such incident")
		return nil, false
	}
	if manage && !acc.can(in, true) {
		writeError(w, http.StatusForbidden, "denied", "only the workspace's managers (app incidents) or system administrators (cluster incidents)")
		return nil, false
	}
	return in, true
}

func (s *Server) incidentDetail(in *store.Incident) map[string]any {
	raw, _ := json.Marshal(s.incidentRowOf(in))
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	timeline := in.Timeline
	if timeline == nil {
		timeline = []store.IncidentEntry{}
	}
	out["title"], out["revision"], out["timeline"], out["guides"], out["rule"], out["target"] = in.Title, in.Revision, timeline, s.incidentGuideVersions(in), in.Rule, in.Target
	out["mcpCalls"] = in.MCPCalls
	if in.MCPCalls == nil {
		out["mcpCalls"] = map[string]int{}
	}
	cands := make([]map[string]any, 0, len(in.Candidates))
	for _, c := range in.Candidates {
		row := map[string]any{"action": c.ID, "label": c.Label}
		if c.Note != "" {
			row["note"] = c.Note
		}
		cands = append(cands, row)
	}
	out["candidates"] = cands
	if len(in.Assessment) > 0 {
		out["assessment"] = in.Assessment
	}
	if in.Op != "" {
		out["op"] = in.Op
	}
	if in.Approval != nil && s.decisionNow(in).Kind == decisionPending {
		act := ""
		if a := chosenAction(in); a != nil {
			act = a.ID
		}
		out["approval"] = map[string]any{"title": in.Approval.Title, "fields": in.Approval.Fields, "expiresAt": rfc3339(in.Decision.ExpiresAt),
			"basisHash": in.Approval.BasisHash, "action": act, "target": in.Target}
	}
	return out
}

// GET /incidents/{id}
func (s *Server) handleGetIncident(w http.ResponseWriter, r *http.Request, ws *webSession) {
	in, ok := s.loadIncident(w, r, ws, false)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, s.incidentDetail(in))
}

// chosenAction is the incident's chosen candidate.
func chosenAction(in *store.Incident) *store.IncidentAction {
	for i := range in.Candidates {
		if in.Candidates[i].ID == in.Mitigation {
			return &in.Candidates[i]
		}
	}
	return nil
}

// incidentBasis binds the approval card to the action, its target and the
// impact it was assessed at.
func incidentBasis(in *store.Incident) string {
	h := sha256.New()
	a := chosenAction(in)
	parts := []string{in.ID, in.Mitigation, in.Impact, in.Target}
	for x := a; x != nil; x = x.Also {
		parts = append(parts, x.Method, x.Path, string(x.Body))
	}
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	h.Write(in.Assessment)
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// POST /incidents/{id}/approve {opId, basisHash} → {op}: sent with the
// approver's own session.
func (s *Server) handleApproveIncident(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID      string `json:"opId"`
		BasisHash string `json:"basisHash"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !uuidRE.MatchString(req.OpID) {
		writeError(w, http.StatusBadRequest, "bad-request", "opId must be a lowercase UUID v4")
		return
	}
	in, ok := s.loadIncident(w, r, ws, true)
	if !ok {
		return
	}
	repeat := in.Decision.Kind == decisionApproved && in.OpID == req.OpID
	switch d := s.decisionNow(in); {
	case repeat:
	case d.Kind == decisionExpired:
		writeError(w, http.StatusGone, "expired", "the approval request expired")
		return
	case d.Kind != decisionPending || in.Approval == nil:
		writeError(w, http.StatusConflict, "not-pending", "the incident is not waiting for approval")
		return
	case req.BasisHash != in.Approval.BasisHash || incidentBasis(in) != in.Approval.BasisHash:
		writeError(w, http.StatusConflict, "incident-changed", "the incident changed; read it again")
		return
	}
	a := chosenAction(in)
	if a == nil {
		writeError(w, http.StatusConflict, "incident-changed", "the incident has no action to run")
		return
	}
	if a.MCP != nil {
		s.approveIncidentMCP(w, r, ws, in, a, req.OpID, repeat)
		return
	}
	status, out, op := s.sendIncidentAction(r.Context(), ws, in, a, req.OpID, "incident-approved")
	if op == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(out)
		return
	}
	if !repeat {
		now := s.now()
		_, err := s.opt.Store.UpdateIncident(in.ID, func(x *store.Incident) error {
			if x.Decision.Kind != decisionPending && !(x.Decision.Kind == decisionApproved && x.OpID == req.OpID) {
				return nil
			}
			x.Decision = store.IncidentDecision{Kind: decisionApproved, By: ws.user.Username, At: now}
			x.Approval, x.Op, x.OpID, x.State, x.MitigatedAt, x.UpdatedAt = nil, op.ID, req.OpID, incidentMitigating, now, now
			x.Timeline = append(x.Timeline, store.IncidentEntry{At: now, Kind: "approve", Text: a.Label + " 승인", Op: op.ID, Signer: ws.user.Username})
			return nil
		})
		if err != nil {
			s.log.Error("incident approve", "err", err, "incident", in.ID)
		}
		s.audit(ws, in.Tenant, "incidents", "approve", in.ID, nil, map[string]any{"action": a.ID, "op": op.ID})
		s.emitIncidentID(in.ID, "approved")
	}
	writeJSON(w, http.StatusOK, map[string]any{"op": op})
}

// sendIncidentAction sends the action through the screen API as ws, with
// the reason and incident id on the op (display metadata).
func (s *Server) sendIncidentAction(ctx context.Context, ws *webSession, in *store.Incident, a *store.IncidentAction, opID, reason string) (int, []byte, *opView) {
	status, out, op := s.sendOneIncidentAction(ctx, ws, in, a, opID, reason)
	if op != nil && a.Also != nil && op.State != "rejected" && op.State != "failed" {
		if st, raw, _ := s.sendOneIncidentAction(ctx, ws, in, a.Also, alsoOpID(opID), reason); st >= 400 {
			s.log.Warn("incident second step", "incident", in.ID, "action", a.Also.ID, "status", st, "body", string(raw))
			_, _ = s.opt.Store.UpdateIncident(in.ID, func(x *store.Incident) error {
				x.Timeline = append(x.Timeline, store.IncidentEntry{At: s.now(), Kind: "notify", Text: a.Also.Label + "을(를) 보내지 못했어요. 사람이 확인해 주세요."})
				return nil
			})
		}
	}
	return status, out, op
}

func (s *Server) sendOneIncidentAction(ctx context.Context, ws *webSession, in *store.Incident, a *store.IncidentAction, opID, reason string) (int, []byte, *opView) {
	body := map[string]any{}
	if len(a.Body) > 0 {
		_ = json.Unmarshal(a.Body, &body)
	}
	body["opId"] = opID
	raw, _ := json.Marshal(body)
	hdr := map[string]string{"X-MyDC-Reason": url.PathEscape(reason), "X-MyDC-Incident": url.PathEscape(in.ID)}
	status, out := s.dispatchWith(ctx, ws, a.Method, a.Path, nil, raw, hdr)
	var res struct {
		Op *opView `json:"op"`
	}
	_ = json.Unmarshal(out, &res)
	if status >= 400 {
		return status, out, nil
	}
	if res.Op == nil {
		return http.StatusBadGateway, []byte(`{"error":{"code":"error","message":"no op in the answer"}}`), nil
	}
	return status, out, res.Op
}

var rejectReasons = map[string]bool{"handled-by-person": true, "wrong-action": true, "not-now": true, "other": true}

// POST /incidents/{id}/reject {reason, note?}
func (s *Server) handleRejectIncident(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Reason string `json:"reason"`
		Note   string `json:"note,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	note := strings.TrimSpace(req.Note)
	if !rejectReasons[req.Reason] || utf8.RuneCountInString(note) > 256 || req.Reason == "other" && note == "" {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "reason: handled-by-person, wrong-action, not-now or other (other needs a note); note at most 256 characters")
		return
	}
	in, ok := s.loadIncident(w, r, ws, true)
	if !ok {
		return
	}
	if d := s.decisionNow(in); d.Kind != decisionPending {
		if d.Kind == decisionExpired {
			writeError(w, http.StatusGone, "expired", "the approval request expired")
			return
		}
		writeError(w, http.StatusConflict, "not-pending", "the incident is not waiting for approval")
		return
	}
	now := s.now()
	_, err := s.opt.Store.UpdateIncident(in.ID, func(x *store.Incident) error {
		x.Decision = store.IncidentDecision{Kind: decisionRejected, By: ws.user.Username, At: now, Reason: req.Reason, Note: note}
		x.Approval, x.UpdatedAt = nil, now
		x.Timeline = append(x.Timeline, store.IncidentEntry{At: now, Kind: "reject", Text: "거절: " + req.Reason, Signer: ws.user.Username})
		return nil
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(ws, in.Tenant, "incidents", "reject", in.ID, nil, map[string]any{"reason": req.Reason})
	s.emitIncidentID(in.ID, "rejected")
	w.WriteHeader(http.StatusNoContent)
}

// DELETE /incidents/{id} {confirmName}: the incident's record goes; ops it
// ran stay in the op log.
func (s *Server) handleDeleteIncident(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		ConfirmName string `json:"confirmName"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	in, ok := s.loadIncident(w, r, ws, true)
	if !ok {
		return
	}
	if req.ConfirmName != in.ID {
		writeError(w, http.StatusUnprocessableEntity, "confirm-name", "type the incident id to delete it")
		return
	}
	if err := s.opt.Store.DeleteIncident(in.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(ws, in.Tenant, "incidents", "delete", in.ID, map[string]any{"title": in.Title}, nil)
	w.WriteHeader(http.StatusNoContent)
}
