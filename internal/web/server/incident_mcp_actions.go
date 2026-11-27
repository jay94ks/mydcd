// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/web/store"
)

// MCP tools as incident candidates (W2.3a): change or notify tools set to
// propose-approve or propose-auto that the incident's workspace may use
// become candidates after the rules' own. Their arguments come from the
// tool's input limits filled from the incident (a required one left open
// drops the tool). A propose-approve tool always asks a person; a
// propose-auto tool may run on its own like a rule action (low impact,
// policy, quiet hours, hourly rate) and only under its own limits per
// incident and per day. The call is not an op: the incident keeps who ran
// it and whether it failed, never the answer.

const incidentMCPCandidates = 4

// mcpCandidates: the MCP candidates for in, and why tools were left out.
func (s *Server) mcpCandidates(in *store.Incident, gd incidentGuides) ([]store.IncidentAction, []string) {
	all, err := s.opt.Store.ListMCPServers()
	if err != nil || len(all) == 0 {
		return nil, nil
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Name < all[j].Name })
	var out []store.IncidentAction
	var skipped []string
	for _, m := range all {
		if len(gd.mcp) > 0 && !slices.Contains(gd.mcp, m.Name) {
			continue
		}
		for _, t := range m.Tools {
			if !strings.HasPrefix(t.Incident, "propose-") || t.Kind == "read" || !mcpToolFor(m, t, in.Tenant) {
				continue
			}
			if t.Auto != nil && len(t.Auto.Signals) > 0 && !slices.Contains(t.Auto.Signals, in.Signal) {
				continue
			}
			if !aiAllows(mcpImpact(t)) {
				continue // high: people act themselves (R19 3.5)
			}
			label := t.Title
			if label == "" {
				label = mcpShown(m.Name, t.Name)
			}
			args, ok := incidentMCPArgs(t, in)
			if !ok {
				skipped = append(skipped, label+": 도구 입력을 사건에서 채울 수 없음")
				continue
			}
			if len(out) >= incidentMCPCandidates {
				skipped = append(skipped, label+": MCP 후보는 "+fmt.Sprint(incidentMCPCandidates)+"개까지")
				continue
			}
			x := &store.IncidentMCP{Server: m.Name, Tool: t.Name, Floor: impactMedium}
			if t.Auto != nil {
				if t.Auto.Floor != "" {
					x.Floor = t.Auto.Floor
				}
				x.Revert, x.Irreversible = t.Auto.Revert.Tool, t.Auto.Revert.Irreversible
			}
			x.Auto = t.Incident == "propose-auto" && len(autoMissing(t, t.Auto)) == 0
			body, _ := json.Marshal(args)
			out = append(out, store.IncidentAction{ID: mcpShown(m.Name, t.Name), Label: label, Method: "MCP", Path: mcpShown(m.Name, t.Name),
				Body: body, Note: mcpArgsNote(args), MCP: x})
		}
	}
	return out, skipped
}

// mcpArgsNote: the arguments in one line ("k=v, …").
func mcpArgsNote(args map[string]any) string {
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+fmt.Sprint(args[k]))
	}
	return oneLine(strings.Join(parts, ", "), 300)
}

// actionFloor is a candidate's impact floor (unknown: high).
func actionFloor(a *store.IncidentAction) string {
	if a.MCP != nil {
		return a.MCP.Floor
	}
	if def := incidentActionByID(a.ID); def != nil {
		return def.floor()
	}
	return impactHigh
}

func actionReversible(a *store.IncidentAction) bool {
	if a.MCP != nil {
		return a.MCP.Revert != ""
	}
	def := incidentActionByID(a.ID)
	return def != nil && webActions[def.Action].Reversible
}

// mcpAutoBlocked: why the MCP candidate may not run on its own now ("" =
// it may).
func (s *Server) mcpAutoBlocked(in *store.Incident, a *store.IncidentAction, now time.Time) string {
	m, err := s.opt.Store.GetMCPServer(a.MCP.Server)
	if err != nil {
		return "MCP 서버가 없어졌어요."
	}
	t := m.Tool(a.MCP.Tool)
	if !a.MCP.Auto || t == nil || t.Incident != "propose-auto" || len(autoMissing(t, t.Auto)) > 0 {
		return "승인이 필요한 MCP 조치예요."
	}
	shown := mcpShown(m.Name, t.Name)
	mine := 0
	for _, r := range in.MCPRuns {
		if r.Tool == shown {
			mine++
		}
	}
	if mine >= t.Auto.PerIncident {
		return fmt.Sprintf("이 사건에서 MCP 도구 한도(%d번)에 닿았어요.", t.Auto.PerIncident)
	}
	all, err := s.opt.Store.ListIncidents()
	if err != nil {
		return "MCP 도구 하루 한도를 셀 수 없어요."
	}
	day := 0
	for _, x := range all {
		for _, r := range x.MCPRuns {
			if r.Tool == shown && now.Sub(r.At) < 24*time.Hour {
				day++
			}
		}
	}
	if day >= t.Auto.PerDay {
		return fmt.Sprintf("MCP 도구 하루 한도(%d번)에 닿았어요.", t.Auto.PerDay)
	}
	return ""
}

// callIncidentMCP calls the candidate's tool once if it is still offered
// for in (the answer is dropped). auto: as the automation account, which
// needs propose-auto.
func (s *Server) callIncidentMCP(ctx context.Context, in *store.Incident, a *store.IncidentAction, by, opID string, auto bool) store.IncidentMCPRun {
	run := store.IncidentMCPRun{Tool: a.ID, At: s.now(), By: by, Auto: auto, OpID: opID}
	m, err := s.opt.Store.GetMCPServer(a.MCP.Server)
	var t *store.MCPTool
	if err == nil {
		t = m.Tool(a.MCP.Tool)
	}
	switch {
	case t == nil || !strings.HasPrefix(t.Incident, "propose-") || t.Kind == "read" || !mcpToolFor(m, t, in.Tenant):
		run.Error = "the tool is no longer offered for incidents"
		return run
	case auto && t.Incident != "propose-auto":
		run.Error = "the tool no longer runs on its own"
		return run
	}
	var args map[string]any
	_ = json.Unmarshal(a.Body, &args)
	_, isErr, cerr := s.mcpCall(context.WithoutCancel(ctx), m, t.Name, args)
	switch {
	case cerr != nil:
		run.Error = oneLine(mcpErrText(cerr), 300)
	case isErr:
		run.Error = "the tool reported an error"
	}
	return run
}

func addMCPRun(x *store.Incident, run store.IncidentMCPRun, server string) {
	x.MCPRuns = append(x.MCPRuns, run)
	if x.MCPCalls == nil {
		x.MCPCalls = map[string]int{}
	}
	x.MCPCalls[server]++
}

// autoRunIncidentMCP runs an MCP candidate as the automation account; a
// failure turns into a request for approval.
func (s *Server) autoRunIncidentMCP(ctx context.Context, ws *webSession, in *store.Incident, a *store.IncidentAction, now time.Time) {
	cluster, _ := s.clusterPolicy()
	s.hooks.mcpAuto.Lock()
	cur, err := s.opt.Store.GetIncident(in.ID)
	why := ""
	if err == nil {
		why = s.mcpAutoBlocked(cur, a, now)
	}
	if err != nil || why != "" {
		s.hooks.mcpAuto.Unlock()
		if err != nil {
			s.log.Error("incident", "err", err, "incident", in.ID)
			return
		}
		_, _ = s.opt.Store.UpdateIncident(in.ID, func(x *store.Incident) error {
			if cluster != nil {
				s.askIncident(x, cluster, why, now)
			}
			return nil
		})
		if x, err := s.opt.Store.GetIncident(in.ID); err == nil {
			s.notifyIncident(ctx, ws, x)
		}
		return
	}
	run := s.callIncidentMCP(ctx, in, a, ws.user.Username, "", true)
	_, err = s.opt.Store.UpdateIncident(in.ID, func(x *store.Incident) error {
		addMCPRun(x, run, a.MCP.Server)
		x.UpdatedAt = now
		if run.Error == "" {
			x.Decision = store.IncidentDecision{Kind: decisionAuto, By: ws.user.Username, At: now}
			x.State, x.MitigatedAt = incidentMitigating, now
			x.Timeline = append(x.Timeline, store.IncidentEntry{At: now, Kind: "auto", Text: a.Label + " 자동 실행 (MCP " + a.ID + ")", Signer: ws.user.Username})
			return nil
		}
		x.Timeline = append(x.Timeline, store.IncidentEntry{At: now, Kind: "auto", Text: "MCP 자동 실행 실패: " + run.Error, Signer: ws.user.Username})
		if cluster != nil {
			s.askIncident(x, cluster, "MCP 도구가 실패했어요("+run.Error+").", now)
		}
		return nil
	})
	s.hooks.mcpAuto.Unlock()
	if err != nil {
		s.log.Error("incident", "err", err, "incident", in.ID)
		return
	}
	if run.Error != "" {
		if x, err := s.opt.Store.GetIncident(in.ID); err == nil {
			s.notifyIncident(ctx, ws, x)
		}
	}
}

func mcpRunOutcome(a *store.IncidentAction, run *store.IncidentMCPRun) map[string]any {
	v := map[string]any{"ok": run.Error == "", "server": a.MCP.Server, "tool": a.MCP.Tool}
	if run.Error != "" {
		v["error"] = run.Error
	}
	return map[string]any{"mcp": v}
}

// approveIncidentMCP is POST /incidents/{id}/approve for an MCP candidate:
// approved first (one call per approval), then called once with the
// approver's authority checked; a repeat with the same opId gets the
// recorded outcome. → {mcp:{ok, server, tool, error?}}
func (s *Server) approveIncidentMCP(w http.ResponseWriter, r *http.Request, ws *webSession, in *store.Incident, a *store.IncidentAction, opID string, repeat bool) {
	if repeat {
		for i := range in.MCPRuns {
			if in.MCPRuns[i].OpID == opID {
				writeJSON(w, http.StatusOK, mcpRunOutcome(a, &in.MCPRuns[i]))
				return
			}
		}
		writeError(w, http.StatusConflict, "in-progress", "the approved call is still running; read the incident again")
		return
	}
	acc, err := s.incidentAccessOf(r, ws)
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	m, err := s.opt.Store.GetMCPServer(a.MCP.Server)
	var t *store.MCPTool
	if err == nil {
		t = m.Tool(a.MCP.Tool)
	}
	if t == nil || !strings.HasPrefix(t.Incident, "propose-") || !mcpToolFor(m, t, in.Tenant) || !mcpUser(acc, m, t) {
		writeError(w, http.StatusForbidden, "denied", "you may not use this MCP tool, or it is no longer offered for incidents")
		return
	}
	now := s.now()
	basis := in.Approval.BasisHash
	_, err = s.opt.Store.UpdateIncident(in.ID, func(x *store.Incident) error {
		if x.Decision.Kind != decisionPending || x.Approval == nil || x.Approval.BasisHash != basis {
			return store.ErrConflict
		}
		x.Decision = store.IncidentDecision{Kind: decisionApproved, By: ws.user.Username, At: now}
		x.Approval, x.OpID, x.State, x.MitigatedAt, x.UpdatedAt = nil, opID, incidentMitigating, now, now
		x.Timeline = append(x.Timeline, store.IncidentEntry{At: now, Kind: "approve", Text: a.Label + " 승인 (MCP " + a.ID + ")", Signer: ws.user.Username})
		return nil
	})
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "incident-changed", "the incident changed or was decided; read it again")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	run := s.callIncidentMCP(r.Context(), in, a, ws.user.Username, opID, false)
	_, err = s.opt.Store.UpdateIncident(in.ID, func(x *store.Incident) error {
		addMCPRun(x, run, a.MCP.Server)
		if run.Error != "" {
			x.Timeline = append(x.Timeline, store.IncidentEntry{At: s.now(), Kind: "notify", Text: "MCP 도구 실행 실패: " + run.Error + ". 사람이 확인해 주세요."})
		}
		return nil
	})
	if err != nil {
		s.log.Error("incident approve", "err", err, "incident", in.ID)
	}
	s.audit(ws, in.Tenant, "incidents", "approve", in.ID, nil, map[string]any{"action": a.ID, "mcp": run.Error == ""})
	s.emitIncidentID(in.ID, "approved")
	writeJSON(w, http.StatusOK, mcpRunOutcome(a, &run))
}
