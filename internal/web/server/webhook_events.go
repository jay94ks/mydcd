// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jay94ks/mydcd/internal/web/mydc"
	"github.com/jay94ks/mydcd/internal/web/store"
)

// What the webhooks are sent for (W2.3b): incident notices and the decide
// webhook of incident response, and the CD checks and notices (UI-44,
// REQ-25 events). Answers are data: a decide webhook only picks among the
// candidates the rules built and cannot lower the impact floor; a CD check
// only approves, rejects or holds the candidate mydcd shows.

// incidentPayload is the incident as webhooks get it (no signal details,
// which may hold anything a container printed).
func incidentPayload(in *store.Incident) map[string]any {
	p := map[string]any{"id": in.ID, "title": in.Title, "scope": in.Scope, "signal": in.Signal, "rule": in.Rule, "state": in.State,
		"decision": in.Decision.Kind, "at": rfc3339(in.At), "link": "/incidents/" + in.ID}
	for k, v := range map[string]string{"tenant": in.Tenant, "app": in.App, "node": in.Node, "target": in.Target, "impact": in.Impact} {
		if v != "" {
			p[k] = v
		}
	}
	if a := chosenAction(in); a != nil {
		p["mitigation"] = map[string]string{"action": a.ID, "label": a.Label}
	}
	return p
}

// emitIncident sends one incident event to the notify links that cover it.
func (s *Server) emitIncident(in *store.Incident, event string) {
	for _, l := range s.linksFor("incident", in.Tenant, in.App) {
		if in.Scope == "cluster" && l.Scope.Tenant != "" || !slices.Contains(l.Events, event) {
			continue
		}
		h, err := s.opt.Store.GetWebhook(l.Webhook)
		if err != nil || h.Role != "notify" || !h.Enabled {
			continue
		}
		s.sendWebhookLater(h, webhookSend{Point: "incident", Link: l.ID, Event: "incident." + event, Summary: fmt.Sprintf("[%s] %s", incidentEventWord[event], in.Title),
			Payload: map[string]any{"incident": incidentPayload(in), "dedupKey": in.ID, "link": l.ID}})
	}
}

var incidentEventWord = map[string]string{"opened": "장애", "approval-required": "승인 요청", "auto-run": "자동 조치", "approved": "승인됨",
	"rejected": "거절됨", "expired": "승인 만료", "recovered": "회복", "closed": "닫힘"}

// emitIncidentID reloads and emits (after a store update).
func (s *Server) emitIncidentID(id, event string) {
	if in, err := s.opt.Store.GetIncident(id); err == nil {
		s.emitIncident(in, event)
	}
}

// decideLink is the most specific decide link for an incident (app, then
// workspace, then cluster) with its webhook ("" link when none, or why it
// cannot be used).
func (s *Server) decideLink(scope, tenant, app string) (*store.WebhookLink, *store.Webhook, string) {
	var best *store.WebhookLink
	rank := func(l *store.WebhookLink) int {
		switch {
		case l.Scope.App != "":
			return 2
		case l.Scope.Tenant != "":
			return 1
		}
		return 0
	}
	for _, l := range s.linksFor("incident", tenant, app) {
		if scope == "cluster" && l.Scope.Tenant != "" || s.webhookRole(l.Webhook) != "decide" {
			continue
		}
		if best == nil || rank(l) > rank(best) {
			best = l
		}
	}
	if best == nil {
		return nil, nil, "none-linked"
	}
	h, err := s.opt.Store.GetWebhook(best.Webhook)
	if err != nil {
		return nil, nil, "none-linked"
	}
	if !h.Enabled {
		return best, h, "disabled"
	}
	return best, h, ""
}

// aiSkip says why AI does not judge incidents of a workspace ("" = it does).
func (s *Server) aiSkip(tenant string) string {
	cfg := s.aiConfig()
	if tenant != "" && newAIExcluder(cfg.Data.ExcludeTenants).has(tenant) {
		return "excluded"
	}
	cats := s.aiCatalogs()
	for _, role := range []string{roleDiagnosis, roleImpact} {
		r := cfg.Roles[role]
		if t, _ := aiTries(cfg, cats, r, false); len(t) == 0 {
			if r.Main == nil && r.Fallback == nil {
				return "role-off"
			}
			return "no-key"
		}
	}
	return ""
}

// decideState is the policy card's order: what is tried, what is used now
// and why the earlier ones are skipped.
func (s *Server) decideState(scope, tenant, app string) map[string]any {
	order := []string{"ai", "rules"}
	_, _, whyHook := s.decideLink(scope, tenant, app)
	if whyHook != "none-linked" {
		order = []string{"ai", "webhook", "rules"}
	}
	skip := map[string]string{}
	now := "rules"
	if why := s.aiSkip(tenant); why == "" {
		now = "ai"
	} else {
		skip["ai"] = why
		if whyHook == "" {
			now = "webhook"
		} else {
			skip["webhook"] = whyHook
		}
	}
	return map[string]any{"decide": order, "decideNow": now, "decideSkip": skip}
}

// decideByWebhook asks the decide webhook to pick among the candidates.
// It returns true when the answer was used (in.Candidates is then that one
// first, or empty for "none").
func (s *Server) decideByWebhook(ctx context.Context, in *store.Incident) bool {
	l, h, why := s.decideLink(in.Scope, in.Tenant, in.App)
	if l == nil || why != "" {
		return false
	}
	cands := []map[string]any{}
	allowed := []string{"none"}
	for _, c := range in.Candidates {
		row := map[string]any{"action": c.ID, "label": c.Label}
		row["impact"] = actionFloor(&c)
		if c.Note != "" {
			row["note"] = c.Note
		}
		cands = append(cands, row)
		allowed = append(allowed, c.ID)
	}
	d, ans := s.deliverWebhook(ctx, h, webhookSend{Point: "incident", Link: l.ID, Event: "incident.decide", Decide: true,
		Payload: map[string]any{"incident": incidentPayload(in), "candidates": cands, "allowed": allowed, "link": l.ID}})
	if d == nil {
		return false
	}
	var res struct {
		Action string `json:"action"`
		Reason string `json:"reason"`
	}
	ok := d.OK() && json.Unmarshal(ans, &res) == nil && slices.Contains(allowed, res.Action)
	reason := oneLine(res.Reason, 200)
	text := ""
	switch {
	case !d.OK():
		text = "판단 웹훅이 답하지 않아 규칙으로 판단해요 (" + d.Error + ")."
		reason = d.Error
	case !ok:
		reason = "응답 형식이 맞지 않음"
		if res.Action != "" {
			reason = oneLine(res.Action, 60) + "은(는) allowed_actions에 없습니다"
		}
		text = "판단 응답을 버렸습니다 · " + reason
	case res.Action == "none":
		text = "판단 웹훅: 맞는 조치가 없어요. 사람에게 넘겨요."
	default:
		text = "판단 웹훅이 골랐어요: " + res.Action
	}
	if reason != "" && ok {
		text += " (" + reason + ")"
	}
	d.Decision, d.Accepted, d.Reason = res.Action, &ok, reason
	s.recordDelivery(h, d)
	in.Timeline = append(in.Timeline, store.IncidentEntry{At: s.now(), Kind: "webhook", Text: text, Webhook: h.Name, Status: d.Status, Accepted: &ok, Reason: reason})
	if !ok {
		return false
	}
	if res.Action == "none" {
		in.Candidates = nil
		return true
	}
	i := slices.IndexFunc(in.Candidates, func(c store.IncidentAction) bool { return c.ID == res.Action })
	first := in.Candidates[i]
	in.Candidates = append([]store.IncidentAction{first}, slices.Delete(slices.Clone(in.Candidates), i, i+1)...)
	return true
}

// CD.

// cdHooksActive: some app has a CD link (the watcher then reads events
// even with incident response off).
func (s *Server) cdHooksActive() bool {
	all, err := s.opt.Store.ListWebhookLinks()
	if err != nil {
		return false
	}
	return slices.ContainsFunc(all, func(l *store.WebhookLink) bool { return l.Point == "cd" })
}

func cdCandidate(e webEvent) map[string]any {
	c := map[string]any{}
	if e.CD != nil {
		c["id"], c["commit"] = e.CD.CandidateID, e.CD.Commit
		if e.CD.FromVersion != "" {
			c["from"] = e.CD.FromVersion
		}
		if e.CD.ToVersion != "" {
			c["to"] = e.CD.ToVersion
		}
	}
	return c
}

// cdEvent handles one cd-* event: notices, then the checks (in the
// background; the watcher round goes on).
func (s *Server) cdEvent(e webEvent) {
	name := strings.TrimPrefix(e.Kind, "cd-")
	if e.Tenant == "" || e.App == "" {
		return
	}
	for _, l := range s.linksFor("cd", e.Tenant, e.App) {
		h, err := s.opt.Store.GetWebhook(l.Webhook)
		if err != nil {
			continue
		}
		switch {
		case l.Kind == "notify" && slices.Contains(l.Events, name) && h.Role == "notify":
			p := map[string]any{"tenant": e.Tenant, "app": e.App, "candidate": cdCandidate(e), "link": l.ID, "dedupKey": e.Tenant + "/" + e.App}
			if e.CD != nil {
				for k, v := range map[string]string{"actor": e.CD.Actor, "code": e.CD.Code, "reason": e.CD.Reason} {
					if v != "" {
						p[k] = v
					}
				}
			}
			s.sendWebhookLater(h, webhookSend{Point: "cd", Link: l.ID, Event: "cd." + name, Payload: p, Summary: fmt.Sprintf("[자동 배포] %s/%s %s", e.Tenant, e.App, name)})
		case l.Kind == "pre-sync" && e.Kind == mydc.EventCDApprovalRequired && e.CD != nil:
			l, h, e := l, h, e
			s.background(func(ctx context.Context) { s.preSync(ctx, l, h, e) })
		case l.Kind == "post-sync" && e.Kind == mydc.EventCDSyncSucceeded:
			l, h, e := l, h, e
			s.background(func(ctx context.Context) { s.postSync(ctx, l, h, e) })
		}
	}
}

// background runs fn with a bounded context, counted for tests.
func (s *Server) background(fn func(ctx context.Context)) {
	s.hooks.wg.Add(1)
	go func() {
		defer s.hooks.wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		fn(ctx)
	}()
}

// cdSend sends a CD screen action as the automation account.
func (s *Server) cdSend(ctx context.Context, tenant, app, verb string, body map[string]any) (int, string) {
	ws, err := s.watchSession(ctx)
	if err != nil {
		return 0, automationErrorCode(err)
	}
	body["opId"] = newOpID()
	// The reason is signed into the op (X-MyDC-Reason); without one the op
	// still says it came from a CD webhook.
	reason := "webhook-cd"
	if v, _ := body["reason"].(string); v != "" {
		reason = v
	}
	delete(body, "reason")
	raw, _ := json.Marshal(body)
	path := "/api/v1/t/" + url.PathEscape(tenant) + "/apps/" + url.PathEscape(app) + "/cd/" + verb
	status, out := s.dispatchWith(ctx, ws, http.MethodPost, path, nil, raw, map[string]string{"X-MyDC-Reason": url.PathEscape(reason)})
	if status >= 400 {
		var res struct {
			Error *apiError `json:"error"`
		}
		_ = json.Unmarshal(out, &res)
		if res.Error != nil {
			return status, res.Error.Code
		}
		return status, fmt.Sprint(status)
	}
	return status, ""
}

func linkTimeout(l *store.WebhookLink) time.Duration {
	if l.Kind == "pre-sync" && l.WaitSeconds > 0 {
		return time.Duration(l.WaitSeconds) * time.Second
	}
	return webhookDecideTimeout
}

// preSync asks the pre-sync webhook about a candidate waiting for
// approval: pass approves it as the automation account (ApproveCD on the
// app), reject rejects it, hold leaves it to a person.
func (s *Server) preSync(ctx context.Context, l *store.WebhookLink, h *store.Webhook, e webEvent) {
	if e.CD.CandidateID == "" {
		return
	}
	ws, err := s.watchSession(ctx)
	if err != nil {
		return
	}
	// Only while it is still the candidate waiting (an older event's
	// candidate is gone or superseded).
	cur := ""
	if err := ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		_, cd, err := cdRow(ctx, c, e.Tenant, e.App)
		if err == nil && cd.Candidate != "" && cd.CandidateDigest != ([32]byte{}) {
			cur = hex.EncodeToString(cd.CandidateDigest[:])
		}
		return err
	}); err != nil || cur != e.CD.CandidateID {
		return
	}
	chk := &store.CDCheck{Tenant: e.Tenant, App: e.App, Kind: "pre-sync", Candidate: e.CD.CandidateID, Commit: e.CD.Commit, Link: l.ID, Webhook: h.Name,
		State: "checking", At: s.now()}
	// Without ApproveCD the answer could not be carried out: the webhook
	// is not called and a person approves.
	if a := s.cdApproverState(ctx, ws, e.Tenant, e.App); a["state"] != "ok" {
		chk.State, chk.Reason = "failed", fmt.Sprintf("배포 확인 계정에 승인 권한이 없어(%v) 웹훅을 부르지 않았어요. 사람이 승인해요", a["state"])
		_ = s.opt.Store.PutCDCheck(chk)
		return
	}
	_ = s.opt.Store.PutCDCheck(chk)
	timeout := linkTimeout(l)
	d, ans := s.deliverWebhook(ctx, h, webhookSend{Point: "cd", Link: l.ID, Event: "pre-sync", Decide: true, Timeout: timeout,
		Payload: map[string]any{"tenant": e.Tenant, "app": e.App, "candidate": cdCandidate(e), "deadline": rfc3339(s.now().Add(timeout)),
			"allowed": []string{"pass", "hold", "reject"}, "link": l.ID}})
	decision, reason := l.OnTimeout, ""
	accepted := false
	if d == nil {
		chk.State, chk.Reason = "failed", "웹훅이 꺼져 있어 사람이 승인해요"
		_ = s.opt.Store.PutCDCheck(chk)
		return
	}
	chk.Delivery, chk.Status = d.ID, d.Status
	var res struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	}
	if d.OK() && json.Unmarshal(ans, &res) == nil && slices.Contains([]string{"pass", "hold", "reject"}, res.Decision) && utf8.RuneCountInString(res.Reason) <= 512 {
		decision, reason, accepted = res.Decision, oneLine(res.Reason, 512), true
	} else if d.OK() {
		reason = "응답 형식이 맞지 않음"
	} else {
		reason = d.Error
	}
	d.Decision, d.Accepted, d.Reason = decision, &accepted, reason
	s.recordDelivery(h, d)
	why := "웹훅 " + h.Name
	if reason != "" {
		why += ": " + reason
	}
	if !accepted {
		why += " (시간 초과·오류 → " + decision + ")"
	}
	switch decision {
	case "pass":
		if st, code := s.cdSend(ctx, e.Tenant, e.App, "candidate/approve", map[string]any{"candidate": e.CD.CandidateID, "reason": oneLine(why, 512)}); code != "" {
			chk.State, chk.Reason, chk.Status = "failed", "승인을 보내지 못함: "+code, st
		} else {
			chk.State = "passed"
		}
	case "reject":
		if st, code := s.cdSend(ctx, e.Tenant, e.App, "candidate/reject", map[string]any{"candidate": e.CD.CandidateID, "reason": oneLine(why, 512)}); code != "" {
			chk.State, chk.Reason, chk.Status = "failed", "반려를 보내지 못함: "+code, st
		} else {
			chk.State = "rejected"
		}
	default:
		chk.State = "held"
	}
	if !accepted && chk.State != "failed" {
		chk.State = "timeout"
	}
	if chk.Reason == "" {
		chk.Reason = reason
	}
	chk.At = s.now()
	_ = s.opt.Store.PutCDCheck(chk)
}

// postSync asks the post-sync webhook after a sync succeeded (when the app
// is healthy for when=healthy); a failure pauses CD and may open an
// incident that proposes the previous version (always with approval).
func (s *Server) postSync(ctx context.Context, l *store.WebhookLink, h *store.Webhook, e webEvent) {
	cand := ""
	if e.CD != nil {
		cand = e.CD.CandidateID
	}
	chk := &store.CDCheck{Tenant: e.Tenant, App: e.App, Kind: "post-sync", Candidate: cand, Link: l.ID, Webhook: h.Name, State: "checking", At: s.now()}
	_ = s.opt.Store.PutCDCheck(chk)
	health := ""
	if ws, err := s.watchSession(ctx); err == nil {
		deadline := time.Now().Add(time.Duration(l.WaitSeconds) * time.Second)
		for {
			_ = ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
				a, _, err := cdRow(ctx, c, e.Tenant, e.App)
				health = a.Health
				return err
			})
			if l.When != "healthy" || health == "healthy" || !time.Now().Before(deadline) || ctx.Err() != nil {
				break
			}
			time.Sleep(2 * time.Second)
		}
	}
	failed, reason := false, ""
	if l.When == "healthy" && health != "healthy" {
		failed, reason = true, fmt.Sprintf("%d초 안에 정상이 되지 않음 (%s)", l.WaitSeconds, health)
	} else {
		d, ans := s.deliverWebhook(ctx, h, webhookSend{Point: "cd", Link: l.ID, Event: "post-sync", Decide: true,
			Payload: map[string]any{"tenant": e.Tenant, "app": e.App, "candidate": cdCandidate(e), "health": health, "link": l.ID}})
		if d == nil {
			chk.State, chk.Reason = "failed", "웹훅이 꺼져 있음"
			_ = s.opt.Store.PutCDCheck(chk)
			return
		}
		chk.Delivery, chk.Status = d.ID, d.Status
		var res struct {
			Result string `json:"result"`
			Reason string `json:"reason"`
		}
		accepted := d.OK() && json.Unmarshal(ans, &res) == nil && (res.Result == "ok" || res.Result == "fail")
		switch {
		case accepted:
			failed, reason = res.Result == "fail", oneLine(res.Reason, 512)
		case d.OK():
			failed, reason = l.OnTimeout == "fail", "응답 형식이 맞지 않음"
		default:
			failed, reason = l.OnTimeout == "fail", d.Error
		}
		d.Decision, d.Accepted, d.Reason = res.Result, &accepted, reason
		s.recordDelivery(h, d)
		if !accepted {
			chk.State = "timeout"
		}
	}
	chk.Reason, chk.At = reason, s.now()
	if !failed {
		if chk.State == "checking" {
			chk.State = "ok"
		}
		_ = s.opt.Store.PutCDCheck(chk)
		return
	}
	chk.State = "failed"
	_ = s.opt.Store.PutCDCheck(chk)
	pause := store.CDCheckAction{Kind: "pause", State: "done"}
	if _, code := s.cdSend(ctx, e.Tenant, e.App, "pause", map[string]any{}); code != "" {
		pause.State, pause.Code = "failed", code
		s.log.Warn("post-sync pause", "tenant", e.Tenant, "app", e.App, "code", code)
	}
	chk.Actions = append(chk.Actions, pause)
	_ = s.opt.Store.PutCDCheck(chk)
	if !l.OpenIncident && l.OnFail != "pause-rollback" {
		return
	}
	req := store.CDCheckAction{Kind: "rollback-request", State: "failed"}
	defer func() {
		chk.Actions = append(chk.Actions, req)
		_ = s.opt.Store.PutCDCheck(chk)
	}()
	cluster, err := s.clusterPolicy()
	ws, werr := s.watchSession(ctx)
	if err != nil || werr != nil {
		req.Code = "automation"
		return
	}
	sig := store.IncidentSignal{At: s.now(), Kind: "cd-post-check-failed", Scope: "app", Tenant: e.Tenant, App: e.App, Target: e.Tenant + "/" + e.App,
		Detail: oneLine("웹훅 "+h.Name+": "+reason, 300)}
	s.incidentSignal(ctx, ws, incidentRules[sig.Kind], sig, 1, cluster, []store.IncidentSignal{sig})
	all, _ := s.opt.Store.ListIncidents()
	for _, in := range all {
		if in.Signal == sig.Kind && in.Tenant == e.Tenant && in.App == e.App && (in.State == incidentOpen || in.State == incidentMitigating) {
			req.Incident, req.State = in.ID, "done"
			if in.Decision.Kind != decisionPending {
				req.State, req.Code = "failed", in.Decision.Kind
			}
			break
		}
	}
}

// cdCheckView is the app's latest checks for GET …/cd, by kind.
func (s *Server) cdCheckView(tenant, app, candidate string) map[string]any {
	out := map[string]any{}
	for _, kind := range []string{"pre-sync", "post-sync"} {
		c, err := s.opt.Store.GetCDCheck(kind, tenant, app)
		if err != nil || c == nil || kind == "pre-sync" && candidate != "" && c.Candidate != candidate && c.State == "checking" {
			continue
		}
		v := checkView(c)
		v["atUnix"] = c.At.UnixNano()
		out[kind] = v
	}
	return out
}

func checkView(c *store.CDCheck) map[string]any {
	v := map[string]any{"kind": c.Kind, "link": c.Link, "webhook": c.Webhook, "state": c.State, "at": rfc3339(c.At), "candidate": c.Candidate}
	if len(c.Actions) > 0 {
		v["actions"] = c.Actions
	}
	if c.Reason != "" {
		v["reason"] = c.Reason
	}
	if c.Status != 0 {
		v["status"] = c.Status
	}
	return v
}
