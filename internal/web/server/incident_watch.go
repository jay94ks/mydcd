// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jay94ks/seafield/internal/web/sfc"
	"github.com/jay94ks/seafield/internal/web/store"
)

// The incident watcher (W2.3): reads sfcd's events as the automation
// account, opens incidents with deterministic rules (no AI), picks a
// temporary action from the fixed list, and either runs it as the
// automation account (low impact, policy allows) or asks a person.
// sfcd judges every action; the automation account's scope is
// the outer limit.

const (
	incidentWatchEvery = 30 * time.Second
	incidentRecentKeep = 30 * time.Minute
	// App signals stay longer: cd-rollback asks whether a signal came in
	// the 30 minutes before a deploy up to 120 minutes ago.
	incidentAppKeep   = incidentRecentKeep + 120*time.Minute
	incidentRecoverAt = 10 * time.Minute
	incidentMaxPages  = 10
)

type incidentWatch struct {
	running atomic.Bool
	mu      sync.Mutex // ws, last
	ws      *webSession
	last    time.Time
}

// incidentTick starts a watch round when one is due and none is running.
func (s *Server) incidentTick(ctx context.Context) {
	s.watch.mu.Lock()
	due := s.now().Sub(s.watch.last) >= incidentWatchEvery
	if due {
		s.watch.last = s.now()
	}
	s.watch.mu.Unlock()
	if !due || !s.watch.running.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer s.watch.running.Store(false)
		s.watchOnce(ctx)
	}()
}

// incidentRule is one detection rule: Count signals of Kind on the same
// target within Window.
type incidentRule struct {
	Kind    string
	Scope   string // app, cluster
	Count   int
	Window  time.Duration
	Words   string
	Title   string
	Actions []string
}

var incidentRules = map[string]incidentRule{
	"task-restarted":    {"task-restarted", "app", 3, 10 * time.Minute, "10분 안에 3번 재시작", "컨테이너 재시작 반복", []string{"cd-rollback", "restart-task", "pause-cd", "rollback-previous"}},
	"probe-failed":      {"probe-failed", "app", 5, 10 * time.Minute, "10분 안에 상태 검사 5번 실패", "상태 검사 연속 실패", []string{"cd-rollback", "restart-task", "pause-cd", "rollback-previous"}},
	"task-exited":       {"task-exited", "app", 2, 10 * time.Minute, "10분 안에 2번 종료", "컨테이너 시작 직후 종료", []string{"cd-rollback", "pause-cd", "restart-task", "rollback-previous"}},
	"node-unreachable":  {"node-unreachable", "cluster", 1, incidentRecentKeep, "서버 연결 끊김", "서버 연결 끊김", []string{"cordon-node"}},
	"node-resource-low": {"node-resource-low", "cluster", 1, incidentRecentKeep, "서버 자원 부족", "서버 자원 부족", []string{"prune-images"}},
	"tunnel-down":       {"tunnel-down", "cluster", 1, incidentRecentKeep, "서버 간 망 끊김", "서버 간 망 끊김", []string{"reconnect-tunnel"}},
	// Raised by a failed post-sync webhook check, not by a sfcd event.
	"cd-post-check-failed": {"cd-post-check-failed", "app", 1, incidentRecentKeep, "배포 후 확인 실패", "배포 후 확인 실패", []string{"rollback-previous"}},
}

// watchOnce is one round: read new events and apply the rules, then
// settle deadlines and recovery.
func (s *Server) watchOnce(ctx context.Context) {
	now := s.now()
	// After the new signals are in, so recovery sees them.
	defer s.settleIncidents(now)
	cluster, err := s.clusterPolicy()
	if err != nil {
		s.log.Error("incident policy", "err", err)
		return
	}
	st, err := s.opt.Store.GetIncidentWatcher()
	if err != nil {
		s.log.Error("incident watcher", "err", err)
		return
	}
	read := false // events were read this round: the reading goes on
	save := func(state, msg string) {
		if state != "running" && !(state == "stopped" && read) {
			st.Since = nil
		}
		st.State, st.Error, st.At = state, msg, now
		if err := s.opt.Store.PutIncidentWatcher(st); err != nil {
			s.log.Error("incident watcher", "err", err)
		}
	}
	// CD and ingress webhooks need the events even with incident response
	// off.
	incidentsOff := cluster.Level == incidentOff
	if incidentsOff && !s.cdHooksActive() && !s.ingressHooksActive() && !s.acmeAutoActive() {
		s.dropWatchSession()
		save("stopped", "")
		return
	}
	ws, err := s.watchSession(ctx)
	if err != nil {
		code := automationErrorCode(err)
		state := "login-failed"
		if code == ErrAutomationMissing {
			state = "no-automation"
		}
		save(state, code)
		return
	}
	// What was read without a break before this round: CD checks act
	// only on events after it (not on a backlog after a first read, a
	// cursor reset or a stop).
	watched := maps.Clone(st.Since)
	events, err := s.readIncidentEvents(ctx, ws, st)
	var se *sfc.Error
	if errors.As(err, &se) && (se.Code == sfc.CodeSessionExpired || se.Code == sfc.CodeClosed) {
		// The kept session or its connection ended between rounds: log
		// in again once. The
		// cursors are unchanged, so nothing is missed.
		s.dropWatchSession()
		if ws, err = s.watchSession(ctx); err == nil {
			events, err = s.readIncidentEvents(ctx, ws, st)
		}
	}
	if err != nil {
		var me *sfc.Error
		if errors.As(err, &me) && me.Code == sfc.CodeCursorExpired {
			// Start over from what sfcd still keeps; the rules only count
			// recent signals, so old ones do not open incidents again.
			st.Cursors = nil
			save("cursor-expired", string(me.Code))
			return
		}
		s.dropWatchSession()
		save("login-failed", automationErrorCode(err))
		return
	}
	read = true
	cut := now.Add(-incidentRecentKeep)
	keep := func(x store.IncidentSignal) bool {
		if incidentRules[x.Kind].Scope == "app" {
			return x.At.After(now.Add(-incidentAppKeep))
		}
		return x.At.After(cut)
	}
	recent := st.Recent[:0]
	for _, x := range st.Recent {
		if keep(x) {
			recent = append(recent, x)
		}
	}
	st.Recent = recent
	for _, e := range events {
		if at := time.Unix(e.Time, 0); at.After(cut) && freshEvent(watched, e.Tenant, at) {
			s.ingressEvent(e)
		}
		if strings.HasPrefix(e.Kind, "cd-") {
			if at := time.Unix(e.Time, 0); at.After(cut) && freshEvent(watched, e.Tenant, at) {
				s.cdEvent(e)
			}
			continue
		}
		if incidentsOff || e.Kind == "cd-post-check-failed" {
			continue
		}
		sig := store.IncidentSignal{At: time.Unix(e.Time, 0), Kind: e.Kind, Scope: e.Scope, Tenant: e.Tenant, App: e.App, Node: e.Node, Network: e.Network, Target: e.Target, Detail: e.Detail}
		rule, ok := incidentRules[e.Kind]
		if !ok || !keep(sig) {
			continue
		}
		st.Recent = append(st.Recent, sig)
		// Rules only fire on recent signals; older app ones are kept for
		// the pre-deploy check.
		if !sig.At.After(cut) {
			continue
		}
		n := 0
		for _, x := range st.Recent {
			if x.Kind == sig.Kind && x.Target == sig.Target && !x.At.Before(sig.At.Add(-rule.Window)) && !x.At.After(sig.At) {
				n++
			}
		}
		if n >= rule.Count {
			s.incidentSignal(ctx, ws, rule, sig, n, cluster, st.Recent)
		}
	}
	s.ingressPoll(ctx, ws)
	s.ingressDue(now)
	s.acmeAutoPoll(ctx, ws)
	s.acmeResponderSync(ctx, ws)
	s.vpsDNSPoll(ctx, ws)
	if incidentsOff {
		save("stopped", "")
		return
	}
	save("running", "")
}

// freshEvent: at is after the unbroken reading of its workspace (or of
// all) began, as recorded before this round.
func freshEvent(since map[string]time.Time, tenant string, at time.Time) bool {
	t, ok := since[""]
	if !ok {
		t, ok = since[tenant]
	}
	return ok && !at.Before(t.Truncate(time.Second))
}

// watchSession is the automation account's session, kept between rounds.
func (s *Server) watchSession(ctx context.Context) (*webSession, error) {
	s.watch.mu.Lock()
	ws := s.watch.ws
	s.watch.mu.Unlock()
	if ws != nil && ws.expiresAt.After(s.now().Add(time.Minute)) {
		return ws, nil
	}
	s.dropWatchSession()
	ws, err := s.automationLogin(ctx, "incident-watch")
	if err != nil {
		return nil, err
	}
	s.watch.mu.Lock()
	s.watch.ws = ws
	s.watch.mu.Unlock()
	return ws, nil
}

func (s *Server) dropWatchSession() {
	s.watch.mu.Lock()
	ws := s.watch.ws
	s.watch.ws = nil
	s.watch.mu.Unlock()
	if ws != nil && ws.conn != nil {
		ws.conn.Close()
	}
}

// readIncidentEvents reads the events after the stored cursors: all of
// them when the account is a system administrator, else each workspace it
// can read.
func (s *Server) readIncidentEvents(ctx context.Context, ws *webSession, st *store.IncidentWatcher) ([]webEvent, error) {
	if st.Cursors == nil {
		st.Cursors = map[string]string{}
	}
	var out []webEvent
	err := ws.do(ctx, func(ctx context.Context, c sfc.Conn) error {
		var scopes []string
		if ws.user.SystemAdmin {
			scopes = []string{""}
		} else {
			ts, err := c.Tenants(ctx)
			if err != nil {
				return err
			}
			for _, t := range ts {
				scopes = append(scopes, t.ID)
			}
		}
		for _, t := range scopes {
			cur := st.Cursors[t]
			for i := 0; i < incidentMaxPages; i++ {
				p, err := c.Events(ctx, sfc.EventQuery{Tenant: t, After: cur, Limit: 100})
				if err != nil {
					return err
				}
				for _, it := range p.Items {
					out = append(out, eventOf(it))
				}
				cur = p.Cursor
				if !p.More {
					break
				}
			}
			st.Cursors[t] = cur
			if st.Since == nil {
				st.Since = map[string]time.Time{}
			}
			if _, ok := st.Since[t]; !ok {
				// Only from now: what came before this first read may be
				// incomplete.
				st.Since[t] = s.now()
			}
		}
		return nil
	})
	return out, err
}

func incidentKey(rule incidentRule, sig store.IncidentSignal) string {
	if rule.Scope == "app" {
		return "app/" + sig.Tenant + "/" + sig.App
	}
	if sig.Network != "" {
		return "cluster/" + sig.Kind + "/" + sig.Tenant + "/" + sig.Network + "/" + sig.Target
	}
	return "cluster/" + sig.Kind + "/" + sig.Target
}

// incidentSignal adds a fired rule to the open incident of its target, or
// opens one.
func (s *Server) incidentSignal(ctx context.Context, ws *webSession, rule incidentRule, sig store.IncidentSignal, n int, cluster *store.IncidentPolicy, recent []store.IncidentSignal) {
	if rule.Scope == "app" && (sig.Scope != "app" || sig.Tenant == "" || sig.App == "") {
		return
	}
	var app *store.AppIncidentPolicy
	if rule.Scope == "app" {
		var err error
		if app, err = s.appPolicy(sig.Tenant, sig.App, cluster); err != nil {
			s.log.Error("incident app policy", "err", err)
			return
		}
		if app.Level == incidentOff {
			return
		}
	}
	key := incidentKey(rule, sig)
	all, err := s.opt.Store.ListIncidents()
	if err != nil {
		s.log.Error("incidents", "err", err)
		return
	}
	now := s.now()
	for _, in := range all {
		if in.Key != key || (in.State != incidentOpen && in.State != incidentMitigating) {
			continue
		}
		if !sig.At.After(in.LastSignal) {
			return
		}
		_, err := s.opt.Store.UpdateIncident(in.ID, func(x *store.Incident) error {
			x.Signals++
			x.LastSignal, x.UpdatedAt = sig.At, now
			x.Timeline = append(x.Timeline, entry(sig.At, "detect", lit(signalText(sig))))
			return nil
		})
		if err != nil {
			s.log.Error("incident", "err", err)
		}
		return
	}
	in := &store.Incident{ID: "inc-" + now.UTC().Format("20060102-150405") + "-" + strings.ToLower(randomID(3)), Scope: rule.Scope, Tenant: sig.Tenant, App: sig.App, Node: sig.Node, Network: sig.Network,
		Key: key, Signal: sig.Kind, Target: sig.Target, Rule: rule.Words, Signals: n, LastSignal: sig.At, State: incidentOpen, At: now, UpdatedAt: now,
		Decision: store.IncidentDecision{Kind: decisionNone}}
	in.Title = rule.Title + ": " + incidentWhere(in)
	in.Timeline = append(in.Timeline, entry(sig.At, "detect", with(ph("incident.detected", "signal", signalText(sig)), "rule", ph("incident-rule."+rule.Kind+".words"))))
	var skipped []store.Phrase
	for _, id := range rule.Actions {
		a := incidentActionByID(id)
		if a == nil || !aiAllows(a.floor()) || cluster.Actions[id] == actionHuman || app != nil && !app.Actions[id] {
			continue
		}
		act, why := s.buildIncidentAction(ctx, ws, a, in, sig, app, recent)
		if act == nil {
			skipped = append(skipped, skipPhrase(actionPhrase(a.ID, a.Label), why))
			continue
		}
		in.Candidates = append(in.Candidates, *act)
	}
	gd := s.guidesFor(in, nil)
	mcpCands, mcpSkipped := s.mcpCandidates(in, gd)
	in.Candidates, skipped = append(in.Candidates, mcpCands...), append(skipped, mcpSkipped...)
	in.Built = slices.Clone(in.Candidates)
	in.Guides = gd.versions
	var dropped []store.Phrase
	in.Candidates, dropped = applyGuides(in.Candidates, gd)
	skipped = append(skipped, dropped...)
	opts := make([]store.IncidentOption, 0, len(in.Candidates))
	for _, c := range in.Candidates {
		opts = append(opts, store.IncidentOption{Action: c.ID, Note: c.Note})
	}
	chose := ph("incident.candidates")
	if len(skipped) > 0 {
		chose = ph("incident.candidates-skipped")
		chose.Parts = skipped
	}
	e := entry(now, "diagnose", chose)
	e.Candidates = opts
	in.Timeline = append(in.Timeline, e)
	v := s.judgeIncident(ctx, ws, in, cluster, recent, gd)
	if !v.used && len(in.Candidates) > 0 && s.decideByWebhook(ctx, in) {
		v.failed = "" // the webhook stood in for AI
	}
	s.decideIncident(ctx, ws, in, cluster, app, now, v)
	if x, err := s.opt.Store.GetIncident(in.ID); err == nil {
		s.emitIncident(x, "opened")
		switch x.Decision.Kind {
		case decisionPending:
			s.emitIncident(x, "approval-required")
		case decisionAuto:
			s.emitIncident(x, "auto-run")
		}
	}
}

func incidentWhere(in *store.Incident) string {
	if in.Scope == "app" {
		return in.Tenant + "/" + in.App
	}
	if in.Node != "" {
		return in.Node
	}
	return in.Target
}

func signalText(sig store.IncidentSignal) string {
	t := sig.Kind + " " + sig.Target
	if sig.Detail != "" {
		t += " (" + sig.Detail + ")"
	}
	return t
}

// buildIncidentAction turns an action of the list into the screen API call
// for this incident, or says why it does not fit (the action's own Build).
func (s *Server) buildIncidentAction(ctx context.Context, ws *webSession, a *incidentActionDef, in *store.Incident, sig store.IncidentSignal, app *store.AppIncidentPolicy, recent []store.IncidentSignal) (*store.IncidentAction, store.Phrase) {
	if a.Build == nil {
		// Moving a service needs a target server; people choose it.
		return nil, ph("incident-skip.not-buildable")
	}
	return a.Build(s, ctx, incidentBuild{ws: ws, def: a, in: in, sig: sig, app: app, recent: recent})
}

// decideIncident picks the first candidate and decides by the rules: low
// impact, policy auto-low, the action allowed, not stopped, outside quiet
// hours and under the hourly limits → run now as the automation account;
// high → refused; otherwise ask a person.
func (s *Server) decideIncident(ctx context.Context, ws *webSession, in *store.Incident, cluster *store.IncidentPolicy, app *store.AppIncidentPolicy, now time.Time, v incidentVerdict) {
	if len(in.Candidates) == 0 {
		note := ph("incident.no-candidates")
		in.Decision = store.IncidentDecision{Kind: decisionNone, At: now, NoteText: &note}
		in.Timeline = append(in.Timeline, entry(now, "notify", note))
		s.putIncident(in)
		return
	}
	a := in.Candidates[0]
	floor := actionFloor(&a)
	if !v.used {
		in.Mitigation, in.Impact = a.ID, floor
		in.Timeline = append(in.Timeline, entry(now, "assess", with(ph("incident.rule-floor"), "impact", impactPhrase(floor))))
	}
	level := effectiveClusterLevel(cluster)
	if app != nil && levelRank(app.Level) < levelRank(level) {
		level = app.Level
	}
	var why store.Phrase
	switch {
	case in.Impact == impactHigh:
		by := "incident-by.rule"
		if v.used {
			by = "incident-by.assessment"
		}
		note := ph("incident.high-impact")
		in.Decision = store.IncidentDecision{Kind: decisionRejected, By: by, At: now, Reason: "high-impact", NoteText: &note}
		in.Timeline = append(in.Timeline, entry(now, "reject", note))
		s.putIncident(in)
		return
	case v.failed != "":
		why = with(ph("incident.why.ai-failed"), "step", ph(v.failed))
	case in.Impact != impactLow:
		why = with(ph("incident.why.impact"), "impact", impactPhrase(in.Impact))
	case a.MCP == nil && cluster.Actions[a.ID] != actionAllow:
		why = ph("incident.why.approval")
	case a.MCP != nil && s.mcpAutoBlocked(in, &a, now).Code != "":
		why = s.mcpAutoBlocked(in, &a, now)
	case cluster.Stopped:
		why = ph("incident.why.stopped")
	case level != incidentAutoLow:
		why = ph("incident.why.suggest-only")
	case inQuiet(now, cluster.Quiet) || app != nil && inQuiet(now, app.Quiet):
		why = ph("incident.why.quiet")
	case !s.underIncidentRate(in, cluster, app, now):
		why = ph("incident.why.rate")
	}
	if why.Code == "" {
		s.putIncident(in)
		s.autoRunIncident(ctx, ws, in, &a, now)
		return
	}
	s.askIncident(in, cluster, why, now)
	s.putIncident(in)
	s.notifyIncident(ctx, ws, in)
}

// notifyIncident tells the people who can approve: the workspace's
// managers for an app incident, the system administrators for a cluster
// one (as sfcd lists them to the automation account).
func (s *Server) notifyIncident(ctx context.Context, ws *webSession, in *store.Incident) {
	var users []string
	add := func(u string) {
		if !slices.Contains(users, u) {
			users = append(users, u)
		}
	}
	cp, _ := s.clusterPolicy()
	tenantToo := cp == nil || cp.Approvers.To != approversSystem
	err := ws.do(ctx, func(ctx context.Context, c sfc.Conn) error {
		// system administrators always; the app's workspace managers too
		// unless the policy asks system administrators only
		after := ""
		for i := 0; i < incidentMaxPages; i++ {
			p, err := c.Users(ctx, after)
			if err != nil {
				if in.Scope != "app" {
					return err
				}
				s.log.Warn("incident approvers: users", "err", err, "incident", in.ID)
				break
			}
			for _, u := range p.Items {
				if u.SystemAdmin && u.Enabled {
					add(u.ID)
				}
			}
			if after = p.Next; after == "" {
				break
			}
		}
		if in.Scope != "app" || !tenantToo {
			return nil
		}
		after = ""
		for i := 0; i < incidentMaxPages; i++ {
			p, err := c.TenantMembers(ctx, in.Tenant, after)
			if err != nil {
				return err
			}
			for _, m := range p.Items {
				if m.Role == sfc.RoleManager && m.Enabled && m.AccountEnabled {
					add(m.User)
				}
			}
			if after = p.Next; after == "" {
				break
			}
		}
		return nil
	})
	if err != nil {
		s.log.Warn("incident approvers", "err", err, "incident", in.ID)
	}
	for _, u := range users {
		if u == ws.user.ID {
			continue
		}
		s.notify(&store.Notification{User: u, Kind: NotifyIncidentApproval, Severity: "warning", Tenant: in.Tenant, Text: approvalNotice(in),
			Link: "/incidents/" + in.ID, Action: true})
	}
	in.Timeline = append(in.Timeline, entry(s.now(), "notify", ph("incident.notified", "count", fmt.Sprint(len(users)))))
	s.putIncident(in)
}

// impactPhrase is the impact level in words (unknown: high).
func impactPhrase(l string) store.Phrase {
	switch l {
	case impactLow, impactMedium:
		return ph("impact." + l)
	}
	return ph("impact." + impactHigh)
}

func (s *Server) putIncident(in *store.Incident) {
	if err := s.opt.Store.PutIncident(in); err != nil {
		s.log.Error("incident", "err", err, "incident", in.ID)
	}
}

// askIncident makes the chosen action a request for approval.
// The approval card's title and fields are made when it is read
// (approvalCard), in the reader's language.
func (s *Server) askIncident(in *store.Incident, cluster *store.IncidentPolicy, why store.Phrase, now time.Time) {
	in.Decision = store.IncidentDecision{Kind: decisionPending, At: now, ExpiresAt: now.Add(time.Duration(cluster.Approvers.DeadlineMinutes) * time.Minute), NoteText: &why}
	in.Approval = &store.IncidentApproval{}
	in.Approval.BasisHash = incidentBasis(in)
	in.Timeline = append(in.Timeline, entry(now, "propose", with(ph("incident.waiting"), "why", why)))
}

// autoRunIncident sends the action as the automation account. A refusal
// turns into a request for approval.
func (s *Server) autoRunIncident(ctx context.Context, ws *webSession, in *store.Incident, a *store.IncidentAction, now time.Time) {
	if a.MCP != nil {
		s.autoRunIncidentMCP(ctx, ws, in, a, now)
		return
	}
	opID := newOpID()
	status, out, op := s.sendIncidentAction(ctx, ws, in, a, opID, "autofix")
	cluster, _ := s.clusterPolicy()
	_, err := s.opt.Store.UpdateIncident(in.ID, func(x *store.Incident) error {
		if op != nil {
			x.Decision = store.IncidentDecision{Kind: decisionAuto, By: ws.user.Username, At: now}
			x.Op, x.OpID, x.State, x.MitigatedAt, x.UpdatedAt = op.ID, opID, incidentMitigating, now, now
			e := entry(now, "auto", with(ph("incident.auto-ran"), "action", actionPhrase(a.ID, a.Label)))
			e.Op, e.Signer = op.ID, ws.user.Username
			x.Timeline = append(x.Timeline, e)
			return nil
		}
		var res struct {
			Error *apiError `json:"error"`
		}
		_ = json.Unmarshal(out, &res)
		code := fmt.Sprint(status)
		if res.Error != nil {
			code = res.Error.Code
		}
		e := entry(now, "auto", ph("incident.auto-failed", "code", code))
		e.Signer = ws.user.Username
		x.Timeline = append(x.Timeline, e)
		if cluster != nil {
			s.askIncident(x, cluster, ph("incident.why.refused", "code", code), now)
		}
		x.UpdatedAt = now
		return nil
	})
	if err != nil {
		s.log.Error("incident", "err", err, "incident", in.ID)
		return
	}
	if op == nil {
		if x, err := s.opt.Store.GetIncident(in.ID); err == nil {
			s.notifyIncident(ctx, ws, x)
		}
	}
}

// underIncidentRate: fewer automatic runs in the last hour than the
// cluster's and the app's limits.
func (s *Server) underIncidentRate(in *store.Incident, cluster *store.IncidentPolicy, app *store.AppIncidentPolicy, now time.Time) bool {
	all, err := s.opt.Store.ListIncidents()
	if err != nil {
		return false
	}
	total, same := 0, 0
	for _, x := range all {
		if x.Decision.Kind != decisionAuto || now.Sub(x.Decision.At) >= time.Hour {
			continue
		}
		total++
		if x.Scope == "app" && x.Tenant == in.Tenant && x.App == in.App {
			same++
		}
	}
	return total < cluster.RatePerHour && (app == nil || same < app.RatePerHour)
}

// inQuiet: now falls in one of the "HH:MM-HH:MM" ranges (server time;
// a range may pass midnight).
func inQuiet(now time.Time, ranges []string) bool {
	m := now.Hour()*60 + now.Minute()
	for _, r := range ranges {
		var h1, m1, h2, m2 int
		if _, err := fmt.Sscanf(r, "%d:%d-%d:%d", &h1, &m1, &h2, &m2); err != nil {
			continue
		}
		a, b := h1*60+m1, h2*60+m2
		if a <= b && m >= a && m < b || a > b && (m >= a || m < b) {
			return true
		}
	}
	return false
}

// settleIncidents expires approval requests past their deadline and
// checks recovery after an action ran.
func (s *Server) settleIncidents(now time.Time) {
	all, err := s.opt.Store.ListIncidents()
	if err != nil {
		s.log.Error("incidents", "err", err)
		return
	}
	for _, in := range all {
		expire := in.Decision.Kind == decisionPending && !now.Before(in.Decision.ExpiresAt)
		recover := in.State == incidentMitigating && now.Sub(in.MitigatedAt) >= incidentRecoverAt
		if !expire && !recover {
			continue
		}
		event := ""
		x, err := s.opt.Store.UpdateIncident(in.ID, func(x *store.Incident) error {
			event = ""
			switch {
			case x.Decision.Kind == decisionPending && !now.Before(x.Decision.ExpiresAt):
				x.Decision.Kind, x.Approval = decisionExpired, nil
				event = "expired"
				x.Timeline = append(x.Timeline, entry(now, "expire", ph("incident.expired")))
			case x.State == incidentMitigating && now.Sub(x.MitigatedAt) >= incidentRecoverAt:
				if x.LastSignal.After(x.MitigatedAt) {
					x.State = incidentOpen
					x.Timeline = append(x.Timeline, entry(now, "notify", ph("incident.signals-continue")))
				} else {
					x.State = incidentRecovered
					event = "recovered"
					x.Timeline = append(x.Timeline, entry(now, "recover", ph("incident.recovered", "minutes", fmt.Sprint(int(incidentRecoverAt/time.Minute)))))
				}
			}
			x.UpdatedAt = now
			return nil
		})
		if err == nil && event != "" {
			s.emitIncident(x, event)
		}
		if err != nil {
			s.log.Error("incident", "err", err, "incident", in.ID)
		}
	}
}
