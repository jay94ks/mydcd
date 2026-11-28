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
			x.Timeline = append(x.Timeline, store.IncidentEntry{At: sig.At, Kind: "detect", Text: signalText(sig)})
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
	in.Timeline = append(in.Timeline, store.IncidentEntry{At: sig.At, Kind: "detect", Text: fmt.Sprintf("%s (%s)", signalText(sig), rule.Words)})
	var skipped []string
	for _, id := range rule.Actions {
		a := incidentActionByID(id)
		if a == nil || !aiAllows(a.floor()) || cluster.Actions[id] == actionHuman || app != nil && !app.Actions[id] {
			continue
		}
		act, why := s.buildIncidentAction(ctx, ws, a, in, sig, app, recent)
		if act == nil {
			skipped = append(skipped, a.Label+": "+why)
			continue
		}
		in.Candidates = append(in.Candidates, *act)
	}
	gd := s.guidesFor(in, nil)
	mcpCands, mcpSkipped := s.mcpCandidates(in, gd)
	in.Candidates, skipped = append(in.Candidates, mcpCands...), append(skipped, mcpSkipped...)
	in.Built = slices.Clone(in.Candidates)
	in.Guides = gd.versions
	var dropped []string
	in.Candidates, dropped = applyGuides(in.Candidates, gd)
	skipped = append(skipped, dropped...)
	opts := make([]store.IncidentOption, 0, len(in.Candidates))
	for _, c := range in.Candidates {
		opts = append(opts, store.IncidentOption{Action: c.ID, Note: c.Note})
	}
	text := "규칙으로 임시 조치 후보를 골랐어요."
	if len(skipped) > 0 {
		text += " 뺀 것: " + strings.Join(skipped, "; ")
	}
	in.Timeline = append(in.Timeline, store.IncidentEntry{At: now, Kind: "diagnose", Text: text, Candidates: opts})
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
func (s *Server) buildIncidentAction(ctx context.Context, ws *webSession, a *incidentActionDef, in *store.Incident, sig store.IncidentSignal, app *store.AppIncidentPolicy, recent []store.IncidentSignal) (*store.IncidentAction, string) {
	if a.Build == nil {
		// Moving a service needs a target server; people choose it.
		return nil, "아직 자동으로 만들 수 없음"
	}
	return a.Build(s, ctx, incidentBuild{ws: ws, def: a, in: in, sig: sig, app: app, recent: recent})
}

// decideIncident picks the first candidate and decides by the rules: low
// impact, policy auto-low, the action allowed, not stopped, outside quiet
// hours and under the hourly limits → run now as the automation account;
// high → refused; otherwise ask a person.
func (s *Server) decideIncident(ctx context.Context, ws *webSession, in *store.Incident, cluster *store.IncidentPolicy, app *store.AppIncidentPolicy, now time.Time, v incidentVerdict) {
	if len(in.Candidates) == 0 {
		in.Decision = store.IncidentDecision{Kind: decisionNone, At: now, Note: "쓸 수 있는 임시 조치가 없어 사람에게 넘깁니다."}
		in.Timeline = append(in.Timeline, store.IncidentEntry{At: now, Kind: "notify", Text: in.Decision.Note})
		s.putIncident(in)
		return
	}
	a := in.Candidates[0]
	floor := actionFloor(&a)
	if !v.used {
		in.Mitigation, in.Impact = a.ID, floor
		in.Timeline = append(in.Timeline, store.IncidentEntry{At: now, Kind: "assess", Text: "규칙 하한: " + impactWord(floor)})
	}
	level := effectiveClusterLevel(cluster)
	if app != nil && levelRank(app.Level) < levelRank(level) {
		level = app.Level
	}
	why := ""
	switch {
	case in.Impact == impactHigh:
		by := "규칙"
		if v.used {
			by = "영향 평가"
		}
		in.Decision = store.IncidentDecision{Kind: decisionRejected, By: by, At: now, Reason: "high-impact", Note: "영향이 높아 자동 대응이 하지 않습니다. 사람이 직접 처리하세요."}
		in.Timeline = append(in.Timeline, store.IncidentEntry{At: now, Kind: "reject", Text: in.Decision.Note})
		s.putIncident(in)
		return
	case v.failed != "":
		why = "AI " + v.failed + "로 자동 실행하지 않아요."
	case in.Impact != impactLow:
		why = "영향이 " + impactWord(in.Impact) + "이라 승인이 필요해요."
	case a.MCP == nil && cluster.Actions[a.ID] != actionAllow:
		why = "승인이 필요한 조치예요."
	case a.MCP != nil && s.mcpAutoBlocked(in, &a, now) != "":
		why = s.mcpAutoBlocked(in, &a, now)
	case cluster.Stopped:
		why = "자동 대응이 멈춰 있어요."
	case level != incidentAutoLow:
		why = "정책이 '제안만'이에요."
	case inQuiet(now, cluster.Quiet) || app != nil && inQuiet(now, app.Quiet):
		why = "자동 실행을 막는 시간이에요."
	case !s.underIncidentRate(in, cluster, app, now):
		why = "시간당 자동 실행 한도에 닿았어요."
	}
	if why == "" {
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
		s.notify(&store.Notification{User: u, Kind: NotifyIncidentApproval, Severity: "warning", Tenant: in.Tenant, Text: notice("incident-approval", map[string]string{"title": in.Title, "note": in.Decision.Note}, bodyIf(in.Decision.Note != "", "incident-approval.note")...),
			Link: "/incidents/" + in.ID, Action: true})
	}
	in.Timeline = append(in.Timeline, store.IncidentEntry{At: s.now(), Kind: "notify", Text: fmt.Sprintf("승인할 수 있는 %d명에게 알렸어요.", len(users))})
	s.putIncident(in)
}

func impactWord(l string) string {
	switch l {
	case impactLow:
		return "낮음"
	case impactMedium:
		return "보통"
	}
	return "높음"
}

func (s *Server) putIncident(in *store.Incident) {
	if err := s.opt.Store.PutIncident(in); err != nil {
		s.log.Error("incident", "err", err, "incident", in.ID)
	}
}

// askIncident makes the chosen action a request for approval.
func (s *Server) askIncident(in *store.Incident, cluster *store.IncidentPolicy, why string, now time.Time) {
	a := chosenAction(in)
	in.Decision = store.IncidentDecision{Kind: decisionPending, At: now, ExpiresAt: now.Add(time.Duration(cluster.Approvers.DeadlineMinutes) * time.Minute), Note: why}
	fields := []store.AIPreviewRow{{Label: "조치", Value: a.Label}, {Label: "대상", Value: incidentWhere(in)}, {Label: "영향", Value: impactWord(in.Impact)}, {Label: "감지", Value: in.Rule}}
	if a.Note != "" {
		fields = append(fields, store.AIPreviewRow{Label: "내용", Value: a.Note})
	}
	in.Approval = &store.IncidentApproval{Title: a.Label, Fields: fields}
	in.Approval.BasisHash = incidentBasis(in)
	in.Timeline = append(in.Timeline, store.IncidentEntry{At: now, Kind: "propose", Text: "승인을 기다려요. " + why})
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
			x.Timeline = append(x.Timeline, store.IncidentEntry{At: now, Kind: "auto", Text: a.Label + " 자동 실행", Op: op.ID, Signer: ws.user.Username})
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
		x.Timeline = append(x.Timeline, store.IncidentEntry{At: now, Kind: "auto", Text: "자동 실행 실패: " + code, Signer: ws.user.Username})
		if cluster != nil {
			s.askIncident(x, cluster, "자동 실행이 거절됐어요("+code+").", now)
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
				x.Timeline = append(x.Timeline, store.IncidentEntry{At: now, Kind: "expire", Text: "승인 요청이 응답 없이 지났어요."})
			case x.State == incidentMitigating && now.Sub(x.MitigatedAt) >= incidentRecoverAt:
				if x.LastSignal.After(x.MitigatedAt) {
					x.State = incidentOpen
					x.Timeline = append(x.Timeline, store.IncidentEntry{At: now, Kind: "notify", Text: "조치 뒤에도 신호가 이어져 사람에게 넘겨요. 같은 조치는 다시 하지 않아요."})
				} else {
					x.State = incidentRecovered
					event = "recovered"
					x.Timeline = append(x.Timeline, store.IncidentEntry{At: now, Kind: "recover", Text: fmt.Sprintf("조치 뒤 %d분 동안 신호가 없어 회복으로 봐요.", int(incidentRecoverAt/time.Minute))})
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
