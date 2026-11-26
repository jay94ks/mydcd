// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/containerops"
)

// Log clearing (`mydc compose logs clear`, real in mydcd): the impact plan
// (app-log-clear-plan), the signed clear-app-logs (Expected = the plan's
// InventoryRevision, Target = its Target, Recreate true) and its status
// (app-log-clear-status). The fake recreates the target task and the tasks
// of services that depend on it; each status read moves one stage on
// (Retiring → Removed → Recreating → Succeeded).

const ActionClearAppLogs = "clear-app-logs"

// Log clear status stages (control.AppLogClearStatus.Status).
const (
	LogClearRetiring   = "Retiring"
	LogClearRemoved    = "Removed"
	LogClearRecreating = "Recreating"
	LogClearSucceeded  = "Succeeded"
)

// LogClearPlan: the app-log-clear-plan reply. Code "ok" carries Plan;
// "unsupported-log-driver" means the container's log driver is not local
// or json-file (LogDriver says which).
type LogClearPlan struct {
	Code      string
	LogDriver string `json:",omitempty"`
	Plan      *control.AppLogClearPlan
}

type logClear struct {
	tenant, app string
	status      control.AppLogClearStatus
	keys        []string // logClearKey of the recreated tasks
}

// SetTaskLogDriver sets a task's log driver (default "local").
func (f *Fake) SetTaskLogDriver(tenant, app, service, instance, driver string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.taskFor(tenant, app, service, instance)
	if f.w.logDrivers == nil {
		f.w.logDrivers = map[string]string{}
	}
	f.w.logDrivers[tenant+"/"+app+"/"+service+"/"+instance] = driver
}

func (w *world) logDriver(t Task) string {
	if d := w.logDrivers[taskKey(t)]; d != "" {
		return d
	}
	return "local"
}

// dependents: the services that depend on svc, directly or through others.
func dependents(doc []byte, svc string) []string {
	var d struct {
		Services map[string]struct {
			DependsOn any `yaml:"depends_on"`
		} `yaml:"services"`
	}
	if yaml.Unmarshal(doc, &d) != nil {
		return nil
	}
	deps := map[string][]string{}
	for name, s := range d.Services {
		ds := words(s.DependsOn)
		if m, ok := s.DependsOn.(map[string]any); ok {
			for k := range m {
				ds = append(ds, k)
			}
		}
		deps[name] = ds
	}
	out := []string{svc}
	for changed := true; changed; {
		changed = false
		for name, ds := range deps {
			if !slices.Contains(out, name) && slices.ContainsFunc(ds, func(x string) bool { return slices.Contains(out, x) }) {
				out = append(out, name)
				changed = true
			}
		}
	}
	return out
}

// logClearPlan: the plan for one selection, or a code.
func (w *world) logClearPlan(user, tenant string, sel ContainerSelection, now int64) (LogClearPlan, error) {
	a := w.apps[tenant+"/"+sel.App]
	if a == nil || a.view.Retiring || sel.Standalone != "" {
		return LogClearPlan{}, errCAS
	}
	if !w.canManage(user, tenant) {
		return LogClearPlan{}, errForbidden
	}
	i := slices.IndexFunc(a.tasks, func(t Task) bool {
		return t.Service == sel.Service && (sel.Instance == "" || t.Instance == sel.Instance)
	})
	if i < 0 {
		return LogClearPlan{}, errCAS
	}
	target := a.tasks[i]
	if d := w.logDriver(target); !containerops.LocalLogDriver(d) {
		return LogClearPlan{Code: "unsupported-log-driver", LogDriver: d}, nil
	}
	src, _ := a.running()
	services := dependents(src.Document, target.Service)
	p := control.AppLogClearPlan{Schema: 1, Tenant: tenant, App: sel.App, InventoryRevision: a.view.Revision, Container: w.streamTarget(tenant, target, a.view.Revision),
		LogDriver: w.logDriver(target), SourcePlan: src.Digest, SourceCandidate: src.Digest, SourceArtifact: src.Digest}
	for _, t := range a.tasks {
		if (t.Service != target.Service || t.Instance != target.Instance) && !slices.Contains(services[1:], t.Service) {
			continue
		}
		p.Impact = append(p.Impact, impactOf(t, w.logDriver(t), a.view.Revision))
	}
	raw, _ := json.Marshal(p.Impact)
	p.Target = digestOf(append([]byte(tenant+"/"+sel.App+"/"), raw...))
	return LogClearPlan{Code: "ok", LogDriver: p.LogDriver, Plan: &p}, nil
}

// logClearKey stands in for mydcd's task state key.
// (mydcd: workload/task/<tenant>/<app>/<service>; the fake adds the
// instance, as it can run more than one).
func logClearKey(t Task) string {
	return "workload/task/" + t.Tenant + "/" + t.App + "/" + t.Service + "/" + t.Instance
}

func impactOf(t Task, driver string, rev uint64) control.AppLogClearImpact {
	return control.AppLogClearImpact{Key: logClearKey(t), Kind: "task", Node: t.Node, NativeID: nativeIDOf(t),
		StartedAt: time.Unix(t.StartedAt, 0).UTC().Format(time.RFC3339Nano), LogDriver: driver, Generation: t.Generation, Revision: max(t.Generation, rev)}
}

// AppLogClearPlan: `app-log-clear-plan` (tenant Deploy; fake: manager).
func (c *fakeConn) AppLogClearPlan(ctx context.Context, tenant string, sel ContainerSelection) (LogClearPlan, error) {
	const m = "app-log-clear-plan"
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return LogClearPlan{}, err
	}
	defer c.unlock()
	p, err := c.f.w.logClearPlan(user, tenant, sel, c.f.now().Unix())
	switch {
	case errors.Is(err, errForbidden):
		return LogClearPlan{}, fail(m, CodeDenied, "")
	case err != nil:
		return LogClearPlan{}, fail(m, CodeMissing, "no running container for that selection")
	}
	return p, nil
}

// AppLogClearStatus: `app-log-clear-status` (tenant Read). Each read moves
// the fake's clear one stage on.
func (c *fakeConn) AppLogClearStatus(ctx context.Context, tenant, app, operation string) (control.AppLogClearStatus, error) {
	const m = "app-log-clear-status"
	if err := c.appRead(ctx, m, tenant); err != nil {
		return control.AppLogClearStatus{}, err
	}
	defer c.unlock()
	w := c.f.w
	lc := w.logClears[tenant+"/"+app+"/"+operation]
	if lc == nil {
		return control.AppLogClearStatus{}, fail(m, CodeMissing, "")
	}
	out := lc.status
	switch lc.status.Status {
	case LogClearRetiring:
		lc.status.Status = LogClearRemoved
	case LogClearRemoved:
		lc.status.Status = LogClearRecreating
	case LogClearRecreating:
		w.finishLogClear(lc, c.f.now().Unix())
	}
	return out, nil
}

func (w *world) finishLogClear(lc *logClear, now int64) {
	a := w.apps[lc.tenant+"/"+lc.app]
	lc.status.Status = LogClearSucceeded
	if a == nil {
		return
	}
	for i := range a.tasks {
		t := &a.tasks[i]
		if !slices.Contains(lc.keys, logClearKey(*t)) {
			continue
		}
		st := w.taskSt(*t, now)
		st.exits = append(st.exits, TaskExit{At: now, Reason: ExitReasonLogClear, Generation: t.Generation, NativeID: nativeIDOf(*t)})
		st.logs = nil
		t.Generation++
		t.Observed, t.StartedAt, t.ObservedAt = "running", now, now
		lc.status.NewContainers = append(lc.status.NewContainers, impactOf(*t, w.logDriver(*t), a.view.Revision))
	}
	if o := a.ops[lc.status.Operation]; o != nil {
		o.Status, o.CompletedAt = "succeeded", now
	}
}

func (c *fakeConn) applyClearAppLogs(op UserOperation, actor string, next uint64) error {
	w := c.f.w
	ch := op.Change
	var q control.AppLogClear
	if decodePayload(ch.Payload, &q) != nil || q.Tenant == "" || q.App == "" || q.Operation == "" || !q.Recreate || q.Target == ([32]byte{}) {
		return errors.New("payload")
	}
	a := w.apps[q.Tenant+"/"+q.App]
	if a == nil || a.view.Revision != ch.Expected {
		return errCAS
	}
	if _, used := a.ops[q.Operation]; used || w.logClears[q.Tenant+"/"+q.App+"/"+q.Operation] != nil {
		return errCAS
	}
	p, err := w.logClearPlan(actor, q.Tenant, ContainerSelection{App: q.App, Service: q.Selection.Service, Instance: q.Selection.Instance}, c.f.now().Unix())
	if err != nil {
		return err
	}
	if p.Plan == nil || p.Plan.Target != q.Target {
		return errCAS
	}
	lc := &logClear{tenant: q.Tenant, app: q.App, status: control.AppLogClearStatus{Operation: q.Operation, Status: LogClearRetiring, Target: q.Target, OldContainers: p.Plan.Impact}}
	for _, im := range p.Plan.Impact {
		lc.keys = append(lc.keys, im.Key)
	}
	if w.logClears == nil {
		w.logClears = map[string]*logClear{}
	}
	w.logClears[q.Tenant+"/"+q.App+"/"+q.Operation] = lc
	now := c.f.now().Unix()
	a.ops[q.Operation] = &AppOperation{Tenant: q.Tenant, App: q.App, ID: q.Operation, Status: "running", Submitter: w.users[actor].rec.Username, StartedAt: now, Steps: []string{"retire", "recreate"}}
	a.view.Revision = next
	return nil
}
