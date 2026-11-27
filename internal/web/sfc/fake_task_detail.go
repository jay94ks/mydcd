// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/deployment"
)

// REQ-20 in the fake. Per task (tenant/app/service/instance) the fake keeps
// exits, check results, log lines and injected secret values. The detail
// is derived from the current app.yaml (environment, secrets_from,
// volumes, networks, ports); Fake.SetTaskDrift sets drift. Logs start with
// 300 generated lines; Fake.AddTaskLog appends, Fake.SetTaskSecretValue
// names a value the task was given (masked on read), Fake.KillTask records
// an exit.

const taskLogPageBytes = 24 << 10

type taskState struct {
	exits   []TaskExit
	checks  map[string][]TaskCheckResult
	logs    []TaskLogLine
	secrets map[string]string // value → object/key
	drift   []string
}

func taskKey(t Task) string { return t.Tenant + "/" + t.App + "/" + t.Service + "/" + t.Instance }

// nativeIDOf: a Docker container ID per task generation (a recreation,
// e.g. clear-app-logs, gives a new one).
func nativeIDOf(t Task) string {
	return fmt.Sprintf("%x", digestOf([]byte(t.Tenant+t.App+t.Service+t.Instance+"#"+fmt.Sprint(t.Generation))))[:12]
}

func (w *world) taskSt(t Task, now int64) *taskState {
	k := taskKey(t)
	if s := w.tasksState[k]; s != nil {
		return s
	}
	s := &taskState{checks: map[string][]TaskCheckResult{}, secrets: map[string]string{}}
	for i := 0; i < t.Restarts; i++ {
		reason := ExitReasonExit
		if t.ExitCode == 137 && strings.Contains(t.LastCheck, "OOM") {
			reason = ExitReasonOOM
		}
		s.exits = append(s.exits, TaskExit{At: now - int64(t.Restarts-i)*600, Reason: reason, ExitCode: t.ExitCode, Generation: t.Generation, NativeID: nativeIDOf(t)})
	}
	if t.Health != "none" {
		for i := 0; i < 5; i++ {
			ok := t.Health != "unhealthy" || i < 2
			r := TaskCheckResult{At: now - int64(5-i)*30, OK: ok, DurationMs: 12 + i}
			if !ok {
				r.Message = "probe failed"
			}
			s.checks["ready"] = append(s.checks["ready"], r)
		}
	}
	for i := 1; i <= 300; i++ {
		s.logs = append(s.logs, TaskLogLine{Seq: uint64(i), LogLine: LogLine{Time: now - int64(300-i)*2, Stream: "stdout", Text: fmt.Sprintf("[%s] request %d handled in %d ms", t.Service, i, 3+i%17)}})
	}
	w.tasksState[k] = s
	return s
}

func (c *fakeConn) taskTarget(ctx context.Context, m, tenant string, sel ContainerSelection) (*fakeApp, *Task, error) {
	if err := c.appRead(ctx, m, tenant); err != nil {
		return nil, nil, err
	}
	if sel.Standalone != "" {
		c.unlock()
		return nil, nil, fail(m, CodeInvalid, "standalone: use the standalone view")
	}
	a := c.f.w.apps[tenant+"/"+sel.App]
	if a != nil && !a.view.Retiring {
		for i := range a.tasks {
			t := &a.tasks[i]
			if t.Service == sel.Service && (sel.Instance == "" || sel.Instance == t.Instance) {
				return a, t, nil
			}
		}
	}
	c.unlock()
	return nil, nil, fail(m, CodeMissing, "")
}

func (c *fakeConn) TaskDetail(ctx context.Context, tenant string, sel ContainerSelection) (TaskDetail, error) {
	a, t, err := c.taskTarget(ctx, "task-detail", tenant, sel)
	if err != nil {
		return TaskDetail{}, err
	}
	defer c.unlock()
	w := c.f.w
	now := c.f.now().Unix()
	st := w.taskSt(*t, now)
	var d struct {
		Services map[string]struct {
			Image       string   `yaml:"image"`
			Command     any      `yaml:"command"`
			Entrypoint  any      `yaml:"entrypoint"`
			WorkingDir  string   `yaml:"working_dir"`
			User        string   `yaml:"user"`
			ReadOnly    bool     `yaml:"read_only"`
			CapAdd      []string `yaml:"cap_add"`
			CPUs        float64  `yaml:"cpus"`
			StopSignal  string   `yaml:"stop_signal"`
			Environment any      `yaml:"environment"`
			Volumes     []any    `yaml:"volumes"`
			Networks    any      `yaml:"networks"`
			Ports       []any    `yaml:"ports"`
			Tmpfs       any      `yaml:"tmpfs"`
			Secrets     []any    `yaml:"secrets"`
			XSfc        struct {
				Sources   deployment.SecretSources        `yaml:"secrets_from"`
				SecretEnv []struct{ Source, Name string } `yaml:"secret_env"`
			} `yaml:"x-sfc"`
		} `yaml:"services"`
	}
	_ = yaml.Unmarshal(a.sources[len(a.sources)-1].Document, &d)
	s := d.Services[t.Service]
	sum := digestOf([]byte(t.Image))
	out := TaskDetail{Selection: selectionOf(t.App, t.Service, t.Instance), Node: t.Node, Name: "sfc-" + t.Tenant + "-" + t.App + "-" + t.Service + "-" + t.Instance,
		NativeID: nativeIDOf(*t), Image: t.Image, Digest: "sha256:" + hexOf(sum[:]), Command: words(s.Command), Entrypoint: words(s.Entrypoint),
		WorkingDir: s.WorkingDir, User: s.User, ReadOnly: s.ReadOnly, CapAdd: s.CapAdd, CPUs: s.CPUs, MemoryBytes: 1 * gib,
		LogDriver: "local", LogOptions: map[string]string{"max-size": "10m", "max-file": "3"}, Env: []TaskEnv{}, Mounts: []TaskMount{}, Networks: []TaskNetwork{},
		StopSignal: "SIGTERM", StopGrace: 10, Generation: t.Generation, Drift: slices.Clone(st.drift), ObservedAt: t.ObservedAt}
	if s.StopSignal != "" {
		out.StopSignal = s.StopSignal
	}
	switch env := s.Environment.(type) {
	case map[string]any:
		for _, k := range sortedKeys(env) {
			out.Env = append(out.Env, TaskEnv{Key: k, Value: fmt.Sprint(env[k])})
		}
	case []any:
		for _, e := range env {
			k, v, _ := strings.Cut(fmt.Sprint(e), "=")
			out.Env = append(out.Env, TaskEnv{Key: k, Value: v})
		}
	}
	// secret_env shows only the reference, never the value.
	for _, e := range s.XSfc.SecretEnv {
		out.Env = append(out.Env, TaskEnv{Key: e.Name, Secret: "secret:" + e.Source})
	}
	for _, src := range s.XSfc.Sources {
		if src.Scope == "cluster" {
			continue
		}
		sel := src.Secret + src.Group
		for _, id := range w.vaultSecretsUnder(tenant, sel) {
			if v := w.vaultObject(tenant, id); v != nil {
				for _, k := range v.Keys {
					if !slices.ContainsFunc(out.Env, func(e TaskEnv) bool { return e.Key == k }) {
						out.Env = append(out.Env, TaskEnv{Key: k, Secret: "secret:" + id + "/" + k})
					}
				}
			}
		}
	}
	for _, v := range s.Volumes {
		switch x := v.(type) {
		case string:
			p := strings.Split(x, ":")
			mt := TaskMount{Kind: "volume", Source: p[0]}
			if len(p) > 1 {
				mt.Target = p[1]
			}
			mt.ReadOnly = len(p) > 2 && p[2] == "ro"
			out.Mounts = append(out.Mounts, mt)
		case map[string]any:
			ro, _ := x["read_only"].(bool)
			out.Mounts = append(out.Mounts, TaskMount{Kind: "volume", Source: fmt.Sprint(x["source"]), Target: fmt.Sprint(x["target"]), ReadOnly: ro})
		}
	}
	for _, x := range s.Secrets {
		mt := TaskMount{Kind: "secret", ReadOnly: true, Mode: "0400"}
		switch v := x.(type) {
		case string:
			mt.Source, mt.Target = "secret:"+v, "/run/secrets/"+v
		case map[string]any:
			src, _ := v["source"].(string)
			target, _ := v["target"].(string)
			if target == "" {
				target = src
			}
			if !strings.HasPrefix(target, "/") {
				target = "/run/secrets/" + target
			}
			mt.Source, mt.Target = "secret:"+src, target
			switch m := v["mode"].(type) {
			case int:
				mt.Mode = fmt.Sprintf("%04o", m)
			case string:
				mt.Mode = m
			}
		default:
			continue
		}
		out.Mounts = append(out.Mounts, mt)
	}
	for _, p := range words(s.Tmpfs) {
		out.Mounts = append(out.Mounts, TaskMount{Kind: "tmpfs", Target: p})
	}
	for i, n := range networkNames(s.Networks) {
		nd := digestOf([]byte(taskKey(*t) + n))
		out.Networks = append(out.Networks, TaskNetwork{Name: n, IP: fmt.Sprintf("10.20.%d.%d", i, 2+nd[0]%250), Aliases: []string{t.Service}, DNS: []string{"10.20.0.1"}})
	}
	// Host bindings: a fixed published port as written; omitted, 0 or a
	// range is a port the fake "Docker" picks (stable per task).
	for _, x := range s.Ports {
		p, ok := parseComposePort(x)
		if !ok {
			continue
		}
		b := TaskPortBinding{HostIP: p.IP}
		if n, ok := p.fixed(); ok {
			b.HostPort = strconv.Itoa(n)
		} else {
			d := digestOf([]byte(taskKey(*t) + fmt.Sprint(p.Target, p.Proto)))
			lo, size := 32768, 28232
			if a, z, ok := strings.Cut(p.Published, "-"); ok {
				if l, e1 := strconv.Atoi(a); e1 == nil {
					if h, e2 := strconv.Atoi(z); e2 == nil && h >= l {
						lo, size = l, h-l+1
					}
				}
			}
			b.HostPort = strconv.Itoa(lo + (int(d[0])<<8|int(d[1]))%size)
		}
		i := slices.IndexFunc(out.Ports, func(q TaskPort) bool { return q.Port == p.Target && q.Protocol == p.Proto })
		if i < 0 {
			out.Ports = append(out.Ports, TaskPort{Port: p.Target, Protocol: p.Proto})
			i = len(out.Ports) - 1
		}
		out.Ports[i].Published = append(out.Ports[i].Published, b)
	}
	return out, nil
}

func words(v any) []string {
	switch x := v.(type) {
	case string:
		return strings.Fields(x)
	case []any:
		var out []string
		for _, e := range x {
			out = append(out, fmt.Sprint(e))
		}
		return out
	}
	return nil
}

func (c *fakeConn) TaskHistory(ctx context.Context, tenant string, sel ContainerSelection, limit int) (TaskHistory, error) {
	_, t, err := c.taskTarget(ctx, "task-history", tenant, sel)
	if err != nil {
		return TaskHistory{}, err
	}
	defer c.unlock()
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	st := c.f.w.taskSt(*t, c.f.now().Unix())
	out := TaskHistory{Selection: selectionOf(t.App, t.Service, t.Instance), Exits: []TaskExit{}, Checks: []TaskCheckHistory{}}
	for i := len(st.exits) - 1; i >= 0 && len(out.Exits) < limit; i-- {
		out.Exits = append(out.Exits, st.exits[i])
	}
	for _, name := range sortedKeys(st.checks) {
		rs := st.checks[name]
		h := TaskCheckHistory{Checker: name}
		for i := len(rs) - 1; i >= 0; i-- {
			if len(h.Results) < limit {
				h.Results = append(h.Results, rs[i])
			}
		}
		for i := len(rs) - 1; i >= 0 && !rs[i].OK; i-- {
			h.ConsecutiveFailures++
		}
		out.Checks = append(out.Checks, h)
	}
	return out, nil
}

func (c *fakeConn) TaskLogs(ctx context.Context, tenant string, q TaskLogQuery) (TaskLogPage, error) {
	const m = "task-logs"
	_, t, err := c.taskTarget(ctx, m, tenant, q.Selection)
	if err != nil {
		return TaskLogPage{}, err
	}
	defer c.unlock()
	st := c.f.w.taskSt(*t, c.f.now().Unix())
	end := len(st.logs)
	if q.Cursor != "" {
		n, err := strconv.Atoi(q.Cursor)
		if err != nil || n < 0 || n > len(st.logs) {
			return TaskLogPage{}, fail(m, CodeInvalid, "cursor")
		}
		end = n
	}
	limit := q.Limit
	if limit <= 0 || limit > 10000 {
		limit = 100
	}
	out := TaskLogPage{Lines: []TaskLogLine{}}
	size, start := 0, end
	for start > 0 && end-start < limit {
		l := c.f.w.maskLine(st, st.logs[start-1])
		if size+len(l.Text) > taskLogPageBytes {
			break
		}
		size += len(l.Text)
		start--
	}
	for _, l := range st.logs[start:end] {
		ml := c.f.w.maskLine(st, l)
		if ml.Text != l.Text {
			out.Masked++
		}
		out.Lines = append(out.Lines, ml)
	}
	if start > 0 {
		out.Cursor = strconv.Itoa(start)
	}
	return out, nil
}

func (w *world) maskLine(st *taskState, l TaskLogLine) TaskLogLine {
	for _, v := range sortedKeys(st.secrets) {
		if v != "" && strings.Contains(l.Text, v) {
			l.Text = strings.ReplaceAll(l.Text, v, "«가림: "+st.secrets[v]+"»")
		}
	}
	return l
}

func (c *fakeConn) TaskStats(ctx context.Context, tenant string, sel ContainerSelection) ([]TaskStatsSample, error) {
	_, t, err := c.taskTarget(ctx, "task-stats", tenant, sel)
	if err != nil {
		return nil, err
	}
	defer c.unlock()
	now := c.f.now().Unix()
	var out []TaskStatsSample
	for i := 119; i >= 0; i-- {
		at := now - int64(i)*30
		if at < t.StartedAt {
			continue
		}
		k := uint64(120 - i)
		out = append(out, TaskStatsSample{At: at, ContainerStats: ContainerStats{CPUPercent: 2 + float64(k%7)/2, MemUsed: 200*mib + k*mib/2, MemLimit: 1 * gib,
			NetRxBytes: k * 100 << 10, NetTxBytes: k * 80 << 10, BlockRead: 4 * mib, BlockWrite: 2*mib + k<<10, PIDs: 7}})
	}
	return out, nil
}

func (c *fakeConn) applyRestartTask(op UserOperation, actor string, next uint64) error {
	w := c.f.w
	ch := op.Change
	// sfcd's control.TaskRestartChange (restart-task, task-restart-plan).
	var q control.TaskRestartChange
	if decodePayload(ch.Payload, &q) != nil || q.Tenant == "" || q.App == "" || q.Standalone != "" || q.ManagementTarget != nil || !lifecycle.ValidID(q.Operation) {
		return errors.New("payload")
	}
	if !w.canManage(actor, q.Tenant) {
		return errForbidden
	}
	a := w.apps[q.Tenant+"/"+q.App]
	if a == nil || a.view.Retiring || a.view.Revision != ch.Expected {
		return errCAS
	}
	if _, used := a.ops[q.Operation]; used {
		return errCAS
	}
	i := slices.IndexFunc(a.tasks, func(t Task) bool { return t.Service == q.Selection.Service && t.Instance == q.Selection.Instance })
	if i < 0 {
		return errCAS
	}
	plan := w.appControlPlan(a, a.tasks[i])
	if plan.Target != q.Target {
		return errCAS
	}
	now := c.f.now().Unix()
	t := &a.tasks[i]
	st := w.taskSt(*t, now)
	st.exits = append(st.exits, TaskExit{At: now, Reason: ExitReasonUser, ExitCode: 0, Generation: t.Generation, NativeID: nativeIDOf(*t)})
	delete(a.overrides, t.Service+"/"+t.Instance)
	t.Restarts++
	t.Observed, t.Health, t.ExitCode, t.LastCheck, t.StartedAt, t.ObservedAt = "running", "healthy", 0, "", now, now
	user := w.users[actor].rec.Username
	a.ops[q.Operation] = &AppOperation{Tenant: q.Tenant, App: a.view.App, ID: q.Operation, Status: "succeeded", Submitter: user, StartedAt: now, CompletedAt: now, Steps: []string{"stop", "start"}}
	a.view.Revision = next
	w.recordControl(containerops.Selection{App: a.view.App}, actor, q, plan, next, now)
	return nil
}

func (f *Fake) taskFor(tenant, app, service, instance string) (*Task, *taskState) {
	a := f.w.apps[tenant+"/"+app]
	if a == nil {
		panic("sfcli fake: no app " + tenant + "/" + app)
	}
	for i := range a.tasks {
		if a.tasks[i].Service == service && a.tasks[i].Instance == instance {
			return &a.tasks[i], f.w.taskSt(a.tasks[i], f.now().Unix())
		}
	}
	panic("sfcli fake: no task " + service + "/" + instance)
}

// AddTaskLog appends a stdout line to a task's log.
func (f *Fake) AddTaskLog(tenant, app, service, instance, text string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, st := f.taskFor(tenant, app, service, instance)
	st.logs = append(st.logs, TaskLogLine{Seq: uint64(len(st.logs) + 1), LogLine: LogLine{Time: f.now().Unix(), Stream: "stdout", Text: text}})
}

// SetTaskSecretValue says the task was given value from ref ("object/key"):
// log reads replace it with «가림: ref».
func (f *Fake) SetTaskSecretValue(tenant, app, service, instance, ref, value string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, st := f.taskFor(tenant, app, service, instance)
	st.secrets[value] = ref
}

// KillTask records an exit (reason, code) and a restart.
func (f *Fake) KillTask(tenant, app, service, instance, reason string, code int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, st := f.taskFor(tenant, app, service, instance)
	now := f.now().Unix()
	st.exits = append(st.exits, TaskExit{At: now, Reason: reason, ExitCode: code, Generation: t.Generation, NativeID: nativeIDOf(*t)})
	t.Restarts++
	t.ExitCode, t.StartedAt = code, now
}

// SetTaskDrift sets the fields task-detail reports as drifted.
func (f *Fake) SetTaskDrift(tenant, app, service, instance string, fields []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, st := f.taskFor(tenant, app, service, instance)
	st.drift = slices.Clone(fields)
}
