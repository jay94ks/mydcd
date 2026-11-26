// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"bufio"
	"bytes"
	"context"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/containerops"
	"github.com/jay94ks/mydcd/internal/userauth"
)

// container-observe in screen form (W1.2 step 2c): logs, top and stats as
// the server answers them, and the allowlisted inspect detail for the task
// detail, history and log pages. mydcd keeps no stats series, so stats
// samples are the current reading only.

func webSelection(t containerops.Target) ContainerSelection {
	if t.Standalone != "" {
		return ContainerSelection{Standalone: t.Standalone, Instance: t.Instance}
	}
	return ContainerSelection{App: t.App, Service: t.Service, Instance: t.Instance}
}

func unixTime(s string) int64 {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || t.IsZero() {
		return 0
	}
	return t.Unix()
}

func rfc3339(unix int64) string {
	if unix == 0 {
		return ""
	}
	return time.Unix(unix, 0).UTC().Format(time.RFC3339Nano)
}

func (c *realConn) observe(ctx context.Context, m, tenant string, q containerops.Query) (userauth.Reply, error) {
	return realCall(ctx, c, m, func(u userauth.Client, s access.Session) (userauth.Reply, error) {
		if q.Kind == "inspect" {
			return u.InspectContainer(ctx, c.peer, s, tenant, q)
		}
		return u.ObserveContainer(ctx, c.peer, s, tenant, q)
	})
}

func (c *realConn) ContainerObserve(ctx context.Context, tenant string, q ContainerQuery) (ContainerResult, error) {
	const m = "container-observe"
	oq := containerops.Query{Schema: 1, Selection: q.Selection.Ops(), Kind: q.Kind, MaxBytes: containerops.MaxOutput}
	if q.Kind == "logs" {
		oq.Tail, oq.Stdout, oq.Stderr, oq.Timestamps, oq.Since, oq.Until = q.Tail, q.Stdout, q.Stderr, true, rfc3339(q.Since), rfc3339(q.Until)
		if oq.Tail == 0 {
			oq.Tail = 200
		}
		if !oq.Stdout && !oq.Stderr {
			oq.Stdout, oq.Stderr = true, true
		}
	}
	if oq.Validate() != nil {
		return ContainerResult{}, fail(m, CodeInvalid, "query")
	}
	reply, err := c.observe(ctx, m, tenant, oq)
	if err != nil {
		return ContainerResult{}, err
	}
	r := reply.Container
	out := ContainerResult{Selection: webSelection(r.Target), Node: r.Target.Node, NativeID: r.Target.NativeID, Kind: r.Kind,
		Truncated: r.Truncated, LogDriver: r.LogDriver, ObservedAt: r.ObservedAt.Unix(), ViewIndex: reply.ContainerViewIndex}
	switch r.Kind {
	case "logs":
		out.Logs = logLines(r.Stdout, r.Stderr)
	case "top":
		out.Processes = processes(r.Titles, r.Processes)
	case "stats":
		if r.Stats != nil {
			s := statsView(*r.Stats)
			out.Stats = &s
		}
	}
	return out, nil
}

// logLines merges the timestamped stdout and stderr lines by time.
func logLines(stdout, stderr []byte) []LogLine {
	var out []LogLine
	read := func(b []byte, stream string) {
		sc := bufio.NewScanner(bytes.NewReader(b))
		sc.Buffer(make([]byte, 0, 4096), containerops.MaxOutput)
		for sc.Scan() {
			stamp, text, _ := strings.Cut(sc.Text(), " ")
			at, err := time.Parse(time.RFC3339Nano, stamp)
			if err != nil {
				text = sc.Text()
			}
			line := LogLine{Stream: stream, Text: text}
			if err == nil {
				line.Time = at.Unix()
			}
			out = append(out, line)
		}
	}
	read(stdout, "stdout")
	read(stderr, "stderr")
	slices.SortStableFunc(out, func(a, b LogLine) int { return int(a.Time - b.Time) })
	return out
}

// processes reads the top table by its column titles.
func processes(titles []string, rows [][]string) []Process {
	col := func(names ...string) int {
		return slices.IndexFunc(titles, func(t string) bool { return slices.Contains(names, strings.ToUpper(t)) })
	}
	pid, user, cmd, cpu, rss := col("PID"), col("USER", "UID"), col("CMD", "COMMAND"), col("%CPU", "C"), col("RSS")
	at := func(r []string, i int) string {
		if i < 0 || i >= len(r) {
			return ""
		}
		return r[i]
	}
	out := make([]Process, 0, len(rows))
	for _, r := range rows {
		p := Process{User: at(r, user), Command: at(r, cmd)}
		p.PID, _ = strconv.Atoi(at(r, pid))
		p.CPU, _ = strconv.ParseFloat(at(r, cpu), 64)
		if kb, err := strconv.ParseUint(at(r, rss), 10, 64); err == nil {
			p.MemRSS = kb * 1024
		}
		out = append(out, p)
	}
	return out
}

func statsView(s containerops.Stats) ContainerStats {
	u := func(p *uint64) uint64 {
		if p == nil {
			return 0
		}
		return *p
	}
	v := ContainerStats{MemUsed: u(s.MemoryBytes), MemLimit: u(s.MemoryLimitBytes), NetRxBytes: u(s.NetworkRXBytes), NetTxBytes: u(s.NetworkTXBytes),
		BlockRead: u(s.BlockReadBytes), BlockWrite: u(s.BlockWriteBytes), PIDs: int(u(s.PIDs))}
	if s.CPUPercent != nil {
		v.CPUPercent = *s.CPUPercent
	}
	return v
}

func (c *realConn) inspect(ctx context.Context, m, tenant string, sel ContainerSelection, history int) (*containerops.Result, error) {
	q := containerops.Query{Schema: 1, Selection: sel.Ops(), Kind: "inspect", MaxBytes: containerops.MaxOutput, HistoryLimit: history}
	if q.Validate() != nil {
		return nil, fail(m, CodeInvalid, "selection")
	}
	reply, err := c.observe(ctx, m, tenant, q)
	if err != nil {
		return nil, err
	}
	if reply.Container.Detail == nil {
		return nil, fail(m, CodeUnknown, "reply without detail")
	}
	return reply.Container, nil
}

func (c *realConn) TaskDetail(ctx context.Context, tenant string, sel ContainerSelection) (TaskDetail, error) {
	r, err := c.inspect(ctx, "task-detail", tenant, sel, 0)
	if err != nil {
		return TaskDetail{}, err
	}
	d := r.Detail
	out := TaskDetail{Selection: webSelection(r.Target), Node: r.Target.Node, Name: d.Name, NativeID: r.Target.NativeID, Image: d.ImageReference,
		Digest: d.ImageID, Command: d.Command, Entrypoint: d.Entrypoint, WorkingDir: d.WorkingDir, User: d.User, ReadOnly: d.ReadOnlyRootFS,
		CapAdd: d.CapabilitiesAdded, Privileged: d.Privileged, CPUs: float64(d.NanoCPUs) / 1e9, MemoryBytes: uint64(max(d.MemoryBytes, 0)),
		LogDriver: d.LogDriver, LogOptions: d.LogOptions, Env: []TaskEnv{}, Mounts: []TaskMount{}, Networks: []TaskNetwork{},
		StopSignal: d.StopSignal, StopGrace: d.StopGraceSeconds, Generation: r.Target.Generation, Drift: d.Drift, ObservedAt: r.ObservedAt.Unix()}
	for _, e := range d.Environment {
		v := TaskEnv{Key: e.Name, Secret: e.SecretReference}
		if e.Value != nil {
			v.Value = *e.Value
		}
		out.Env = append(out.Env, v)
	}
	for _, mnt := range d.Mounts {
		v := TaskMount{Kind: mnt.Kind, Source: mnt.Name, Target: mnt.Target, ReadOnly: mnt.ReadOnly}
		if mnt.Mode != nil {
			v.Mode = strconv.FormatUint(uint64(*mnt.Mode), 8)
		}
		out.Mounts = append(out.Mounts, v)
	}
	for _, n := range d.Networks {
		out.Networks = append(out.Networks, TaskNetwork{Name: n.Name, IP: n.IPv4, Aliases: n.Aliases, DNS: d.DNS})
	}
	for _, p := range d.Ports {
		i := slices.IndexFunc(out.Ports, func(x TaskPort) bool { return x.Port == int(p.Port) && x.Protocol == p.Protocol })
		if i < 0 {
			out.Ports = append(out.Ports, TaskPort{Port: int(p.Port), Protocol: p.Protocol})
			i = len(out.Ports) - 1
		}
		if p.HostPort != "" {
			out.Ports[i].Published = append(out.Ports[i].Published, TaskPortBinding{HostIP: p.HostIP, HostPort: p.HostPort})
		}
	}
	for _, in := range d.DeclaredIngress {
		i := slices.IndexFunc(out.Ports, func(x TaskPort) bool { return x.Port == int(in.BackendPort) })
		if i < 0 {
			out.Ports = append(out.Ports, TaskPort{Port: int(in.BackendPort), Protocol: "tcp"})
			i = len(out.Ports) - 1
		}
		out.Ports[i].Ingress = in.Host
	}
	return out, nil
}

// TaskHistory: exits from the container event history, checks grouped by
// checker (newest first).
func (c *realConn) TaskHistory(ctx context.Context, tenant string, sel ContainerSelection, limit int) (TaskHistory, error) {
	if limit <= 0 {
		limit = 20
	}
	r, err := c.inspect(ctx, "task-history", tenant, sel, min(limit, 100))
	if err != nil {
		return TaskHistory{}, err
	}
	out := TaskHistory{Selection: webSelection(r.Target), Exits: []TaskExit{}, Checks: []TaskCheckHistory{}}
	for _, h := range r.Detail.History {
		if h.Kind != "task-exited" {
			continue // a restart record repeats the exit before it
		}
		e := TaskExit{At: h.At.Unix(), Reason: exitReason(h), Generation: h.Generation, NativeID: h.NativeID}
		if h.ExitCode != nil {
			e.ExitCode = *h.ExitCode
		}
		out.Exits = append(out.Exits, e)
	}
	slices.SortStableFunc(out.Exits, func(a, b TaskExit) int { return int(b.At - a.At) })
	for _, ch := range r.Detail.Checks {
		i := slices.IndexFunc(out.Checks, func(x TaskCheckHistory) bool { return x.Checker == ch.Checker })
		if i < 0 {
			out.Checks = append(out.Checks, TaskCheckHistory{Checker: ch.Checker})
			i = len(out.Checks) - 1
		}
		h := &out.Checks[i]
		h.Results = append(h.Results, TaskCheckResult{At: ch.At.Unix(), OK: ch.Status == "pass", DurationMs: int(ch.DurationMS), Message: ch.Message})
		if ch.ConsecutiveFailures != nil {
			h.ConsecutiveFailures = max(h.ConsecutiveFailures, int(*ch.ConsecutiveFailures))
		}
	}
	for i := range out.Checks {
		slices.SortStableFunc(out.Checks[i].Results, func(a, b TaskCheckResult) int { return int(b.At - a.At) })
	}
	return out, nil
}

func exitReason(h containerops.DetailHistory) string {
	switch h.Reason {
	case ExitReasonOOM, ExitReasonHealth, ExitReasonNodeRestart, ExitReasonUser, ExitReasonLogClear:
		return h.Reason
	}
	return ExitReasonExit
}

// TaskLogs pages logs backwards with mydcd's log cursor. Seq numbers the
// lines of this page only. mydcd masks nothing here; Masked stays 0.
func (c *realConn) TaskLogs(ctx context.Context, tenant string, q TaskLogQuery) (TaskLogPage, error) {
	const m = "task-logs"
	limit := q.Limit
	if limit <= 0 || limit > 10000 {
		limit = 200
	}
	oq := containerops.Query{Schema: 1, Selection: q.Selection.Ops(), Kind: "logs", Tail: limit, Stdout: true, Stderr: true, Timestamps: true,
		MaxBytes: containerops.MaxOutput, Cursor: q.Cursor}
	if oq.Validate() != nil {
		return TaskLogPage{}, fail(m, CodeInvalid, "query")
	}
	reply, err := c.observe(ctx, m, tenant, oq)
	if err != nil {
		return TaskLogPage{}, err
	}
	out := TaskLogPage{Lines: []TaskLogLine{}, Cursor: reply.Container.NextCursor}
	for i, l := range logLines(reply.Container.Stdout, reply.Container.Stderr) {
		out.Lines = append(out.Lines, TaskLogLine{Seq: uint64(i + 1), LogLine: l})
	}
	return out, nil
}

func (c *realConn) TaskStats(ctx context.Context, tenant string, sel ContainerSelection) ([]TaskStatsSample, error) {
	const m = "task-stats"
	reply, err := c.observe(ctx, m, tenant, containerops.Query{Schema: 1, Selection: sel.Ops(), Kind: "stats", MaxBytes: containerops.MaxOutput})
	if err != nil {
		return nil, err
	}
	s := reply.Container.Stats
	if s == nil {
		return []TaskStatsSample{}, nil
	}
	return []TaskStatsSample{{At: s.SampleAt.Unix(), ContainerStats: statsView(*s)}}, nil
}
