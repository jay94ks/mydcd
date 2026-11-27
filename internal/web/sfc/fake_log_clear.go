// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"
	"slices"

	"github.com/jay94ks/seafield/internal/cluster/control"
)

// Log clearing (devel/proposals/seafield-log-clear.md, real in sfcd):
// logs-clear asks every member server to clear its own log store for a
// selection, without touching containers; stored-logs lists what each
// server's store keeps. The fake keeps each task's lines with the task and
// answers per member: a server set down (SetLogStoreDown) is "unreachable"
// and keeps its lines, so the same clear sent again clears them too.

// LogsClear is the web's selection: App or Standalone, Service (empty =
// every service), Key (one task key, workload/task/...).
type LogsClear struct {
	App, Standalone, Service, Key string
}

func (q LogsClear) control(tenant string) control.LogsClear {
	out := control.LogsClear{Tenant: tenant}
	out.Selection.App, out.Selection.Standalone, out.Selection.Service, out.Selection.Instance = q.App, q.Standalone, q.Service, q.Key
	return out
}

// SetLogStoreDown makes a member server not answer logs-clear and
// stored-logs.
func (f *Fake) SetLogStoreDown(node string, down bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.w.logStoreDown == nil {
		f.w.logStoreDown = map[string]bool{}
	}
	f.w.logStoreDown[node] = down
}

// logClearKey stands in for sfcd's task key (the fake adds the instance, as
// it can run more than one).
func logClearKey(t Task) string {
	return "workload/task/" + t.Tenant + "/" + t.App + "/" + t.Service + "/" + t.Instance
}

// logTasks: the tasks the selection names, or nil and false when it names
// no app (a standalone is not modeled by the fake's tasks).
func (w *world) logTasks(tenant string, q LogsClear) ([]Task, bool) {
	if q.Standalone != "" {
		return nil, w.standalones[tenant+"/"+q.Standalone] != nil
	}
	a := w.apps[tenant+"/"+q.App]
	if a == nil {
		return nil, false
	}
	var out []Task
	for _, t := range a.tasks {
		if (q.Service == "" || t.Service == q.Service) && (q.Key == "" || logClearKey(t) == q.Key) {
			out = append(out, t)
		}
	}
	return out, true
}

func (c *fakeConn) logsEntry(ctx context.Context, m, tenant string, q LogsClear) (string, []Task, error) {
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return "", nil, err
	}
	w := c.f.w
	if tenant == "" || (q.App == "") == (q.Standalone == "") {
		c.unlock()
		return "", nil, fail(m, CodeInvalid, "selection")
	}
	if !w.canRead(user, tenant) {
		c.unlock()
		return "", nil, fail(m, CodeDenied, "")
	}
	tasks, ok := w.logTasks(tenant, q)
	if !ok {
		c.unlock()
		return "", nil, fail(m, CodeDenied, "")
	}
	return user, tasks, nil
}

// ClearLogs: `logs-clear` (entry: tenant Read; each server: Deploy).
func (c *fakeConn) ClearLogs(ctx context.Context, tenant string, q LogsClear) (control.LogsClearReply, error) {
	user, tasks, err := c.logsEntry(ctx, "logs-clear", tenant, q)
	if err != nil {
		return control.LogsClearReply{}, err
	}
	defer c.unlock()
	w := c.f.w
	now := c.f.now().Unix()
	var out control.LogsClearReply
	for _, mb := range w.members {
		if mb.Phase == NodePhasePending {
			continue
		}
		n := control.LogsClearNode{Node: mb.ID, Code: "ok"}
		switch {
		case w.logStoreDown[mb.ID]:
			n.Code = "unreachable"
		case !w.canManage(user, tenant):
			n.Code = "denied"
		default:
			for _, t := range tasks {
				if t.Node != mb.ID {
					continue
				}
				st := w.taskSt(t, now)
				n.Containers++
				n.Removed += len(st.logs)
				st.logs = nil
			}
		}
		out.Nodes = append(out.Nodes, n)
	}
	return out, nil
}

// StoredLogs: `stored-logs` (entry: tenant Read; each server: Read). node
// empty = every member server.
func (c *fakeConn) StoredLogs(ctx context.Context, tenant string, q LogsClear, node string) (control.StoredLogsReply, error) {
	_, tasks, err := c.logsEntry(ctx, "stored-logs", tenant, q)
	if err != nil {
		return control.StoredLogsReply{}, err
	}
	defer c.unlock()
	w := c.f.w
	now := c.f.now().Unix()
	var out control.StoredLogsReply
	for _, mb := range w.members {
		if mb.Phase == NodePhasePending || node != "" && mb.ID != node {
			continue
		}
		n := control.StoredLogsNode{Node: mb.ID, Code: "ok"}
		if w.logStoreDown[mb.ID] {
			n.Code = "unreachable"
		} else {
			for _, t := range tasks {
				if t.Node != mb.ID {
					continue
				}
				st := w.taskSt(t, now)
				var size int64
				for _, l := range st.logs {
					size += int64(len(l.Text))
				}
				n.Logs = append(n.Logs, control.StoredLog{Container: nativeIDOf(t), Name: t.App + "-" + t.Service + "-" + t.Instance, Service: t.Service, Key: logClearKey(t), Lines: uint64(len(st.logs)), Size: size})
			}
		}
		out.Nodes = append(out.Nodes, n)
	}
	if node != "" && !slices.ContainsFunc(out.Nodes, func(n control.StoredLogsNode) bool { return n.Node == node }) {
		return control.StoredLogsReply{}, fail("stored-logs", CodeMissing, "node")
	}
	return out, nil
}
