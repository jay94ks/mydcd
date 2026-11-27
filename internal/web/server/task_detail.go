// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"
	"strconv"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

// One container beyond container-observe and the 배치 tab's
// pre-move check. The container is named the same way as for
// /observe: /apps/{app}/task?service=&instance= or /standalone/{name}/task.
// sfcd reads the server, masks secret values and judges permissions.

// GET …/task → the applied settings with drift (task-detail).
func (s *Server) handleTaskDetail(w http.ResponseWriter, r *http.Request, ws *webSession) {
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (sfc.TaskDetail, error) {
		return c.TaskDetail(ctx, r.PathValue("t"), selectionOf(r))
	})
}

// GET …/task/history?limit= → {selection, exits, checks} (newest first).
func (s *Server) handleTaskHistory(w http.ResponseWriter, r *http.Request, ws *webSession) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 0 || limit > 200 {
		writeError(w, http.StatusBadRequest, "bad-request", "limit must be 0..200")
		return
	}
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (sfc.TaskHistory, error) {
		return c.TaskHistory(ctx, r.PathValue("t"), selectionOf(r), limit)
	})
}

// GET …/task/logs?cursor=&limit= → {lines:[{seq, …}], cursor?, masked}:
// lines before cursor ("" = the newest), oldest first; the reply's cursor
// reads further back.
func (s *Server) handleTaskLogs(w http.ResponseWriter, r *http.Request, ws *webSession) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 0 || limit > 5000 {
		writeError(w, http.StatusBadRequest, "bad-request", "limit must be 0..5000")
		return
	}
	q := sfc.TaskLogQuery{Selection: selectionOf(r), Cursor: r.URL.Query().Get("cursor"), Limit: limit}
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (sfc.TaskLogPage, error) {
		p, err := c.TaskLogs(ctx, r.PathValue("t"), q)
		if p.Lines == nil {
			p.Lines = []sfc.TaskLogLine{}
		}
		return p, err
	})
}

// GET …/task/stats → {items:[{at, …stats}]}: the last hour, 30 s apart.
func (s *Server) handleTaskStats(w http.ResponseWriter, r *http.Request, ws *webSession) {
	readList(s, w, r, ws, func(ctx context.Context, c sfc.Conn) ([]sfc.TaskStatsSample, error) {
		return c.TaskStats(ctx, r.PathValue("t"), selectionOf(r))
	})
}

// POST /t/{t}/apps/{app}/task/restart {opId, service, instance,
// operation?} → restart-task. The daemon reads sfcd's task-restart-plan
// for that task and signs control.TaskRestartChange with the plan's Target
// (pinned to the running container) and Expected = plan.InventoryRevision,
// as the CLI does; a container that changed in between fails the op with
// ConditionFailed. Only that task restarts; operation (default
// "restart-<opId>", a lifecycle ID) names the app operation that reports
// the result. expected is no longer used (ignored when sent).
func (s *Server) handleRestartTask(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID      string `json:"opId"`
		Service   string `json:"service"`
		Instance  string `json:"instance"`
		Operation string `json:"operation,omitempty"`
		Expected  uint64 `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if req.Operation == "" {
		req.Operation = "restart-" + req.OpID
	}
	tenant, app := r.PathValue("t"), r.PathValue("app")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		if req.Service == "" || req.Instance == "" {
			return "", nil, 0, "", invalid("service and instance: the task to restart")
		}
		if !lifecycle.ValidID(req.Operation) {
			return "", nil, 0, "", invalid("operation: starts with a lowercase letter; lowercase letters, digits and -, at most 63")
		}
		plan, err := c.TaskRestartPlan(ctx, tenant, control.TaskRestartQuery{Selection: containerops.Selection{App: app, Service: req.Service, Instance: req.Instance}})
		if err != nil {
			return "", nil, 0, "", err
		}
		q := control.TaskRestartChange{Tenant: tenant, App: app, Operation: req.Operation, Target: plan.Target}
		q.Selection.Service, q.Selection.Instance = req.Service, req.Instance
		return sfc.ActionRestartTask, q, plan.InventoryRevision, "app/" + app, nil
	})
}

// GET /t/{t}/apps/{app}/relocation-check?service=&node= → {from, to, ok,
// checks, volumes, steps}: sfcd's plan of the running version with the
// service on node, and which steps the move takes ("app" = a new version
// with x-sfc.node changed, "volume-move" = the volume move carrying that
// version).
func (s *Server) handleRelocationCheck(w http.ResponseWriter, r *http.Request, ws *webSession) {
	q := r.URL.Query()
	if q.Get("service") == "" || q.Get("node") == "" {
		writeError(w, http.StatusBadRequest, "bad-request", "service and node are required")
		return
	}
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (relocationView, error) {
		return relocationCheck(ctx, c, r.PathValue("t"), r.PathValue("app"), q.Get("service"), q.Get("node"))
	})
}
