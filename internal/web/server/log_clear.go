// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/web/mydc"
)

// Log clearing (UI-3C '로그 정리…', `mydc compose logs clear`): mydcd plans
// which containers are recreated (the target and the ones that depend on
// it), refuses log drivers other than local/json-file, and runs the signed
// clear-app-logs. The web shows the plan, sends the change with the plan's
// Target and InventoryRevision as the CLI does, and reads the status. The
// clear's operation is "logs-clear-<opId>".

type logClearTargetView struct {
	Key        string `json:"key"`
	Service    string `json:"service,omitempty"`
	Instance   string `json:"instance,omitempty"`
	Kind       string `json:"kind"`
	Node       string `json:"node"`
	NativeID   string `json:"nativeID,omitempty"`
	StartedAt  string `json:"startedAt,omitempty"`
	LogDriver  string `json:"logDriver,omitempty"`
	Generation uint64 `json:"generation"`
	Retained   bool   `json:"retained,omitempty"`
	Reason     string `json:"reason,omitempty"` // target / depends-on (plan only)
}

// viewTargets maps impact rows; the service comes from the task key
// (workload/task/<tenant>/<app>/<service>[/<instance>]).
func viewTargets(in []control.AppLogClearImpact, tenant, app, targetNative string) []logClearTargetView {
	out := []logClearTargetView{}
	for _, im := range in {
		v := logClearTargetView{Key: im.Key, Kind: im.Kind, Node: im.Node, NativeID: im.NativeID, StartedAt: im.StartedAt, LogDriver: im.LogDriver, Generation: im.Generation, Retained: im.Retained}
		if rest, ok := strings.CutPrefix(im.Key, "workload/task/"+tenant+"/"+app+"/"); ok {
			v.Service, v.Instance, _ = strings.Cut(rest, "/")
		}
		if targetNative != "" {
			v.Reason = "depends-on"
			if im.NativeID == targetNative {
				v.Reason = "target"
			}
		}
		out = append(out, v)
	}
	return out
}

type logClearPlanView struct {
	Clearable         bool                 `json:"clearable"`
	Driver            string               `json:"driver,omitempty"`
	Reason            string               `json:"reason,omitempty"` // unsupported-log-driver
	Service           string               `json:"service"`
	Instance          string               `json:"instance,omitempty"`
	Node              string               `json:"node,omitempty"`
	Target            string               `json:"target,omitempty"`
	InventoryRevision uint64               `json:"inventoryRevision,omitempty"`
	Targets           []logClearTargetView `json:"targets"`
}

// GET /t/{t}/apps/{app}/logs-clear/plan?service=&instance= → {clearable,
// driver, reason?, service, instance?, node?, target?, inventoryRevision?,
// targets:[{key, service, instance?, kind, node, nativeID, startedAt,
// logDriver, generation, retained?, reason(target/depends-on)}]}. When the
// container does not log to local/json-file: clearable false, reason
// unsupported-log-driver, no targets. Needs the tenant's Deploy permission
// (mydcd decides).
func (s *Server) handleLogClearPlan(w http.ResponseWriter, r *http.Request, ws *webSession) {
	q := r.URL.Query()
	tenant, sel := r.PathValue("t"), mydc.ContainerSelection{App: r.PathValue("app"), Service: q.Get("service"), Instance: q.Get("instance")}
	if sel.Service == "" {
		writeError(w, http.StatusBadRequest, "bad-request", "service is required")
		return
	}
	read(s, w, r, ws, func(ctx context.Context, c mydc.Conn) (logClearPlanView, error) {
		p, err := c.AppLogClearPlan(ctx, tenant, sel)
		v := logClearPlanView{Driver: p.LogDriver, Service: sel.Service, Instance: sel.Instance, Targets: []logClearTargetView{}}
		if pl := p.Plan; pl != nil {
			v.Clearable, v.Node, v.Target, v.InventoryRevision = true, pl.Container.Node, hex.EncodeToString(pl.Target[:]), pl.InventoryRevision
			v.Targets = viewTargets(pl.Impact, tenant, sel.App, pl.Container.NativeID)
		} else {
			v.Reason = p.Code
		}
		return v, err
	})
}

// POST /t/{t}/apps/{app}/logs-clear {opId, service, instance?, target} →
// clear-app-logs with operation "logs-clear-<opId>". target is the plan's
// target the person agreed to; a plan that moved on is 409 plan-changed
// (read the plan again), a driver that cannot be cleared 409
// unsupported-log-driver. Expected = the plan's inventoryRevision.
func (s *Server) handleClearAppLogs(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID     string `json:"opId"`
		Service  string `json:"service"`
		Instance string `json:"instance,omitempty"`
		Target   string `json:"target"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant, app := r.PathValue("t"), r.PathValue("app")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c mydc.Conn, _ mydc.Session) (string, any, uint64, string, error) {
		if req.Service == "" || len(req.Target) != 64 {
			return "", nil, 0, "", invalid("service and target (the plan's target) are required")
		}
		p, err := c.AppLogClearPlan(ctx, tenant, mydc.ContainerSelection{App: app, Service: req.Service, Instance: req.Instance})
		if err != nil {
			return "", nil, 0, "", err
		}
		if p.Plan == nil {
			return "", nil, 0, "", &httpErr{http.StatusConflict, p.Code, "the container's log driver (" + p.LogDriver + ") is not local or json-file"}
		}
		if hex.EncodeToString(p.Plan.Target[:]) != req.Target {
			return "", nil, 0, "", &httpErr{http.StatusConflict, "plan-changed", "the containers to recreate changed; read the plan again"}
		}
		q := control.AppLogClear{Tenant: tenant, App: app, Operation: "logs-clear-" + req.OpID, Target: p.Plan.Target, Recreate: true}
		q.Selection.Service, q.Selection.Instance = req.Service, req.Instance
		return mydc.ActionClearAppLogs, q, p.Plan.InventoryRevision, "app/" + app, nil
	})
}

// GET /t/{t}/apps/{app}/logs-clear/{opId} → {operation, phase
// (Retiring/Removed/Recreating/Succeeded), target, oldContainers,
// newContainers}. 404 until mydcd has the clear.
func (s *Server) handleLogClearStatus(w http.ResponseWriter, r *http.Request, ws *webSession) {
	tenant, app := r.PathValue("t"), r.PathValue("app")
	read(s, w, r, ws, func(ctx context.Context, c mydc.Conn) (map[string]any, error) {
		st, err := c.AppLogClearStatus(ctx, tenant, app, "logs-clear-"+r.PathValue("op"))
		if err != nil {
			return nil, err
		}
		return map[string]any{"operation": st.Operation, "phase": st.Status, "target": hex.EncodeToString(st.Target[:]),
			"oldContainers": viewTargets(st.OldContainers, tenant, app, ""), "newContainers": viewTargets(st.NewContainers, tenant, app, "")}, nil
	})
}
