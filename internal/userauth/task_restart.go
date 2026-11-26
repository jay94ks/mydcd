// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"errors"
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"time"
)

func (s Service) taskRestartQuery(view cluster.View, q Request, session access.Session) Reply {
	out := Reply{Schema: 1, Code: "unavailable", Tenant: q.Tenant, RootRevision: view.State.Object(control.CatalogKey).Revision, AppsRootRevision: view.State.Object(control.AppsKey).Revision, ModuleEpoch: view.State.ModuleEpoch()}
	if q.TaskRestart == nil || !q.TaskRestart.Valid(q.Method == "task-restart-plan") {
		return out
	}
	if q.Method == "task-restart-plan" {
		plan, err := s.Policy.PlanTaskControl(view.State, session, time.Now().Unix(), q.Tenant, q.TaskRestart.Selection, func() string {
			if q.TaskRestart.Action != "" {
				return q.TaskRestart.Action
			}
			return "restart-task"
		}())
		if err == nil {
			out.Code = "ok"
			out.TaskRestartPlan = &plan
		} else if errors.Is(err, access.ErrDenied) {
			out.Code = "denied"
		}
		return out
	}
	apps, err := s.Policy.ReadApps(view.State)
	if err != nil {
		return out
	}
	scope := q.TaskRestart.Selection.App
	if q.TaskRestart.Selection.Standalone != "" {
		scope, _ = apps.StandaloneScope(q.Tenant, q.TaskRestart.Selection.Standalone)
	}
	status := apps.TaskRestartStatus(q.Tenant, scope, q.TaskRestart.Operation)
	if status == nil {
		return out
	}
	out.Code = "ok"
	out.TaskRestartStatus = status
	return out
}
func (c Client) QueryTaskRestart(ctx context.Context, peer mydcp.Peer, session access.Session, tenant string, plan bool, q control.TaskRestartQuery) (Reply, error) {
	if tenant == "" || !q.Valid(plan) {
		return Reply{}, mydcp.ErrAdmission
	}
	method := "task-restart-status"
	if plan {
		method = "task-restart-plan"
	}
	reply, err := c.query(ctx, peer, session, Request{Method: method, Tenant: tenant, TaskRestart: &q})
	if err != nil {
		return reply, err
	}
	if plan {
		v := reply.TaskRestartPlan
		if v == nil || !v.Valid() || v.Tenant != tenant || (q.Selection.Standalone == "" && v.App != q.Selection.App || q.Selection.Standalone != "" && v.Container.Standalone != q.Selection.Standalone) || v.Container.Cluster != c.Cluster || q.Selection.Service != "" && v.Container.Service != q.Selection.Service || q.Selection.Instance != "" && v.Container.Instance != q.Selection.Instance {
			return Reply{}, mydcp.ErrFrame
		}
	} else {
		v := reply.TaskRestartStatus
		if v == nil || v.Operation != q.Operation || !v.Plan.Valid() || v.Plan.Container.Cluster != c.Cluster || v.Plan.Tenant != tenant || (q.Selection.Standalone == "" && v.Plan.App != q.Selection.App || q.Selection.Standalone != "" && v.Plan.Container.Standalone != q.Selection.Standalone) {
			return Reply{}, mydcp.ErrFrame
		}
	}
	return reply, nil
}
