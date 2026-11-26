// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"errors"
	"github.com/jay94ks/mydcd/internal/workload"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

func (s Service) logClearQuery(view cluster.View, q Request, session access.Session) Reply {
	out := Reply{Schema: 1, Code: "unavailable", Tenant: q.Tenant, RootRevision: view.State.Object(control.CatalogKey).Revision, AppsRootRevision: view.State.Object(control.AppsKey).Revision, ModuleEpoch: view.State.ModuleEpoch()}
	if q.LogClear == nil || !q.LogClear.Valid(q.Method == "app-log-clear-plan") {
		return out
	}
	if q.Method == "app-log-clear-plan" {
		plan, err := s.Policy.PlanAppLogClear(view.State, session, time.Now().Unix(), q.Tenant, q.LogClear.Selection)
		if err == nil {
			out.Code, out.LogClearPlan = "ok", &plan
		} else if errors.Is(err, workload.ErrLogPolicy) {
			out.Code = "unsupported-log-driver"
		} else if errors.Is(err, access.ErrDenied) {
			out.Code = "denied"
		}
		return out
	}
	apps, err := s.Policy.ReadApps(view.State)
	if err != nil {
		return out
	}
	scope := q.LogClear.Selection.App
	if q.LogClear.Selection.Standalone != "" {
		scope, _ = apps.StandaloneScope(q.Tenant, q.LogClear.Selection.Standalone)
	} else if apps.IsStandalone(q.Tenant, scope) {
		out.Code = "denied"
		return out
	}
	status := apps.LogClearStatus(q.Tenant, scope, q.LogClear.Operation)
	if status == nil {
		return out
	}
	out.Code, out.LogClearStatus = "ok", status
	return out
}

func (c Client) QueryLogClear(ctx context.Context, peer mydcp.Peer, session access.Session, tenant string, plan bool, q control.AppLogClearQuery) (Reply, error) {
	if tenant == "" || !q.Valid(plan) {
		return Reply{}, mydcp.ErrAdmission
	}
	method := "app-log-clear-status"
	if plan {
		method = "app-log-clear-plan"
	}
	reply, err := c.query(ctx, peer, session, Request{Method: method, Tenant: tenant, LogClear: &q})
	if err != nil {
		return reply, err
	}
	if plan {
		v := reply.LogClearPlan
		if v == nil || v.Schema != 1 || v.Tenant != tenant || (q.Selection.Standalone == "" && v.App != q.Selection.App || q.Selection.Standalone != "" && v.Container.Standalone != q.Selection.Standalone) || v.Container.Cluster != c.Cluster || v.Container.Tenant != tenant || (q.Selection.Standalone == "" && v.Container.App != q.Selection.App) || q.Selection.Service != "" && v.Container.Service != q.Selection.Service || q.Selection.Instance != "" && v.Container.Instance != q.Selection.Instance || v.Target == ([32]byte{}) || v.InventoryRevision == 0 || len(v.Impact) == 0 {
			return reply, mydcp.ErrFrame
		}
	} else if reply.LogClearStatus == nil || reply.LogClearStatus.Operation != q.Operation {
		return reply, mydcp.ErrFrame
	}
	return reply, nil
}
