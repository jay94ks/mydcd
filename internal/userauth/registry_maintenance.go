// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// RegistryMaintenancePlanQuery asks for the change one maintenance action
// (other than prune) would submit.
type RegistryMaintenancePlanQuery struct {
	Tenant string
	Query  control.RegistryMaintenanceQuery
}

func (q RegistryMaintenancePlanQuery) Valid() bool {
	return lifecycle.ValidID(q.Tenant) && q.Query.Valid(true) && q.Query.Action != control.RegistryPruneAction
}

// RegistryMaintenanceStatusQuery reads one maintenance operation.
type RegistryMaintenanceStatusQuery struct{ Tenant, Operation string }

func (q RegistryMaintenanceStatusQuery) Valid() bool {
	return lifecycle.ValidID(q.Tenant) && (control.RegistryMaintenanceQuery{Operation: q.Operation}).Valid(false)
}

var (
	RegistryMaintenancePlanMethod = define(Method[RegistryMaintenancePlanQuery, control.RegistryMaintenancePlan]{Name: "registry-maintenance-plan"}, true, func(_ context.Context, s Service, view cluster.View, session access.Session, q RegistryMaintenancePlanQuery) (control.RegistryMaintenancePlan, string) {
		if !s.mayAny(view, session, q.Tenant, access.ManageRegistry) {
			return control.RegistryMaintenancePlan{}, "denied"
		}
		plan, err := s.Policy.PlanRegistryMaintenance(view.State, session, time.Now().Unix(), q.Tenant, q.Query)
		if err != nil {
			return control.RegistryMaintenancePlan{}, errorCode(err)
		}
		return plan, "ok"
	})
	RegistryMaintenanceStatusMethod = define(Method[RegistryMaintenanceStatusQuery, control.RegistryMaintenanceStatus]{Name: "registry-maintenance-status"}, true, func(_ context.Context, s Service, view cluster.View, session access.Session, q RegistryMaintenanceStatusQuery) (control.RegistryMaintenanceStatus, string) {
		if !s.mayAny(view, session, q.Tenant, access.Read, access.ManageRegistry) {
			return control.RegistryMaintenanceStatus{}, "denied"
		}
		status, err := s.Policy.RegistryMaintenanceStatus(view.State, session, time.Now().Unix(), q.Tenant, q.Operation)
		if err != nil {
			return control.RegistryMaintenanceStatus{}, errorCode(err)
		}
		return status, "ok"
	})
)

func (c Client) PlanRegistryMaintenance(ctx context.Context, peer sfcp.Peer, session access.Session, tenant string, q control.RegistryMaintenanceQuery) (control.RegistryMaintenancePlan, error) {
	p, err := call(ctx, c, peer, session, RegistryMaintenancePlanMethod, RegistryMaintenancePlanQuery{Tenant: tenant, Query: q})
	if err != nil {
		return control.RegistryMaintenancePlan{}, err
	}
	if p.Schema != 1 || p.Cluster != c.Cluster || p.Tenant != tenant || p.Action != q.Action || p.Expected == 0 || p.Expected != p.Change.ExpectedRevision() || p.Epoch == 0 || p.Change.Query(q.Action) != q || p.Change.Operation != "" {
		return control.RegistryMaintenancePlan{}, sfcp.ErrFrame
	}
	change := p.Change
	change.Operation = "validation"
	if !change.Valid(c.Cluster, p.Action) {
		return control.RegistryMaintenancePlan{}, sfcp.ErrFrame
	}
	return p, nil
}

func (c Client) RegistryMaintenanceStatus(ctx context.Context, peer sfcp.Peer, session access.Session, tenant, operation string) (control.RegistryMaintenanceStatus, error) {
	s, err := call(ctx, c, peer, session, RegistryMaintenanceStatusMethod, RegistryMaintenanceStatusQuery{Tenant: tenant, Operation: operation})
	if err == nil && !c.validMaintenanceStatus(tenant, operation, s) {
		return control.RegistryMaintenanceStatus{}, sfcp.ErrFrame
	}
	return s, err
}

// validMaintenanceStatus keeps an unknown or running operation separate from
// a terminal result, and the result tied to the original change.
func (c Client) validMaintenanceStatus(tenant, operation string, s control.RegistryMaintenanceStatus) bool {
	if s.Schema != 1 || s.Tenant != tenant || s.Operation != operation || s.Revision == 0 || s.At == 0 || s.Change.Tenant != tenant || s.Change.Operation != s.Operation || !s.Change.Valid(c.Cluster, s.Action) {
		return false
	}
	switch s.State {
	case "queued", "running", "unknown":
		return s.Result == nil
	case "done", "failed":
		return s.Result != nil && control.RegistryMaintenanceResultFor(s.Change, *s.Result) && (s.State == "done") == (s.Result.Code == "OK" || s.Result.Code == "ALREADY_ABSENT")
	}
	return false
}
