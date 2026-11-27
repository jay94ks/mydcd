// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"errors"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/sfcp"
)

func (s Service) registryMaintenanceQuery(view cluster.View, q Request, session access.Session) Reply {
	out := Reply{Schema: 1, Code: "unavailable"}
	var err error
	if q.Method == "registry-maintenance-plan" {
		var plan control.RegistryMaintenancePlan
		plan, err = s.Policy.PlanRegistryMaintenance(view.State, session, time.Now().Unix(), q.Tenant, *q.RegistryMaintenance)
		if err == nil {
			out.Code = "ok"
			out.RegistryMaintenancePlan = &plan
		}
	} else {
		var status control.RegistryMaintenanceStatus
		status, err = s.Policy.RegistryMaintenanceStatus(view.State, session, time.Now().Unix(), q.Tenant, q.RegistryMaintenance.Operation)
		if err == nil {
			out.Code = "ok"
			out.RegistryMaintenanceStatus = &status
		}
	}
	if errors.Is(err, access.ErrDenied) || errors.Is(err, access.ErrInvalid) {
		out.Code = "denied"
	}
	if errors.Is(err, access.ErrConflict) {
		out.Code = "conflict"
	}
	if out.Code == "ok" {
		out.Tenant = q.Tenant
	}
	return out
}
func (c Client) RegistryMaintenance(ctx context.Context, peer sfcp.Peer, session access.Session, tenant string, plan bool, q control.RegistryMaintenanceQuery) (Reply, error) {
	if tenant == "" || !q.Valid(plan) || q.Action == control.RegistryPruneAction {
		return Reply{}, sfcp.ErrAdmission
	}
	method := "registry-maintenance-status"
	if plan {
		method = "registry-maintenance-plan"
	}
	reply, err := c.query(ctx, peer, session, Request{Method: method, Tenant: tenant, RegistryMaintenance: &q})
	if err != nil {
		return reply, err
	}
	if err = c.validateRegistryMaintenanceReply(reply, tenant, plan, q); err != nil {
		return Reply{}, err
	}
	return reply, nil
}

func (c Client) validateRegistryMaintenanceReply(reply Reply, tenant string, plan bool, q control.RegistryMaintenanceQuery) error {
	if reply.Tenant != tenant {
		return sfcp.ErrFrame
	}
	if plan {
		p := reply.RegistryMaintenancePlan
		if p == nil || reply.RegistryMaintenanceStatus != nil || p.Schema != 1 || p.Cluster != c.Cluster || p.Tenant != tenant || p.Action != q.Action || p.Expected == 0 || p.Expected != p.Change.ExpectedRevision() || p.Epoch == 0 || p.Change.Query(q.Action) != q || p.Change.Operation != "" {
			return sfcp.ErrFrame
		}
		change := p.Change
		change.Operation = "validation"
		if !change.Valid(c.Cluster, p.Action) {
			return sfcp.ErrFrame
		}
	} else {
		s := reply.RegistryMaintenanceStatus
		if s == nil || reply.RegistryMaintenancePlan != nil || s.Schema != 1 || s.Tenant != tenant || s.Operation != q.Operation || s.Revision == 0 || s.At == 0 || s.Change.Tenant != tenant || s.Change.Operation != s.Operation || !s.Change.Valid(c.Cluster, s.Action) {
			return sfcp.ErrFrame
		}
		if s.State == "queued" || s.State == "running" || s.State == "unknown" {
			if s.Result != nil {
				return sfcp.ErrFrame
			}
		} else if s.State == "done" || s.State == "failed" {
			if s.Result == nil || !control.RegistryMaintenanceResultFor(s.Change, *s.Result) || (s.State == "done") != (s.Result.Code == "OK" || s.Result.Code == "ALREADY_ABSENT") {
				return sfcp.ErrFrame
			}
		} else {
			return sfcp.ErrFrame
		}
	}
	return nil
}
