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

func (s Service) registryActionPlan(view cluster.View, request Request, session access.Session) Reply {
	plan, err := s.Policy.PlanRegistryAction(view.State, session, time.Now().Unix(), request.Tenant, *request.RegistryAction)
	if err == nil {
		return Reply{Schema: 1, Code: "ok", RegistryActionPlan: &plan}
	}
	if errors.Is(err, access.ErrDenied) {
		return Reply{Schema: 1, Code: "denied"}
	}
	if errors.Is(err, access.ErrConflict) {
		return Reply{Schema: 1, Code: "conflict"}
	}
	return Reply{Schema: 1, Code: "unavailable"}
}

func (c Client) PlanRegistryAction(ctx context.Context, peer sfcp.Peer, session access.Session, tenant string, query control.RegistryActionQuery) (control.RegistryActionPlan, error) {
	var out control.RegistryActionPlan
	if !query.Valid() || tenant == "" {
		return out, sfcp.ErrAdmission
	}
	reply, err := c.query(ctx, peer, session, Request{Method: "registry-action-plan", Tenant: tenant, RegistryAction: &query})
	if err != nil {
		return out, err
	}
	plan := reply.RegistryActionPlan
	if plan == nil || plan.Schema != 1 || plan.Cluster != c.Cluster || plan.Tenant != tenant || plan.ID != query.ID || plan.Action != query.Action || plan.Expected == 0 || plan.RootRevision == 0 || plan.Epoch == 0 || plan.Current.Deleted || plan.Current.Revision != plan.Expected || plan.Current.Spec.Tenant != tenant || plan.Current.Spec.ID != query.ID || plan.Current.Spec.Validate(c.Cluster) != nil || !plan.DataPreserved || plan.WouldEnable != (query.Action == "start-registry") {
		return out, sfcp.ErrFrame
	}
	return *plan, nil
}
