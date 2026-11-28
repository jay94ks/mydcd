// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"errors"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// RegistryActionQuery asks for the change starting, stopping or deleting one
// registry would submit.
type RegistryActionQuery struct {
	Tenant string
	Query  control.RegistryActionQuery
}

func (q RegistryActionQuery) Valid() bool { return lifecycle.ValidID(q.Tenant) && q.Query.Valid() }

// RegistryActionPlanMethod: the policy planner authorizes the action.
var RegistryActionPlanMethod = define(Method[RegistryActionQuery, control.RegistryActionPlan]{Name: "registry-action-plan"}, true, func(_ context.Context, s Service, view cluster.View, session access.Session, q RegistryActionQuery) (control.RegistryActionPlan, string) {
	plan, err := s.Policy.PlanRegistryAction(view.State, session, time.Now().Unix(), q.Tenant, q.Query)
	switch {
	case err == nil:
		return plan, "ok"
	case errors.Is(err, access.ErrDenied):
		return control.RegistryActionPlan{}, "denied"
	case errors.Is(err, access.ErrConflict):
		return control.RegistryActionPlan{}, "conflict"
	}
	return control.RegistryActionPlan{}, "unavailable"
})

func (c Client) PlanRegistryAction(ctx context.Context, peer sfcp.Peer, session access.Session, tenant string, query control.RegistryActionQuery) (control.RegistryActionPlan, error) {
	plan, err := call(ctx, c, peer, session, RegistryActionPlanMethod, RegistryActionQuery{Tenant: tenant, Query: query})
	if err != nil {
		return control.RegistryActionPlan{}, err
	}
	if plan.Schema != 1 || plan.Cluster != c.Cluster || plan.Tenant != tenant || plan.ID != query.ID || plan.Action != query.Action || plan.Expected == 0 || plan.RootRevision == 0 || plan.Epoch == 0 || plan.Current.Deleted || plan.Current.Revision != plan.Expected || plan.Current.Spec.Tenant != tenant || plan.Current.Spec.ID != query.ID || plan.Current.Spec.Validate(c.Cluster) != nil || !plan.DataPreserved || plan.WouldEnable != (query.Action == "start-registry") {
		return control.RegistryActionPlan{}, sfcp.ErrFrame
	}
	return plan, nil
}
