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

// ExternalRegistryBindQuery asks for the change that binds an external
// source to the server that reads it.
type ExternalRegistryBindQuery struct {
	Tenant string
	Query  control.ExternalRegistryBindQuery
}

func (q ExternalRegistryBindQuery) Valid() bool {
	return lifecycle.ValidID(q.Tenant) && q.Query.Valid()
}

// ExternalRegistryBindPlanMethod: the policy planner authorizes the bind.
var ExternalRegistryBindPlanMethod = define(Method[ExternalRegistryBindQuery, control.ExternalRegistryBindPlan]{Name: "external-registry-bind-plan"}, true, func(_ context.Context, s Service, view cluster.View, session access.Session, q ExternalRegistryBindQuery) (control.ExternalRegistryBindPlan, string) {
	plan, err := s.Policy.PlanExternalRegistryBind(view.State, session, time.Now().Unix(), q.Tenant, q.Query.ID, q.Query.Node)
	if err != nil {
		return control.ExternalRegistryBindPlan{}, "denied"
	}
	return plan, "ok"
})

func (c Client) PlanExternalRegistryBind(ctx context.Context, peer sfcp.Peer, session access.Session, tenant string, q control.ExternalRegistryBindQuery) (control.ExternalRegistryBindPlan, error) {
	plan, err := call(ctx, c, peer, session, ExternalRegistryBindPlanMethod, ExternalRegistryBindQuery{Tenant: tenant, Query: q})
	if err == nil && (plan.Cluster != c.Cluster || !plan.Valid(session, tenant, q)) {
		return control.ExternalRegistryBindPlan{}, sfcp.ErrFrame
	}
	return plan, err
}
