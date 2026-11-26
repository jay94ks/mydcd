// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

func (s Service) externalRegistryBindPlan(view cluster.View, q Request, session access.Session) Reply {
	plan, err := s.Policy.PlanExternalRegistryBind(view.State, session, time.Now().Unix(), q.Tenant, q.ExternalRegistryBind.ID, q.ExternalRegistryBind.Node)
	if err != nil {
		return Reply{Schema: 1, Code: "denied"}
	}
	return Reply{Schema: 1, Code: "ok", Tenant: q.Tenant, ExternalRegistryBindPlan: &plan}
}
func (c Client) PlanExternalRegistryBind(ctx context.Context, peer mydcp.Peer, session access.Session, tenant string, q control.ExternalRegistryBindQuery) (control.ExternalRegistryBindPlan, error) {
	if !q.Valid() || tenant == "" {
		return control.ExternalRegistryBindPlan{}, mydcp.ErrAdmission
	}
	reply, err := c.query(ctx, peer, session, Request{Method: "external-registry-bind-plan", Tenant: tenant, ExternalRegistryBind: &q})
	if err != nil {
		return control.ExternalRegistryBindPlan{}, err
	}
	plan := reply.ExternalRegistryBindPlan
	if plan == nil || plan.Cluster != c.Cluster || !plan.Valid(session, tenant, q) {
		return control.ExternalRegistryBindPlan{}, mydcp.ErrFrame
	}
	return *plan, nil
}
