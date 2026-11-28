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

// TenantPageQuery selects one page of a tenant's list.
type TenantPageQuery struct {
	Tenant string
	After  string `json:",omitempty"`
}

func (q TenantPageQuery) Valid() bool { return lifecycle.ValidID(q.Tenant) && len(q.After) <= 512 }

// mayAny says whether session holds any of actions on tenant now.
func (s Service) mayAny(view cluster.View, session access.Session, tenant string, actions ...access.Action) bool {
	c, err := s.Policy.Catalog(view.State)
	if err != nil || tenant == "" {
		return false
	}
	now := time.Now().Unix()
	for _, action := range actions {
		if c.AuthorizeSession(session, s.Policy.Cluster, s.Policy.Issuer(session.Issuer), now, tenant, action, "") == nil {
			return true
		}
	}
	return false
}

// errorCode maps a policy error to a reply code: denied, conflict or
// unavailable.
func errorCode(err error) string {
	switch {
	case errors.Is(err, access.ErrDenied) || errors.Is(err, access.ErrInvalid):
		return "denied"
	case errors.Is(err, access.ErrConflict):
		return "conflict"
	}
	return "unavailable"
}

// RegistryPullsMethod pages the tenant's recent external image pulls as
// servers reported them. Reports can involve a node read, so the session's
// tenant authority is checked again on a fresh view after it.
var RegistryPullsMethod = define(Method[TenantPageQuery, control.RegistryPullPage]{Name: "external-registry-pulls"}, true, func(ctx context.Context, s Service, view cluster.View, session access.Session, q TenantPageQuery) (control.RegistryPullPage, string) {
	if !s.mayAny(view, session, q.Tenant, access.Read, access.ManageRegistry) {
		return control.RegistryPullPage{}, "denied"
	}
	if s.NodeObservations == nil {
		return control.RegistryPullPage{}, "unavailable"
	}
	reports, _, err := s.NodeObservations(ctx, view)
	if err != nil {
		return control.RegistryPullPage{}, "unavailable"
	}
	latest, err := s.Engine.Read(ctx, true)
	if err != nil || latest.Local {
		return control.RegistryPullPage{}, "unavailable"
	}
	page, err := s.Policy.RegistryPulls(latest.State, session, time.Now().Unix(), q.Tenant, q.After, reports)
	if err != nil {
		return control.RegistryPullPage{}, errorCode(err)
	}
	return page, "ok"
})

func (c Client) RegistryPulls(ctx context.Context, peer sfcp.Peer, session access.Session, tenant, after string) (control.RegistryPullPage, error) {
	page, err := call(ctx, c, peer, session, RegistryPullsMethod, TenantPageQuery{Tenant: tenant, After: after})
	if err == nil && !page.Valid(tenant, after) {
		return control.RegistryPullPage{}, sfcp.ErrFrame
	}
	return page, err
}
