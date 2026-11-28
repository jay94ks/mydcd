// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/certstore"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// TenantDomainsQuery reads the domains one tenant owns.
type TenantDomainsQuery struct{ Tenant string }

func (q TenantDomainsQuery) Valid() bool { return lifecycle.ValidID(q.Tenant) }

// TenantDomainsReply is the reply of tenant-domains: the domains the tenant
// owns now (control.DomainTenant) at the certificate store revision.
type TenantDomainsReply struct {
	Revision     uint64
	Domains      []certstore.Domain `json:",omitempty"`
	RootRevision uint64
}

// TenantDomainsMethod lets a tenant user (read, deploy or routes on that
// tenant) see its own domains; the whole list stays system-admin only
// (certificates). devel/design/tenant-domains.md.
var TenantDomainsMethod = define(Method[TenantDomainsQuery, TenantDomainsReply]{Name: "tenant-domains"}, true, func(_ context.Context, s Service, view cluster.View, session access.Session, q TenantDomainsQuery) (TenantDomainsReply, string) {
	if !s.mayAny(view, session, q.Tenant, access.Read, access.Deploy, access.ManageRoutes) {
		return TenantDomainsReply{}, "denied"
	}
	users, err := s.Policy.Catalog(view.State)
	if err != nil {
		return TenantDomainsReply{}, "unavailable"
	}
	c, err := s.Policy.Certificates(view.State)
	if err != nil {
		return TenantDomainsReply{}, "unavailable"
	}
	out := TenantDomainsReply{Revision: c.Revision, RootRevision: view.State.Object(control.CertificatesKey).Revision}
	for _, d := range c.TenantDomains(q.Tenant) {
		if control.DomainTenant(users, d) == q.Tenant {
			out.Domains = append(out.Domains, d)
		}
	}
	return out, "ok"
})

func (c Client) QueryTenantDomains(ctx context.Context, target sfcp.Peer, session access.Session, tenant string) (TenantDomainsReply, error) {
	return call(ctx, c, target, session, TenantDomainsMethod, TenantDomainsQuery{Tenant: tenant})
}
