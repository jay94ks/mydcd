// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"time"

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

// HostRequestsQuery reads the route hosts under cluster-level domains: of one
// tenant (its read, deploy or routes users), or of every tenant when Tenant
// is empty (system administrators).
type HostRequestsQuery struct {
	Tenant string `json:",omitempty"`
}

func (q HostRequestsQuery) Valid() bool { return q.Tenant == "" || lifecycle.ValidID(q.Tenant) }

// HostRequestsReply lists them at the certificate store revision, which the
// approve/deny/revoke changes compare against.
type HostRequestsReply struct {
	Revision     uint64
	Requests     []control.HostRequest `json:",omitempty"`
	RootRevision uint64
}

var HostRequestsMethod = define(Method[HostRequestsQuery, HostRequestsReply]{Name: "ingress-host-requests"}, true, func(_ context.Context, s Service, view cluster.View, session access.Session, q HostRequestsQuery) (HostRequestsReply, string) {
	if q.Tenant == "" {
		if s.Policy.CertificateAllowed(view.State, session, time.Now().Unix(), "certificates") != nil {
			return HostRequestsReply{}, "denied"
		}
	} else if !s.mayAny(view, session, q.Tenant, access.Read, access.Deploy, access.ManageRoutes) {
		return HostRequestsReply{}, "denied"
	}
	rows, revision, err := s.Policy.HostRequests(view.State, q.Tenant)
	if err != nil {
		return HostRequestsReply{}, "unavailable"
	}
	return HostRequestsReply{Revision: revision, Requests: rows, RootRevision: view.State.Object(control.CertificatesKey).Revision}, "ok"
})

func (c Client) QueryHostRequests(ctx context.Context, target sfcp.Peer, session access.Session, tenant string) (HostRequestsReply, error) {
	return call(ctx, c, target, session, HostRequestsMethod, HostRequestsQuery{Tenant: tenant})
}

// TenantCertificatesReply lists the public facts of certificates linked to
// one tenant's hosts.
type TenantCertificatesReply struct {
	Revision     uint64
	Certificates []control.TenantCertificate `json:",omitempty"`
	RootRevision uint64
}

// TenantCertificatesMethod: a tenant user (read, deploy or routes) reads the
// certificates serving its own domains and approved hosts. Uploads, ACME and
// keys stay system-admin only.
var TenantCertificatesMethod = define(Method[TenantDomainsQuery, TenantCertificatesReply]{Name: "tenant-certificates"}, true, func(_ context.Context, s Service, view cluster.View, session access.Session, q TenantDomainsQuery) (TenantCertificatesReply, string) {
	if !s.mayAny(view, session, q.Tenant, access.Read, access.Deploy, access.ManageRoutes) {
		return TenantCertificatesReply{}, "denied"
	}
	rows, revision, err := s.Policy.TenantCertificates(view.State, q.Tenant, time.Now().Unix())
	if err != nil {
		return TenantCertificatesReply{}, "unavailable"
	}
	return TenantCertificatesReply{Revision: revision, Certificates: rows, RootRevision: view.State.Object(control.CertificatesKey).Revision}, "ok"
})

func (c Client) QueryTenantCertificates(ctx context.Context, target sfcp.Peer, session access.Session, tenant string) (TenantCertificatesReply, error) {
	return call(ctx, c, target, session, TenantCertificatesMethod, TenantDomainsQuery{Tenant: tenant})
}
