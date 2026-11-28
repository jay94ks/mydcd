// SPDX-License-Identifier: Apache-2.0

package control

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/certstore"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/ingress"
)

// Route host states of a tenant app (devel/design/tenant-domains.md).
const (
	HostOpen    = "open"    // under the tenant's own domain, or approved
	HostPending = "pending" // under a cluster-level domain, waiting
	HostDenied  = "denied"  // under a cluster-level domain, denied
)

// hostJudgment says how tenant may use route host: a state, or a refusal
// code (INGRESS_DOMAIN_UNKNOWN, INGRESS_DOMAIN_OTHER_TENANT). "*" is judged
// elsewhere (system administrators only) and is open here.
func hostJudgment(c certstore.Catalog, users access.Catalog, tenant, host string) (string, string) {
	if host == "*" {
		return HostOpen, ""
	}
	d, ok := c.DomainOwner(host)
	if !ok {
		return "", "INGRESS_DOMAIN_UNKNOWN"
	}
	switch owner := DomainTenant(users, d); owner {
	case tenant:
		return HostOpen, ""
	case "":
	default:
		return "", "INGRESS_DOMAIN_OTHER_TENANT"
	}
	if !grantTenantLive(users, tenant) {
		return HostPending, ""
	}
	// An approved pattern ("*.shop.example") also opens names under it.
	for _, g := range c.Grants {
		if g.Tenant == tenant && g.State == certstore.GrantApproved && certstore.HostWithin(host, g.Host) {
			return HostOpen, ""
		}
	}
	if g, ok := c.Grant(tenant, host); ok && g.State == certstore.GrantDenied {
		return HostDenied, ""
	}
	return HostPending, ""
}

// TenantHostPolicy is the host list ingress serves for tenant: each domain
// the tenant owns (the name and every name under it) and each host approved
// to it. Any gateway kind; only the hosts decide.
func TenantHostPolicy(c certstore.Catalog, users access.Catalog, tenant string) ingress.HostPolicy {
	var hosts []string
	for _, d := range c.Domains {
		if DomainTenant(users, d) != tenant || tenant == "" {
			continue
		}
		hosts = append(hosts, d.Name)
		if _, err := netip.ParseAddr(d.Name); err != nil {
			hosts = append(hosts, "*."+d.Name)
		}
	}
	if grantTenantLive(users, tenant) {
		for _, g := range c.Grants {
			if g.Tenant == tenant && g.State == certstore.GrantApproved {
				hosts = append(hosts, g.Host)
			}
		}
	}
	slices.Sort(hosts)
	hosts = slices.Compact(hosts)
	return ingress.HostPolicy{ExternalAllowed: true, ExternalHosts: hosts, LocalHosts: slices.Clone(hosts)}
}

// grantTenantLive: a deleted tenant's decisions no longer count.
func grantTenantLive(users access.Catalog, tenant string) bool {
	t, ok := users.Tenant(tenant)
	return ok && t.Phase != access.TenantDeleted
}

// admitTenantIngressHosts judges every route host of d for tenant: a host
// under no registered domain, or under another tenant's domain, is refused
// even with --force; a host under a cluster-level domain is accepted and
// waits for a system administrator unless already decided. Waiting hosts of
// one tenant (all its apps) are bounded by MaxTenantHostRequests.
func (p Policy) admitTenantIngressHosts(s state.State, tenant string, d deployment.IngressDeclaration, others []ingressRouteUse) error {
	if tenant == "" || tenant == deployment.ClusterAppTenant {
		return nil
	}
	c, err := p.Certificates(s)
	if err != nil {
		return err
	}
	users, err := p.Catalog(s)
	if err != nil {
		return err
	}
	waiting := map[string]bool{}
	judge := func(host string) error {
		st, code := hostJudgment(c, users, tenant, host)
		if code != "" {
			return &deployment.InputError{Code: code, Path: "x-sfc.ingress." + host}
		}
		if st == HostPending {
			waiting[host] = true
		}
		return nil
	}
	for _, mine := range ingressRouteUsesOf(tenant, "", d.Node, d) {
		if err := judge(mine.Host); err != nil {
			return err
		}
	}
	if len(waiting) == 0 {
		return nil
	}
	for _, o := range others {
		if o.Tenant == tenant {
			if st, code := hostJudgment(c, users, tenant, o.Host); code == "" && st == HostPending {
				waiting[o.Host] = true
			}
		}
	}
	if len(waiting) > certstore.MaxTenantHostRequests {
		return &deployment.InputError{Code: "INGRESS_HOST_REQUESTS_LIMIT", Path: "x-sfc.ingress"}
	}
	return nil
}

// HostRequest is one tenant route host under a cluster-level domain: waiting,
// approved or denied, with the apps that route it now.
type HostRequest struct {
	Tenant, Host string
	State        string
	Apps         []string `json:",omitempty"`
	DecidedBy    string   `json:",omitempty"`
	DecidedAt    int64    `json:",omitempty"`
}

// HostRequests lists the route hosts of tenant (every tenant when empty)
// under cluster-level domains: each one a route uses, and each recorded
// decision even when no route uses it any more. Sorted by tenant, host.
func (p Policy) HostRequests(s state.State, tenant string) ([]HostRequest, uint64, error) {
	c, err := p.Certificates(s)
	if err != nil {
		return nil, 0, err
	}
	users, err := p.Catalog(s)
	if err != nil {
		return nil, 0, err
	}
	uses, err := p.ingressRouteUses(s)
	if err != nil {
		return nil, 0, err
	}
	rows := map[string]*HostRequest{}
	key := func(t, h string) string { return t + "\x00" + h }
	for _, u := range uses {
		if u.Tenant == deployment.ClusterAppTenant || tenant != "" && u.Tenant != tenant {
			continue
		}
		st, code := hostJudgment(c, users, u.Tenant, u.Host)
		if code != "" || u.Host == "*" {
			continue
		}
		if d, _ := c.DomainOwner(u.Host); DomainTenant(users, d) != "" {
			continue // the tenant's own domain: open, no request
		}
		r := rows[key(u.Tenant, u.Host)]
		if r == nil {
			r = &HostRequest{Tenant: u.Tenant, Host: u.Host, State: st}
			rows[key(u.Tenant, u.Host)] = r
		}
		if !slices.Contains(r.Apps, u.App) {
			r.Apps = append(r.Apps, u.App)
		}
	}
	for _, g := range c.Grants {
		if tenant != "" && g.Tenant != tenant || !grantTenantLive(users, g.Tenant) {
			continue
		}
		r := rows[key(g.Tenant, g.Host)]
		if r == nil {
			st := HostOpen
			if g.State == certstore.GrantDenied {
				st = HostDenied
			}
			r = &HostRequest{Tenant: g.Tenant, Host: g.Host, State: st}
			rows[key(g.Tenant, g.Host)] = r
		}
		r.DecidedBy, r.DecidedAt = g.DecidedBy, g.DecidedAt
	}
	out := make([]HostRequest, 0, len(rows))
	for _, r := range rows {
		slices.Sort(r.Apps)
		out = append(out, *r)
	}
	slices.SortFunc(out, func(a, b HostRequest) int { return strings.Compare(key(a.Tenant, a.Host), key(b.Tenant, b.Host)) })
	return out, c.Revision, nil
}

// HostDecision is the payload of approve-ingress-host, deny-ingress-host and
// revoke-ingress-host. Host is a canonical route host (NormalizeRouteHost).
type HostDecision struct{ Tenant, Host string }

// decideHostAllowed checks an approval or denial target: a live tenant's
// route host under a cluster-level domain. An approval must not overlap a
// tenant domain or a cluster app route host.
func (p Policy) decideHostAllowed(s state.State, c certstore.Catalog, users access.Catalog, q HostDecision, approve bool) bool {
	if !grantTenantLive(users, q.Tenant) {
		return false
	}
	d, ok := c.DomainOwner(q.Host)
	if !ok || DomainTenant(users, d) != "" {
		return false
	}
	if !approve {
		return true
	}
	for _, other := range c.Domains {
		if DomainTenant(users, other) != "" && certstore.HostWithin(other.Name, q.Host) {
			return false
		}
	}
	book, err := p.IngressManagement(s)
	if err != nil {
		return false
	}
	for _, r := range book.ClusterAppRoutes {
		if r.Removed {
			continue
		}
		for _, claim := range ingressClaims(r.Ingress) {
			if certstore.HostsOverlap(claim.Host, q.Host) {
				return false
			}
		}
	}
	return true
}

// domainInUseElsewhere reports whether giving name to tenant would take
// hosts another owner uses now: another tenant's app route host or host
// decision under name, or a cluster app route host under name. Giving a
// domain to cluster level is never refused here (tenant hosts under it then
// wait for approval).
func (p Policy) domainInUseElsewhere(s state.State, c certstore.Catalog, name, tenant string) (bool, error) {
	if tenant == "" {
		return false, nil
	}
	uses, err := p.ingressRouteUses(s)
	if err != nil {
		return false, err
	}
	for _, u := range uses {
		if u.Tenant != tenant && u.Host != "*" && certstore.HostWithin(u.Host, name) {
			return true, nil
		}
	}
	for _, g := range c.Grants {
		if g.Tenant != tenant && certstore.HostWithin(g.Host, name) {
			return true, nil
		}
	}
	book, err := p.IngressManagement(s)
	if err != nil {
		return false, err
	}
	for _, r := range book.ClusterAppRoutes {
		if r.Removed {
			continue
		}
		for _, claim := range ingressClaims(r.Ingress) {
			if certstore.HostWithin(claim.Host, name) {
				return true, nil
			}
		}
	}
	return false, nil
}

// clusterAppHostsOnClusterDomains: a cluster app (sfc-web) routes only
// hosts under cluster-level domains that no tenant holds an approval
// overlapping. "*" stays allowed (system administrators set these routes).
func (p Policy) clusterAppHostsOnClusterDomains(s state.State, d deployment.IngressDeclaration) bool {
	c, err := p.Certificates(s)
	if err != nil {
		return false
	}
	users, err := p.Catalog(s)
	if err != nil {
		return false
	}
	for _, claim := range ingressClaims(d) {
		if claim.Host == "*" {
			continue
		}
		owner, ok := c.DomainOwner(claim.Host)
		if !ok || DomainTenant(users, owner) != "" {
			return false
		}
		for _, g := range c.Grants {
			if g.State == certstore.GrantApproved && grantTenantLive(users, g.Tenant) && certstore.HostsOverlap(g.Host, claim.Host) {
				return false
			}
		}
	}
	return true
}

// TenantCertificate is what a tenant user sees of a stored certificate
// linked to one of its hosts: names, expiry and link state, never the
// chain, the key or other tenants' names on the same certificate.
type TenantCertificate struct {
	ID                  certstore.ID
	Hosts               []string
	Algorithm, Issuer   string
	NotBefore, NotAfter int64
	State               string
	Links               []certstore.Link `json:",omitempty"`
}

// tenantServes reports whether host is in tenant's host list (its domains
// and approved hosts, TenantHostPolicy).
func tenantServes(hosts []string, host string) bool {
	for _, pattern := range hosts {
		if host == pattern || strings.HasPrefix(pattern, "*.") && strings.HasSuffix(host, pattern[1:]) {
			return true
		}
	}
	return false
}

// TenantCertificates lists the certificates linked to tenant's hosts, each
// with only those links and names, in ID order (devel/design/tenant-domains.md).
func (p Policy) TenantCertificates(s state.State, tenant string, at int64) ([]TenantCertificate, uint64, error) {
	c, err := p.Certificates(s)
	if err != nil {
		return nil, 0, err
	}
	users, err := p.Catalog(s)
	if err != nil {
		return nil, 0, err
	}
	hosts := TenantHostPolicy(c, users, tenant).LocalHosts
	var out []TenantCertificate
	for _, row := range c.Public(at) {
		v := TenantCertificate{ID: row.Metadata.ID, Algorithm: row.Metadata.Algorithm, Issuer: row.Metadata.Issuer, NotBefore: row.Metadata.NotBefore, NotAfter: row.Metadata.NotAfter, State: row.State}
		for _, l := range row.Links {
			if tenantServes(hosts, l.Host) {
				v.Links = append(v.Links, l)
			}
		}
		if len(v.Links) == 0 {
			continue
		}
		for _, h := range row.Metadata.Hosts {
			if tenantServes(hosts, h) || slices.ContainsFunc(v.Links, func(l certstore.Link) bool { return certstore.MatchHost(h, l.Host) > 0 }) {
				v.Hosts = append(v.Hosts, h)
			}
		}
		out = append(out, v)
	}
	return out, c.Revision, nil
}
