// SPDX-License-Identifier: Apache-2.0

package certstore

import (
	"math"
	"net/netip"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
)

// MaxHostGrants bounds the recorded host decisions of the whole cluster;
// MaxTenantHostRequests bounds one tenant's waiting route hosts.
const (
	MaxHostGrants         = 1024
	MaxTenantHostRequests = 64
)

// Host grant states. A waiting request has no record: it is a tenant route
// host under a cluster-level domain with no decision yet.
const (
	GrantApproved = "approved"
	GrantDenied   = "denied"
)

// HostGrant is a system administrator's decision on one tenant route host
// under a cluster-level domain (devel/design/tenant-domains.md). It lives in
// the certificate store so domain owners and decisions change under one
// revision.
type HostGrant struct {
	Tenant, Host string
	State        string
	DecidedBy    string
	DecidedAt    int64
}

// NormalizeRouteHost returns the canonical form of a route host: a domain
// name (A-label, lower case), optionally prefixed by "*.", or an IP address.
func NormalizeRouteHost(host string) (string, bool) {
	wild := strings.HasPrefix(host, "*.")
	n, ok := NormalizeDomain(strings.TrimPrefix(host, "*."))
	if !ok {
		return "", false
	}
	if wild {
		if _, err := netip.ParseAddr(n); err == nil {
			return "", false
		}
		return "*." + n, true
	}
	return n, true
}

// HostsOverlap reports whether one host pattern equals or lies under the
// other ("*.a.example" lies under "a.example").
func HostsOverlap(a, b string) bool {
	return HostWithin(a, b) || HostWithin(b, a)
}

// HostWithin reports whether host is outer or a name below it.
func HostWithin(host, outer string) bool {
	h, o := strings.TrimPrefix(host, "*."), strings.TrimPrefix(outer, "*.")
	if h == o {
		return !strings.HasPrefix(outer, "*.") || strings.HasPrefix(host, "*.")
	}
	return strings.HasSuffix(h, "."+o)
}

func grantKey(a HostGrant) string { return a.Tenant + "\x00" + a.Host }

func (c Catalog) validateGrants() error {
	if len(c.Grants) > MaxHostGrants {
		return ErrCertificate
	}
	last := ""
	for _, g := range c.Grants {
		n, ok := NormalizeRouteHost(g.Host)
		if !ok || n != g.Host || !lifecycle.ValidID(g.Tenant) || grantKey(g) <= last || g.State != GrantApproved && g.State != GrantDenied || g.DecidedBy == "" || len(g.DecidedBy) > 128 || g.DecidedAt <= 0 {
			return ErrCertificate
		}
		last = grantKey(g)
	}
	// One host is approved to one tenant only.
	for _, a := range c.Grants {
		for _, b := range c.Grants {
			if a.State == GrantApproved && b.State == GrantApproved && a.Tenant != b.Tenant && HostsOverlap(a.Host, b.Host) {
				return ErrCertificate
			}
		}
	}
	return nil
}

// Grant returns the decision recorded for tenant's host.
func (c Catalog) Grant(tenant, host string) (HostGrant, bool) {
	i := slices.IndexFunc(c.Grants, func(g HostGrant) bool { return g.Tenant == tenant && g.Host == host })
	if i < 0 {
		return HostGrant{}, false
	}
	return c.Grants[i], true
}

// ApprovedElsewhere reports whether host overlaps a host approved to a
// tenant other than tenant.
func (c Catalog) ApprovedElsewhere(tenant, host string) bool {
	return slices.ContainsFunc(c.Grants, func(g HostGrant) bool {
		return g.State == GrantApproved && g.Tenant != tenant && HostsOverlap(g.Host, host)
	})
}

// DecideHost records an approval or a denial of tenant's host, replacing an
// earlier decision. The caller checks the host is a waiting request under a
// cluster-level domain; an approval overlapping another tenant's approval is
// refused here.
func (c Catalog) DecideHost(tenant, host, decision, user string, expected uint64, at int64) (Catalog, error) {
	if c.Validate() != nil || expected != c.Revision || c.Revision == math.MaxUint64 || at <= 0 || user == "" || len(user) > 128 || decision != GrantApproved && decision != GrantDenied {
		return c, ErrConflict
	}
	if n, ok := NormalizeRouteHost(host); !ok || n != host || !lifecycle.ValidID(tenant) {
		return c, ErrCertificate
	}
	if decision == GrantApproved && c.ApprovedElsewhere(tenant, host) {
		return c, ErrConflict
	}
	next := c.Own()
	g := HostGrant{Tenant: tenant, Host: host, State: decision, DecidedBy: user, DecidedAt: at}
	if i := slices.IndexFunc(next.Grants, func(x HostGrant) bool { return grantKey(x) == grantKey(g) }); i >= 0 {
		if next.Grants[i].State == decision {
			return c, ErrConflict
		}
		next.Grants[i] = g
	} else {
		if len(next.Grants) >= MaxHostGrants {
			return c, ErrConflict
		}
		next.Grants = append(next.Grants, g)
		slices.SortFunc(next.Grants, func(a, b HostGrant) int { return strings.Compare(grantKey(a), grantKey(b)) })
	}
	next.Revision++
	return next, nil
}

// RevokeHost drops the decision on tenant's host: an approved host waits
// again, a denied one becomes a fresh request while a route still uses it.
func (c Catalog) RevokeHost(tenant, host string, expected uint64) (Catalog, error) {
	if c.Validate() != nil || expected != c.Revision || c.Revision == math.MaxUint64 {
		return c, ErrConflict
	}
	if _, ok := c.Grant(tenant, host); !ok {
		return c, ErrConflict
	}
	next := c.Own()
	next.Grants = slices.DeleteFunc(next.Grants, func(g HostGrant) bool { return g.Tenant == tenant && g.Host == host })
	if len(next.Grants) == 0 {
		next.Grants = nil
	}
	next.Revision++
	return next, nil
}
