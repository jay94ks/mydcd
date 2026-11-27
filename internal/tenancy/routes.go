// SPDX-License-Identifier: Apache-2.0

package tenancy

import (
	"crypto/ed25519"
	"encoding/json"
	"net/netip"
	"slices"

	"github.com/jay94ks/seafield/internal/access"
)

type Binding struct {
	Tenant, Network, Node string
	Owner                 [32]byte
	Generation, Revision  uint64
	Prefix                netip.Prefix
}
type Ports struct{ First, Last uint16 }
type RoutePhase string

const (
	Pending  RoutePhase = "pending"
	Active   RoutePhase = "active"
	Revoking RoutePhase = "revoking"
)

type Approval struct {
	Tenant, User   string
	PolicyRevision uint64
}
type Route struct {
	ID                   string
	Generation, Revision uint64
	Source, Destination  Binding
	Protocol             uint8
	Ports                []Ports
	Phase                RoutePhase
	Approvals            []Approval
	Closures             []RouteClosure
}

func ownRoute(r Route) Route {
	r.Ports = slices.Clone(r.Ports)
	r.Approvals = slices.Clone(r.Approvals)
	r.Closures = slices.Clone(r.Closures)
	for i := range r.Closures {
		r.Closures[i].Signature = slices.Clone(r.Closures[i].Signature)
	}
	return r
}
func (n Networks) Route(tenant, id string) (Route, bool) {
	r, ok := n.routes[key(tenant, id)]
	return ownRoute(r), ok
}

// AllRoutes is an owned FSM inventory, including the other side of a
// cross-tenant route. Authorization belongs at the external read boundary.
func (n Networks) AllRoutes() []Route {
	var out []Route
	for _, r := range n.routes {
		out = append(out, ownRoute(r))
	}
	slices.SortFunc(out, func(a, b Route) int {
		ak, bk := key(a.Source.Tenant, a.ID), key(b.Source.Tenant, b.ID)
		if ak < bk {
			return -1
		}
		if ak > bk {
			return 1
		}
		return 0
	})
	return out
}
func (n Networks) VisibleRoutes(c access.Catalog, actor string) []Route {
	var out []Route
	for _, r := range n.routes {
		if c.Authorize(actor, r.Source.Tenant, access.Read, "") == nil || c.Authorize(actor, r.Destination.Tenant, access.Read, "") == nil {
			out = append(out, ownRoute(r))
		}
	}
	slices.SortFunc(out, func(a, b Route) int {
		ak, bk := key(a.Source.Tenant, a.ID), key(b.Source.Tenant, b.ID)
		if ak < bk {
			return -1
		}
		if ak > bk {
			return 1
		}
		return 0
	})
	return out
}
func (n Networks) Bind(tenant, id string, prefix netip.Prefix) (Binding, error) {
	v, ok := n.networks[key(tenant, id)]
	if !ok || v.Draining {
		return Binding{}, ErrPolicy
	}
	for _, p := range v.Pools {
		if p.Prefix == prefix {
			return Binding{v.Tenant, v.ID, v.Node, v.Owner, v.Generation, v.Revision, prefix}, nil
		}
	}
	return Binding{}, ErrPolicy
}
func (n Networks) current(b Binding) bool {
	now, err := n.Bind(b.Tenant, b.Network, b.Prefix)
	return err == nil && now == b
}

// A reserved network change closes new policy acceptance without invalidating
// the original stored route bindings needed for observation and retirement.
func (n Networks) freshRouteBinding(b Binding) bool {
	v, exists := n.networks[key(b.Tenant, b.Network)]
	return exists && v.PendingChange == 0 && n.current(b)
}
func validBinding(b Binding) bool {
	return validID(b.Tenant) && validID(b.Network) && validID(b.Node) && b.Owner != ([32]byte{}) && b.Generation > 0 && b.Revision >= b.Generation && b.Prefix.IsValid() && b.Prefix == b.Prefix.Masked() && !b.Prefix.Addr().Is4In6()
}
func validRoute(r Route) bool {
	if !validID(r.ID) || r.Generation == 0 || r.Revision < r.Generation || !validBinding(r.Source) || !validBinding(r.Destination) || r.Source.Tenant == r.Destination.Tenant || r.Source.Prefix.Addr().Is4() != r.Destination.Prefix.Addr().Is4() || r.Protocol != 6 && r.Protocol != 17 || len(r.Ports) == 0 || len(r.Ports) > 64 {
		return false
	}
	for i, p := range r.Ports {
		if p.First == 0 || p.Last < p.First || i > 0 && p.First <= r.Ports[i-1].Last {
			return false
		}
	}
	if r.Phase != Pending && r.Phase != Active && r.Phase != Revoking || len(r.Approvals) > 2 || len(r.Closures) > 1 || r.Phase == Active && len(r.Approvals) != 2 || r.Phase == Pending && len(r.Approvals) > 1 || r.Phase != Revoking && len(r.Closures) != 0 {
		return false
	}
	for i, a := range r.Approvals {
		if a.Tenant != r.Source.Tenant && a.Tenant != r.Destination.Tenant || !validID(a.User) || a.PolicyRevision == 0 || i > 0 && a.Tenant <= r.Approvals[i-1].Tenant {
			return false
		}
	}
	return true
}
func (n Networks) validRouteOwners(r Route) bool {
	for _, b := range []Binding{r.Source, r.Destination} {
		v, ok := n.networks[key(b.Tenant, b.Network)]
		if !ok || v.Node != b.Node || v.Owner != b.Owner || v.Generation != b.Generation || b.Revision > v.Revision {
			return false
		}
		found := false
		for _, p := range v.Pools {
			if p.Prefix == b.Prefix {
				found = true
			}
		}
		if !found {
			return false
		}
		if r.Phase != Revoking && !n.current(b) {
			return false
		}
	}
	for i, p := range r.Closures {
		if i > 0 && p.Tenant <= r.Closures[i-1].Tenant || !n.verifyRouteClosure(r, p) {
			return false
		}
	}
	return true
}
func (n Networks) Propose(c access.Catalog, actor string, expected uint64, r Route) (Networks, error) {
	if r.Source.Tenant == "" || r.Destination.Tenant == "" {
		return n, ErrPolicy
	}
	if c.Authorize(actor, r.Source.Tenant, access.ManageRoutes, r.Source.Node) != nil {
		return n, access.ErrDenied
	}
	if expected != n.revision {
		return n, access.ErrConflict
	}
	if len(n.routes) >= maxRoutes || r.Generation != 0 || r.Revision != 0 || r.Phase != "" || len(r.Approvals) != 0 || len(r.Closures) != 0 {
		return n, ErrPolicy
	}
	if _, ok := n.routes[key(r.Source.Tenant, r.ID)]; ok {
		return n, access.ErrConflict
	}
	q, err := n.clone()
	if err != nil {
		return n, err
	}
	r = ownRoute(r)
	r.Generation = q.revision
	r.Revision = q.revision
	r.Phase = Pending
	if !validRoute(r) || !n.freshRouteBinding(r.Source) || !n.freshRouteBinding(r.Destination) {
		return n, ErrPolicy
	}
	// The proposal itself is not an approval, even for a system administrator.
	q.routes[key(r.Source.Tenant, r.ID)] = r
	return q, nil
}
func (n Networks) Approve(c access.Catalog, actor, sourceTenant, id, side string, expected uint64) (Networks, error) {
	r, ok := n.routes[key(sourceTenant, id)]
	if !ok || r.Revision != expected {
		return n, access.ErrConflict
	}
	b := r.Source
	if side == r.Destination.Tenant {
		b = r.Destination
	} else if side != r.Source.Tenant {
		return n, ErrPolicy
	}
	if c.Authorize(actor, side, access.ManageRoutes, b.Node) != nil {
		return n, access.ErrDenied
	}
	if r.Phase == Revoking || !n.freshRouteBinding(r.Source) || !n.freshRouteBinding(r.Destination) {
		return n, ErrPolicy
	}
	for _, a := range r.Approvals {
		if a.Tenant == side {
			return n, access.ErrConflict
		}
	}
	q, err := n.clone()
	if err != nil {
		return n, err
	}
	r = ownRoute(r)
	r.Revision = q.revision
	r.Approvals = append(r.Approvals, Approval{side, actor, c.Revision()})
	slices.SortFunc(r.Approvals, func(a, b Approval) int {
		if a.Tenant < b.Tenant {
			return -1
		}
		if a.Tenant > b.Tenant {
			return 1
		}
		return 0
	})
	if len(r.Approvals) == 2 {
		r.Phase = Active
	}
	q.routes[key(sourceTenant, id)] = r
	return q, nil
}

// ValidateRoute checks the canonical policy shape independently of live
// ownership. Runtime journals retain this original policy during retirement.
func ValidateRoute(r Route) error {
	if !validRoute(r) {
		return ErrPolicy
	}
	return nil
}

// RouteAuthorized is policy admission only, not evidence of native installation.
func (n Networks) RouteAuthorized(c access.Catalog, sourceTenant, id string) bool {
	r, ok := n.routes[key(sourceTenant, id)]
	if !ok || r.Phase != Active || !n.current(r.Source) || !n.current(r.Destination) {
		return false
	}
	for _, a := range r.Approvals {
		b := r.Source
		if a.Tenant == r.Destination.Tenant {
			b = r.Destination
		}
		if c.Authorize(a.User, a.Tenant, access.ManageRoutes, b.Node) != nil {
			return false
		}
	}
	return true
}

// AllowsNewFlow checks one direct, one-way policy. src/dst are authenticated
// current endpoint addresses, resolved by the caller from shared IPAM. This is
// neither endpoint authentication nor a conntrack/reverse-flow implementation.
func (n Networks) AllowsNewFlow(c access.Catalog, sourceTenant, id string, src, dst netip.Addr, protocol uint8, port uint16) bool {
	r, ok := n.routes[key(sourceTenant, id)]
	if !ok || !n.RouteAuthorized(c, sourceTenant, id) || protocol != r.Protocol || !src.IsValid() || !dst.IsValid() || src.Is4In6() || dst.Is4In6() || src.Zone() != "" || dst.Zone() != "" || !r.Source.Prefix.Contains(src) || !r.Destination.Prefix.Contains(dst) {
		return false
	}
	for _, p := range r.Ports {
		if port >= p.First && port <= p.Last {
			return true
		}
	}
	return false
}
func (n Networks) Withdraw(c access.Catalog, actor, sourceTenant, id, side string, expected uint64) (Networks, error) {
	r, ok := n.routes[key(sourceTenant, id)]
	if !ok || r.Revision != expected {
		return n, access.ErrConflict
	}
	if side != r.Source.Tenant && side != r.Destination.Tenant {
		return n, ErrPolicy
	}
	if !mayRetire(c, actor, side, access.ManageRoutes) {
		return n, access.ErrDenied
	}
	if r.Phase == Revoking {
		return n, nil
	}
	q, err := n.clone()
	if err != nil {
		return n, err
	}
	r.Phase = Revoking
	r.Revision = q.revision
	r.Closures = nil
	q.routes[key(sourceTenant, id)] = r
	return q, nil
}

// RevokeUnauthorized is the deterministic consequence of a committed catalog
// change. It never reopens a withdrawn route or returns either owner's pins.
func (n Networks) RevokeUnauthorized(c access.Catalog) (Networks, error) {
	var revoked []string
	for key, route := range n.routes {
		if route.Phase == Active && !n.RouteAuthorized(c, route.Source.Tenant, route.ID) {
			revoked = append(revoked, key)
		}
	}
	if len(revoked) == 0 {
		return n, nil
	}
	slices.Sort(revoked)
	next, err := n.clone()
	if err != nil {
		return n, err
	}
	for _, key := range revoked {
		route := ownRoute(next.routes[key])
		route.Phase, route.Revision, route.Closures = Revoking, next.revision, nil
		next.routes[key] = route
	}
	return next, nil
}

type RouteClosure struct {
	Cluster                           [32]byte
	SourceTenant, Route, Tenant, Node string
	Owner                             [32]byte
	Generation, Revision              uint64
	NativeGone                        bool
	PendingFlows, PendingPins         uint64
	Signature                         []byte
}

func RouteClosureBytes(p RouteClosure) []byte {
	p.Signature = nil
	b, _ := json.Marshal(p)
	return append([]byte("sfc-route-closure-1\x00"), b...)
}
func (n Networks) verifyRouteClosure(r Route, p RouteClosure) bool {
	return VerifyRouteClosure(n.cluster, r, p)
}

// VerifyRouteClosure also verifies an archived original policy. It grants no
// current mutation authority and does not look up a newer route by its name.
func VerifyRouteClosure(cluster [32]byte, r Route, p RouteClosure) bool {
	b := r.Source
	if p.Tenant == r.Destination.Tenant {
		b = r.Destination
	} else if p.Tenant != r.Source.Tenant {
		return false
	}
	return cluster != ([32]byte{}) && r.Phase == Revoking && p.Cluster == cluster && p.SourceTenant == r.Source.Tenant && p.Route == r.ID && p.Node == b.Node && p.Owner == b.Owner && p.Generation == r.Generation && p.Revision == r.Revision && p.NativeGone && p.PendingFlows == 0 && p.PendingPins == 0 && ed25519.Verify(ed25519.PublicKey(b.Owner[:]), RouteClosureBytes(p), p.Signature)
}

// ObserveRetired remains callable after user/node grants were withdrawn. It
// grants no mutation authority: it only accepts the exact original owner's
// authenticated zero-resource receipt for an already committed retirement.
func (n Networks) ObserveRetired(p RouteClosure) (Networks, error) {
	k := key(p.SourceTenant, p.Route)
	r, ok := n.routes[k]
	if !ok || r.Phase != Revoking || !n.verifyRouteClosure(r, p) {
		return n, ErrPolicy
	}
	for _, old := range r.Closures {
		if old.Tenant == p.Tenant {
			return n, nil
		}
	}
	q, err := n.clone()
	if err != nil {
		return n, err
	}
	r = ownRoute(r)
	p.Signature = slices.Clone(p.Signature)
	r.Closures = append(r.Closures, p)
	if len(r.Closures) == 2 {
		delete(q.routes, k)
	} else {
		q.routes[k] = r
	}
	return q, nil
}
