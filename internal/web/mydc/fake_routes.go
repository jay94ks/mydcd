// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"errors"
	"slices"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

// Cross-tenant routes with the real payload types and the tenancy.Networks
// rules the web can see: propose (source manager, Expected = networks
// revision, both endpoints named by network name + node + pool) → pending;
// approve by each side (Expected = route revision; the proposal is not an
// approval) → active when both approved; withdraw by either side →
// revoking. The fake does not model the closures that finish a revoke.

// fixtureRoutes: shop/shop-net on node-a → payments/payments-net on node-a,
// TCP 5432, approved by shop and waiting for payments.
func (w *world) fixtureRoutes() {
	src, ok1 := w.routeEndpoint(control.RouteEndpoint{Tenant: "shop", Network: "shop-net", Node: "node-a", Pool: "main"})
	dst, ok2 := w.routeEndpoint(control.RouteEndpoint{Tenant: "payments", Network: "payments-net", Node: "node-a", Pool: "main"})
	if !ok1 || !ok2 {
		return
	}
	w.routes = append(w.routes, tenancy.Route{ID: "shop-to-ledger", Generation: 23, Revision: 24, Source: src, Destination: dst, Protocol: 6,
		Ports: []tenancy.Ports{{First: 5432, Last: 5432}}, Phase: tenancy.Pending, Approvals: []tenancy.Approval{{Tenant: "shop", User: "u-alice", PolicyRevision: 1}}})
}

// routeEndpoint is control routeEndpoint: the member of the named network
// on that node (tenancy.NamedNetwork) and its pool.
func (w *world) routeEndpoint(e control.RouteEndpoint) (tenancy.Binding, bool) {
	for _, r := range w.resources {
		if r.Tenant != e.Tenant || r.Network == nil || r.Network.Name != e.Network {
			continue
		}
		for _, m := range r.Network.Members {
			if m.Node != e.Node || m.Draining || activeChange(m.Change) {
				continue
			}
			for _, p := range m.Source.Pools {
				if p.ID == e.Pool {
					return tenancy.Binding{Tenant: e.Tenant, Network: m.ID, Node: m.Node, Owner: m.Source.Owner, Generation: m.Generation, Revision: m.Revision, Prefix: p.Prefix}, true
				}
			}
		}
	}
	return tenancy.Binding{}, false
}

// routeEntries: the route rows visible in a tenant's resources (either side).
func (w *world) routeEntries(tenant string) []ResourceEntry {
	var out []ResourceEntry
	for _, r := range w.routes {
		if tenant != "" && r.Source.Tenant != tenant && r.Destination.Tenant != tenant {
			continue
		}
		v := RouteView(r)
		out = append(out, ResourceEntry{Key: "route/" + r.Source.Tenant + "/" + r.ID, Tenant: tenant, Route: &v})
	}
	return out
}

func (c *fakeConn) applyRoute(op UserOperation, actor string, next uint64) error {
	w := c.f.w
	ch := op.Change
	if ch.Action == ActionProposeRoute {
		var q control.RouteProposal
		if decodePayload(ch.Payload, &q) != nil || q.ID == "" || q.Protocol != 6 && q.Protocol != 17 || len(q.Ports) == 0 || len(q.Ports) > 64 || q.Source.Tenant == q.Destination.Tenant {
			return errors.New("payload")
		}
		for i, p := range q.Ports {
			if p.First == 0 || p.Last < p.First || i > 0 && p.First <= q.Ports[i-1].Last {
				return errors.New("payload")
			}
		}
		if !w.canManage(actor, q.Source.Tenant) {
			return errForbidden
		}
		if ch.Expected != w.netRev || slices.ContainsFunc(w.routes, func(r tenancy.Route) bool { return r.Source.Tenant == q.Source.Tenant && r.ID == q.ID }) {
			return errCAS
		}
		src, ok1 := w.routeEndpoint(q.Source)
		dst, ok2 := w.routeEndpoint(q.Destination)
		if !ok1 || !ok2 || src.Prefix.Addr().Is4() != dst.Prefix.Addr().Is4() {
			return errCAS
		}
		w.routes = append(w.routes, tenancy.Route{ID: q.ID, Generation: next, Revision: next, Source: src, Destination: dst, Protocol: q.Protocol, Ports: slices.Clone(q.Ports), Phase: tenancy.Pending})
		w.netRev = next
		return nil
	}
	var q control.RouteSelection
	if decodePayload(ch.Payload, &q) != nil {
		return errors.New("payload")
	}
	i := slices.IndexFunc(w.routes, func(r tenancy.Route) bool { return r.Source.Tenant == q.SourceTenant && r.ID == q.ID })
	if i < 0 || w.routes[i].Revision != ch.Expected {
		return errCAS
	}
	r := w.routes[i]
	r.Approvals = slices.Clone(r.Approvals)
	if q.Tenant != r.Source.Tenant && q.Tenant != r.Destination.Tenant {
		return errForbidden
	}
	if !w.canManage(actor, q.Tenant) {
		return errForbidden
	}
	if ch.Action == ActionWithdrawRoute {
		if r.Phase == tenancy.Revoking {
			return nil
		}
		r.Phase, r.Revision = tenancy.Revoking, next
	} else {
		if r.Phase == tenancy.Revoking || slices.ContainsFunc(r.Approvals, func(a tenancy.Approval) bool { return a.Tenant == q.Tenant }) {
			return errCAS
		}
		r.Approvals = append(r.Approvals, tenancy.Approval{Tenant: q.Tenant, User: actor, PolicyRevision: next})
		slices.SortFunc(r.Approvals, func(a, b tenancy.Approval) int {
			if a.Tenant < b.Tenant {
				return -1
			}
			if a.Tenant > b.Tenant {
				return 1
			}
			return 0
		})
		if len(r.Approvals) == 2 {
			r.Phase = tenancy.Active
		}
		r.Revision = next
	}
	w.routes[i] = r
	w.netRev = next
	return nil
}
