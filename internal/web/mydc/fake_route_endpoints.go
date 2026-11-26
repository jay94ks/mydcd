// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"context"
	"slices"

	"github.com/jay94ks/mydcd/internal/cluster/control"
)

// routeEndpoints: the rows PublicRead("route-endpoints") pages; any user who can manage routes in some tenant
// (manager in the fake) reads the networks the destination tenant offers
// (Fixture.RouteOpen / Fake.SetRouteOpen); a system administrator and the
// tenant's own managers see all its networks. Members that are draining or
// mid-change are left out, as propose-route would refuse them.
func (c *fakeConn) routeEndpoints(ctx context.Context, tenant string) (RouteEndpoints, error) {
	const m = "route-endpoints"
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return RouteEndpoints{}, err
	}
	defer c.unlock()
	w := c.f.w
	if _, ok := w.tenants[tenant]; !ok {
		return RouteEndpoints{}, fail(m, CodeMissing, "")
	}
	all := w.admin(user) || w.canManage(user, tenant)
	if !all && !slices.ContainsFunc(sortedKeys(w.tenants), func(t string) bool { return w.canManage(user, t) }) {
		return RouteEndpoints{}, fail(m, CodeDenied, "")
	}
	out := RouteEndpoints{Tenant: tenant, Endpoints: []control.RouteEndpoint{}}
	for _, r := range w.resources {
		n := r.Network
		if r.Tenant != tenant || n == nil || !all && !w.routeOpen[tenant+"/"+n.Name] {
			continue
		}
		for _, mem := range n.Members {
			if mem.Draining || activeChange(mem.Change) {
				continue
			}
			for _, p := range mem.Source.Pools {
				out.Endpoints = append(out.Endpoints, control.RouteEndpoint{Tenant: tenant, Network: n.Name, Node: mem.Node, Pool: p.ID})
			}
		}
	}
	return out, nil
}

// SetRouteOpen offers (or stops offering) a network as a route destination
// to other tenants' managers (REQ-38 mock policy).
func (f *Fake) SetRouteOpen(tenant, network string, open bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if open {
		f.w.routeOpen[tenant+"/"+network] = true
	} else {
		delete(f.w.routeOpen, tenant+"/"+network)
	}
}
