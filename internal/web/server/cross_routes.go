// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"github.com/jay94ks/mydcd/internal/web/mydc"
)

// Cross-tenant routes (UI-53). mydcd keeps them in `resources` as
// route/<source tenant>/<id> rows, visible to readers of either side, and
// takes propose-route / approve-route / withdraw-route. The daemon fills
// the endpoint node and pool from the network rows it can read; mydcd
// decides permission, freshness and approval.

type routeSideView struct {
	Name string `json:"name,omitempty"` // network name, when this session can read that side
	mydc.RouteSide
}

type routeView struct {
	Key         string        `json:"key"` // route/<source tenant>/<id>
	Source      routeSideView `json:"source"`
	Destination routeSideView `json:"destination"`
	// Side is this tenant's side; State: active, waiting-me (this side has
	// not approved), waiting-peer, revoking.
	Side  string `json:"side"`
	State string `json:"state"`
	mydc.Route
}

type routesPage struct {
	Items            []routeView `json:"items"`
	Next             string      `json:"next"` // always "": the list is whole
	NetworksRevision uint64      `json:"networksRevision"`
}

// tenantRoutes reads the tenant's resources: its route rows, the member
// network ID → name map and the networks revision.
func tenantRoutes(ctx context.Context, c mydc.Conn, tenant string) ([]mydc.Route, map[string]string, uint64, error) {
	var routes []mydc.Route
	names := map[string]string{}
	rev := uint64(0)
	after := ""
	for {
		p, err := c.Resources(ctx, tenant, after)
		if err != nil {
			return nil, nil, 0, err
		}
		rev = p.Collection
		for _, e := range p.Items {
			if e.Route != nil {
				routes = append(routes, *e.Route)
			}
			if n := e.Network; n != nil && e.Tenant == tenant {
				for _, m := range n.Members {
					names[m.ID] = n.Name
				}
			}
		}
		if p.Next == "" {
			return routes, names, rev, nil
		}
		after = p.Next
	}
}

func viewRoute(tenant string, r mydc.Route, names map[string]string) routeView {
	v := routeView{Key: "route/" + r.SourceTenant + "/" + r.ID, Route: r, Source: routeSideView{RouteSide: r.Source}, Destination: routeSideView{RouteSide: r.Destination}, Side: "source"}
	if r.Source.Tenant == tenant {
		v.Source.Name = names[r.Source.Network]
	}
	if r.Destination.Tenant == tenant {
		v.Side = "destination"
		v.Destination.Name = names[r.Destination.Network]
	}
	mine := false
	for _, a := range r.Approvals {
		mine = mine || a.Tenant == tenant
	}
	switch {
	case r.Phase == string(tenancy.Revoking):
		v.State = "revoking"
	case r.Phase == string(tenancy.Active):
		v.State = "active"
	case !mine:
		v.State = "waiting-me"
	default:
		v.State = "waiting-peer"
	}
	return v
}

// GET /t/{t}/routes
func (s *Server) handleRouteList(w http.ResponseWriter, r *http.Request, ws *webSession) {
	tenant := r.PathValue("t")
	read(s, w, r, ws, func(ctx context.Context, c mydc.Conn) (routesPage, error) {
		routes, names, rev, err := tenantRoutes(ctx, c, tenant)
		if err != nil {
			return routesPage{}, err
		}
		out := routesPage{Items: []routeView{}, NetworksRevision: rev}
		for _, x := range routes {
			out.Items = append(out.Items, viewRoute(tenant, x, names))
		}
		return out, nil
	})
}

// parsePorts reads [443, "8000-8100", {first, last}] into sorted, disjoint ranges.
func parsePorts(raw []json.RawMessage) ([]tenancy.Ports, error) {
	bad := invalid("ports: 1..64 ports or ranges such as 443 or \"8000-8100\", ascending and not overlapping")
	if len(raw) == 0 || len(raw) > 64 {
		return nil, bad
	}
	var out []tenancy.Ports
	for _, m := range raw {
		var p tenancy.Ports
		var n uint16
		var str string
		var obj struct{ First, Last uint16 }
		switch {
		case json.Unmarshal(m, &n) == nil:
			p = tenancy.Ports{First: n, Last: n}
		case json.Unmarshal(m, &str) == nil:
			a, b, rng := strings.Cut(str, "-")
			x, err1 := strconv.ParseUint(strings.TrimSpace(a), 10, 16)
			y, err2 := x, error(nil)
			if rng {
				y, err2 = strconv.ParseUint(strings.TrimSpace(b), 10, 16)
			}
			if err1 != nil || err2 != nil {
				return nil, bad
			}
			p = tenancy.Ports{First: uint16(x), Last: uint16(y)}
		case json.Unmarshal(m, &obj) == nil:
			p = tenancy.Ports{First: obj.First, Last: obj.Last}
		default:
			return nil, bad
		}
		if p.First == 0 || p.Last < p.First || len(out) > 0 && p.First <= out[len(out)-1].Last {
			return nil, bad
		}
		out = append(out, p)
	}
	return out, nil
}

// endpointOn picks the member of n (on node, or its only member) and its
// first pool.
func endpointOn(tenant string, n *mydc.Network, node string) (control.RouteEndpoint, error) {
	var m *mydc.NetworkMember
	if node != "" {
		mm, err := memberOn(n, node)
		if err != nil {
			return control.RouteEndpoint{}, err
		}
		m = mm
	} else if len(n.Members) == 1 {
		m = &n.Members[0]
	} else {
		return control.RouteEndpoint{}, &httpErr{http.StatusUnprocessableEntity, "node-required", "this network is on several servers; give node"}
	}
	if len(m.Source.Pools) == 0 {
		return control.RouteEndpoint{}, &httpErr{http.StatusConflict, "no-pool", "this network member has no address pool"}
	}
	return control.RouteEndpoint{Tenant: tenant, Network: n.Name, Node: m.Node, Pool: m.Source.Pools[0].ID}, nil
}

// POST /t/{t}/routes {opId, id?, source:{network, node?},
// destination:{tenant, network, node?, pool?}, protocol, ports, expected?}
// → propose-route. Node and pool come from the network rows; when this
// session cannot read the destination tenant, destination.node is needed
// (pool defaults to "main", the web's pool name) until REQ-37.
func (s *Server) handleRoutePropose(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID   string `json:"opId"`
		ID     string `json:"id,omitempty"`
		Source struct {
			Network string `json:"network"`
			Node    string `json:"node,omitempty"`
		} `json:"source"`
		Destination struct {
			Tenant  string `json:"tenant"`
			Network string `json:"network"`
			Node    string `json:"node,omitempty"`
			Pool    string `json:"pool,omitempty"`
		} `json:"destination"`
		Protocol string            `json:"protocol"`
		Ports    []json.RawMessage `json:"ports"`
		Expected uint64            `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant := r.PathValue("t")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c mydc.Conn, _ mydc.Session) (string, any, uint64, string, error) {
		id := req.ID
		if id == "" {
			id = "rt-" + req.OpID[:8]
		}
		if !storageIDRE.MatchString(id) {
			return "", nil, 0, "", invalid("id: lowercase letters, digits and -, starting with a letter")
		}
		proto := map[string]uint8{"tcp": 6, "udp": 17}[req.Protocol]
		if proto == 0 {
			return "", nil, 0, "", invalid("protocol: tcp or udp")
		}
		ports, err := parsePorts(req.Ports)
		if err != nil {
			return "", nil, 0, "", err
		}
		d := req.Destination
		if !validName(req.Source.Network) || !validName(d.Network) || d.Tenant == "" {
			return "", nil, 0, "", invalid("source.network, destination.tenant and destination.network")
		}
		if d.Tenant == tenant {
			return "", nil, 0, "", invalid("destination.tenant: another workspace (a route joins two workspaces)")
		}
		srcNet, rev, err := findNetwork(ctx, c, tenant, req.Source.Network)
		if err != nil {
			return "", nil, 0, "", err
		}
		src, err := endpointOn(tenant, srcNet, req.Source.Node)
		if err != nil {
			return "", nil, 0, "", err
		}
		var dst control.RouteEndpoint
		dstNet, _, err := findNetwork(ctx, c, d.Tenant, d.Network)
		switch {
		case err == nil:
			if dst, err = endpointOn(d.Tenant, dstNet, d.Node); err != nil {
				if he, ok := err.(*httpErr); ok && he.code == "node-required" {
					err = &httpErr{http.StatusUnprocessableEntity, "destination-node-required", "the destination network is on several servers; give destination.node"}
				}
				return "", nil, 0, "", err
			}
		case !unreadable(err):
			return "", nil, 0, "", err
		default:
			// the other workspace is not readable here: its open endpoints
			// (route-endpoints, REQ-38) name the node and pool
			if dst, err = openEndpoint(ctx, c, d.Tenant, d.Network, d.Node, d.Pool); err != nil {
				return "", nil, 0, "", err
			}
		}
		if req.Expected != 0 {
			rev = req.Expected
		}
		q := control.RouteProposal{ID: id, Source: src, Destination: dst, Protocol: proto, Ports: ports}
		return mydc.ActionProposeRoute, q, rev, "route/" + id, nil
	})
}

// POST /t/{t}/routes/{source}/{id}/approve | withdraw {opId, expected?} →
// approve-route / withdraw-route for this tenant's side. Expected = the
// route revision (expected, else the current one).
func (s *Server) handleRouteSelect(action string) func(http.ResponseWriter, *http.Request, *webSession) {
	return func(w http.ResponseWriter, r *http.Request, ws *webSession) {
		var req struct {
			OpID     string `json:"opId"`
			Expected uint64 `json:"expected,omitempty"` // the route revision the screen showed
		}
		if !readJSON(w, r, &req) {
			return
		}
		tenant, source, id := r.PathValue("t"), r.PathValue("source"), r.PathValue("id")
		body := struct {
			Action string
			Req    any
		}{action, req}
		s.sharedCreate(w, r, ws, req.OpID, body, func(ctx context.Context, c mydc.Conn, _ mydc.Session) (string, any, uint64, string, error) {
			routes, _, _, err := tenantRoutes(ctx, c, tenant)
			if err != nil {
				return "", nil, 0, "", err
			}
			for _, x := range routes {
				if x.SourceTenant != source || x.ID != id {
					continue
				}
				if x.Phase == string(tenancy.Revoking) {
					return "", nil, 0, "", &httpErr{http.StatusConflict, "revoking", "this route is being withdrawn"}
				}
				if action == mydc.ActionApproveRoute {
					for _, a := range x.Approvals {
						if a.Tenant == tenant {
							return "", nil, 0, "", &httpErr{http.StatusConflict, "already-approved", "this workspace already approved the route"}
						}
					}
				}
				return action, control.RouteSelection{Tenant: tenant, SourceTenant: source, ID: id}, expectedOr(req.Expected, x.Revision), "route/" + id, nil
			}
			return "", nil, 0, "", &httpErr{http.StatusNotFound, "not-found", "no such route"}
		})
	}
}

// unreadable: the other side's rows are hidden from this session (denied)
// or not there; transport and session errors are not this.
func unreadable(err error) bool {
	var me *mydc.Error
	var he *httpErr
	return errors.As(err, &me) && me.Code == mydc.CodeDenied || errors.As(err, &he) && he.status == http.StatusNotFound
}

// openEndpoint picks the destination among the tenant's open route
// endpoints: the named network (on node, when given; pool, when given).
func openEndpoint(ctx context.Context, c mydc.Conn, tenant, network, node, pool string) (control.RouteEndpoint, error) {
	endpoints, err := readRouteEndpoints(ctx, c, tenant)
	if err != nil {
		return control.RouteEndpoint{}, err
	}
	var found []control.RouteEndpoint
	for _, e := range endpoints {
		if e.Network == network && (node == "" || e.Node == node) && (pool == "" || e.Pool == pool) {
			found = append(found, e)
		}
	}
	switch {
	case len(found) == 1:
		return found[0], nil
	case len(found) == 0:
		return control.RouteEndpoint{}, &httpErr{http.StatusUnprocessableEntity, "destination-not-open", "the destination workspace does not offer this network for routes"}
	case node == "":
		return control.RouteEndpoint{}, &httpErr{http.StatusUnprocessableEntity, "destination-node-required", "the destination network is on several servers; give destination.node"}
	}
	return control.RouteEndpoint{}, &httpErr{http.StatusUnprocessableEntity, "destination-pool-required", "the destination server has several pools; give destination.pool"}
}

// GET /t/{t}/route-endpoints?tenant= → {tenant, items:[{tenant, network,
// node, pool}]}: what another workspace offers as route destinations.
func (s *Server) handleRouteEndpoints(w http.ResponseWriter, r *http.Request, ws *webSession) {
	other := r.URL.Query().Get("tenant")
	read(s, w, r, ws, func(ctx context.Context, c mydc.Conn) (map[string]any, error) {
		if other == "" || other == r.PathValue("t") {
			return nil, invalid("tenant: another workspace")
		}
		endpoints, err := readRouteEndpoints(ctx, c, other)
		if err != nil {
			return nil, err
		}
		items := []map[string]string{}
		for _, e := range endpoints {
			items = append(items, map[string]string{"tenant": e.Tenant, "network": e.Network, "node": e.Node, "pool": e.Pool})
		}
		return map[string]any{"tenant": other, "items": items}, nil
	})
}
