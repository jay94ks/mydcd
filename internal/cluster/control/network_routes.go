// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/network/services"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

// RouteEndpoint names a managed pool. The server fixes its current owner,
// prefix and generation; an app cannot grant itself cross-tenant routing.
type RouteEndpoint struct {
	Tenant, Network, Node, Pool string
}
type RouteProposal struct {
	ID                  string
	Source, Destination RouteEndpoint
	Protocol            uint8
	Ports               []tenancy.Ports
}

// Tenant is the approving/withdrawing side, SourceTenant selects the stable
// policy namespace. A destination manager does not act as the source tenant.
type RouteSelection struct {
	Tenant, SourceTenant, ID string
}

func (p Policy) routeEndpoint(s state.State, n tenancy.Networks, endpoint RouteEndpoint) (tenancy.Binding, error) {
	network, exists := n.NamedNetwork(endpoint.Tenant, endpoint.Network, endpoint.Node)
	owner, err := p.workNodeOwner(s, endpoint.Node)
	if !exists || err != nil || owner != network.Owner {
		return tenancy.Binding{}, ErrCatalog
	}
	for _, pool := range network.Pools {
		if pool.ID == endpoint.Pool {
			return n.Bind(network.Tenant, network.ID, pool.Prefix)
		}
	}
	return tenancy.Binding{}, ErrCatalog
}

func (p Policy) authorizeRouteChange(s state.State, c access.Catalog, op UserOperation) error {
	if op.Change.Action == "propose-route" {
		var proposal RouteProposal
		if canonical(op.Change.Payload, &proposal) != nil {
			return access.ErrInvalid
		}
		return c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, proposal.Source.Tenant, access.ManageRoutes, proposal.Source.Node)
	}
	var selection RouteSelection
	if canonical(op.Change.Payload, &selection) != nil {
		return access.ErrInvalid
	}
	resources, err := p.Resources(s)
	if err != nil {
		return err
	}
	route, exists := resources.Networks.Route(selection.SourceTenant, selection.ID)
	if !exists {
		return access.ErrInvalid
	}
	local := route.Source
	if selection.Tenant == route.Destination.Tenant {
		local = route.Destination
	} else if selection.Tenant != route.Source.Tenant {
		return access.ErrDenied
	}
	if op.Change.Action == "withdraw-route" {
		return c.AuthorizeSessionCleanup(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, selection.Tenant, access.ManageRoutes)
	}
	return c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, selection.Tenant, access.ManageRoutes, local.Node)
}

func (p Policy) changeRoutePolicy(s state.State, c access.Catalog, r Resources, op UserOperation) (tenancy.Networks, error) {
	if op.Change.Action == "propose-route" {
		var proposal RouteProposal
		if canonical(op.Change.Payload, &proposal) != nil {
			return r.Networks, access.ErrInvalid
		}
		source, err := p.routeEndpoint(s, r.Networks, proposal.Source)
		if err != nil {
			return r.Networks, err
		}
		destination, err := p.routeEndpoint(s, r.Networks, proposal.Destination)
		if err != nil {
			return r.Networks, err
		}
		return r.Networks.Propose(c, op.Change.Principal, op.Change.Expected, tenancy.Route{ID: proposal.ID, Source: source, Destination: destination, Protocol: proposal.Protocol, Ports: proposal.Ports})
	}
	var selection RouteSelection
	if canonical(op.Change.Payload, &selection) != nil {
		return r.Networks, access.ErrInvalid
	}
	if op.Change.Action == "approve-route" {
		route, exists := r.Networks.Route(selection.SourceTenant, selection.ID)
		if !exists {
			return r.Networks, access.ErrInvalid
		}
		for _, endpoint := range []tenancy.Binding{route.Source, route.Destination} {
			owner, err := p.workNodeOwner(s, endpoint.Node)
			if err != nil || owner != endpoint.Owner {
				return r.Networks, access.ErrDenied
			}
		}
		return r.Networks.Approve(c, op.Change.Principal, selection.SourceTenant, selection.ID, selection.Tenant, op.Change.Expected)
	}
	if op.Change.Action == "withdraw-route" {
		return r.Networks.Withdraw(c, op.Change.Principal, selection.SourceTenant, selection.ID, selection.Tenant, op.Change.Expected)
	}
	return r.Networks, access.ErrInvalid
}

func (p Policy) changeRoute(s state.State, c access.Catalog, r Resources, op UserOperation) (tenancy.Networks, map[string][]byte, error) {
	next, err := p.changeRoutePolicy(s, c, r, op)
	if err != nil || op.Change.Action != "approve-route" {
		return next, nil, err
	}
	var selection RouteSelection
	if canonical(op.Change.Payload, &selection) != nil {
		return r.Networks, nil, access.ErrInvalid
	}
	route, found := next.Route(selection.SourceTenant, selection.ID)
	if !found || route.Phase != tenancy.Active {
		return next, nil, nil
	}
	projection, err := p.ProjectResources(s)
	if err != nil {
		return r.Networks, nil, err
	}
	authority, err := projection.addressAuthority(p.Cluster)
	if err != nil {
		return r.Networks, nil, err
	}
	for _, approval := range route.Approvals {
		local := route.Source
		if approval.Tenant == route.Destination.Tenant {
			local = route.Destination
		}
		binding, err := routeBridgeBinding(s, projection, local)
		if err != nil {
			return r.Networks, nil, err
		}
		expected, err := authority.RouteReferenceGeneration(next, selection.SourceTenant, selection.ID, approval.Tenant)
		if err != nil {
			return r.Networks, nil, err
		}
		authority, _, err = authority.GrantRouteInstance(c, next, approval.User, selection.SourceTenant, selection.ID, approval.Tenant, expected, binding)
		if err != nil {
			return r.Networks, nil, err
		}
	}
	projection.RouteConsumers = routeConsumerDemand(authority)
	for _, local := range []tenancy.Binding{route.Source, route.Destination} {
		if err := admitIngressConsumers(projection, deployment.GoalResources{Goal: deployment.GoalCommand{Tenant: local.Tenant, Node: local.Node, Owner: local.Owner}}); err != nil {
			return r.Networks, nil, err
		}
	}
	writes, err := p.networkTransitionWrites(s, authority, next, "", "", false)
	if err != nil {
		return r.Networks, nil, err
	}
	return next, writes, nil
}

func routeBridgeBinding(s state.State, projection ResourceProjection, local tenancy.Binding) (services.RouteNativeBinding, error) {
	for key, source := range projection.ManagedSources {
		if source.Closed != nil || source.Bridge == nil || source.Network.Tenant != local.Tenant || source.Network.ID != local.Network || source.Network.Node != local.Node || source.Network.Owner != local.Owner || source.Network.Generation != local.Generation || source.Network.Revision != local.Revision || source.Network.Draining || source.Network.PendingChange != 0 {
			continue
		}
		object := s.Object(key)
		if !object.Present {
			return services.RouteNativeBinding{}, ErrCatalog
		}
		return services.RouteNativeBinding{Key: key, Generation: object.Generation, Revision: object.Revision, Spec: sha256.Sum256([]byte(object.Value))}, nil
	}
	return services.RouteNativeBinding{}, ErrCatalog
}

func routeConsumerDemand(authority services.Authority) []deployment.NetworkConsumerDemand {
	var out []deployment.NetworkConsumerDemand
	for _, ref := range authority.RouteReferences() {
		if ref.Closed != nil {
			continue
		}
		key := ref.RouteNativeKey()
		bridge := key + "/unbound-bridge"
		if ref.Native != nil {
			bridge = ref.Native.Key
		}
		for _, edge := range [][2]string{{bridge, key + "/bridge"}, {key, key + "/packet-plane"}} {
			out = append(out, deployment.NetworkConsumerDemand{Source: edge[0], Consumer: edge[1], Tenant: ref.Local.Tenant, Node: ref.Local.Node, Owner: ref.Local.Owner})
		}
	}
	return out
}
