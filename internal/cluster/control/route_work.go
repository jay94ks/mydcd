// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/network/services"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

type RouteWorkRequest struct {
	Reference [32]byte
	At        int64
}

// RouteWork is a latest-quorum preparation/cleanup view of an ORIGINAL shared
// instance. PrepareAllowed permits preparing its durable local record only;
// it is not native dispatch, Started/Applied/Ready, or a new flow permission.
type RouteWork struct {
	Schema                          uint8
	Reference, Peer                 services.ReferenceConsumer
	Tunnel                          network.TunnelSpec
	ResourcesRevision, AppsRevision uint64
	Epoch                           uint64
	PrepareAllowed                  bool
	Retiring                        bool `json:",omitempty"`
	MaxConsumers                    int
	Packets                         network.PacketLimits
}

func routeReferenceBinding(ref services.ReferenceConsumer) tenancy.Binding {
	if ref.Route.Side == ref.Route.Policy.Source.Tenant {
		return ref.Route.Policy.Source
	}
	return ref.Route.Policy.Destination
}

func (p Policy) RouteWork(s state.State, caller [32]byte, request RouteWorkRequest) (RouteWork, error) {
	_, work, err := p.ProjectRouteWork(s, caller, request)
	return work, err
}

// ProjectRouteWork returns permissions and their resource projection from the
// same immutable committed state. It does not obtain or renew quorum authority.
func (p Policy) ProjectRouteWork(s state.State, caller [32]byte, request RouteWorkRequest) (ResourceProjection, RouteWork, error) {
	members, err := p.Members(s)
	if err != nil || !members.MemberKey(caller) {
		return ResourceProjection{}, RouteWork{}, ErrCatalog
	}
	projection, err := p.ProjectResources(s)
	if err != nil || projection.NetworkAuthority == nil {
		return ResourceProjection{}, RouteWork{}, ErrCatalog
	}
	work, err := p.routeWork(s, caller, request, projection)
	return projection, work, err
}

// RouteTransportAllowed grants only the coarse MYDCP PathControl/Packet
// purpose for a currently approved original owner pair. Path scope, native
// readiness and every packet/flow still pass their existing owner gates.
func (p Policy) RouteTransportAllowed(s state.State, local, remote [32]byte) bool {
	if local == remote {
		return false
	}
	members, err := p.Members(s)
	if err != nil || !members.WorkKey(local) || !members.WorkKey(remote) {
		return false
	}
	projection, err := p.ProjectResources(s)
	if err != nil || projection.NetworkAuthority == nil {
		return false
	}
	for _, ref := range projection.NetworkAuthority.RouteReferences() {
		if !members.OwnsResource(local, ref.Local.Owner) || ref.Closed != nil || ref.RouteClosed != nil {
			continue
		}
		work, err := p.routeWork(s, local, RouteWorkRequest{Reference: ref.ID}, projection)
		if err == nil && work.PrepareAllowed && members.OwnsResource(remote, work.Peer.Local.Owner) {
			return true
		}
	}
	return false
}

// The caller checked membership and decoded this same immutable projection.
func (p Policy) routeWork(s state.State, caller [32]byte, request RouteWorkRequest, projection ResourceProjection) (RouteWork, error) {
	authority := *projection.NetworkAuthority
	ref, found := authority.ReferenceConsumer(request.Reference)
	if !found || ref.Route == nil || ref.Native == nil || !p.ownsResource(s, caller, ref.Local.Owner) || ref.Local.Cluster != p.Cluster {
		return RouteWork{}, ErrCatalog
	}
	spec, err := services.RouteTunnelDefinition(ref)
	if err != nil {
		return RouteWork{}, err
	}
	work := RouteWork{Schema: 1, Reference: ref, Tunnel: spec, ResourcesRevision: s.Object(ResourcesKey).Revision, AppsRevision: s.Object(AppsKey).Revision, Epoch: s.ModuleEpoch()}
	for _, peer := range authority.RouteReferences() {
		if peer.Route.Policy.Source.Tenant == ref.Route.Policy.Source.Tenant && peer.Route.Policy.ID == ref.Route.Policy.ID && peer.Route.Policy.Generation == ref.Route.Policy.Generation && peer.Route.Side != ref.Route.Side && authority.CurrentRouteReference(peer.ID) {
			work.Peer = peer
			break
		}
	}
	// Preparation can close after acceptance; cleanup still gets the same
	// frozen spec/dependencies. Missing current policy never means no effect.
	catalog, err := p.Catalog(s)
	if err != nil {
		return RouteWork{}, err
	}
	global, gok := projection.Resources.Quotas.Limit("", ref.Local.Node)
	scoped, sok := projection.Resources.Quotas.Limit(ref.Local.Tenant, ref.Local.Node)
	if gok && sok && projection.Resources.Quotas.SameOwner(ref.Local.Node, global.Owner, ref.Local.Owner) && projection.Resources.Quotas.SameOwner(ref.Local.Node, scoped.Owner, ref.Local.Owner) {
		work.MaxConsumers = min(global.MaxConsumers, scoped.MaxConsumers)
		work.Packets = network.PacketLimits{QueuePackets: min(global.PacketQueuePackets, scoped.PacketQueuePackets), QueueBytes: min(global.PacketQueueBytes, scoped.PacketQueueBytes)}
	}
	policy, current := projection.Resources.Networks.Route(ref.Route.Policy.Source.Tenant, ref.Route.Policy.ID)
	work.Retiring = current && policy.Generation == ref.Route.Policy.Generation && policy.Phase == tenancy.Revoking
	if !current || policy.Generation != ref.Route.Policy.Generation || policy.Revision != ref.DesiredSource || !projection.Resources.Networks.RouteAuthorized(catalog, policy.Source.Tenant, policy.ID) || !authority.CurrentRouteReference(ref.ID) || work.Peer.Route == nil || work.Peer.Native == nil || work.MaxConsumers < 1 || work.Packets.QueuePackets < 1 || work.Packets.QueueBytes < spec.MTU+120 {
		return work, nil
	}
	for _, original := range []services.ReferenceConsumer{ref, work.Peer} {
		binding, err := routeBridgeBinding(s, projection, routeReferenceBinding(original))
		owner, ownerErr := p.workNodeOwner(s, original.Local.Node)
		if err != nil || ownerErr != nil || !p.ownsResource(s, owner, original.Local.Owner) || binding != *original.Native {
			return work, nil
		}
		source := projection.ManagedSources[binding.Key]
		if source.Bridge == nil || source.Bridge.GatewayMode != network.ManagedGatewayMode {
			return work, nil // Legacy native needs an explicit management transition.
		}
		request := NativeRequest{Source: deployment.ObjectRef{Key: binding.Key, Generation: binding.Generation, Revision: binding.Revision}}
		permit, err := p.managedNetworkNativePermit(s, owner, request, projection, projection.ManagedSources[binding.Key])
		if err != nil || permit.Spec != binding.Spec {
			return work, nil
		}
	}
	if err := admitIngressConsumers(projection, deployment.GoalResources{Goal: deployment.GoalCommand{Tenant: ref.Local.Tenant, Node: ref.Local.Node, Owner: caller}}); err != nil {
		return work, nil
	}
	work.PrepareAllowed = true
	return work, nil
}
