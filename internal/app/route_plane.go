// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/network/services"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/schema"
)

func (t *tunnelRuntime) routeInstance(id [32]byte, name string) (*tunnelInstance, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil, errTunnelPending
	}
	if t.instances[network.NetworkID(t.r.policy.Cluster, name)] != nil {
		return nil, network.ErrPolicy
	}
	if t.routes == nil {
		t.routes = map[[32]byte]*tunnelInstance{}
	}
	i := t.routes[id]
	if i == nil {
		i = &tunnelInstance{r: t.r, network: name, paths: map[[32]byte]tunnelPath{}}
		t.routes[id] = i
	} else if i.network != name {
		return nil, network.ErrPolicy
	}
	return i, nil
}

func (t *tunnelRuntime) routeReading(id [32]byte) bool {
	t.mu.Lock()
	i := t.routes[id]
	t.mu.Unlock()
	return i != nil && i.routeReading.Load()
}

func (t *tunnelRuntime) routePacketReady(id [32]byte) bool {
	t.mu.Lock()
	i := t.routes[id]
	t.mu.Unlock()
	if i == nil || !i.routeReading.Load() {
		return false
	}
	plane := i.serving.Load()
	return plane != nil && plane.PathReady()
}

// The caller already synced/published the denying flow gate under routeMu.
// No instance/serving plane means no packet IO in this exclusive DB owner;
// an in-progress Stop must finish before its reader flag can prove closure.
func (t *tunnelRuntime) routePacketBarrier(ctx context.Context, id [32]byte) error {
	t.mu.Lock()
	i := t.routes[id]
	t.mu.Unlock()
	if i == nil {
		return ctx.Err()
	}
	if plane := i.serving.Load(); plane != nil {
		return plane.PacketBarrier(ctx)
	}
	if i.routeReading.Load() {
		return errTunnelPending
	}
	return ctx.Err()
}

func routePathScope(work control.RouteWork) ([]byte, int, error) {
	if !work.PrepareAllowed || work.Reference.Route == nil || work.Peer.Route == nil || work.Reference.Local.Owner == work.Peer.Local.Owner {
		return nil, 0, errTunnelPending
	}
	anchor := func(ref services.ReferenceConsumer) tunnelAnchor {
		return tunnelAnchor{Key: hex.EncodeToString(ref.ID[:]), Spec: hex.EncodeToString(ref.DesiredHash[:]), Revision: ref.DesiredSource, Generation: ref.Generation}
	}
	a, b := anchor(work.Reference), anchor(work.Peer)
	if bytes.Compare(work.Reference.Local.Owner[:], work.Peer.Local.Owner[:]) > 0 {
		a, b = b, a
	}
	id := network.NetworkID(work.Reference.Local.Cluster, work.Tunnel.Network)
	raw, err := json.Marshal(tunnelScope{Schema: 1, Network: hex.EncodeToString(id[:]), A: a, B: b})
	return raw, work.Tunnel.MTU, err
}

func (t *tunnelRuntime) routePathWork(v cluster.View, scope []byte) (control.RouteWork, bool, error) {
	var empty control.RouteWork

	s, err := schema.Decode[tunnelScope](scope)
	if err != nil {
		return empty, false, err
	}
	projection, err := t.r.controlPolicy.ProjectResources(v.State)
	if err != nil || projection.NetworkAuthority == nil {
		return empty, false, err
	}
	for _, ref := range projection.NetworkAuthority.RouteReferences() {
		if ref.Local.Owner != t.r.Identity.Public || ref.Native == nil {
			continue
		}
		spec, err := services.RouteTunnelDefinition(ref)
		if err != nil {
			return empty, false, err
		}
		id := network.NetworkID(ref.Local.Cluster, spec.Network)
		if s.Network != hex.EncodeToString(id[:]) {
			continue
		}
		work, err := t.r.controlPolicy.RouteWork(v.State, t.r.commandIdentity().Public, control.RouteWorkRequest{Reference: ref.ID})
		return work, true, err
	}
	return empty, false, nil
}

func routePacketPolicy(work control.RouteWork, authority services.Authority) (network.PacketPolicy, error) {
	ref := work.Reference
	id := network.NetworkID(ref.Local.Cluster, work.Tunnel.Network)
	var endpoints []network.Endpoint
	for _, allocation := range authority.AddressBook().Checkpoint().Allocations {
		for _, source := range []services.Source{ref.Route.Source, ref.Route.Destination} {
			pool := source.Tenant + "/" + source.Network + "/" + source.Pool
			if allocation.Pool != pool || allocation.Owner != hex.EncodeToString(source.Owner[:]) || !source.Prefix.Contains(allocation.Address) {
				continue
			}
			owner, err := identity.ParseKey(allocation.Owner)
			if err != nil {
				return network.PacketPolicy{}, err
			}
			endpoints = append(endpoints, network.Endpoint{Owner: owner, Network: id, ID: network.EndpointID(ref.Local.Cluster, work.Tunnel.Network, allocation.Owner, allocation.Endpoint, allocation.Generation, allocation.Address), Address: allocation.Address})
		}
	}
	return network.NewPacketPolicy(endpoints)
}

// Called outside routeMu: Stop must join a reader that may be waiting to enter
// its original owner. Native removal remains blocked until this join finishes.
func (t *tunnelRuntime) stopRetiringRoutePlanes(v cluster.View) error {
	t.mu.Lock()
	instances := make(map[[32]byte]*tunnelInstance, len(t.routes))
	for id, i := range t.routes {
		instances[id] = i
	}
	t.mu.Unlock()
	var failed error
	for id, i := range instances {
		work, err := t.r.controlPolicy.RouteWork(v.State, t.r.commandIdentity().Public, control.RouteWorkRequest{Reference: id})
		ready := err == nil && work.PrepareAllowed
		if ready {
			t.r.routeMu.Lock()
			record, found, readErr := t.r.loadRouteOwner(work.Reference)
			if readErr == nil && found {
				core, decodeErr := services.DecodeRouteRuntime(record.Core)
				ready = decodeErr == nil && !core.Journal().Stopped && core.Journal().Pending == nil && core.Journal().Desired.Present && core.Journal().Applied.Present
			} else {
				ready = false
			}
			t.r.routeMu.Unlock()
		}
		if ready {
			continue
		}
		i.mu.Lock()
		failed = errors.Join(failed, i.stopPlane())
		i.mu.Unlock()
	}
	return failed
}

func (t *tunnelRuntime) reconcileRoutePlanes(v cluster.View, projection control.ResourceProjection) error {
	if projection.NetworkAuthority == nil {
		return nil
	}
	for _, ref := range projection.NetworkAuthority.RouteReferences() {
		if ref.Local.Owner != t.r.Identity.Public || ref.Native == nil {
			continue
		}
		work, err := t.r.controlPolicy.RouteWork(v.State, t.r.commandIdentity().Public, control.RouteWorkRequest{Reference: ref.ID})
		if err != nil || !work.PrepareAllowed {
			continue
		}
		i, err := t.routeInstance(ref.ID, work.Tunnel.Network)
		if err != nil {
			return err
		}
		if err := t.reconcileRoutePlane(v, projection, work, i); err != nil {
			i.mu.Lock()
			i.lastError = err
			_ = i.stopPlane()
			i.mu.Unlock()
		}
	}
	return nil
}

func (t *tunnelRuntime) reconcileRoutePlane(v cluster.View, projection control.ResourceProjection, work control.RouteWork, i *tunnelInstance) error {
	r := t.r
	ref := work.Reference
	r.routeMu.Lock()
	record, found, err := r.loadRouteOwner(ref)
	if err != nil || !found || !record.NativeStarted || record.BridgeReturned || record.Report != nil || record.Retirement != nil {
		r.routeMu.Unlock()
		return errTunnelPending
	}
	core, err := services.DecodeRouteRuntime(record.Core)
	if err != nil || core.Journal().Pending != nil || !core.Journal().Desired.Present || !core.Journal().Applied.Present {
		r.routeMu.Unlock()
		return errTunnelPending
	}
	gate := r.routeGate(ref.ID)
	raw, err := json.Marshal(work.Tunnel)
	var io network.PacketIO
	if err == nil {
		io, err = r.nativeRouteDriver().PacketIO(ref.RouteNativeKey(), reconcile.Resource{Generation: ref.Generation, Present: true, Spec: string(raw)})
	}
	r.routeMu.Unlock()
	if err != nil {
		return err
	}
	policy, err := routePacketPolicy(work, *projection.NetworkAuthority)
	if err != nil {
		return err
	}
	wire, err := r.localTunnelWireKey(v)
	if err != nil {
		return err
	}
	peerWire, err := r.tunnelWireKey(v.State, work.Peer.Local.Owner)
	if err != nil {
		return err
	}
	plan := network.PacketPlan{WireKey: wire, Policy: policy, Peers: map[[32]byte]network.PacketPeer{}, Gate: gate, Admit: func(ctx context.Context, packet []byte) error { return r.admitRoutePacket(ctx, ref.ID, packet) }}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closed || r.ctx.Err() != nil {
		return errTunnelPending
	}
	if peerWire == wire {
		plan.LocalOwners = map[[32]byte]bool{ref.Local.Owner: true, work.Peer.Local.Owner: true}
		plan.Relay = func(endpoint network.Endpoint, token [16]byte, packet []byte) error {
			return t.relayRoutePacket(work.Peer.ID, token, packet)
		}
	} else {
		scope, mtu, err := routePathScope(work)
		if err != nil {
			return err
		}
		pub := work.Peer.Local.Owner
		path, known := i.paths[pub]
		if known {
			route, routeErr := currentRoute(path.Session, work.Tunnel, mtu)
			known = routeErr == nil && route == path.route && path.scope == string(scope) && [32]byte(path.Session.Peer().Key) == peerWire && path.Session.PathCurrent(path.Path)
		}
		if !known {
			if err := i.stopPlane(); err != nil {
				return err
			}
			if bytes.Compare(wire[:], peerWire[:]) > 0 {
				return errTunnelPending
			}
			peer, known := r.Mesh.Peer(mydcp.Identity(peerWire))
			if !known || !peer.Member {
				return mydcp.ErrAdmission
			}
			ctx, cancel := context.WithTimeout(r.ctx, 10*time.Second)
			defer cancel()
			session, err := r.Mesh.Dial(ctx, peer)
			if err != nil {
				return err
			}
			if current, err := session.NativeRouteCurrent(); err != nil || !current {
				_ = session.RetirePath()
				return errors.Join(err, errTunnelPending)
			}
			route, err := currentRoute(session, work.Tunnel, mtu)
			if err != nil {
				return err
			}
			pair, err := session.ObservePath(ctx, scope, mtu)
			if err != nil {
				return err
			}
			a, b := pair.Samples()
			if err := admitPair(pair, a, b); err != nil {
				return err
			}
			path = tunnelPath{PacketPeer: network.PacketPeer{WireKey: peerWire, Session: session, Path: pair}, route: route, scope: string(scope)}
			i.paths[pub] = path
		}
		path.WireKey = peerWire
		plan.Peers[pub] = path.PacketPeer
	}
	if i.plane != nil && i.plane.Err() == nil {
		i.plane.SetPlan(plan)
		return nil
	}
	if err := i.stopPlane(); err != nil {
		return err
	}
	plane, err := network.NewPacketPlane(r.ctx, r.Identity.Public, network.NetworkID(ref.Local.Cluster, work.Tunnel.Network), work.Tunnel, io, work.Packets, plan)
	if err != nil {
		return err
	}
	i.plane, i.key = plane, ref.RouteNativeKey()
	i.routeReading.Store(true)
	i.serving.Store(plane)
	return nil
}

func (t *tunnelRuntime) relayRoutePacket(destination [32]byte, token [16]byte, packet []byte) error {
	var selected *network.PacketPlane
	for _, owner := range t.r.physicalOwners() {
		candidate := owner.tunnel
		if candidate == nil {
			continue
		}
		candidate.mu.Lock()
		i, closed := candidate.routes[destination], candidate.closed
		candidate.mu.Unlock()
		if closed || i == nil {
			continue
		}
		plane := i.serving.Load()
		if plane == nil {
			continue
		}
		if selected != nil {
			return mydcp.ErrAdmission
		}
		selected = plane
	}
	if selected == nil {
		return errTunnelPending
	}
	return selected.ReceiveLocal(token, packet)
}
