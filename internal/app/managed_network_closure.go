// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"errors"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/network/services"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

// managedNetworkClosure signs only this owner's exact drained member, after
// shared address/reference preflight AND positive native Bridge/TUN closure.
// Every other member still owes its own proof. No new journal or RPC is used.
func (r *Runtime) managedNetworkClosure(ctx context.Context, v cluster.View, p control.ResourceProjection, n tenancy.Network) (*tenancy.NetworkClosure, error) {
	if r.network == nil || n.Owner != r.Identity.Public || n.Node == "" || !n.Draining || n.Logical == "" {
		return nil, errors.New("managed network closure requires its installed local owner and Drain")
	}
	current, found := p.Resources.Networks.Network(n.Tenant, n.ID)
	if !found || current.Owner != n.Owner || current.Node != n.Node || current.Generation != n.Generation || current.Revision != n.Revision || !current.Draining {
		return nil, errors.New("managed network closure source changed")
	}
	authority := p.NetworkAuthority
	if authority == nil {
		derived, err := services.NewAuthority(r.controlPolicy.Cluster, p.Addresses)
		if err != nil {
			return nil, err
		}
		authority = &derived
	}
	if authority.Cluster() != r.controlPolicy.Cluster || !authority.NetworkReferencesSettled(current) {
		return nil, nil
	}
	rows, err := p.Resources.Networks.TUNSources(n.Tenant, n.Logical)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if row.Network.ID != n.ID {
			continue
		}
		bridge, found := p.ManagedSources[row.BridgeKey]
		object := v.State.Object(row.BridgeKey)
		if !found || bridge.Bridge == nil || !object.Present || !bridge.Bridge.Lifecycle.Drain || bridge.Network.Generation != n.Generation || bridge.Network.Revision != n.Revision {
			return nil, errors.New("managed Bridge closure lacks its exact committed Drain")
		}
		gone, err := r.network.Gone(ctx, row.BridgeKey, object.Revision, object.Generation, *bridge.Bridge)
		if err != nil || !gone {
			return nil, err
		}
		if row.Tunnel != nil {
			tunnel, found := p.ManagedSources[row.TunnelKey]
			object := v.State.Object(row.TunnelKey)
			if r.tunnel == nil || !found || tunnel.Tunnel == nil || !object.Present || !tunnel.Tunnel.Lifecycle.Drain || tunnel.Network.Generation != n.Generation || tunnel.Network.Revision != n.Revision {
				return nil, errors.New("managed TUN closure lacks its exact committed Drain")
			}
			gone, err := r.tunnel.manager.Gone(ctx, row.TunnelKey, object.Revision, object.Generation, *tunnel.Tunnel)
			if err != nil || !gone {
				return nil, err
			}
		}
		proof := tenancy.NetworkClosure{Cluster: r.controlPolicy.Cluster, Tenant: n.Tenant, Network: n.ID, Node: n.Node, Owner: n.Owner, Generation: n.Generation, Revision: n.Revision, NativeGone: true}
		proof.Signature = ed25519.Sign(r.Identity.Private, tenancy.NetworkClosureBytes(proof))
		return &proof, nil
	}
	return nil, errors.New("managed network member has no original native source")
}
