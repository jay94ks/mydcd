// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/json"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/network/services"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

// NetworkJoin adds one server to an existing TUN network (join-tun-network).
// The other members keep their reservations and native sources; only their
// tunnel route sets are rewritten in place.
type NetworkJoin struct {
	Tenant, Name string
	Member       tenancy.TUNNode
}

// NetworkToggleSet turns one toggle of a TUN network on or off
// (set-network-toggle). Expected is the networks revision. No native source
// changes: the device is the same whatever the toggles are.
type NetworkToggleSet struct {
	Tenant, Name string
	Toggle       tenancy.NetworkToggle
	On           bool
}

// joinManagedNetworkSources writes the joiner's sources and rewrites every
// other member's tunnel source in place (same object and generation), so its
// node changes routes under the same device. No existing bridge is written.
func joinManagedNetworkSources(s state.State, networks tenancy.Networks, tenant, name, node string) (map[string][]byte, error) {
	rows, err := networks.TUNSources(tenant, name)
	if err != nil {
		return nil, err
	}
	writes := map[string][]byte{}
	for _, row := range rows {
		if row.Tunnel == nil {
			return nil, ErrCatalog
		}
		if row.Network.Node == node {
			if s.Object(row.BridgeKey).Present || s.Object(row.TunnelKey).Present {
				return nil, ErrCatalog
			}
			writes[row.BridgeKey], _ = json.Marshal(row.Bridge)
		} else if !s.Object(row.BridgeKey).Present || !s.Object(row.TunnelKey).Present {
			return nil, ErrCatalog
		}
		writes[row.TunnelKey], _ = json.Marshal(row.Tunnel)
	}
	return writes, nil
}

// leaveNetwork retires one drained member (leave-tun-network) on its own
// signed closure. Its Bridge and TUN sources are withdrawn and archived as
// closed; every other member keeps its reservation, Bridge and device, and
// only its TUN route set is rewritten in place.
func (p Policy) leaveNetwork(s state.State, c access.Catalog, r Resources, op UserOperation) (tenancy.Networks, map[string][]byte, error) {
	var proof tenancy.NetworkClosure
	if canonical(op.Change.Payload, &proof) != nil {
		return r.Networks, nil, access.ErrInvalid
	}
	v, ok := r.Networks.Network(proof.Tenant, proof.Network)
	if !ok || v.Logical == "" || !v.Draining || v.Revision != op.Change.Expected {
		return r.Networks, nil, ErrCatalog
	}
	var sources []services.RetiredNativeSource
	for _, kind := range []string{"bridge", "tun"} {
		key := (tenancy.SourceIdentity{Kind: kind, Tenant: v.Tenant, Network: v.Logical, Node: v.Node}).Key()
		o := s.Object(key)
		if !o.Present {
			return r.Networks, nil, ErrCatalog
		}
		source := services.RetiredNativeSource{Key: key, Generation: o.Generation, Revision: o.Revision}
		if kind == "bridge" {
			b, err := network.DecodeBridge(o.Value)
			if err != nil || !b.Lifecycle.Drain {
				return r.Networks, nil, ErrCatalog
			}
			b.Lifecycle = schema.Lifecycle{}
			source.Bridge = &b
		} else {
			t, err := network.DecodeTunnel(o.Value)
			if err != nil || !t.Lifecycle.Drain {
				return r.Networks, nil, ErrCatalog
			}
			t.Lifecycle = schema.Lifecycle{}
			source.Tunnel = &t
		}
		sources = append(sources, source)
	}
	projection, err := p.ProjectResources(s)
	if err != nil {
		return r.Networks, nil, err
	}
	authority, err := projection.addressAuthority(p.Cluster)
	if err != nil {
		return r.Networks, nil, err
	}
	authority, next, err := authority.LeaveTUN(c, r.Networks, op.Change.Principal, proof, sources)
	if err != nil || r.Quotas.ValidateNetworks(next) != nil {
		if err == nil {
			err = ErrCatalog
		}
		return r.Networks, nil, err
	}
	writes, err := p.networkTransitionWrites(s, authority, next, v.Tenant, v.Logical, false)
	if err != nil {
		return r.Networks, nil, err
	}
	for _, source := range sources {
		writes[source.Key] = nil
	}
	rows, err := next.TUNSources(v.Tenant, v.Logical)
	if err != nil {
		return r.Networks, nil, err
	}
	for _, row := range rows {
		if row.Tunnel == nil || !s.Object(row.TunnelKey).Present {
			return r.Networks, nil, ErrCatalog
		}
		writes[row.TunnelKey], _ = json.Marshal(row.Tunnel)
	}
	return next, writes, nil
}
