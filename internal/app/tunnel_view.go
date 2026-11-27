// SPDX-License-Identifier: Apache-2.0

package app

import (
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/tenancy"
)

type tunnelBudget struct {
	Consumers int
	Packets   network.PacketLimits
}

// tunnelView is an owned routing projection of one committed logical network.
// Native Bridge identity is not rewritten to its packet namespace.
type tunnelView struct {
	Topology network.TunnelTopology
	Owners   map[string][32]byte
	Budgets  map[string]tunnelBudget
	Packets  network.PacketPolicy
	Rows     map[string]state.Object
}

func newTunnelView() tunnelView {
	return tunnelView{Topology: network.TunnelTopology{Tunnels: map[string]network.TunnelSpec{}}, Owners: map[string][32]byte{}, Budgets: map[string]tunnelBudget{}, Rows: map[string]state.Object{}}
}

func (r *Runtime) tunnelViews(s state.State) (map[string]tunnelView, error) {
	projection, err := r.controlPolicy.ProjectResources(s)
	if err != nil {
		return nil, err
	}
	return managedTunnelViews(r.controlPolicy.Cluster, s, projection)
}

func managedTunnelViews(cluster [32]byte, s state.State, p control.ResourceProjection) (map[string]tunnelView, error) {
	views := map[string]tunnelView{}
	objects := s.Objects("")
	endpoints := map[string][]network.Endpoint{}
	hosts := p.Resources.Networks.ClusterAppHosts()
	add := func(name, key, owner string, pub [32]byte, a netip.Addr) {
		endpoints[name] = append(endpoints[name], network.Endpoint{Owner: pub, Network: network.NetworkID(cluster, name), ID: network.EndpointID(cluster, name, owner, key, s.Object(key).Generation, a), Address: a})
	}
	for key, source := range p.ManagedSources {
		if source.Closed != nil || source.Tunnel == nil {
			continue
		}
		t := *source.Tunnel
		view, exists := views[t.Network]
		if !exists {
			view = newTunnelView()
		}
		for _, prior := range view.Topology.Tunnels {
			if prior.Owner == t.Owner && !prior.Lifecycle.Released() && !t.Lifecycle.Released() {
				return nil, network.ErrPolicy
			}
		}
		view.Topology.Tunnels[key] = t
		view.Rows[key] = s.Object(key)
		view.Owners[t.Owner] = source.Network.Owner
		global, gok := p.Resources.Quotas.Limit("", source.Network.Node)
		scoped, sok := p.Resources.Quotas.Limit(source.Network.Tenant, source.Network.Node)
		if gok && sok && p.Resources.Quotas.SameOwner(source.Network.Node, global.Owner, source.Network.Owner) && p.Resources.Quotas.SameOwner(source.Network.Node, scoped.Owner, source.Network.Owner) {
			view.Budgets[t.Owner] = tunnelBudget{Consumers: min(global.MaxConsumers, scoped.MaxConsumers), Packets: network.PacketLimits{QueuePackets: min(global.PacketQueuePackets, scoped.PacketQueuePackets), QueueBytes: min(global.PacketQueueBytes, scoped.PacketQueueBytes)}}
		}
		if !t.Lifecycle.Released() {
			for _, address := range t.Addresses {
				add(t.Network, key, t.Owner, source.Network.Owner, address.Addr())
			}
		}
		for bridgeKey, bridge := range p.ManagedSources {
			if bridge.Closed != nil || bridge.Bridge == nil || bridge.Network.Tenant != source.Network.Tenant || bridge.Network.Logical != source.Network.Logical {
				continue
			}
			if _, present := view.Rows[bridgeKey]; present {
				continue
			}
			view.Rows[bridgeKey] = s.Object(bridgeKey)
			view.Owners[bridge.Bridge.Owner] = bridge.Network.Owner
			if !bridge.Bridge.Lifecycle.Released() {
				for _, pool := range bridge.Bridge.Pools {
					view.Topology.Pools = append(view.Topology.Pools, network.RoutePool{Network: t.Network, Owner: bridge.Bridge.Owner, Prefix: pool.Prefix})
					add(t.Network, bridgeKey, bridge.Bridge.Owner, bridge.Network.Owner, pool.Gateway)
				}
				if bridge.Network.System {
					// the cluster apps this member runs: their cluster-wide
					// addresses are its, like its pool (tenancy ClusterAppHosts)
					for _, a := range hosts[bridge.Network.Node] {
						view.Topology.Pools = append(view.Topology.Pools, network.RoutePool{Network: t.Network, Owner: bridge.Bridge.Owner, Prefix: netip.PrefixFrom(a, 32)})
						add(t.Network, bridgeKey, bridge.Bridge.Owner, bridge.Network.Owner, a)
					}
				}
			}
		}
		views[t.Network] = view
	}
	for key, g := range p.Goals {
		if g.Tunnel == nil {
			continue
		}
		t := *g.Tunnel
		view, ok := views[t.Network]
		if !ok {
			view = newTunnelView()
		}
		for _, prior := range view.Topology.Tunnels {
			if prior.Owner == t.Owner && !prior.Lifecycle.Released() && !t.Lifecycle.Released() {
				return nil, network.ErrPolicy
			}
		}
		view.Topology.Tunnels[key] = t
		view.Rows[key] = s.Object(key)
		view.Owners[t.Owner] = g.Goal.Owner
		global, gok := p.Resources.Quotas.Limit("", g.Goal.Node)
		scoped, sok := p.Resources.Quotas.Limit(g.Goal.Tenant, g.Goal.Node)
		if gok && sok && p.Resources.Quotas.SameOwner(g.Goal.Node, global.Owner, g.Goal.Owner) && p.Resources.Quotas.SameOwner(g.Goal.Node, scoped.Owner, g.Goal.Owner) {
			view.Budgets[t.Owner] = tunnelBudget{Consumers: min(global.MaxConsumers, scoped.MaxConsumers), Packets: network.PacketLimits{QueuePackets: min(global.PacketQueuePackets, scoped.PacketQueuePackets), QueueBytes: min(global.PacketQueueBytes, scoped.PacketQueueBytes)}}
		}
		if !t.Lifecycle.Released() {
			for _, a := range t.Addresses {
				add(t.Network, key, t.Owner, g.Goal.Owner, a.Addr())
			}
		}
		for _, dep := range g.Goal.Dependencies {
			if _, exists := view.Rows[dep.Key]; exists {
				continue
			}
			bridge, exists := p.Goals[dep.Key]
			if !exists || bridge.Bridge == nil {
				return nil, network.ErrPolicy
			}
			view.Rows[dep.Key] = s.Object(dep.Key)
			view.Owners[bridge.Bridge.Owner] = bridge.Goal.Owner
			if bridge.Bridge.Lifecycle.Released() {
				continue
			}
			for _, pool := range bridge.Bridge.Pools {
				view.Topology.Pools = append(view.Topology.Pools, network.RoutePool{Network: t.Network, Owner: bridge.Bridge.Owner, Prefix: pool.Prefix})
				add(t.Network, dep.Key, bridge.Bridge.Owner, bridge.Goal.Owner, pool.Gateway)
			}
		}
		views[t.Network] = view
	}
	for key, g := range p.Goals {
		if g.Goal.Kind != "task" || g.Goal.Lifecycle != nil && g.Goal.Lifecycle.Released() {
			continue
		}
		var service deployment.ComposeService
		if json.Unmarshal(g.Goal.Config, &service) != nil {
			return nil, network.ErrPolicy
		}
		for alias, attachment := range service.Networks {
			name := g.Goal.Tenant + "/" + g.Goal.App + "/" + alias
			refKey := deployment.ResourceKey("network-ref", g.Goal.Tenant, g.Goal.App, alias+"/"+g.Goal.Node)
			if reference, exists := p.Goals[refKey]; exists {
				var ref deployment.NetworkReference
				if json.Unmarshal(reference.Goal.Config, &ref) != nil {
					return nil, network.ErrPolicy
				}
				if ref.PacketNetwork != "" {
					name = ref.PacketNetwork
				}
			}
			view, exists := views[name]
			if !exists {
				continue
			}
			view.Rows[key] = s.Object(key)
			if _, exists := p.Goals[refKey]; exists {
				view.Rows[refKey] = s.Object(refKey)
			}
			for family, address := range []string{attachment.IPv4, attachment.IPv6} {
				if address != "" {
					a, err := netip.ParseAddr(address)
					if err != nil {
						return nil, err
					}
					material, materialErr := deployment.ResolveRetainedTaskNetwork(cluster, g.Goal, alias, objects)
					packetOwner := material.NativeOwner(cluster)
					endpoint := key + "/" + alias + "/" + strconv.Itoa(family)
					allocation, held := p.Addresses.Allocation(endpoint)
					pool, pooled := p.Addresses.Pool(allocation.Pool)
					if materialErr != nil || packetOwner == ([32]byte{}) || !held || !pooled || allocation.Owner != hex.EncodeToString(packetOwner[:]) || pool.Owner != allocation.Owner || allocation.Generation != s.Object(key).Generation || allocation.Address != a {
						return nil, network.ErrPolicy
					}
					owner := engine.Owner(cluster, packetOwner)
					view.Owners[owner] = packetOwner
					add(name, key, owner, packetOwner, a)
				}
			}
			views[name] = view
		}
	}
	for name, view := range views {
		packets, err := network.NewPacketPolicy(endpoints[name])
		if err != nil {
			return nil, err
		}
		view.Packets = packets
		views[name] = view
	}
	return views, nil
}

// Transport admission remains a cheap check over already-validated committed
// Goals. Exact refs, bilateral scope, endpoint and native budgets are checked
// again by the path/packet owner. A pair in different networks grants nothing.
func managedTunnelGrant(s state.State, local, remote [32]byte, policies ...control.Policy) bool {
	current := func(original [32]byte) [32]byte {
		if len(policies) == 1 {
			return policies[0].ResourceWorkKey(s, original)
		}
		return original
	}
	if local == remote {
		return false
	}
	networks := map[string]uint8{}
	for key, o := range s.Objects(tenancy.ManagedNetworkSourcePrefix + "tun/") {
		if !o.Present {
			continue
		}
		source, identityErr := tenancy.ParseSourceIdentity(key)
		t, err := network.DecodeTunnel(o.Value)
		owner := strings.Split(t.Owner, "/")
		if err != nil || identityErr != nil || source.Kind != "tun" || len(owner) != 2 || len(owner[0]) != 64 || t.Network != tenancy.PacketNamespace(source.Tenant, source.Network) || t.Lifecycle.Drain {
			continue
		}
		bit := uint8(0)
		original, decodeErr := hex.DecodeString(owner[1])
		if decodeErr != nil || len(original) != 32 {
			continue
		}
		wire := current([32]byte(original))
		if wire == local {
			bit = 1
		} else if wire == remote {
			bit = 2
		}
		name := owner[0] + "/" + t.Network
		networks[name] |= bit
		if networks[name] == 3 {
			return true
		}
	}
	for key, o := range s.Objects("network/tun/") {
		if !o.Present {
			continue
		}
		parts := strings.Split(key, "/")
		var g deployment.GoalCommand
		if len(parts) != 6 || json.Unmarshal([]byte(o.Value), &g) != nil || g.Kind != "tunnel" || g.Tenant != parts[2] || g.App != parts[3] || g.Node != parts[5] || g.Lifecycle != nil && g.Lifecycle.Drain {
			continue
		}
		name := strings.Join(parts[2:5], "/")
		bit := uint8(0)
		if current(g.Owner) == local {
			bit = 1
		} else if current(g.Owner) == remote {
			bit = 2
		}
		networks[name] |= bit
		if networks[name] == 3 {
			return true
		}
	}
	return false
}
