// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/ingress"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/workload"
)

// GoalResources describes already-committed declaration space, not native
// readiness. Bridge is the typed immutable spec consumed by the real manager.
type GoalResources struct {
	Goal        GoalCommand
	Network     *tenancy.Network
	Bridge      *network.BridgeSpec
	Tunnel      *network.TunnelSpec
	Ingress     *ingress.Spec
	Reservation *tenancy.Reservation
}

func DecodeGoalResources(cluster [32]byte, key string, o state.Object) (GoalResources, error) {
	var out GoalResources
	g, err := schema.Decode[GoalCommand]([]byte(o.Value))
	if err != nil || !o.Present || o.Generation == 0 || o.Revision < o.Generation || g.Schema != 1 || g.Cluster != cluster || !identifier(g.Tenant) || !identifier(g.App) || !identifier(g.Deployment) {
		return out, ErrInputs
	}
	prefix := ResourceKey(g.Kind, g.Tenant, g.App, "root")
	if prefix == "" || !strings.HasPrefix(key, prefix[:len(prefix)-4]) || ResourceKey(g.Kind, g.Tenant, g.App, strings.TrimPrefix(key, prefix[:len(prefix)-4])) != key {
		return out, ErrInputs
	}
	if g.Node != "" && (!identifier(g.Node) || g.Owner == ([32]byte{})) || g.Node == "" && (g.Owner != ([32]byte{}) || g.Kind != "namespace" && g.Kind != "delivery" && g.Kind != "route") {
		return out, ErrInputs
	}
	if len(g.ResourceKeys) > 0 && !lifecycle.ResourceIdentity(cluster, g.Node, g.Owner, g.Owner, g.ResourceKeys) {
		return out, ErrInputs
	}
	if g.Lifecycle != nil && !g.Lifecycle.Valid() {
		return out, ErrInputs
	}
	if len(g.Follow) != 0 {
		var declaration IngressDeclaration
		if g.Kind != "ingress" || len(g.Follow) > 1024 || !slices.IsSorted(g.Follow) || json.Unmarshal(g.Config, &declaration) != nil {
			return out, ErrInputs
		}
		for index, key := range g.Follow {
			instance, err := ReplicaInstanceForKey(g.Tenant, g.App, key)
			if err != nil || !ingressHasService(declaration, instance.Service) || index > 0 && g.Follow[index-1] == key {
				return out, ErrInputs
			}
		}
	}
	draining := g.Lifecycle != nil && g.Lifecycle.Drain
	out.Goal = g
	switch g.Kind {
	case "bridge":
		var b bridgeDeclaration
		if json.Unmarshal(g.Config, &b) != nil || b.Pool.AddressPlan != nil || !identifier(b.Network) || ResourceKey("bridge", g.Tenant, g.App, b.Network+"/"+g.Node) != key {
			return out, ErrInputs
		}
		prefix, err := netip.ParsePrefix(b.Pool.CIDR)
		if err != nil {
			return out, err
		}
		gateway, err := netip.ParseAddr(b.Pool.Gateway)
		if err != nil {
			return out, err
		}
		id := PoolID(g.Tenant, g.App, b.Network, g.Node)
		owner := engine.Owner(cluster, g.Owner)
		spec := network.BridgeSpec{Schema: 1, Network: id, Owner: owner, MTU: b.MTU, Internal: true, Pools: []network.Pool{{ID: id + "/pool", Network: id, Owner: owner, Prefix: prefix, Gateway: gateway, MTU: b.MTU}}}
		if g.Lifecycle != nil {
			spec.Lifecycle = *g.Lifecycle
			spec.Lifecycle.Proof = append([]byte(nil), g.Lifecycle.Proof...)
		}
		raw, _ := json.Marshal(spec)
		if _, err = network.DecodeBridge(string(raw)); err != nil {
			return out, err
		}
		out.Bridge = &spec
		out.Network = &tenancy.Network{Tenant: g.Tenant, ID: id, Node: g.Node, Owner: g.Owner, Generation: o.Generation, Revision: o.Revision, Draining: draining, Pools: []tenancy.Subnet{{ID: "pool", Prefix: prefix, Gateway: gateway, MTU: b.MTU}}}
	case "task", "registry":
		var need workload.Resources
		if g.Kind == "task" {
			var s ComposeService
			if json.Unmarshal(g.Config, &s) != nil || s.Sfc.Node != g.Node {
				return out, ErrInputs
			}
			if _, err := TaskInstanceForKey(g.Tenant, g.App, key, s); err != nil {
				return out, err
			}
			need.CPU, err = nanoCPU(s.CPUs)
			if err == nil {
				need.Memory, err = byteSize(s.Memory)
			}
		} else {
			var r RegistryDeclaration
			if json.Unmarshal(g.Config, &r) != nil || r.Node != g.Node {
				return out, ErrInputs
			}
			need.CPU, err = nanoCPU(r.Resources.CPUs)
			need.Memory = r.Resources.Memory
		}
		if err != nil || need.CPU == 0 || need.Memory == 0 {
			return out, ErrInputs
		}
		out.Reservation = &tenancy.Reservation{Key: key, Tenant: g.Tenant, Node: g.Node, Owner: g.Owner, Generation: o.Generation, Revision: o.Revision, Need: need, Draining: draining}
	}
	return out, nil
}
