// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/network"
)

// ResolveTunnel binds an original tunnel Goal to its exact committed bridge
// dependencies. It performs no OS IO and never claims path/native readiness.
func ResolveTunnel(cluster [32]byte, key string, o state.Object, objects map[string]state.Object) (network.TunnelSpec, error) {
	g, err := DecodeGoalResources(cluster, key, o)
	if err != nil || g.Goal.Kind != "tunnel" {
		return network.TunnelSpec{}, ErrInputs
	}
	goal := g.Goal
	prefix := ResourceKey("tunnel", goal.Tenant, goal.App, "root")
	parts := strings.Split(strings.TrimPrefix(key, strings.TrimSuffix(prefix, "root")), "/")
	if len(parts) != 2 || !identifier(parts[0]) || parts[1] != goal.Node || len(goal.Dependencies) < 2 || len(goal.Dependencies) > 64 {
		return network.TunnelSpec{}, ErrInputs
	}
	var addresses map[string]string
	if json.Unmarshal(goal.Config, &addresses) != nil || len(addresses) > 64 {
		return network.TunnelSpec{}, ErrInputs
	}
	// The route metric is part of the native adapter's schema=1 policy. Route
	// ownership/readback still rejects an existing foreign route at that metric.
	spec := network.TunnelSpec{Schema: 1, Owner: engine.Owner(cluster, goal.Owner), Network: goal.Tenant + "/" + goal.App + "/" + parts[0], RouteMetric: 100}
	owners := map[string]bool{}
	var pools []netip.Prefix
	for _, ref := range goal.Dependencies {
		source, exists := objects[ref.Key]
		if !exists || !source.Present || source.Generation != ref.Generation || source.Revision != ref.Revision {
			return spec, ErrInputs
		}
		bridge, err := DecodeGoalResources(cluster, ref.Key, source)
		if err != nil || bridge.Bridge == nil || bridge.Goal.Tenant != goal.Tenant || bridge.Goal.App != goal.App || bridge.Goal.Deployment != goal.Deployment || ref.Key != ResourceKey("bridge", goal.Tenant, goal.App, parts[0]+"/"+bridge.Goal.Node) || owners[bridge.Goal.Node] || bridge.Goal.Lifecycle != nil && bridge.Goal.Lifecycle.Drain {
			return spec, ErrInputs
		}
		owners[bridge.Goal.Node] = true
		if spec.MTU == 0 {
			spec.MTU = bridge.Bridge.MTU
		} else if spec.MTU != bridge.Bridge.MTU {
			return spec, ErrInputs
		}
		if bridge.Goal.Node == goal.Node && bridge.Goal.Owner != goal.Owner {
			return spec, ErrInputs
		}
		for _, pool := range bridge.Bridge.Pools {
			pools = append(pools, pool.Prefix)
			if bridge.Goal.Node != goal.Node {
				spec.Routes = append(spec.Routes, pool.Prefix)
			}
		}
	}
	if !owners[goal.Node] {
		return spec, ErrInputs
	}
	seen := map[netip.Addr]bool{}
	for node, address := range addresses {
		a, err := netip.ParsePrefix(address)
		if err != nil || !owners[node] || a.Bits() != a.Addr().BitLen() || seen[a.Addr()] {
			return spec, ErrInputs
		}
		seen[a.Addr()] = true
		for _, pool := range pools {
			if pool.Contains(a.Addr()) {
				return spec, ErrInputs
			}
		}
		if node == goal.Node {
			spec.Addresses = append(spec.Addresses, a)
		} else {
			spec.Routes = append(spec.Routes, a)
		}
	}
	if goal.Lifecycle != nil {
		spec.Lifecycle = *goal.Lifecycle
		spec.Lifecycle.Proof = slices.Clone(goal.Lifecycle.Proof)
	}
	for _, list := range [][]netip.Prefix{spec.Addresses, spec.Routes} {
		slices.SortFunc(list, func(a, b netip.Prefix) int { return strings.Compare(a.String(), b.String()) })
	}
	raw, _ := json.Marshal(spec)
	return network.DecodeTunnel(string(raw))
}
