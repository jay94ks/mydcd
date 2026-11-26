// SPDX-License-Identifier: Apache-2.0

package network

import (
	"net/netip"
	"slices"
)

// RoutePool names overlay ownership without changing the native Bridge's
// independently scoped network/pool identity.
type RoutePool struct {
	Network, Owner string
	Prefix         netip.Prefix
}
type TunnelTopology struct {
	Tunnels map[string]TunnelSpec
	Pools   []RoutePool
}

// Peers requires a whole committed remote pool or host endpoint and its
// explicit opposite TUN intent. Neither routes nor packets create membership.
func (g TunnelTopology) Peers(key string) ([]string, error) {
	t, ok := g.Tunnels[key]
	if !ok || t.Lifecycle.Drain {
		return nil, ErrPolicy
	}
	peers := map[string]bool{}
	for _, route := range t.Routes {
		owner := ""
		assign := func(candidate string) bool {
			if owner != "" && owner != candidate {
				return false
			}
			owner = candidate
			return true
		}
		for _, p := range g.Pools {
			if p.Owner != t.Owner && p.Network == t.Network && p.Prefix == route && !assign(p.Owner) {
				return nil, ErrPolicy
			}
		}
		for _, other := range g.Tunnels {
			if other.Owner == t.Owner || other.Network != t.Network || other.Lifecycle.Released() {
				continue
			}
			for _, address := range other.Addresses {
				if address == route && !assign(other.Owner) {
					return nil, ErrPolicy
				}
			}
		}
		if owner == "" {
			return nil, ErrPolicy
		}
		remote := false
		for _, other := range g.Tunnels {
			if other.Owner == owner && other.Network == t.Network && !other.Lifecycle.Released() {
				remote = true
			}
		}
		if !remote {
			return nil, ErrPolicy
		}
		peers[owner] = true
	}
	owners := make([]string, 0, len(peers))
	for owner := range peers {
		owners = append(owners, owner)
	}
	slices.Sort(owners)
	return owners, nil
}
