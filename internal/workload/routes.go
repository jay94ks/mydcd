// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"github.com/jay94ks/mydcd/internal/network"
	"net/netip"
)

// ContainerRoute is part of the original immutable Task. Internal bridges do
// not grant a default route. Only admitted remote overlay pools get a route
// through the original local bridge gateway.
type ContainerRoute struct {
	Destination netip.Prefix
	Gateway     netip.Addr
}

func ValidateContainerRoutes(s ContainerSpec, bridge network.BridgeSpec) error {
	return validateContainerRoutes(s, &bridge)
}

func validateContainerRoutes(s ContainerSpec, bridge *network.BridgeSpec) error {
	if len(s.Routes) > 64 {
		return ErrPlacement
	}
	previous := ""
	for i, r := range s.Routes {
		p, g := r.Destination, r.Gateway
		if !p.IsValid() || p != p.Masked() || p.Bits() == 0 || !routeAddress(p.Addr()) || !routeAddress(g) || g.Is4() != p.Addr().Is4() || p.String() <= previous {
			return ErrPlacement
		}
		previous = p.String()
		local := s.IPv6
		if g.Is4() {
			local = s.IPv4
		}
		if !local.IsValid() || g == local || p.Contains(local) || p.Contains(g) {
			return ErrPlacement
		}
		for _, old := range s.Routes[:i] {
			if p.Overlaps(old.Destination) {
				return ErrPlacement
			}
		}
		if bridge != nil {
			allowed := false
			for _, pool := range bridge.Pools {
				if p.Overlaps(pool.Prefix) {
					return ErrPlacement
				}
				if pool.Prefix.Contains(local) && pool.Gateway == g && pool.Prefix.Contains(g) {
					allowed = true
				}
			}
			if !allowed {
				return ErrPlacement
			}
		}
	}
	return nil
}

func routeAddress(a netip.Addr) bool {
	return a.IsValid() && !a.Is4In6() && a.Zone() == "" && !a.IsUnspecified() && !a.IsMulticast() && !a.IsLoopback() && !a.IsLinkLocalUnicast()
}
