// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"github.com/jay94ks/seafield/internal/network"
	"net/netip"
)

// ContainerRoute is part of the original immutable Task. Internal bridges do
// not grant a default route. Only admitted remote overlay pools get a route
// through the original local bridge gateway.
type ContainerRoute struct {
	Destination netip.Prefix
	Gateway     netip.Addr
}

// ValidateContainerRoutes checks the Task's routes against the Bridge specs
// of its attachments, given in ContainerSpec.Networks order.
func ValidateContainerRoutes(s ContainerSpec, bridges ...network.BridgeSpec) error {
	if bridges == nil {
		bridges = []network.BridgeSpec{}
	}
	return validateContainerRoutes(s, bridges)
}

// attachedRoute is one route with the index (Networks order) of the
// attachment it leaves through: ContainerSpec.Routes leave through the
// primary attachment, each TaskAttachment.Routes through that attachment.
type attachedRoute struct {
	at    int
	route ContainerRoute
}

func (s ContainerSpec) allRoutes() []attachedRoute {
	var out []attachedRoute
	for i, a := range s.Networks() {
		routes := s.Routes
		if i > 0 {
			routes = a.Routes
		}
		for _, r := range routes {
			out = append(out, attachedRoute{at: i, route: r})
		}
	}
	return out
}

// A nil bridges checks only the spec itself (decode time). With bridges, each
// route's gateway must be in a pool of its own attachment's Bridge.
func validateContainerRoutes(s ContainerSpec, bridges []network.BridgeSpec) error {
	networks := s.Networks()
	all := s.allRoutes()
	if len(all) > 64 || bridges != nil && len(bridges) != len(networks) {
		return ErrPlacement
	}
	previous := map[int]string{}
	for i, ar := range all {
		p, g := ar.route.Destination, ar.route.Gateway
		if !p.IsValid() || p != p.Masked() || p.Bits() == 0 || !routeAddress(p.Addr()) || !routeAddress(g) || g.Is4() != p.Addr().Is4() || p.String() <= previous[ar.at] || p.Contains(g) {
			return ErrPlacement
		}
		previous[ar.at] = p.String()
		local := routeFamily(networks[ar.at], g)
		if !local.IsValid() || g == local {
			return ErrPlacement
		}
		for _, a := range networks {
			if other := routeFamily(a, g); other.IsValid() && p.Contains(other) {
				return ErrPlacement
			}
		}
		for _, old := range all[:i] {
			if p.Overlaps(old.route.Destination) {
				return ErrPlacement
			}
		}
		if bridges != nil {
			for _, bridge := range bridges {
				for _, pool := range bridge.Pools {
					if p.Overlaps(pool.Prefix) {
						return ErrPlacement
					}
				}
			}
			allowed := false
			for _, pool := range bridges[ar.at].Pools {
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

func routeFamily(a TaskAttachment, gateway netip.Addr) netip.Addr {
	if gateway.Is4() {
		return a.IPv4
	}
	return a.IPv6
}

func routeAddress(a netip.Addr) bool {
	return a.IsValid() && !a.Is4In6() && a.Zone() == "" && !a.IsUnspecified() && !a.IsMulticast() && !a.IsLoopback() && !a.IsLinkLocalUnicast()
}
