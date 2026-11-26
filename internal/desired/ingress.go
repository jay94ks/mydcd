// SPDX-License-Identifier: Apache-2.0

package desired

import (
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/ingress"
	"github.com/jay94ks/mydcd/internal/network"
	"net/netip"
	"strconv"
)

func (g Graph) validateIngress(s state.State) error {
	for _, n := range g.Nodes {
		if n.MaxIngressInstances < 0 || n.MaxIngressInstances > 128 || n.MaxIngressListeners < 0 || n.MaxIngressListeners > 256 || n.MaxIngressRequests < 0 || n.MaxIngressRequests > 65536 || n.MaxIngressConnections < 0 || n.MaxIngressConnections > 65536 || n.IngressBufferBytes < 0 || n.IngressBufferBytes > 256<<20 {
			return ErrPolicy
		}
	}
	counts, requests, connections, buffers := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	ports := map[string]network.Ports{}
	consumers := map[string]int{}
	owners := map[string]string{}
	sharedRoutes := map[string][]ingress.Route{}
	for key, b := range g.Bridges {
		if !b.Lifecycle.Released() {
			owners[key] = b.Owner
		}
	}
	for key, t := range g.Tunnels {
		if !t.Lifecycle.Released() {
			consumers[key] = 1
			owners[key] = t.Owner
		}
	}
	for _, t := range g.Tasks {
		if !t.Lifecycle.Released() {
			consumers[t.Bridge]++
		}
	}
	for _, key := range Sorted(g.Ingress) {
		v := g.Ingress[key]
		if v.Lifecycle.Released() {
			continue
		}
		n, ok := g.Nodes[v.Owner]
		direct := false
		for _, l := range v.Listeners {
			direct = direct || l.Shared == ""
		}
		if !ok || n.MaxIngressInstances == 0 || direct && n.MaxIngressListeners == 0 {
			return ErrPolicy
		}
		counts[v.Owner]++
		requests[v.Owner] += v.MaxRequests
		connections[v.Owner] += v.MaxConnections
		buffers[v.Owner] += v.BufferBytes
		if counts[v.Owner] > n.MaxIngressInstances || requests[v.Owner] > n.MaxIngressRequests || connections[v.Owner] > n.MaxIngressConnections || buffers[v.Owner] > n.IngressBufferBytes {
			return ErrPolicy
		}
		p, ok := ports[v.Owner]
		if !ok {
			p, _ = network.NewPorts(n.MaxIngressListeners)
		}
		for _, l := range v.Listeners {
			if l.Shared != "" {
				for _, gateway := range []string{"local", "external"} {
					id := v.Owner + "/" + l.Shared + "/" + gateway
					for _, route := range v.Routes {
						g := route.Gateway
						if g == "" {
							g = "local"
						}
						if g == gateway || g == "both" {
							route.ID = key + "/" + route.ID
							sharedRoutes[id] = append(sharedRoutes[id], route)
						}
					}
					if _, err := ingress.NewTable(sharedRoutes[id]); err != nil {
						return err
					}
				}
				continue
			}
			a, _ := netip.ParseAddrPort(l.Address)
			for _, proto := range []uint8{6, 17} {
				if proto == 17 && !l.HTTP3 {
					continue
				}
				var err error
				p, err = p.Reserve(network.Listener{ID: key + "/" + l.ID + "/" + strconv.Itoa(int(proto)), Owner: v.Owner, Generation: s.Object(key).Generation, Address: a.Addr(), Protocol: proto, Port: a.Port()})
				if err != nil {
					return err
				}
			}
		}
		ports[v.Owner] = p
		for _, svc := range v.Services {
			for _, b := range svc.Backends {
				t, ok := g.Tasks[b.Task]
				if !ok || t.Lifecycle.Drain || s.Object(b.Task).Generation != b.Generation || b.Address != t.IPv4 && b.Address != t.IPv6 || g.Bridges[t.Bridge].Network != b.Network {
					return ErrPolicy
				}
				if t.Node != v.Owner {
					// Shared Ingress is a durable task/path reference until the owner
					// commits signed Gone. It cannot be bypassed by remote task Drain.
					for _, owner := range []string{v.Owner, t.Node} {
						found := false
						for _, tun := range g.Tunnels {
							if tun.Owner == owner && tun.Network == b.Network && !tun.Lifecycle.Drain {
								found = true
							}
						}
						if !found {
							return ErrPolicy
						}
					}
					for key, tun := range g.Tunnels {
						if tun.Owner == v.Owner && tun.Network == b.Network && !tun.Lifecycle.Drain {
							consumers[key]++
						}
					}
				} else {
					consumers[t.Bridge]++
				}
			}
		}
	}
	for key, n := range consumers {
		if n > g.Nodes[owners[key]].MaxConsumers {
			return ErrPolicy
		}
	}
	return nil
}
