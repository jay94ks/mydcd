// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"strconv"
	"time"

	"github.com/jay94ks/seafield/internal/ingress"
	"gopkg.in/yaml.v3"
)

// The yaml form of x-sfc.ingress is a list of routes
// (devel/design/yaml-formats.md 3.1). Listeners and the request/connection
// limits are not in the file: the listeners are the route gateway's shared
// listeners on the route's node (GatewayListeners, filled when planning) and
// the limits are DefaultIngressRuntime, lowered to the tenant's ingress
// limit. The Go fields and their JSON stay as they are.

// DefaultIngressRuntime is the limit set of every ingress declared in a file.
var DefaultIngressRuntime = IngressRuntime{
	MaxRequests:             64,
	MaxConnections:          256,
	MaxHeaderBytes:          16 << 10,
	MaxBodyBytes:            8 << 20,
	BufferBytes:             64 * (64 << 10), // ingress needs 64KiB of buffer per request
	RequestTimeoutMS:        int(30 * time.Second / time.Millisecond),
	DialTimeoutMS:           int(2 * time.Second / time.Millisecond),
	ResponseHeaderTimeoutMS: int(10 * time.Second / time.Millisecond),
	HealthIntervalMS:        int(time.Second / time.Millisecond),
}

// ingressRouteYAML is one route of x-sfc.ingress.
type ingressRouteYAML struct {
	ID      string           `yaml:"id,omitempty"`
	Node    string           `yaml:"node"`
	Host    string           `yaml:"host"`
	Prefix  string           `yaml:"prefix,omitempty"`
	Service string           `yaml:"service,omitempty"`
	Port    uint16           `yaml:"port,omitempty"`
	Network string           `yaml:"network,omitempty"`
	Health  string           `yaml:"health,omitempty"`
	Gateway string           `yaml:"gateway,omitempty"`
	Balance *ingress.Balance `yaml:"balance,omitempty"`
}

func (i *IngressDeclaration) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.SequenceNode || len(n.Content) == 0 || len(n.Content) > 256 {
		return inputError("INVALID_INGRESS", "x-sfc.ingress")
	}
	var routes []ingressRouteYAML
	if err := strictNode(n, &routes); err != nil {
		return err
	}
	out := IngressDeclaration{Node: routes[0].Node, Runtime: DefaultIngressRuntime, Routes: []IngressRouteDeclaration{}}
	ids := map[string]bool{}
	for at, r := range routes {
		if r.Node != out.Node {
			return inputError("INGRESS_NODE_MIXED", "x-sfc.ingress")
		}
		// An unnamed route is route-N by its place (IngressRoutes).
		id := r.ID
		if id == "" {
			id = "route-" + strconv.Itoa(at+1)
		} else if !identifier(id) {
			return inputError("INVALID_INGRESS_ROUTE", "x-sfc.ingress")
		}
		if ids[id] {
			return inputError("INVALID_INGRESS_ROUTE", "x-sfc.ingress")
		}
		ids[id] = true
		gateway := r.Gateway
		switch gateway {
		case "":
			gateway = "external"
		case "external", "local":
		default:
			return inputError("INVALID_INGRESS_ROUTE", "x-sfc.ingress")
		}
		out.Routes = append(out.Routes, IngressRouteDeclaration{ID: r.ID, Host: r.Host, Prefix: r.Prefix, Service: r.Service, Network: r.Network, Port: r.Port, HealthPath: r.Health, Gateway: gateway, Balance: r.Balance})
	}
	*i = out
	return nil
}

func (i IngressDeclaration) MarshalYAML() (any, error) {
	routes := []ingressRouteYAML{}
	declared := i.Routes
	if len(declared) == 0 {
		declared = IngressRoutes(i) // the older single-host form
	}
	for _, r := range declared {
		routes = append(routes, ingressRouteYAML{ID: r.ID, Node: i.Node, Host: r.Host, Prefix: r.Prefix, Service: r.Service, Port: r.Port, Network: r.Network, Health: r.HealthPath, Gateway: r.Gateway, Balance: r.Balance})
	}
	return routes, nil
}

// ingressGateways lists the gateways the routes use ("both" is both).
func ingressGateways(i IngressDeclaration) (external, local bool) {
	for _, r := range IngressRoutes(i) {
		switch r.Gateway {
		case "external":
			external = true
		case "both":
			external, local = true, true
		default:
			local = true
		}
	}
	return external, local
}

// GatewayListeners fills an ingress declared without listeners with the
// shared listeners of the gateways its routes use on its node. A
// declaration that names its own listeners is kept as it is.
func GatewayListeners(i IngressDeclaration, gateways ingress.GatewayConfiguration) (IngressDeclaration, error) {
	if len(i.Listeners) != 0 {
		return i, nil
	}
	external, local := ingressGateways(i)
	var listeners []ListenerDeclaration
	for _, g := range []struct {
		used    bool
		gateway ingress.Gateway
	}{{external, gateways.External}, {local, gateways.Local}} {
		if !g.used {
			continue
		}
		if !g.gateway.Enabled || len(g.gateway.Listeners) == 0 {
			return i, inputError("INGRESS_GATEWAY_REQUIRED", i.Node)
		}
		for _, l := range g.gateway.Listeners {
			listeners = append(listeners, ListenerDeclaration{Shared: l.ID})
		}
	}
	if len(listeners) > 16 {
		return i, inputError("INVALID_INGRESS", "x-sfc.ingress")
	}
	i.Listeners = listeners
	return i, nil
}

// LowerIngressRuntime lowers each limit to the given ceiling (0 keeps it).
func LowerIngressRuntime(r IngressRuntime, requests, connections, buffer int) IngressRuntime {
	if requests > 0 {
		r.MaxRequests = min(r.MaxRequests, requests)
	}
	if connections > 0 {
		r.MaxConnections = min(r.MaxConnections, connections)
	}
	if buffer > 0 {
		r.BufferBytes = min(r.BufferBytes, buffer)
	}
	// Each request in flight holds 64KiB of the buffer.
	r.MaxRequests = max(1, min(r.MaxRequests, r.BufferBytes/(64<<10)))
	return r
}
