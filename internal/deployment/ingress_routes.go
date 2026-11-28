// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"

	"github.com/jay94ks/seafield/internal/ingress"
)

// IngressRoutes expands the legacy single host/backend declaration without
// creating a second routing implementation. Canonical route order is input
// order; ingress.NewTable remains the sole host/prefix matching authority.
func IngressRoutes(i IngressDeclaration) []IngressRouteDeclaration {
	if len(i.Routes) == 0 {
		return []IngressRouteDeclaration{{ID: "http", Host: i.Host, Prefix: "/", Service: i.Backend.Service, Network: i.Backend.Network, Port: i.Backend.Port, HealthPath: i.Backend.HealthPath, Gateway: i.Gateway, Balance: i.Balance}}
	}
	out := append([]IngressRouteDeclaration(nil), i.Routes...)
	for at := range out {
		r := &out[at]
		if r.ID == "" {
			r.ID = "route-" + strconv.Itoa(at+1)
		}
		if r.Prefix == "" {
			r.Prefix = "/"
		}
		if r.Port == 0 {
			r.Port = i.Backend.Port
		}
		if r.HealthPath == "" {
			r.HealthPath = i.Backend.HealthPath
		}
		if r.HealthPath == "" {
			r.HealthPath = "/"
		}
		if r.Network == "" {
			r.Network = i.Backend.Network
		}
		if r.Gateway == "" {
			r.Gateway = i.Gateway
		}
		if r.Balance == nil {
			r.Balance = i.Balance
		}
	}
	return out
}
func ingressForRoute(i IngressDeclaration, r IngressRouteDeclaration) IngressDeclaration {
	i.Backend.Service, i.Backend.Network, i.Backend.Port, i.Backend.HealthPath = r.Service, r.Network, r.Port, r.HealthPath
	return i
}
func ingressHasService(i IngressDeclaration, service string) bool {
	for _, r := range IngressRoutes(i) {
		if r.Service == service {
			return true
		}
	}
	return false
}
func validateIngressDeclaration(c Compose, i IngressDeclaration) error {
	// No listeners: the route gateways' shared listeners on the node, filled
	// when planning (GatewayListeners).
	if i.Runtime.validate() != nil || !identifier(i.Node) || len(i.Listeners) > 16 || len(i.Routes) > 256 {
		return inputError("INVALID_INGRESS", "x-sfc.ingress")
	}
	if len(i.Routes) > 0 && i.Host != "" {
		return inputError("AMBIGUOUS_INGRESS_ROUTES", "x-sfc.ingress")
	}
	routes := []ingress.Route{}
	for _, r := range IngressRoutes(i) {
		if r.Network != "" && !identifier(r.Network) || r.Port == 0 || !strings.HasPrefix(r.HealthPath, "/") || r.Balance != nil && r.Balance.Validate() != nil || r.Gateway != "" && r.Gateway != "external" && r.Gateway != "local" && r.Gateway != "both" {
			return inputError("INVALID_INGRESS_ROUTE", r.ID)
		}
		if _, ok := c.Services[r.Service]; !ok {
			return inputError("MISSING_BACKEND", r.Service)
		}
		routes = append(routes, ingress.Route{ID: r.ID, Host: r.Host, Prefix: r.Prefix, Service: r.Service})
	}
	// external/local routes may intentionally use the same host+prefix. Their
	// conflict checks happen independently at each selected shared gateway.
	for _, kind := range []string{"local", "external"} {
		selected := []ingress.Route{}
		for at, r := range routes {
			g := IngressRoutes(i)[at].Gateway
			if g == "" {
				g = "local"
			}
			if g == kind || g == "both" {
				selected = append(selected, r)
			}
		}
		if _, err := ingress.NewTable(selected); err != nil {
			return inputError("INVALID_INGRESS_ROUTE", "x-sfc.ingress")
		}
	}
	return nil
}

// AutomationPathRoutes lists "ROUTE HOSTPREFIX" for ingress routes whose
// prefix is the certificate automation path or below it. Plain HTTP
// requests there for hosts inside a registered domain always go to the ACME
// responder, so such a route is ignored for them; deploy goes on with a
// warning (devel/design/certificate-store.md §8). Broader prefixes such as
// "/" or "/.well-known" are not listed.
func AutomationPathRoutes(d IngressDeclaration) []string {
	automation := strings.TrimSuffix(ingress.ACMEChallengePath, "/")
	var out []string
	for _, r := range IngressRoutes(d) {
		if r.Prefix == automation || strings.HasPrefix(r.Prefix, automation+"/") {
			out = append(out, r.ID+" "+r.Host+r.Prefix)
		}
	}
	slices.Sort(out)
	return out
}

// AutomationPathRoutes is AutomationPathRoutes of the planned ingress.
func (b Blueprint) AutomationPathRoutes() []string {
	var out []string
	for _, s := range b.d.Steps {
		var d IngressDeclaration
		if s.Kind == "ingress" && json.Unmarshal(s.Goal, &d) == nil {
			out = append(out, AutomationPathRoutes(d)...)
		}
	}
	return out
}
