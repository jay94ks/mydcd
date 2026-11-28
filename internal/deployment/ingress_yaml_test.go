// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/ingress"
	"gopkg.in/yaml.v3"
)

func TestIngressYAMLIsARouteList(t *testing.T) {
	const list = `- {node: node-b, host: shop.example.com, service: web, port: 8080, health: /readyz}
- {id: admin, node: node-b, host: shop.example.com, prefix: /admin, service: web, port: 8080, gateway: local}
`
	var d IngressDeclaration
	if err := yaml.Unmarshal([]byte(list), &d); err != nil {
		t.Fatal(err)
	}
	if d.Node != "node-b" || d.Runtime != DefaultIngressRuntime || len(d.Listeners) != 0 || len(d.Routes) != 2 {
		t.Fatalf("parse: %+v", d)
	}
	routes := IngressRoutes(d)
	if routes[0].ID != "route-1" || routes[0].Gateway != "external" || routes[0].HealthPath != "/readyz" || routes[1].ID != "admin" || routes[1].Gateway != "local" || routes[1].HealthPath != "/" {
		t.Fatalf("routes: %+v", routes)
	}
	raw, err := yaml.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var again IngressDeclaration
	if err := yaml.Unmarshal(raw, &again); err != nil || len(again.Routes) != 2 || again.Routes[0] != d.Routes[0] || again.Routes[1] != d.Routes[1] {
		t.Fatalf("round trip:\n%s%+v %v", raw, again, err)
	}
	for name, bad := range map[string]string{
		"object":       "node: node-b\nhost: a.example.com\n",
		"empty":        "[]\n",
		"mixed nodes":  list + "- {node: node-a, host: b.example.com, service: web, port: 8080}\n",
		"both":         strings.Replace(list, "gateway: local", "gateway: both", 1),
		"bad id":       strings.Replace(list, "id: admin", "id: Admin", 1),
		"duplicate id": strings.Replace(list, "id: admin", "id: route-1", 1),
		"runtime":      strings.Replace(list, "health: /readyz", "health: /readyz, runtime: {max_requests: 1}", 1),
		"listeners":    strings.Replace(list, "health: /readyz", "health: /readyz, listeners: []", 1),
	} {
		var d IngressDeclaration
		if err := yaml.Unmarshal([]byte(bad), &d); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestIngressGatewayListenersAndLimits(t *testing.T) {
	d := IngressDeclaration{Node: "node-b", Runtime: DefaultIngressRuntime, Routes: []IngressRouteDeclaration{{Host: "a.example.com", Service: "web", Port: 8080, Gateway: "external"}}}
	gateways := ingress.GatewayConfiguration{
		External: ingress.Gateway{Enabled: true, Listeners: []ingress.Listener{{ID: "http"}, {ID: "https", TLS: true}}},
		Local:    ingress.Gateway{Enabled: true, Listeners: []ingress.Listener{{ID: "internal"}}},
	}
	filled, err := GatewayListeners(d, gateways)
	if err != nil || len(filled.Listeners) != 2 || filled.Listeners[0].Shared != "http" || filled.Listeners[1].Shared != "https" {
		t.Fatalf("external: %+v %v", filled.Listeners, err)
	}
	d.Routes = append(d.Routes, IngressRouteDeclaration{Host: "a.internal", Service: "web", Port: 8080, Gateway: "local"})
	if filled, err = GatewayListeners(d, gateways); err != nil || len(filled.Listeners) != 3 {
		t.Fatalf("both gateways: %+v %v", filled.Listeners, err)
	}
	// A declaration naming its own listeners keeps them.
	own := d
	own.Listeners = []ListenerDeclaration{{Address: "192.0.2.1:80"}}
	if kept, err := GatewayListeners(own, ingress.GatewayConfiguration{}); err != nil || len(kept.Listeners) != 1 {
		t.Fatalf("own listeners: %+v %v", kept.Listeners, err)
	}
	gateways.Local.Enabled = false
	if _, err := GatewayListeners(d, gateways); err == nil || !strings.Contains(err.Error(), "INGRESS_GATEWAY_REQUIRED") {
		t.Fatalf("disabled gateway: %v", err)
	}
	r := LowerIngressRuntime(DefaultIngressRuntime, 0, 128, 1<<20)
	if r.MaxConnections != 128 || r.BufferBytes != 1<<20 || r.MaxRequests != 16 || r.validate() != nil {
		t.Fatalf("lowered: %+v", r)
	}
	if r := LowerIngressRuntime(DefaultIngressRuntime, 0, 0, 0); r != DefaultIngressRuntime || r.validate() != nil {
		t.Fatalf("default: %+v", r)
	}
}
