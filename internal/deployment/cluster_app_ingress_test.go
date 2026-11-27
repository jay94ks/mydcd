// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

const clusterAppRouteFile = `name: cluster-app/web
x-sfc:
  ingress:
    runtime:
      max_requests: 8
      max_connections: 32
      max_header_bytes: 16384
      max_body_bytes: 1048576
      buffer_bytes: 524288
      request_timeout_ms: 30000
      dial_timeout_ms: 2000
      response_header_timeout_ms: 5000
      health_interval_ms: 1000
    node: node-a
    listeners:
    - shared: internal-https
    routes:
    - id: ui
      host: sfc.example.com
      gateway: local
`

func TestClusterAppRouteFileHoldsOnlyRoutes(t *testing.T) {
	app, d, err := ParseClusterAppRoutes([]byte(clusterAppRouteFile))
	if err != nil || app != "web" || d.Node != "node-a" || len(d.Routes) != 1 {
		t.Fatalf("parse: %q %+v %v", app, d, err)
	}
	for name, bad := range map[string]string{
		"workspace app":  strings.Replace(clusterAppRouteFile, "cluster-app/web", "shop", 1),
		"unknown app":    strings.Replace(clusterAppRouteFile, "cluster-app/web", "cluster-app/other", 1),
		"services":       clusterAppRouteFile + "services:\n  web:\n    image: x\n",
		"route backend":  strings.Replace(clusterAppRouteFile, "      gateway: local\n", "      gateway: local\n      port: 9000\n", 1),
		"no routes":      strings.Replace(clusterAppRouteFile, "    routes:\n    - id: ui\n      host: sfc.example.com\n      gateway: local\n", "", 1),
		"no listeners":   strings.Replace(clusterAppRouteFile, "    - shared: internal-https\n", "", 1),
		"unknown option": strings.Replace(clusterAppRouteFile, "    node: node-a\n", "    node: node-a\n    nodes: [a]\n", 1),
	} {
		if _, _, err := ParseClusterAppRoutes([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, _, err := ParseClusterAppRoutes([]byte(clusterAppRouteFile + "services: {}\n")); !errors.Is(err, ErrClusterAppRoutes) {
		t.Fatalf("services: %v", err)
	}
}

func TestClusterAppIngressSpecRoutesToTheEndpoint(t *testing.T) {
	_, d, err := ParseClusterAppRoutes([]byte(clusterAppRouteFile))
	if err != nil {
		t.Fatal(err)
	}
	addr := netip.MustParseAddr("10.254.0.2")
	s, err := ClusterAppIngressSpec("owner", "web", d, &ClusterAppBackend{Node: "node-b", Address: addr}, 7)
	if err != nil {
		t.Fatal(err)
	}
	b := s.Services[0].Backends[0]
	if s.Tenant != ClusterAppTenant || s.App != "cluster-app/web" || !s.DynamicBackends || s.BindingRevision != 7 || s.Routes[0].Service != "web" || s.Routes[0].Prefix != "/" || b.Address != addr || b.Port != 8080 || b.HealthPath != "/healthz" || b.Network != "sfc-system" || b.Node != "node-b" {
		t.Fatalf("spec: %+v", s)
	}
	// no endpoint yet: no backend, the listeners still stand
	if s, err = ClusterAppIngressSpec("owner", "web", d, nil, 7); err != nil || len(s.Services[0].Backends) != 0 {
		t.Fatalf("no endpoint: %+v %v", s, err)
	}
}
