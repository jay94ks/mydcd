// SPDX-License-Identifier: Apache-2.0

package server

import (
	"strings"
	"testing"
)

const webRouteFile = `name: cluster-app/web
x-sfc:
  ingress:
    node: node-a
    runtime: {max_requests: 8, max_connections: 32, max_header_bytes: 16384, max_body_bytes: 1048576, buffer_bytes: 524288, request_timeout_ms: 30000, dial_timeout_ms: 2000, response_header_timeout_ms: 5000, health_interval_ms: 1000}
    listeners: [{shared: internal-https}]
    routes:
      - {id: ui, host: sfc.example.com, gateway: local}
`

func TestClusterAppRoutesScreen(t *testing.T) {
	f, _ := newFakeFixture(t)
	op := opSeq("1a9e00c1")
	fakeLogin(t, f, "admin")
	code, v := f.do("GET", "/api/v1/cluster-apps/web/routes", nil)
	if code != 200 || v["revision"].(float64) != 0 || v["file"] != nil || len(v["routes"].([]any)) != 0 {
		t.Fatalf("empty: %d %v", code, v)
	}
	if code, _ := f.do("GET", "/api/v1/cluster-apps/other/routes", nil); code != 404 {
		t.Fatalf("unknown app: %d", code)
	}
	if code, out := f.do("PUT", "/api/v1/cluster-apps/web/routes", map[string]any{"opId": op(), "file": strings.Replace(webRouteFile, "    node: node-a\n", "    node: node-a\n    backend: {port: 9000}\n", 1)}); code != 422 {
		t.Fatalf("backend field: %d %v", code, out)
	}
	if code, out := f.do("PUT", "/api/v1/cluster-apps/web/routes", map[string]any{"opId": op(), "file": webRouteFile}); opState(t, code, out) != "applied" {
		t.Fatalf("put: %d %v", code, out)
	}
	_, v = f.do("GET", "/api/v1/cluster-apps/web/routes", nil)
	routes := v["routes"].([]any)
	if v["revision"].(float64) != 1 || v["node"] != "node-a" || len(routes) != 1 || routes[0].(map[string]any)["host"] != "sfc.example.com" || routes[0].(map[string]any)["prefix"] != "/" {
		t.Fatalf("after put: %v", v)
	}
	// the file reads back as one the PUT takes again
	file := strings.Replace(v["file"].(string), "sfc.example.com", "ui.example.com", 1)
	if code, out := f.do("PUT", "/api/v1/cluster-apps/web/routes", map[string]any{"opId": op(), "expected": 0, "file": file}); opState(t, code, out) != "failed" {
		t.Fatalf("stale: %d %v", code, out)
	}
	if code, out := f.do("PUT", "/api/v1/cluster-apps/web/routes", map[string]any{"opId": op(), "expected": 1, "file": file}); opState(t, code, out) != "applied" {
		t.Fatalf("edit: %d %v", code, out)
	}
	if code, out := f.do("DELETE", "/api/v1/cluster-apps/web/routes", map[string]any{"opId": op()}); opState(t, code, out) != "applied" {
		t.Fatalf("delete: %d %v", code, out)
	}
	_, v = f.do("GET", "/api/v1/cluster-apps/web/routes", nil)
	if v["revision"].(float64) != 3 || v["removed"] != true {
		t.Fatalf("after delete: %v", v)
	}
	bobLogin(t, f)
	if code, _ := f.do("GET", "/api/v1/cluster-apps/web/routes", nil); code != 403 {
		t.Fatalf("not a system administrator: %d", code)
	}
}
