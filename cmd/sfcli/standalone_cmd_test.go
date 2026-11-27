// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/workload"
)

func TestStandaloneCommands(t *testing.T) {
	n := newGroup9Node(t)
	must := func(r state.Result) {
		t.Helper()
		if r.Code != state.Applied {
			t.Fatal(r)
		}
	}
	tenant, _ := n.m.Catalog().Tenant("shop")
	must(n.m.Change("nodes", "set-nodes", tenant.Revision, control.NodeChangeTo("shop", tenant.AllowedNodes, []string{"node-a"})))
	tenant, _ = n.m.Catalog().Tenant("shop")
	must(n.m.Change("trust", "set-trust", tenant.Revision, control.TrustChange{Tenant: "shop", Add: []access.TrustRule{{Registry: "registry.example", Repository: "debug"}}}))
	for i, scope := range []string{"", "shop"} {
		must(n.m.Change("quota"+string(rune('0'+i)), "set-node-quota", 0, tenancy.NodeLimit{Tenant: scope, Node: "node-a", Capacity: workload.Resources{CPU: 4e9, Memory: 1 << 30}, Networks: 4, MaxConsumers: map[string]int{"": 64, "shop": 8}[scope]}))
	}
	v, err := n.m.Runtime.Engine().Read(n.m.ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	resources, err := n.m.Policy.Resources(v.State)
	if err != nil {
		t.Fatal(err)
	}
	lan := composeFixtureNetwork()
	lan.Tenant = "shop"
	must(n.m.Change("shared-lan", "create-tun-network", resources.Networks.Revision(), lan))
	if got := strings.TrimSpace(n.run(0, "-o", "json", "standalone", "list")); got != "[]" {
		t.Fatal("empty list", got)
	}
	n.run(3, "standalone", "show", "debug")
	n.run(3, "standalone", "remove", "debug")
	n.run(3, "standalone", "extend", "debug", "1h")
	n.run(2, "standalone", "run", "debug")
	n.run(2, "standalone", "run", "debug", "-f", "app.yaml", "--ttl", "1.5s")
	n.run(2, "standalone", "run", "debug", "-f", "app.yaml", "--ttl", "25h")
	n.run(2, "standalone", "extend", "debug", "soon")
	n.run(2, "standalone", "keep", "debug", "--restart", "sometimes")
	n.run(2, "standalone", "exec", "debug")
	file := n.file("debug.yaml", "name: debug\nservices:\n  debug:\n    image: registry.example/debug@sha256:"+strings.Repeat("a", 64)+"\n    cpus: 0.1\n    mem_limit: 16m\n    networks: {app: {ipv4_address: 10.79.0.10}}\nnetworks:\n  app: {external: true, name: shared-lan}\n")
	out := n.run(0, "-o", "json", "standalone", "run", "debug", "-f", file, "--node", "node-a", "--dry-run")
	if !strings.Contains(out, "debug") {
		t.Fatal("dry-run plan", out)
	}
	if ops := n.run(0, "-o", "json", "op", "list"); strings.Contains(ops, "standalone run") {
		t.Fatal("dry-run recorded an operation", ops)
	}
	out = n.run(0, "-o", "json", "standalone", "run", "debug", "-f", file, "--node", "node-a", "--ttl", "30m", "--id", "debug-run")
	if !strings.Contains(out, `"id": "debug-run"`) {
		t.Fatal("run reply", out)
	}
	// The same ID continues the same start instead of planning again.
	n.run(0, "standalone", "run", "debug", "--id", "debug-run")
	if st := n.opState("debug-run"); st.State != cli.Accepted {
		t.Fatal("run state", st)
	}
	if list := n.run(0, "standalone", "list"); !strings.Contains(list, "debug") || !strings.Contains(list, "temp") {
		t.Fatal("list", list)
	}
	if shown := n.run(0, "-o", "json", "standalone", "show", "debug"); !strings.Contains(shown, `"Body": "`) {
		t.Fatal("show has no app.yaml", shown)
	}
	n.run(0, "standalone", "extend", "debug", "2h", "--id", "debug-extend")
	n.run(0, "standalone", "extend", "debug", "2h", "--id", "debug-extend")
	n.run(0, "standalone", "remove", "debug", "--id", "debug-remove")
}
