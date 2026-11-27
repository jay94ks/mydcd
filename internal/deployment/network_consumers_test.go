// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestNetworkConsumerDemandUsesSameGraphForLocalAndRemoteIngress(t *testing.T) {
	for _, node := range []string{"node-a", "node-b"} {
		t.Run(node, func(t *testing.T) {
			f := makeFixture(t)
			input := smallCompose(t)
			i := &IngressDeclaration{Node: node, Host: "app.test", Listeners: []ListenerDeclaration{{Address: "192.0.2.12:8080"}}, Runtime: IngressRuntime{MaxRequests: 2, MaxConnections: 8, MaxHeaderBytes: 4096, MaxBodyBytes: 1 << 20, BufferBytes: 128 << 10, RequestTimeoutMS: 30000, DialTimeoutMS: 1000, ResponseHeaderTimeoutMS: 2000, HealthIntervalMS: 100}}
			i.Backend.Service = "web"
			i.Backend.Port = 8080
			i.Backend.HealthPath = "/readyz"
			input.Sfc.Ingress = i
			plan, err := Compile(input, f.c, contextFor(t, f))
			if err != nil {
				t.Fatal(err)
			}
			demands, err := plan.NetworkConsumers()
			if err != nil {
				t.Fatal(err)
			}
			counts := map[string]int{}
			seen := map[string]bool{}
			for _, d := range demands {
				id := d.Source + "/" + d.Consumer
				if seen[id] || d.Tenant != "tenant" || d.Owner == ([32]byte{}) {
					t.Fatal("invalid or duplicated original edge", d)
				}
				seen[id] = true
				counts[d.Source]++
			}
			bridge := ResourceKey("bridge", "tenant", "php-mysql", "app/node-a")
			tunnel := ResourceKey("tunnel", "tenant", "php-mysql", "app/node-b")
			wantBridge, wantTunnel := 2, 1
			if node == "node-b" {
				wantBridge, wantTunnel = 1, 2
			}
			if counts[bridge] != wantBridge || counts[tunnel] != wantTunnel {
				t.Fatal("local bridge / remote packet-plane edge", counts)
			}
			raw, err := plan.Encode()
			if err != nil {
				t.Fatal(err)
			}
			restored, err := DecodeBlueprint(raw)
			if err != nil {
				t.Fatal(err)
			}
			again, err := restored.NetworkConsumers()
			if err != nil || !reflect.DeepEqual(demands, again) {
				t.Fatal("artifact did not retain exact desired dependencies", err)
			}
		})
	}
}

func TestNetworkConsumersMultipleRoutesPreserveFixedReplicaAndDistinctLeases(t *testing.T) {
	f, input, ctx := replicaFixture(t)
	i := &IngressDeclaration{Node: "node-a", Listeners: []ListenerDeclaration{{Shared: "https"}}, Runtime: IngressRuntime{MaxRequests: 2, MaxConnections: 8, MaxHeaderBytes: 4096, MaxBodyBytes: 1 << 20, BufferBytes: 128 << 10, RequestTimeoutMS: 30000, DialTimeoutMS: 1000, ResponseHeaderTimeoutMS: 2000, HealthIntervalMS: 100}, Routes: []IngressRouteDeclaration{
		{ID: "web", Host: "app.test", Prefix: "/", Service: "web", Network: "app", Port: 8080, HealthPath: "/readyz"},
		{ID: "db", Host: "app.test", Prefix: "/db", Service: "db", Network: "app", Port: 3306, HealthPath: "/"},
		{ID: "audit", Host: "app.test", Prefix: "/audit", Service: "web", Network: "app", Port: 8080, HealthPath: "/readyz"},
	}}
	input.Sfc.Ingress = i
	plan, err := CompileApp(input, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	demands, err := plan.NetworkConsumers()
	if err != nil {
		t.Fatal("mixed route demand rejected by the native permit core", err)
	}
	key := ResourceKey("ingress", "tenant", "php-mysql", "http")
	seen, counts := map[string]bool{}, map[string]int{}
	for _, demand := range demands {
		id := demand.Source + "/" + demand.Consumer
		if seen[id] {
			t.Fatal("distinct route leases collapsed to one consumer", demand)
		}
		seen[id] = true
		for _, route := range []string{"web", "db", "audit"} {
			if strings.HasPrefix(demand.Consumer, key+"/route/"+route+"/") {
				counts[route]++
			}
		}
	}
	if counts["web"] != 2 || counts["audit"] != 2 || counts["db"] != 1 {
		t.Fatal("route/replica/fixed native edge count", counts)
	}
	raw, _ := plan.Encode()
	restored, err := DecodeBlueprint(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := restored.NetworkConsumers()
	if err != nil || !reflect.DeepEqual(demands, again) {
		t.Fatal("frozen original graph changed consumer edges", err)
	}
	for _, mode := range []string{"unmatched-identity", "missing-service"} {
		steps := plan.Steps()
		for at := range steps {
			if steps[at].Key != key {
				continue
			}
			if mode == "unmatched-identity" {
				steps[at].Identity = append(steps[at].Identity, ResourceKey("task", "tenant", "php-mysql", (TaskInstance{Service: "foreign", Node: "node-a", Ordinal: 1}).ResourceID()))
			} else {
				var declaration IngressDeclaration
				if err := json.Unmarshal(steps[at].Goal, &declaration); err != nil {
					t.Fatal(err)
				}
				declaration.Routes[0].Service = "missing"
				steps[at].Goal, _ = json.Marshal(declaration)
			}
		}
		if _, err := NetworkConsumers(plan.Scope(), steps); err == nil {
			t.Fatal("route demand accepted unrelated task/service", mode)
		}
	}
}

func TestBorrowedNetworkDemandRetainsReferenceAndTaskConsumers(t *testing.T) {
	f, input, ctx, source := externalFixture(t)
	plan, err := Compile(input, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	demands, err := plan.NetworkConsumers()
	if err != nil {
		t.Fatal(err)
	}
	if len(demands) != 2 {
		t.Fatal("borrow and Task must reserve separate actual pins", demands)
	}
	for _, d := range demands {
		if d.Source != source || d.Tenant != "tenant" || d.Node != "node-a" || d.Owner != public(f.na) {
			t.Fatal("borrow changed source identity", d)
		}
	}
	resources, err := plan.ResourceDemands()
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 1 || len(resources[0].Addresses) != 1 || resources[0].Addresses[0].Network != "tenant/shared-lan" {
		t.Fatal("borrowed static IP did not use existing registry", resources)
	}
}
