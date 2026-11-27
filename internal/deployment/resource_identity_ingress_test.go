// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"encoding/json"
	"maps"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
)

func TestReplacementIdentityKeepsOriginalIngressOwnerForNewAppPlan(t *testing.T) {
	f, input, ctx := managedNetworkFixture(t)
	declaration := &IngressDeclaration{Node: "node-b", Host: "app.test", Listeners: []ListenerDeclaration{{Address: "192.0.2.12:8080"}}, Runtime: IngressRuntime{MaxRequests: 2, MaxConnections: 8, MaxHeaderBytes: 4096, MaxBodyBytes: 1 << 20, BufferBytes: 128 << 10, RequestTimeoutMS: 30000, DialTimeoutMS: 1000, ResponseHeaderTimeoutMS: 2000, HealthIntervalMS: 100}}
	declaration.Backend.Service, declaration.Backend.Port, declaration.Backend.HealthPath = "web", 8080, "/readyz"
	input.Sfc.Ingress = declaration
	original, err := CompileApp(input, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	ctx.Current = frozenManagedGoals(t, original, ctx.Current)
	objects := maps.Clone(ctx.Current)
	nextKey := private(75)
	node := ctx.Nodes["node-b"]
	node.Key = public(nextKey)
	node.ResourceKeys = replacementResourceKey(t, f.cluster, "node-b", f.nb, nextKey)
	ctx.Nodes["node-b"] = node
	next, err := CompileApp(input, f.c, ctx)
	if err != nil {
		t.Fatal("new plan lost original listener", err)
	}
	steps := stepMap(next)
	ingressKey := ResourceKey("ingress", "tenant", "php-mysql", "http")
	if steps[ingressKey].Owner != public(f.nb) || steps[ResourceKey("task", "tenant", "php-mysql", "db")].Owner != public(nextKey) {
		t.Fatal("listener owner or new Task identity changed incorrectly")
	}
	raw, err := next.Encode()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeBlueprint(raw)
	if err != nil || stepMap(decoded)[ingressKey].Owner != public(f.nb) {
		t.Fatal("retained listener lost verified key lineage", err)
	}
	if !maps.Equal(objects, ctx.Current) {
		t.Fatal("planning rewrote original resources")
	}
	for _, name := range []string{"missing-lineage", "forged-lineage", "foreign-owner", "other-app", "other-node"} {
		t.Run(name, func(t *testing.T) {
			changed := ctx
			changed.Nodes = maps.Clone(ctx.Nodes)
			changed.Current = maps.Clone(ctx.Current)
			n := changed.Nodes["node-b"]
			n.ResourceKeys = lifecycle.OwnIdentityTransitions(n.ResourceKeys)
			var g GoalCommand
			object := changed.Current[ingressKey]
			if json.Unmarshal([]byte(object.Value), &g) != nil {
				t.Fatal("original goal")
			}
			switch name {
			case "missing-lineage":
				n.ResourceKeys = nil
			case "forged-lineage":
				n.ResourceKeys[0].Proof.NewSignature[0] ^= 1
			case "foreign-owner":
				g.Owner = public(private(76))
			case "other-app":
				g.App = "foreign"
			case "other-node":
				g.Node = "node-a"
			}
			changed.Nodes["node-b"] = n
			body, _ := json.Marshal(g)
			object.Value = string(body)
			changed.Current[ingressKey] = object
			if _, err := CompileApp(input, f.c, changed); err == nil {
				t.Fatal("unrelated listener adopted")
			}
		})
	}
}
