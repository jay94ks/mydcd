// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"encoding/json"
	"maps"
	"slices"
	"testing"

	"github.com/jay94ks/mydcd/internal/schema"
)

func TestTaskNetworkResolverPreservesManagedRawAndFrozenGoalSources(t *testing.T) {
	for _, mode := range []string{"managed", "raw", "legacy-goal"} {
		t.Run(mode, func(t *testing.T) {
			var f *fixture
			var c Compose
			var ctx PlanningContext
			var b Blueprint
			var err error
			switch mode {
			case "managed":
				f, c, ctx = managedNetworkFixture(t)
				b, err = CompileApp(c, f.c, ctx)
			case "raw":
				f, c, ctx, _ = externalFixture(t)
				b, err = CompileApp(c, f.c, ctx)
			default:
				f = makeFixture(t)
				c, ctx = smallCompose(t), contextFor(t, f)
				b, err = Compile(c, f.c, ctx)
			}
			if err != nil {
				t.Fatal(err)
			}
			objects := frozenManagedGoals(t, b, ctx.Current)
			key := ResourceKey("task", b.d.Tenant, b.d.App, "web")
			var task GoalCommand
			if json.Unmarshal([]byte(objects[key].Value), &task) != nil {
				t.Fatal("original Task")
			}
			before, _ := json.Marshal(objects)
			material, err := ResolveTaskNetwork(f.cluster, task, "app", objects)
			if err != nil || material.Source.Key == "" || material.Bridge.Network == "" {
				t.Fatal("original source not resolved", err)
			}
			if (mode == "legacy-goal") != (material.Reference == nil) {
				t.Fatal("frozen source kind changed")
			}
			if ref := material.Reference; ref != nil {
				if ref.Source != material.Source || ref.Namespace() == "" {
					t.Fatal("original reference replaced")
				}
				tun, exists := ref.LocalTunnel()
				if exists != (mode == "managed") || exists && tun.Key != "control/network-sources/tun/tenant/shared-services/node-a" {
					t.Fatal("wrong node-local frozen tunnel")
				}
			}
			after, _ := json.Marshal(objects)
			if string(before) != string(after) {
				t.Fatal("read mutated original bytes or identity")
			}
			for _, mutation := range []struct {
				name  string
				apply func(*GoalCommand)
			}{
				{"tenant", func(g *GoalCommand) { g.Tenant = "other" }},
				{"app", func(g *GoalCommand) { g.App = "other" }},
				{"node", func(g *GoalCommand) { g.Node = "other" }},
				{"deployment", func(g *GoalCommand) { g.Deployment = "other" }},
				{"owner", func(g *GoalCommand) { g.Owner = [32]byte{99} }},
				{"missing", func(g *GoalCommand) { g.Dependencies = nil }},
				{"stale", func(g *GoalCommand) {
					for i := range g.Dependencies {
						g.Dependencies[i].Revision++
					}
				}},
				{"duplicate", func(g *GoalCommand) { g.Dependencies = append(g.Dependencies, g.Dependencies...) }},
			} {
				t.Run(mutation.name, func(t *testing.T) {
					g := task
					g.Dependencies = slices.Clone(task.Dependencies)
					mutation.apply(&g)
					if _, err := ResolveTaskNetwork(f.cluster, g, "app", objects); err == nil {
						t.Fatal("accepted a replacement or ambiguous original source")
					}
				})
			}
			depKey := ResourceKey("bridge", task.Tenant, task.App, "app/"+task.Node)
			otherKey := ResourceKey("network-ref", task.Tenant, task.App, "app/"+task.Node)
			if material.Reference != nil {
				depKey, otherKey = otherKey, depKey
			}
			for _, mutate := range []func(*GoalCommand){
				func(g *GoalCommand) { g.Deployment = "other" },
				func(g *GoalCommand) { g.Lifecycle = &schema.Lifecycle{Drain: true, Nonce: [16]byte{1}} },
			} {
				changed := maps.Clone(objects)
				o := changed[depKey]
				var g GoalCommand
				_ = json.Unmarshal([]byte(o.Value), &g)
				mutate(&g)
				raw, _ := json.Marshal(g)
				o.Value = string(raw)
				changed[depKey] = o
				if _, err := ResolveTaskNetwork(f.cluster, task, "app", changed); err == nil {
					t.Fatal("accepted foreign or draining dependency")
				}
			}
			g := task
			g.Dependencies = append(slices.Clone(task.Dependencies), ObjectRef{Key: otherKey, Generation: 99, Revision: 99})
			if _, err := ResolveTaskNetwork(f.cluster, g, "app", objects); err == nil {
				t.Fatal("missing alternate source concealed ambiguous dependency")
			}
		})
	}
}
