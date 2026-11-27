// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
)

// Simulated committed claims are inputs to the real compiler and retirement
// selection algorithm. This is no assertion of Docker or Raft success.
func replacementPlanFixture(t *testing.T) (Inventory, Blueprint) {
	inventory, blueprint, _, _ := replacementCoreFixture(t)
	return inventory, blueprint
}

func replacementCoreFixture(t *testing.T) (Inventory, Blueprint, *fixture, PlanningContext) {
	t.Helper()
	f, input, ctx := replicaFixture(t)
	i := &IngressDeclaration{Node: "node-a", Host: "app.test", Listeners: []ListenerDeclaration{{Address: "192.0.2.11:8080"}}, Runtime: IngressRuntime{MaxRequests: 2, MaxConnections: 8, MaxHeaderBytes: 4096, MaxBodyBytes: 1 << 20, BufferBytes: 128 << 10, RequestTimeoutMS: 30000, DialTimeoutMS: 1000, ResponseHeaderTimeoutMS: 2000, HealthIntervalMS: 100}}
	i.Backend.Service, i.Backend.Port, i.Backend.HealthPath = "web", 8080, "/readyz"
	input.Sfc.Ingress = i
	original, err := CompileApp(input, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	objects := frozenManagedGoals(t, original, ctx.Current)
	for _, step := range original.Steps() {
		object := objects[step.Key]
		var goal GoalCommand
		_ = json.Unmarshal([]byte(object.Value), &goal)
		goal.Activation = slices.Clone(step.Activation)
		value, _ := json.Marshal(goal)
		object.Value = string(value)
		objects[step.Key] = object
	}
	ctx.Current, ctx.Addresses = objects, map[string]ObjectRef{}
	inventory, _ := NewInventory(f.cluster, "tenant", "php-mysql", "deploy")
	for _, step := range original.Steps() {
		object := objects[step.Key]
		claim := Claim{Step: step, Operation: "original", Plan: original.Digest(), Native: "original-native-" + step.Key,
			Command: state.Command{Actor: "user/original", Epoch: 1, RequestID: requestID("original", step.Key), Key: step.Key, Value: object.Value, Expected: step.Base.Revision},
			Result:  state.Result{Code: state.Applied, Index: object.Revision, Generation: object.Generation, Revision: object.Revision}}
		inventory.d.Claims = append(inventory.d.Claims, claim)
		if step.Kind == "task" {
			var service ComposeService
			if json.Unmarshal(step.Goal, &service) != nil {
				t.Fatal("original Task goal")
			}
			for _, attachment := range service.Networks {
				for _, address := range []string{attachment.IPv4, attachment.IPv6} {
					if address != "" {
						ctx.Addresses[address] = ObjectRef{Key: step.Key, Generation: object.Generation, Revision: object.Revision}
					}
				}
			}
		}
	}
	slices.SortFunc(inventory.d.Claims, func(a, b Claim) int { return strings.Compare(a.Step.Key, b.Step.Key) })
	web := input.Services["web"]
	web.Image = strings.ReplaceAll(web.Image, strings.Repeat("a", 64), strings.Repeat("b", 64))
	input.Services["web"] = web
	target, err := CompileApp(input, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	return inventory, target, f, ctx
}

func TestReplacementPlanUsesExactNativeClosureAndLeavesOtherNodeUntouched(t *testing.T) {
	inventory, target := replacementPlanFixture(t)
	before, _ := json.Marshal(inventory.d)
	plan, err := inventory.ReplacementPlan(target, false)
	if err != nil || plan == nil || !plan.Valid("tenant", "php-mysql") || plan.BlockedCode != "" || len(plan.Waves) != 2 {
		t.Fatal("no node-at-a-time replacement plan", plan, err)
	}
	seen := map[string]bool{}
	for index, node := range []string{"node-a", "node-b"} {
		wave := plan.Waves[index]
		id := (TaskInstance{Service: "web", Node: node, Ordinal: 1}).ResourceID()
		key := ResourceKey("task", "tenant", "php-mysql", id)
		if wave.Node != node || !slices.Equal(wave.Tasks, []string{key}) {
			t.Fatal("declared node order or exact Task identity lost", wave)
		}
		closure, err := inventory.retirementSelection([]string{key}, false)
		if err != nil {
			t.Fatal(err)
		}
		for _, ref := range wave.Targets {
			claim := inventory.d.Claims[inventory.claim(ref.Key)]
			if seen[ref.Key] || !closure[ref.Key] || ref.Revision != claim.Result.Revision || ref.Generation != claim.Result.Generation {
				t.Fatal("preview invented a source or repeated a stop", ref)
			}
			seen[ref.Key] = true
		}
	}
	if seen[ResourceKey("ingress", "tenant", "php-mysql", "http")] || seen[ResourceKey("task", "tenant", "php-mysql", "db")] {
		t.Fatal("unchanged listener or unrelated database stopped")
	}
	// A caller can edit its returned plan without changing the original claims.
	plan.Waves[0].Targets[0].Generation++
	after, _ := json.Marshal(inventory.d)
	if !bytes.Equal(before, after) {
		t.Fatal("preflight changed original native/operation ownership")
	}
	again, err := inventory.ReplacementPlan(target, false)
	if err != nil || again.Waves[0].Targets[0].Generation == plan.Waves[0].Targets[0].Generation {
		t.Fatal("preflight aliases mutable inventory state")
	}
}

func TestReplacementPlanRefusesCrossNodeLifetimeCascade(t *testing.T) {
	inventory, target := replacementPlanFixture(t)
	first := ResourceKey("task", "tenant", "php-mysql", "web/node-a/r1")
	second := ResourceKey("task", "tenant", "php-mysql", "web/node-b/r1")
	index := inventory.claim(second)
	// This models an original cross-node lifetime edge, including historical
	// mistakenly chained replicas. It must not be relabeled as rollout order.
	inventory.d.Claims[index].Step.Dependencies = append(inventory.d.Claims[index].Step.Dependencies, Dependency{Key: first, Condition: Healthy})
	plan, err := inventory.ReplacementPlan(target, false)
	if err != nil || plan == nil || !plan.Valid("tenant", "php-mysql") || plan.BlockedCode != "ROLLING_DEPENDENCY_CONFLICT" || plan.Blocker != second || len(plan.Waves) != 0 {
		t.Fatal("cross-node stop set mislabeled as rolling", plan, err)
	}
}

func TestReplacementPlanDoesNotInventWorkForInitialOrUnchangedApp(t *testing.T) {
	inventory, target := replacementPlanFixture(t)
	empty, _ := NewInventory(target.d.Cluster, target.d.Tenant, target.d.App, target.d.Deployment)
	if plan, err := empty.ReplacementPlan(target, false); err != nil || plan != nil {
		t.Fatal("initial creation reported as native replacement", plan, err)
	}
	for index := range inventory.d.Claims {
		claim := &inventory.d.Claims[index]
		if step, exists := stepMap(target)[claim.Step.Key]; exists {
			claim.Step = step
			var goal GoalCommand
			_ = json.Unmarshal([]byte(claim.Command.Value), &goal)
			goal.Config, goal.Activation = step.Goal, step.Activation
			value, _ := json.Marshal(goal)
			claim.Command.Value = string(value)
		}
	}
	if plan, err := inventory.ReplacementPlan(target, false); err != nil || plan != nil {
		t.Fatal("unchanged declarations manufactured a rollout", plan, err)
	}
}
