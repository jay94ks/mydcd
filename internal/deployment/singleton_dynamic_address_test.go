// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/json"
	"maps"
	"net/netip"
	"testing"

	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/network"
)

// All native/network observations are explicit model inputs. These tests use
// the product compiler, Book, artifact, Binding and Task recipe; they do not
// establish Docker/Raft/DB adapter readiness.
func singletonDynamicFixture(t *testing.T) (*fixture, Compose, PlanningContext) {
	t.Helper()
	f, input, ctx := managedNetworkFixture(t)
	web := input.Services["web"]
	web.DependsOn, web.Secrets, web.Sfc.Sources = nil, nil, nil
	web.Environment = map[string]string{"MODE": "generic"}
	web.Networks = map[string]Attachment{"app": {}}
	input.Services = map[string]ComposeService{"web": web, "other": web}
	input.Volumes, input.Secrets = nil, nil
	return f, input, ctx
}

func singletonDynamicMaterial(t *testing.T, f *fixture, b Blueprint, ctx PlanningContext, service, consumer string, generation uint64) TaskMaterial {
	t.Helper()
	needs, err := b.Inputs(service, consumer, generation, public(private(30)))
	if err != nil || needs.Instance != nil || needs.Use.Service != service {
		t.Fatal("singleton Inputs lost logical identity", needs, err)
	}
	bound := f.reserve(needs).Bindings[0]
	for _, step := range b.Steps() {
		if step.Key != ResourceKey("network-ref", b.d.Tenant, b.d.App, "app/"+needs.Use.Node) {
			continue
		}
		var ref NetworkReference
		if json.Unmarshal(step.Goal, &ref) != nil {
			t.Fatal("frozen network reference")
		}
		bridge, err := ReferenceBridge(f.cluster, ref, ctx.Current)
		if err != nil {
			t.Fatal("original material source", err)
		}
		return TaskMaterial{Binding: bound, Network: ref.Source, Bridge: bridge}
	}
	t.Fatal("missing original network reference")
	return TaskMaterial{}
}

func TestSingletonDynamicAddressFrozenGoalSurvivesArtifactInputsAndTaskRecipe(t *testing.T) {
	f, input, ctx := singletonDynamicFixture(t)
	before, _ := json.Marshal(input)
	networkBefore, _ := ctx.Networks.Encode()
	b, err := CompileApp(input, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	addresses := map[netip.Addr]bool{}
	for _, name := range []string{"other", "web"} {
		declared, ok := b.DeclaredService(name)
		if !ok || declared.Networks["app"].IPv4 != "" || declared.Networks["app"].IPv6 != "" {
			t.Fatal("planned address became a static user declaration", name)
		}
		service, logical, err := b.TaskInput(name)
		address, parseErr := netip.ParseAddr(service.Networks["app"].IPv4)
		if err != nil || parseErr != nil || logical != name || service.Sfc.Instance != nil || service.Sfc.Node != "node-a" || addresses[address] {
			t.Fatal("singleton lost its frozen independent address or original key", name, service, err)
		}
		addresses[address] = true
		step := stepMap(b)[ResourceKey("task", "tenant", "php-mysql", name)]
		var goal ComposeService
		if json.Unmarshal(step.Goal, &goal) != nil || goal.Networks["app"].IPv4 != address.String() {
			t.Fatal("TaskInput differs from the accepted Task goal")
		}
	}
	raw, err := b.Encode()
	decoded, decodeErr := DecodeBlueprint(raw)
	if err != nil || decodeErr != nil || decoded.ValidateCurrent(f.c, ctx) != nil {
		t.Fatal("accepted dynamic intent did not survive replay", err, decodeErr)
	}
	replayed, _ := decoded.Encode()
	if !bytes.Equal(raw, replayed) {
		t.Fatal("artifact replay changed signed source bytes")
	}
	material := singletonDynamicMaterial(t, f, decoded, ctx, "web", "web-original", 11)
	service, recipe, err := decoded.taskRecipe("web", material, material.Bridge.Owner)
	if err != nil || recipe.IPv4.String() != service.Networks["app"].IPv4 || !addresses[recipe.IPv4] {
		t.Fatal("frozen address was lost at actual Task recipe consumption", err)
	}
	bindingBytes, _ := material.Binding.Encode()
	restoredBinding, err := DecodeBinding(bindingBytes)
	if err != nil || restoredBinding.Digest() != material.Binding.Digest() {
		t.Fatal("original Binding did not survive replay", err)
	}
	material.Binding = restoredBinding
	_, replayRecipe, err := decoded.taskRecipe("web", material, material.Bridge.Owner)
	wantRecipe, _ := json.Marshal(recipe)
	gotRecipe, _ := json.Marshal(replayRecipe)
	if err != nil || !bytes.Equal(wantRecipe, gotRecipe) {
		t.Fatal("replayed metadata changed native arguments/address", err)
	}
	book, _ := network.NewBook(2)
	for _, pool := range material.Bridge.Pools {
		book, err = book.AddPool(pool)
		if err != nil {
			t.Fatal(err)
		}
	}
	book, _, err = book.Reserve("original-web", material.Bridge.Owner, material.Bridge.Network, "", 11, recipe.IPv4)
	if err != nil {
		t.Fatal("frozen address is ineligible in the real Book", err)
	}
	if _, _, err = book.Reserve("foreign-task", material.Bridge.Owner, material.Bridge.Network, "", 12, recipe.IPv4); err == nil {
		t.Fatal("frozen dynamic address bypassed duplicate Book protection")
	}
	for _, mutate := range []func(*TaskMaterial){
		func(m *TaskMaterial) { m.Network.Generation++ },
		func(m *TaskMaterial) { m.Network.Key = ResourceKey("bridge", "other", "php-mysql", "app/node-a") },
		func(m *TaskMaterial) { m.Bridge.Owner = engine.Owner(f.cluster, public(f.nb)) },
		func(m *TaskMaterial) { m.Binding.d.Needs.Use.Node = "node-b" },
	} {
		bad := cloneTaskMaterial(material)
		mutate(&bad)
		if _, _, err := decoded.taskRecipe("web", bad, material.Bridge.Owner); err == nil {
			t.Fatal("dynamic singleton accepted foreign material")
		}
	}
	after, _ := json.Marshal(input)
	networkAfter, _ := ctx.Networks.Encode()
	if !bytes.Equal(before, after) || !bytes.Equal(networkBefore, networkAfter) {
		t.Fatal("preview/recipe changed source declaration or shared network")
	}
}

func TestSingletonDynamicRelocationUsesDestinationPoolAndRetainsAddressIntent(t *testing.T) {
	f, input, ctx := singletonDynamicFixture(t)
	original, err := CompileApp(input, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	from, _, err := original.TaskInput("web")
	if err != nil {
		t.Fatal(err)
	}
	next, err := original.RelocateNode(f.c, ctx, "node-a", "node-b", []string{"web"})
	if err != nil {
		t.Fatal("planned address prevented declared dynamic relocation", err)
	}
	declared, _ := next.DeclaredService("web")
	target, _, err := next.TaskInput("web")
	if err != nil || declared.Networks["app"].IPv4 != "" || target.Sfc.Node != "node-b" || target.Networks["app"].IPv4 == from.Networks["app"].IPv4 {
		t.Fatal("relocation reused a source-node address or fixed declaration", err)
	}
	material := singletonDynamicMaterial(t, f, next, ctx, "web", "web-target", 12)
	_, spec, err := next.taskRecipe("web", material, material.Bridge.Owner)
	if err != nil || spec.IPv4.String() != target.Networks["app"].IPv4 {
		t.Fatal("destination Task recipe lost planned address", err)
	}
	inside := false
	for _, pool := range material.Bridge.Pools {
		inside = inside || pool.Prefix.Contains(spec.IPv4) && spec.IPv4 != pool.Gateway
	}
	if !inside {
		t.Fatal("relocation address is outside the actual destination pool")
	}
	originalTask, _, _ := original.TaskInput("web")
	originalDeclared, _ := original.DeclaredService("web")
	if originalTask.Networks["app"].IPv4 != from.Networks["app"].IPv4 || originalDeclared.Sfc.Node != "node-a" || originalDeclared.Networks["app"].IPv4 != "" {
		t.Fatal("relocation mutated the original artifact")
	}
}

func TestSingletonDynamicAddressRespectsAcceptedIntentsAndOriginalTaskReference(t *testing.T) {
	f, input, ctx := singletonDynamicFixture(t)
	original, err := CompileApp(input, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	held := ctx
	held.Nodes = maps.Clone(ctx.Nodes)
	addresses := map[netip.Addr]bool{}
	for _, demand := range mustResourceDemands(t, original) {
		held.Planned = append(held.Planned, PlannedResource{Origin: [32]byte{1}, Scope: original.Scope(), Demand: demand})
		for _, address := range demand.Addresses {
			addresses[address.Address] = true
		}
		node := held.Nodes[demand.Node]
		node.Used.CPU += demand.Need.CPU
		node.Used.Memory += demand.Need.Memory
		held.Nodes[demand.Node] = node
	}
	again, err := CompileApp(input, f.c, held)
	if err != nil {
		t.Fatal("accepted exact dynamic target could not reuse its held resources", err)
	}
	// Nodes.Used is part of the frozen planning snapshot and has deliberately
	// changed above. The full artifact therefore need not have the same digest.
	// The accepted Task goals/address demands must still be the exact originals.
	originalSteps := stepMap(original)
	for _, step := range again.Steps() {
		if step.Kind != "task" {
			continue
		}
		old, found := originalSteps[step.Key]
		if !found || old.Node != step.Node || old.Owner != step.Owner || !bytes.Equal(old.Goal, step.Goal) {
			t.Fatal("accepted exact dynamic target changed its frozen Task goal")
		}
	}
	for _, name := range []string{"other", "web"} {
		before, _, beforeErr := original.TaskInput(name)
		after, _, afterErr := again.TaskInput(name)
		if beforeErr != nil || afterErr != nil || before.Networks["app"].IPv4 != after.Networks["app"].IPv4 || before.Networks["app"].IPv6 != after.Networks["app"].IPv6 {
			t.Fatal("accepted exact dynamic target replaced its held address", name, beforeErr, afterErr)
		}
	}
	beforeDemands, _ := json.Marshal(mustResourceDemands(t, original))
	afterDemands, _ := json.Marshal(mustResourceDemands(t, again))
	if !bytes.Equal(beforeDemands, afterDemands) {
		t.Fatal("reused exact Task goals changed their original resource/address demands")
	}
	foreignInput := input
	foreignInput.Name = "different-app"
	foreign := held
	foreign.Project = foreignInput.Name
	other, err := CompileApp(foreignInput, f.c, foreign)
	if err != nil {
		t.Fatal(err)
	}
	for _, demand := range mustResourceDemands(t, other) {
		for _, address := range demand.Addresses {
			if addresses[address.Address] {
				t.Fatal("another scope borrowed an accepted dynamic address")
			}
		}
	}
	current := ctx
	current.Current = frozenManagedGoals(t, original, ctx.Current)
	current.Addresses = map[string]ObjectRef{}
	for _, step := range original.Steps() {
		if step.Kind == "task" {
			var service ComposeService
			_ = json.Unmarshal(step.Goal, &service)
			object := current.Current[step.Key]
			current.Addresses[service.Networks["app"].IPv4] = ObjectRef{Key: step.Key, Generation: object.Generation, Revision: object.Revision}
		}
	}
	replanned, err := CompileApp(input, f.c, current)
	if err != nil {
		t.Fatal("exact original Task address reference was not reusable", err)
	}
	for _, name := range []string{"other", "web"} {
		before, _, _ := original.TaskInput(name)
		after, _, _ := replanned.TaskInput(name)
		if before.Networks["app"].IPv4 != after.Networks["app"].IPv4 {
			t.Fatal("replan replaced an original Task's reserved address")
		}
	}
	// Keep reference identity meaningful: the same number on another Task is
	// not permission to consume its address.
	for address, ref := range current.Addresses {
		ref.Key = ResourceKey("task", "tenant", "different-app", "web")
		current.Addresses[address] = ref
	}
	competing, err := CompileApp(input, f.c, current)
	if err != nil {
		t.Fatal("free alternative address should remain plannable", err)
	}
	for _, demand := range mustResourceDemands(t, competing) {
		for _, address := range demand.Addresses {
			if addresses[address.Address] {
				t.Fatal("foreign Task reference was reused as the original address owner")
			}
		}
	}
}

func TestSingletonStaticAddressPreservesLegacyTaskShape(t *testing.T) {
	f, input, ctx := managedNetworkFixture(t)
	b, err := CompileApp(input, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"web", "db"} {
		service, logical, err := b.TaskInput(name)
		want, _ := json.Marshal(b.d.Input.Services[name])
		got, _ := json.Marshal(service)
		if err != nil || logical != name || service.Sfc.Instance != nil || !bytes.Equal(want, got) {
			t.Fatal("static singleton changed its legacy public Task input", name, err)
		}
	}
	raw, _ := b.Encode()
	restored, err := DecodeBlueprint(raw)
	again, _ := restored.Encode()
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatal("static schema1 bytes changed on replay", err)
	}
	if _, err := b.RelocateNode(f.c, ctx, "node-a", "node-b", []string{"web"}); err == nil {
		t.Fatal("dynamic support weakened explicit static relocation refusal")
	}
}
