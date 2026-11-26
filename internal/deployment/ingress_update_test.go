// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/ingress"
)

func TestCurrentIngressNativeRequiresExactCommittedClaimBeforeNextDispatch(t *testing.T) {
	declaration := IngressDeclaration{Node: "node-a", Host: "app.test", Listeners: []ListenerDeclaration{{Shared: "https"}}}
	step := Step{Key: "ingress/app/tenant/app/http", Kind: "ingress", Node: "node-a", Owner: [32]byte{1}, Goal: goal(declaration)}
	original := GoalCommand{Schema: 1, Kind: "ingress", Tenant: "tenant", App: "app", Node: step.Node, Owner: step.Owner, Config: step.Goal}
	claim := Claim{Step: step, Command: state.Command{Kind: state.Mutate, Key: step.Key, Value: string(goal(original))}, Result: state.Result{Code: state.Applied, Index: 10, Revision: 10, Generation: 8}, Native: "ingress/original"}
	ref := ObjectRef{Key: step.Key, Generation: 8, Revision: 10}
	if native, ok := CurrentIngressNative(claim, ref, claim.Command.Value); !ok || native != claim.Native {
		t.Fatal("current committed listener required an unrelated next-stage command", native, ok)
	}
	// Merely accepting a different plan cannot turn its desired bytes into
	// the current source, mint a result or borrow the original ID for it.
	planned := declaration
	planned.Balance = &ingress.Balance{Method: "least-request"}
	future := original
	future.Config = goal(planned)
	if _, ok := CurrentIngressNative(claim, ref, string(goal(future))); ok {
		t.Fatal("undispatched policy became a committed original source")
	}
	for _, changed := range []ObjectRef{{Key: "ingress/app/other/app/http", Generation: 8, Revision: 10}, {Key: ref.Key, Generation: 9, Revision: 10}, {Key: ref.Key, Generation: 8, Revision: 11}} {
		if _, ok := CurrentIngressNative(claim, changed, claim.Command.Value); ok {
			t.Fatal("another source borrowed the original native", changed)
		}
	}
	for _, change := range []func(*Claim){
		func(c *Claim) { c.Removed = true },
		func(c *Claim) { c.Retained = true },
		func(c *Claim) { c.Native = "" },
		func(c *Claim) { c.Step.Kind = "task" },
		func(c *Claim) { c.Step.Node = "node-b" },
		func(c *Claim) { c.Step.Owner = [32]byte{2} },
		func(c *Claim) { c.Step.Goal = goal(planned) },
		func(c *Claim) { c.Command.Key = "another-source" },
		func(c *Claim) { c.Command.Delete = true },
		func(c *Claim) { c.Result.Code = state.Forbidden },
	} {
		bad := claim
		change(&bad)
		if _, ok := CurrentIngressNative(bad, ref, claim.Command.Value); ok {
			t.Fatal("invalid ownership claim selected an existing identity")
		}
	}
}

func TestIngressRuntimeUpdateRetainsExactOriginalNativeAndDependencies(t *testing.T) {
	i := IngressDeclaration{Node: "node-a", Host: "a.test", Listeners: []ListenerDeclaration{{Address: "192.0.2.1:443", TLS: true, HTTP3: true}}}
	i.Backend.Service, i.Backend.Network, i.Backend.Port, i.Backend.HealthPath = "web", "app", 8080, "/"
	originalStep := Step{Key: "ingress/app/tenant/app/http", Kind: "ingress", Node: "node-a", Owner: [32]byte{1}, Goal: goal(i), Dependencies: []Dependency{{Key: "workload/task/tenant/app/web", Condition: Healthy}}}
	originalGoal := GoalCommand{Schema: 1, Kind: "ingress", Node: "node-a", Owner: originalStep.Owner, Config: originalStep.Goal, Dependencies: []ObjectRef{{Key: originalStep.Dependencies[0].Key, Generation: 2, Revision: 3}}}
	claim := Claim{Step: originalStep, Command: state.Command{Key: originalStep.Key, Value: string(goal(originalGoal))}, Result: state.Result{Code: state.Applied, Index: 10, Revision: 10, Generation: 8}, Native: "ingress/original"}
	target := originalStep
	i.Host = "new.test"
	i.Balance = &ingress.Balance{Method: "least-request"}
	target.Goal = goal(i)
	if !IngressRuntimeUpdate(claim, target) {
		t.Fatal("same listener route policy requires replacement")
	}
	next := originalGoal
	next.Config = target.Goal
	command := state.Command{Key: target.Key, Value: string(goal(next)), Expected: 10}
	result := state.Result{Code: state.Applied, Index: 11, Revision: 11, Generation: 8}
	if native, ok := RetainedIngressNative(claim, target, command, result); !ok || native != claim.Native {
		t.Fatal("original native lost", native, ok)
	}
	for _, mutate := range []func(*IngressDeclaration){func(i *IngressDeclaration) { i.Listeners[0].Address = "192.0.2.1:8443" }, func(i *IngressDeclaration) { i.Listeners[0].TLS = false }, func(i *IngressDeclaration) { i.Listeners[0].HTTP3 = false }, func(i *IngressDeclaration) { i.Backend.Port = 9090 }, func(i *IngressDeclaration) { i.Runtime.MaxConnections++ }} {
		var changed IngressDeclaration
		json.Unmarshal(target.Goal, &changed)
		changed.Listeners = append([]ListenerDeclaration(nil), changed.Listeners...)
		mutate(&changed)
		bad := target
		bad.Goal = goal(changed)
		if IngressRuntimeUpdate(claim, bad) {
			t.Fatal("physical/backend change used runtime update")
		}
	}
	next.Dependencies[0].Revision++
	command.Value = string(goal(next))
	if _, ok := RetainedIngressNative(claim, target, command, result); ok {
		t.Fatal("changed original producer position retained native")
	}
	if _, ok := RetainedIngressNative(claim, target, command, state.Result{Code: state.Applied, Index: 11, Revision: 11, Generation: 9}); ok {
		t.Fatal("new generation used original native")
	}
}

func TestIngressRuntimeUpdateAllowsOnlyOneWaySingleListenerHandoffCandidate(t *testing.T) {
	before := IngressDeclaration{Node: "node-a", Host: "a.test", Listeners: []ListenerDeclaration{{Address: "192.0.2.1:443", TLS: true, HTTP3: true}}}
	original := GoalCommand{Schema: 1, Kind: "ingress", Node: "node-a", Owner: [32]byte{1}, Config: goal(before)}
	step := Step{Key: "ingress/key", Kind: "ingress", Node: original.Node, Owner: original.Owner, Goal: original.Config}
	claim := Claim{Step: step, Command: state.Command{Key: step.Key, Value: string(goal(original))}, Result: state.Result{Code: state.Applied, Generation: 1, Revision: 2}, Native: "original-native"}
	after := before
	after.Listeners = []ListenerDeclaration{{Shared: "https"}}
	next := step
	next.Goal = goal(after)
	if !IngressRuntimeUpdate(claim, next) {
		t.Fatal("same-owner handoff candidate forced teardown")
	}
	after.Listeners = append(after.Listeners, ListenerDeclaration{Shared: "other"})
	next.Goal = goal(after)
	if IngressRuntimeUpdate(claim, next) {
		t.Fatal("multiple listener handoff accepted without exact socket proof")
	}
}
