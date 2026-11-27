// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

// Full product planner/FSM/Binding/Catalog, with injected acceptance/native
// facts. This does not advertise a live runner or prove transport/native IO.
func shutdownPermitFixture(t *testing.T) (*backupCoreFixture, CheckerShutdownRequest, [32]byte) {
	t.Helper()
	f := managedDNSTaskCoreFixture(t)
	managedDNSChange(t, f, "shutdown-policy", "set-lifecycle-policy", 0, checkerPolicy(), state.Applied)
	task := managedDNSTaskCoreBegin(t, f, "first", "10.80.1.10", "first", func(input *deployment.Compose, planning *deployment.PlanningContext) {
		service := input.Services["web"]
		service.Sfc.Lifecycle = &deployment.ServiceLifecycle{Checks: []deployment.LifecycleCheck{{ID: "before-stop", Phase: contract.Shutdown, LifecycleTemplate: deployment.LifecycleTemplate{Builtin: "docker_health"}}}}
		input.Services["web"] = service
		planning.Features["lifecycle"] = true // pure-core planning input, not product support
	})
	managedDNSTaskCoreSubmit(t, f, "first", deployment.ResourceKey("network-ref", "tenant", "first", "lan/node-a"), true, state.Applied)
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	managedDNSTaskCoreSubmit(t, f, "first", task, true, state.Applied)
	managedDNSTaskCoreProgress(t, f, "first", "bind-inputs", task, nil)
	apps, err := f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	o := f.s.Object(task)
	ref := deployment.ObjectRef{Key: task, Generation: o.Generation, Revision: o.Revision}
	b, ok := apps.Binding(ref)
	if !ok {
		t.Fatal("original Task has no binding")
	}
	owner := [32]byte(f.node.Public().(ed25519.PublicKey))
	if _, err = f.p.AppBindingPermit(f.s, owner, AppBindingRequest{Task: ref, Digest: b.Digest(), At: 10}); err != nil {
		t.Fatal("pre-retirement activation fixture", err)
	}
	i, _ := apps.Inventory("tenant", "first")
	managedDNSChange(t, f, "shutdown-down", "down-app", i.Revision(), AppDown{Tenant: "tenant", App: "first", Operation: "stop-first"}, state.Applied)
	apps, err = f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	i, _ = apps.Inventory("tenant", "first")
	retirement, ok := i.Retirement()
	if !ok {
		t.Fatal("missing accepted stop")
	}
	return f, CheckerShutdownRequest{Schema: 1, Task: ref, Binding: b.Digest(), Stop: checker.ShutdownScope{Operation: retirement.ID, Revision: retirement.Revision}, At: 11}, owner
}

func TestShutdownPermitIsLimitedToOriginalRetirementAndCannotActivate(t *testing.T) {
	f, q, owner := shutdownPermitFixture(t)
	permit, err := f.p.CheckerShutdownPermit(f.s, owner, q)
	if err != nil || permit.Schema != 1 || permit.Task != q.Task || permit.Binding != q.Binding || permit.Stop != q.Stop || permit.Program == ([32]byte{}) || permit.Index != f.s.Index() {
		t.Fatal("original shutdown check denied", permit, err)
	}
	if _, err = f.p.AppBindingPermit(f.s, owner, AppBindingRequest{Task: q.Task, Digest: q.Binding, At: q.At}); err == nil {
		t.Fatal("shutdown revived activation permission")
	}
	for label, mutate := range map[string]func(*CheckerShutdownRequest){
		"schema":    func(q *CheckerShutdownRequest) { q.Schema = 2 },
		"Task":      func(q *CheckerShutdownRequest) { q.Task.Generation++ },
		"binding":   func(q *CheckerShutdownRequest) { q.Binding[0]++ },
		"operation": func(q *CheckerShutdownRequest) { q.Stop.Operation = "other-stop" },
		"revision":  func(q *CheckerShutdownRequest) { q.Stop.Revision++ },
		"compiled":  func(q *CheckerShutdownRequest) { q.Compiled = &checker.CompiledFact{Schema: 1} },
	} {
		changed := q
		mutate(&changed)
		if _, err = f.p.CheckerShutdownPermit(f.s, owner, changed); err == nil {
			t.Fatal("foreign shutdown authority", label)
		}
	}
	foreign := owner
	foreign[0]++
	if _, err = f.p.CheckerShutdownPermit(f.s, foreign, q); err == nil {
		t.Fatal("foreign caller used owner permit")
	}
	policy := checkerPolicy()
	policy.Enabled = false
	managedDNSChange(t, f, "disable-shutdown-checks", "set-lifecycle-policy", 1, policy, state.Applied)
	if _, err = f.p.CheckerShutdownPermit(f.s, owner, q); err == nil {
		t.Fatal("current disabled policy ran an old check")
	}
}
