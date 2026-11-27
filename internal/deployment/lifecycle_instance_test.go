// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/engine"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

func restartingExecution(t *testing.T, appChecks ...LifecycleCheck) *executionFixture {
	t.Helper()
	x, _ := restartingExecutionContext(t, appChecks...)
	return x
}

func restartingExecutionContext(t *testing.T, appChecks ...LifecycleCheck) (*executionFixture, PlanningContext) {
	t.Helper()
	x := runFixture(t)
	ctx := contextFor(t, x.f)
	policy := checker.TenantPolicy{Tenant: "tenant", Enabled: true, Execution: checker.ExecutionPolicy{MaxConcurrent: 1, TimeoutMS: 5000, NanoCPU: 100000000, MemoryBytes: 32 << 20, MaxPIDs: 16, OutputBytes: 4096, ProbeBytes: 4096, Capabilities: []string{"file"}}, Resolver: checker.ResolverPolicy{AllowPackages: []string{"context", "github.com/jay94ks/seafield/lifecycle/v1"}, SourceCacheBytes: 1 << 20}}
	book, err := checker.NewCatalog(x.f.cluster)
	if err != nil {
		t.Fatal(err)
	}
	book, err = book.SetPolicy(x.f.c, "alice", 0, policy)
	if err != nil {
		t.Fatal(err)
	}
	ctx.Checkers = book
	if ctx.Features == nil {
		ctx.Features = map[string]bool{}
	}
	ctx.Features["lifecycle"] = true
	c := smallCompose(t)
	web := c.Services["web"]
	web.Sfc.Lifecycle = &ServiceLifecycle{Checks: []LifecycleCheck{{ID: "alive", Phase: contract.Liveness, LifecycleTemplate: LifecycleTemplate{Builtin: "docker_health"}, Actions: &checker.ActionPolicy{OnDead: checker.RestartContainer}}}}
	c.Services["web"] = web
	if len(appChecks) > 0 {
		c.Sfc.Lifecycle = &LifecycleDeclaration{Checks: appChecks}
	}
	x.b, err = Compile(c, x.f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	x.e, err = NewExecution(x.b, x.f.c, ctx, "operation", "submitter", 1)
	if err != nil {
		t.Fatal(err)
	}
	return x, ctx
}

// Shared state/signatures/planner and canonical snapshot round trips are real.
// Native observations and the completed local control are injected facts here.
func TestSignedPolicyRestartBridgesOriginalExitAndPreservesItsReceipt(t *testing.T) {
	x := restartingExecution(t)
	key := ResourceKey("task", "tenant", "php-mysql", "web")
	x.before(key)
	x.completeStep(key)
	// A committed Task precedes its private-input identity edge. Positive
	// native observations require the same inputs to have activated as well.
	for _, step := range x.b.Steps() {
		stage, _ := x.e.Stage(step.Key)
		if stage.Result == nil {
			x.completeStep(step.Key)
		}
	}
	old := x.observation(key, false, false)
	old.StartedAt = 50_000_000_000
	old.Exit = &engine.ContainerExit{StartedAt: old.StartedAt, FinishedAt: 99_000_000_000, Code: 0}
	old = signCompletion(x, old)
	x.save(x.e.Observe(x.e.Revision(), old, x.now))
	x.now = 102
	o := x.observation(key, true, false)
	o.StartedAt = 101_000_000_000
	run := sha256.Sum256([]byte("completed original run"))
	o.Restart = &TaskRestart{Program: x.b.d.Checkers.Digest(), Checker: "alive", Status: contract.Fail, Control: checker.ContainerControl{Schema: 1, RunID: hex.EncodeToString(run[:]), RequestDigest: sha256.Sum256([]byte("original Request")), Action: checker.RestartContainer, Phase: checker.ControlCompleted, Target: contract.Target{Service: "web", TaskKey: key, NativeID: o.Native, Owner: hex.EncodeToString(o.Owner[:]), OwnerBoot: hex.EncodeToString(run[:]), Generation: o.Generation, Revision: o.Revision, StartedAt: time.Unix(0, old.StartedAt).UTC().Format(time.RFC3339Nano)}}, PreviousExit: old.Exit}
	for _, change := range []func(*Observation){
		func(o *Observation) { o.Restart = nil },
		func(o *Observation) { o.Restart.Program[0]++ },
		func(o *Observation) { o.Restart.Control.Phase = checker.ControlStartSent },
		func(o *Observation) { o.Restart.Control.Target.TaskKey += "-foreign" },
		func(o *Observation) { o.Restart.Control.Target.NativeID += "-foreign" },
		func(o *Observation) { o.Restart.Control.Action = checker.StopContainer },
		func(o *Observation) { o.Restart.Status = contract.Unknown },
		func(o *Observation) { o.Restart.PreviousExit = nil },
		func(o *Observation) { o.StartedAt = old.StartedAt },
	} {
		bad := o
		proof := o.Restart.Clone()
		bad.Restart = &proof
		change(&bad)
		bad = signCompletion(x, bad)
		if _, err := x.e.Observe(x.e.Revision(), bad, x.now); err == nil {
			t.Fatal("external/unbound restart rewrote original exit", bad.Restart)
		}
	}
	o = signCompletion(x, o)
	next, err := x.e.Observe(x.e.Revision(), o, x.now)
	if err != nil {
		t.Fatal("permitted same-native restart rejected", err)
	}
	originalRun := o.Restart.Control.RunID
	o.Restart.Control.RunID = "caller mutation"
	x.save(next, nil)
	stage, _ := x.e.Stage(key)
	if stage.Observation.Exit != nil || stage.Observation.StartedAt != 101_000_000_000 || stage.Observation.Restart.Control.RunID != originalRun || *stage.Observation.Restart.PreviousExit != *old.Exit {
		t.Fatal("receipt/old exit lost across ownership or snapshot", stage.Observation)
	}
	heartbeat := x.observation(key, true, false)
	heartbeat.StartedAt = stage.Observation.StartedAt
	heartbeat.Restart = nil
	heartbeat = signCompletion(x, heartbeat)
	if _, err = x.e.Observe(x.e.Revision(), heartbeat, x.now); err == nil {
		t.Fatal("same instance erased restart receipt")
	}
	proof := stage.Observation.Restart.Clone()
	heartbeat.Restart = &proof
	heartbeat = signCompletion(x, heartbeat)
	x.save(x.e.Observe(x.e.Revision(), heartbeat, x.now))
	legacy, _ := json.Marshal(Observation{})
	if bytes.Contains(legacy, []byte("StartedAt")) || bytes.Contains(legacy, []byte("Restart")) {
		t.Fatal("old schema1 observation bytes changed")
	}
}

// A container can stop again before its first restart observation commits.
// Both product cores must retain the same original exit/receipt in that case.
func TestInventoryAcceptsPolicyRestartThenExitBeforePublication(t *testing.T) {
	x, ctx := restartingExecutionContext(t)
	i := inventoryFor(t, x, ctx)
	for _, step := range x.b.Steps() {
		x.completeStep(step.Key)
	}
	key := ResourceKey("task", "tenant", "php-mysql", "web")
	old := x.observation(key, false, false)
	old.StartedAt = 50_000_000_000
	old.Exit = &engine.ContainerExit{StartedAt: old.StartedAt, FinishedAt: 99_000_000_000, Code: 0}
	old = signCompletion(x, old)
	x.save(x.e.Observe(x.e.Revision(), old, x.now))
	i.sync()
	x.now = 104
	o := x.observation(key, false, false)
	o.StartedAt = 101_000_000_000
	o.Exit = &engine.ContainerExit{StartedAt: o.StartedAt, FinishedAt: 103_000_000_000, Code: 0}
	run := sha256.Sum256([]byte("inventory original restart"))
	o.Restart = &TaskRestart{Program: x.b.d.Checkers.Digest(), Checker: "alive", Status: contract.Fail, PreviousExit: old.Exit, Control: checker.ContainerControl{Schema: 1, RunID: hex.EncodeToString(run[:]), RequestDigest: sha256.Sum256([]byte("original control")), Action: checker.RestartContainer, Phase: checker.ControlCompleted, Target: contract.Target{Service: "web", TaskKey: key, NativeID: o.Native, Owner: hex.EncodeToString(o.Owner[:]), OwnerBoot: hex.EncodeToString(run[:]), Generation: o.Generation, Revision: o.Revision, StartedAt: time.Unix(0, old.StartedAt).UTC().Format(time.RFC3339Nano)}}}
	o = signCompletion(x, o)
	next, err := x.e.Observe(x.e.Revision(), o, x.now)
	if err != nil {
		t.Fatal("execution refused original restart", err)
	}
	for _, variant := range []string{"missing-receipt", "wrong-exit", "same-instance", "unsettled-control"} {
		bad, err := next.clone()
		if err != nil {
			t.Fatal(err)
		}
		n := bad.index(key)
		fact := *bad.d.Stages[n].Observation
		proof := fact.Restart.Clone()
		fact.Restart = &proof
		switch variant {
		case "missing-receipt":
			fact.Restart = nil
		case "wrong-exit":
			fact.Restart.PreviousExit.Code++
		case "same-instance":
			fact.StartedAt = old.StartedAt
			fact.Exit.StartedAt = old.StartedAt
		case "unsettled-control":
			fact.Restart.Control.Phase = checker.ControlStartSent
		}
		fact = signCompletion(x, fact)
		bad.d.Stages[n].Observation = &fact
		if _, err := i.a.Advance(i.a.Revision(), bad, x.shared); err == nil {
			t.Fatal("inventory admitted invalid restart", variant)
		}
	}
	x.save(next, nil)
	i.sync()
	stored, _ := i.a.Execution()
	stage, _ := stored.Stage(key)
	if stage.Observation.Restart == nil || *stage.Observation.Restart.PreviousExit != *old.Exit || *stage.Observation.Exit != *o.Exit || stage.Command == nil || *stage.Command != *next.d.Stages[next.index(key)].Command {
		t.Fatal("inventory lost original command, previous exit, or restarted exit")
	}
}
