// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
	"gopkg.in/yaml.v3"
)

// Uses signed metadata and the real planner/core. It does not stage source
// bytes or advertise a live runner; the fixture's feature bit is planning only.
func lifecyclePlanFixture(t *testing.T) (*fixture, Compose, PlanningContext, Blueprint) {
	t.Helper()
	f, _, ctx, _ := externalFixture(t)
	c, err := ParseApp([]byte(lifecycleInputDocument()))
	if err != nil {
		t.Fatal(err)
	}
	c.MyDC.Lifecycle.Optimizer.Compile = false
	named := c.MyDC.Lifecycle.Scripts["registered"]
	named.Ref.Revision = 1
	c.MyDC.Lifecycle.Scripts["registered"] = named
	policy := checker.TenantPolicy{Tenant: "tenant", Enabled: true,
		Execution: checker.ExecutionPolicy{MaxConcurrent: 1, TimeoutMS: 5000, NanoCPU: 100000000, MemoryBytes: 32 << 20, MaxPIDs: 16, OutputBytes: 4096, ProbeBytes: 4096, Capabilities: []string{"file"}},
		Resolver:  checker.ResolverPolicy{AllowPackages: []string{"context", "github.com/jay94ks/mydcd/lifecycle/v1"}, SourceCacheBytes: 1 << 20}}
	book, err := checker.NewCatalog(f.cluster)
	if err != nil {
		t.Fatal(err)
	}
	book, err = book.SetPolicy(f.c, "alice", 0, policy)
	if err != nil {
		t.Fatal(err)
	}
	fact := func(source string) checker.SourceFact {
		v := checker.SourceFact{Schema: 1, Cluster: f.cluster, Owner: public(f.na), Tenant: "tenant", SDK: 1,
			Digest: sha256.Sum256([]byte(source)), Length: uint64(len(source))}
		v.Signature = ed25519.Sign(f.na, checker.SourceFactBytes(v))
		return v
	}
	book, err = book.PutScript(f.c, "alice", 0, "tenant", "ready-file", fact("package checker\n"))
	if err != nil {
		t.Fatal(err)
	}
	ctx.Checkers = book
	ctx.CheckerProviders = map[[32]byte]bool{public(f.na): true}
	ctx.CheckerSources = map[string]checker.SourceFact{"inline": fact(c.MyDC.Lifecycle.Scripts["inline"].Source)}
	ctx.Features["lifecycle"] = true
	plan, err := CompileApp(c, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	return f, c, ctx, plan
}

func TestCheckerAcceptedPlanSurvivesPositiveRetirementAndEquivalentPolicyRestore(t *testing.T) {
	f := newDeliveryFixture(t, "automatic")
	policy := checker.TenantPolicy{Tenant: "tenant", Enabled: true,
		Execution: checker.ExecutionPolicy{MaxConcurrent: 1, TimeoutMS: 5000, NanoCPU: 100000000, MemoryBytes: 32 << 20, MaxPIDs: 16, OutputBytes: 4096, ProbeBytes: 4096, Capabilities: []string{"file"}},
		Resolver:  checker.ResolverPolicy{AllowPackages: []string{"context", "github.com/jay94ks/mydcd/lifecycle/v1"}, SourceCacheBytes: 1 << 20}}
	book, err := checker.NewCatalog(f.f.cluster)
	if err != nil {
		t.Fatal(err)
	}
	book, err = book.SetPolicy(f.f.c, "alice", 0, policy)
	if err != nil {
		t.Fatal(err)
	}
	f.ctx.Checkers, f.ctx.Features["lifecycle"] = book, true
	input, err := ParseApp(f.body)
	if err != nil {
		t.Fatal(err)
	}
	db := input.Services["db"]
	db.MyDC.Lifecycle = &ServiceLifecycle{Checks: []LifecycleCheck{{ID: "marker", Phase: "liveness", LifecycleTemplate: LifecycleTemplate{Builtin: "file", Parameters: LifecycleParameters(`{"path":"/run/ready","kind":"regular"}`)}}}}
	input.Services["db"] = db
	f.body, err = yaml.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	f.saveDelivery(NewDelivery(f.f.c, f.ctx, f.body))
	f.receive(f.body)
	f.start("first-with-checker")
	f.completeDelivery()
	accepted, ok := f.d.AcceptedPlan()
	if !ok || accepted.CheckerProgram() == nil {
		t.Fatal("missing accepted original checker")
	}
	f.ctx.CheckerPrograms = map[AppScope]checker.FrozenProgram{accepted.Scope(): *accepted.CheckerProgram()}
	disabled := policy.Clone()
	disabled.Enabled = false
	f.ctx.Checkers, err = f.ctx.Checkers.SetPolicy(f.f.c, "alice", 1, disabled)
	if err != nil {
		t.Fatal(err)
	}
	f.ctx.Checkers, err = f.ctx.Checkers.SetPolicy(f.f.c, "alice", 2, policy)
	if err != nil {
		t.Fatal(err)
	}
	f.receive(f.imageChange("b"))
	f.approve()
	f.beginTransition("second-with-checker", DeliveryUpdate)
	f.closeTargets()
	f.finishRetirement()
	if _, active := f.d.Inventory().Execution(); active {
		t.Fatal("retirement kept an execution")
	}
	f.ctx.CheckerPrograms = nil // the former active-execution-only lookup
	if _, err = f.d.ContinueTransition(f.d.Revision(), f.f.c, f.ctx, "alice"); err == nil || !strings.Contains(err.Error(), "CD_TARGET_REPLAN_REQUIRED") {
		t.Fatal("missing continuity did not reproduce ready-phase intent mismatch", err)
	}
	plan, ok := f.d.AcceptedPlan()
	if !ok || plan.CheckerProgram() == nil || plan.CheckerProgram().Digest() != accepted.CheckerProgram().Digest() {
		t.Fatal("positive closure lost accepted recipe")
	}
	f.ctx.CheckerPrograms = map[AppScope]checker.FrozenProgram{plan.Scope(): *plan.CheckerProgram()}
	f.continueTransition()
	if f.e.ActiveOperation() != "second-with-checker" || f.e.Blueprint().CheckerProgram().Digest() != accepted.CheckerProgram().Digest() {
		t.Fatal("original operation or program replaced")
	}
}

func TestCheckerFrozenPlanTaskAndBindingUseSameOriginalSelection(t *testing.T) {
	f, _, ctx, b := lifecyclePlanFixture(t)
	raw, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeBlueprint(raw)
	if err != nil || decoded.Digest() != b.Digest() || decoded.ValidateCurrent(f.c, ctx) != nil || decoded.ValidateLifecycleCatalog(ctx.Checkers) != nil {
		t.Fatal("frozen plan roundtrip/current catalog", err)
	}
	if b.d.Input.Services["web"].LifecycleProgram != nil || b.d.Input.Services["web"].LifecycleSources != nil {
		t.Fatal("accepted facts leaked into raw app")
	}
	needs, err := b.Inputs("web", "task-web", 3, public(f.issuer))
	if err != nil || needs.Lifecycle == nil || len(needs.Lifecycle.Scripts) != 1 || len(needs.Lifecycle.Sources) != 1 {
		t.Fatal("binding selection", err)
	}
	var task ComposeService
	for _, step := range b.Steps() {
		if step.Kind == "task" && json.Unmarshal(step.Goal, &task) != nil {
			t.Fatal("Task goal")
		}
	}
	if task.LifecycleProgram == nil || task.LifecycleProgram.Program != b.d.Checkers.Digest() || task.CheckLifecycleNeeds(needs) != nil || task.LifecycleProgram.Service != "web" || len(task.LifecycleProgram.AppChecks) != 1 {
		t.Fatal("Task did not consume its frozen program")
	}
	copy := task.LifecycleProgram.Clone()
	copy.Sources["inline"].Signature[0] ^= 1
	if task.LifecycleProgram.Validate(f.cluster) != nil || copy.Validate(f.cluster) == nil {
		t.Fatal("program aliasing or unsigned source")
	}
	other := ownNeeds(needs)
	other.Lifecycle.PolicyRevision++
	if task.CheckLifecycleNeeds(other) == nil {
		t.Fatal("Binding swapped policy")
	}
	// Returned recipes cannot change the original frozen plan.
	needs.Lifecycle.Sources[0].Signature[0] ^= 1
	after, _ := b.Encode()
	if !bytes.Equal(raw, after) {
		t.Fatal("Inputs aliased frozen facts")
	}
}

func TestBlueprintMetadataCacheKeepsOwnedBytesAndRejectsChangedFacts(t *testing.T) {
	_, _, _, b := lifecyclePlanFixture(t)
	first, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Clone(first)
	first[0] = '!'
	second, err := b.Encode()
	if err != nil || !bytes.Equal(second, want) {
		t.Fatal("returned bytes changed the cached declaration", err)
	}
	for alias, fact := range b.d.Checkers.Sources {
		fact = fact.Clone()
		fact.Signature[0] ^= 1
		b.d.Checkers.Sources[alias] = fact
		if _, err := b.Encode(); err == nil {
			t.Fatal("changed signed metadata reused a previous validation")
		}
		break
	}
}

func TestCheckerFrozenPlanPreservesOriginalAfterRetirementButRefusesNewAcceptance(t *testing.T) {
	f, _, ctx, b := lifecyclePlanFixture(t)
	book, err := ctx.Checkers.RetireScript(f.c, "alice", 1, "tenant", checker.NamedReference{Name: "ready-file", Revision: 1}, false)
	if err != nil {
		t.Fatal(err)
	}
	ctx.Checkers = book
	if b.ValidateLifecycleCatalog(book) != nil {
		t.Fatal("retirement erased original provenance")
	}
	if b.ValidateCurrent(f.c, ctx) == nil {
		t.Fatal("retired version admitted to new execution")
	}
	policy, _ := book.Policy("tenant", 0)
	policy.Revision = 0
	policy.Enabled = false
	book, err = book.SetPolicy(f.c, "alice", 1, policy)
	if err != nil {
		t.Fatal(err)
	}
	ctx.Checkers = book
	raw, err := b.Encode()
	if err != nil || b.ValidateLifecycleCatalog(book) != nil {
		t.Fatal("disabled current policy changed original", err)
	}
	if _, err := DecodeBlueprint(raw); err != nil {
		t.Fatal("original cannot resume structurally", err)
	}
	if b.ValidateCurrent(f.c, ctx) == nil {
		t.Fatal("old permission replaced current acceptance")
	}
}

func TestCheckerFrozenPlanRejectsChangedSourceProviderAndTaskProjection(t *testing.T) {
	f, c, ctx, b := lifecyclePlanFixture(t)
	raw, _ := b.Encode()
	for label, mutate := range map[string]func(*Blueprint){
		"normalized phase":       func(b *Blueprint) { b.d.Checkers.Program.Services["web"][0].Phase = "shutdown" },
		"raw declaration":        func(b *Blueprint) { b.d.Input.MyDC.Lifecycle.Optimizer.Compile = true },
		"policy":                 func(b *Blueprint) { b.d.Checkers.Policy.Revision++ },
		"extra source":           func(b *Blueprint) { b.d.Checkers.Sources["extra"] = b.d.Checkers.Sources["inline"] },
		"missing frozen program": func(b *Blueprint) { b.d.Checkers = nil },
		"Task mapping": func(b *Blueprint) {
			for i := range b.d.Steps {
				if b.d.Steps[i].Kind != "task" {
					continue
				}
				var s ComposeService
				_ = json.Unmarshal(b.d.Steps[i].Goal, &s)
				s.LifecycleProgram.Service = "foreign"
				b.d.Steps[i].Goal, _ = json.Marshal(s)
			}
		},
	} {
		t.Run(label, func(t *testing.T) {
			changed, err := DecodeBlueprint(raw)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&changed)
			if _, err := changed.Encode(); err == nil {
				t.Fatal("changed frozen provenance encoded")
			}
		})
	}
	ctx.CheckerProviders = nil
	if _, err := CompileApp(c, f.c, ctx); err == nil || !strings.Contains(err.Error(), "LIFECYCLE_PROVIDER_REQUIRED") {
		t.Fatal("uninstalled source provider", err)
	}
	ctx.CheckerProviders = map[[32]byte]bool{public(f.na): true}
	ctx.CheckerSources = nil
	if _, err := CompileApp(c, f.c, ctx); err == nil {
		t.Fatal("missing inline source was fabricated")
	}
}

func TestCheckerDependenciesMergeStartedButKeepHealthAndCompletionDistinct(t *testing.T) {
	key := func(kind, id string) string { return ResourceKey(kind, "tenant", "app", id) }
	checks := []checker.ResolvedCheck{{Builtin: &checker.Builtin{Kind: "depends_on", Dependency: &checker.DependencyCondition{Services: []string{"db"}, Condition: "service_started"}}}}
	deps, err := mergeCheckerDependencies([]Dependency{{key("task", "db"), Healthy}}, checks, key)
	if err != nil || len(deps) != 1 || deps[0].Condition != Healthy {
		t.Fatal("downgraded/duplicated original health dependency", err)
	}
	checks[0].Builtin.Dependency.Condition = "service_healthy"
	deps, err = mergeCheckerDependencies([]Dependency{{key("task", "db"), Applied}}, checks, key)
	if err != nil || len(deps) != 1 || deps[0].Condition != Healthy {
		t.Fatal("failed to require actual health", err)
	}
	checks[0].Builtin.Dependency.Condition = "service_completed_successfully"
	deps, err = mergeCheckerDependencies([]Dependency{{key("task", "db"), Applied}}, checks, key)
	if err != nil || len(deps) != 1 || deps[0].Condition != Completed {
		t.Fatal("successful job exit became started", err)
	}
	if _, err := mergeCheckerDependencies([]Dependency{{key("task", "db"), Healthy}}, checks, key); err == nil {
		t.Fatal("simultaneous healthy/completed requirements silently replaced")
	}
}

func TestCheckerTaskMetadataCannotBypassPlansWithoutFixedVolume(t *testing.T) {
	f, input, ctx, _ := externalFixture(t)
	b, err := CompileApp(input, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.d.FixedVolumes) != 0 {
		t.Fatal("fixture must exercise the no-fixed-volume path")
	}
	for i := range b.d.Steps {
		if b.d.Steps[i].Kind != "task" {
			continue
		}
		var s ComposeService
		if json.Unmarshal(b.d.Steps[i].Goal, &s) != nil {
			t.Fatal("Task config")
		}
		s.LifecycleSources = &checker.Selection{PolicyRevision: 1, Scripts: []checker.NamedReference{{Name: "injected", Revision: 1}}}
		b.d.Steps[i].Goal, _ = json.Marshal(s)
	}
	if _, err := b.Encode(); err == nil {
		t.Fatal("injected checker facts bypassed the no-volume metadata path")
	}
}

func TestCheckerEquivalentPolicyRestorationPreservesOwnedTaskProgram(t *testing.T) {
	f, input, ctx, original := lifecyclePlanFixture(t)
	accepted := original.CheckerProgram()
	ctx.CheckerPrograms = map[AppScope]checker.FrozenProgram{original.Scope(): *accepted}
	policy, _ := ctx.Checkers.Policy("tenant", 0)
	restored := policy.Clone()
	restored.Revision = 0
	disabled := restored.Clone()
	disabled.Enabled = false
	var err error
	ctx.Checkers, err = ctx.Checkers.SetPolicy(f.c, "alice", policy.Revision, disabled)
	if err != nil {
		t.Fatal(err)
	}
	// An accepted program never replaces the current disabled-policy check.
	if _, err = CompileApp(input, f.c, ctx); err == nil {
		t.Fatal("old program bypassed disabled current policy")
	}
	ctx.Checkers, err = ctx.Checkers.SetPolicy(f.c, "alice", policy.Revision+1, restored)
	if err != nil {
		t.Fatal(err)
	}
	next, err := CompileApp(input, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if next.d.Checkers.Digest() != accepted.Digest() {
		t.Fatal("equivalent restoration replaced accepted identity")
	}
	for _, step := range original.Steps() {
		for _, candidate := range next.Steps() {
			if step.Key == candidate.Key && step.Kind == "task" && !bytes.Equal(step.Goal, candidate.Goal) {
				t.Fatal("equivalent restoration changed an owned Task")
			}
		}
	}
	if next.ValidateLifecycleCatalog(ctx.Checkers) != nil {
		t.Fatal("accepted historical provenance invalid")
	}
	// Neither a foreign scope nor a fabricated history revision gets continuity.
	foreign := original.Scope()
	foreign.App = "another"
	ctx.CheckerPrograms = map[AppScope]checker.FrozenProgram{foreign: *accepted}
	fresh, err := CompileApp(input, f.c, ctx)
	if err != nil || fresh.d.Checkers.Digest() == accepted.Digest() {
		t.Fatal("foreign app program adopted", err)
	}
	forged := fresh.CheckerProgram()
	forged.Policy.Revision = 999
	ctx.CheckerPrograms = map[AppScope]checker.FrozenProgram{original.Scope(): *forged}
	next, err = CompileApp(input, f.c, ctx)
	if err != nil || next.d.Checkers.Digest() == forged.Digest() {
		t.Fatal("fabricated policy history adopted", err)
	}
	// A real policy change is a new program; only its sequence is incidental.
	ctx.CheckerPrograms = map[AppScope]checker.FrozenProgram{original.Scope(): *accepted}
	changed := restored.Clone()
	changed.Execution.OutputBytes *= 2
	ctx.Checkers, err = ctx.Checkers.SetPolicy(f.c, "alice", policy.Revision+2, changed)
	if err != nil {
		t.Fatal(err)
	}
	next, err = CompileApp(input, f.c, ctx)
	if err != nil || next.d.Checkers.Digest() == accepted.Digest() {
		t.Fatal("changed policy reused old identity", err)
	}
}
