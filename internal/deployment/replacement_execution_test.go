// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
)

// Fake native owner observations run through the same real Execution,
// Inventory, A1 result ledger and signed retirement proof algorithms. This
// fixture is not a Docker/KVM success claim.
func runningReplacementFixture(t *testing.T) *inventoryFixture {
	return runningReplacementFixtureWith(t, nil)
}

func runningReplacementFixtureWith(t *testing.T, configure func(*Compose)) *inventoryFixture {
	return runningReplacementFixtureFor(t, configure, nil)
}

// runningReplacementFixtureFor also adjusts the context of the rolling
// deploy (the original one is planned without it).
func runningReplacementFixtureFor(t *testing.T, configure func(*Compose), rolling func(*PlanningContext)) *inventoryFixture {
	t.Helper()
	return redeployedFixture(t, configure, func(input *Compose) {
		web := input.Services["web"]
		web.Image = strings.ReplaceAll(web.Image, strings.Repeat("a", 64), strings.Repeat("b", 64))
		input.Services["web"] = web
	}, rolling)
}

// redeployedFixture deploys the replica fixture, runs it to Succeeded and
// begins a second deploy of it after change.
func redeployedFixture(t *testing.T, configure, change func(*Compose), rolling func(*PlanningContext)) *inventoryFixture {
	t.Helper()
	return redeployedFixtureIn(t, func(_ *fixture, input *Compose, _ *PlanningContext) {
		if configure != nil {
			configure(input)
		}
	}, change, rolling)
}

// redeployedFixtureIn is redeployedFixture whose setup also sees the
// planning context of both deploys.
func redeployedFixtureIn(t *testing.T, setup func(*fixture, *Compose, *PlanningContext), change func(*Compose), rolling func(*PlanningContext)) *inventoryFixture {
	t.Helper()
	f, input, ctx := replicaFixture(t)
	setup(f, &input, &ctx)
	original, err := CompileApp(input, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	shared, _ := state.New("submitter")
	inventory, _ := NewInventory(f.cluster, "tenant", "php-mysql", "deploy")
	inventory, err = inventory.Begin(inventory.Revision(), f.c, ctx, original, "original", "submitter", 1, false)
	if err != nil {
		t.Fatal(err)
	}
	execution, _ := inventory.Execution()
	x := &inventoryFixture{executionFixture: &executionFixture{f: f, b: original, e: execution, shared: shared, now: 100}, a: inventory}
	// Runtime schedules available stages in rounds: commit ordering alone
	// cannot put private inputs before a consumer's Healthy dependency.
	for {
		pending, progress := false, false
		for _, step := range original.Steps() {
			stage, _ := x.e.Stage(step.Key)
			if stage.Result != nil {
				continue
			}
			pending = true
			if !x.e.dependencies(x.e.index(step.Key), x.now) {
				continue
			}
			x.completeStep(step.Key)
			progress = true
		}
		if !pending {
			break
		}
		if !progress {
			t.Fatal("initial fixture has no eligible stage or native input progress")
		}
	}
	for _, step := range original.Steps() {
		if step.Kind == "ingress" && len(step.Identity) != 0 {
			x.observe(step.Key, true, false)
		}
	}
	x.save(x.e.Finish(x.e.Revision(), x.now))
	x.sync()
	for key, object := range x.shared.Objects("") {
		ctx.Current[key] = object
	}
	ctx.Addresses = map[string]ObjectRef{}
	for _, claim := range x.a.Claims() {
		if claim.Step.Kind != "task" {
			continue
		}
		var service ComposeService
		_ = json.Unmarshal(claim.Step.Goal, &service)
		for _, attachment := range service.Networks {
			for _, address := range []string{attachment.IPv4, attachment.IPv6} {
				if address != "" {
					ctx.Addresses[address] = ObjectRef{Key: claim.Step.Key, Generation: claim.Result.Generation, Revision: claim.Result.Revision}
				}
			}
		}
	}
	change(&input)
	if rolling != nil {
		rolling(&ctx)
	}
	target, err := CompileApp(input, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	x.keep(x.a.Begin(x.a.Revision(), f.c, ctx, target, "rolling", "submitter", 1, false))
	x.b = target
	x.e, _ = x.a.Execution()
	return x
}

func TestReplacementWaitsForActualNewIngressBackendEvidence(t *testing.T) {
	x := runningReplacementFixtureWith(t, func(input *Compose) {
		i := &IngressDeclaration{Node: "node-a", Host: "app.test", Listeners: []ListenerDeclaration{{Address: "192.0.2.11:8080"}}, Runtime: IngressRuntime{MaxRequests: 2, MaxConnections: 8, MaxHeaderBytes: 4096, MaxBodyBytes: 1 << 20, BufferBytes: 128 << 10, RequestTimeoutMS: 30000, DialTimeoutMS: 1000, ResponseHeaderTimeoutMS: 2000, HealthIntervalMS: 100}}
		i.Backend.Service, i.Backend.Port, i.Backend.HealthPath = "web", 8080, "/readyz"
		input.Sfc.Ingress = i
	})
	listener := ResourceKey("ingress", "tenant", "php-mysql", "http")
	retirement, _ := x.a.Retirement()
	if !retirement.Preserves(listener) {
		t.Fatal("rolling update stopped the whole listener")
	}
	first := ResourceKey("task", "tenant", "php-mysql", "web/node-a/r1")
	if x.a.CanRetire(first) {
		t.Fatal("Task stop was allowed before listener request-drain acknowledgement")
	}
	if _, err := x.a.SendRemoval(x.a.Revision(), x.f.c, "admin", first, "drain"); err == nil {
		t.Fatal("original Drain dispatched without positive listener acknowledgement")
	}
	publishReplacementDrains(t, x)
	stage, _ := x.e.Stage(listener)
	if !x.a.CanRetire(first) || len(stage.Observation.IngressDrained) != 1 {
		t.Fatal("positive original listener drain did not release the selected Task")
	}
	for _, mutate := range []func(*Observation){
		func(o *Observation) { o.IngressDrained[0].Generation++ },
		func(o *Observation) { o.IngressDrained[0].Revision++ },
		func(o *Observation) { o.IngressDrained[0].Key += "-foreign" },
		func(o *Observation) { o.IngressBackends = append(o.IngressBackends, o.IngressDrained[0]) },
	} {
		raw, _ := json.Marshal(stage.Observation)
		var invalid Observation
		_ = json.Unmarshal(raw, &invalid)
		invalid.Sequence++
		mutate(&invalid)
		invalid.Signature = ed25519.Sign(x.f.na, ObservationBytes(invalid))
		if _, err := x.e.Observe(x.e.Revision(), invalid, x.now); err == nil {
			t.Fatal("foreign or simultaneously serving original accepted as drained")
		}
	}
	closeReplacementWave(t, x)
	applyReplacementWave(t, x)
	if x.a.ReplacementReady(x.now) {
		t.Fatal("Task health alone advanced before new backend was serving")
	}
	task, _ := x.e.Stage(first)
	stage, _ = x.e.Stage(listener)
	if stage.Result == nil || !stage.Noop || stage.Previous != nil {
		t.Fatal("unchanged listener was recreated")
	}
	o := *stage.Observation
	o.Sequence++
	o.IngressBackends = []ObjectRef{{Key: first, Generation: task.Previous.Result.Generation, Revision: task.Previous.Result.Revision}}
	o.Signature = ed25519.Sign(x.f.na, ObservationBytes(o))
	if _, err := x.e.Observe(x.e.Revision(), o, x.now); err == nil {
		t.Fatal("old backend generation counted as new target readiness")
	}
	o.IngressBackends = []ObjectRef{{Key: first, Generation: task.Result.Generation, Revision: task.Result.Revision}}
	o.Signature = ed25519.Sign(x.f.na, ObservationBytes(o))
	x.save(x.e.Observe(x.e.Revision(), o, x.now))
	x.sync()
	if !x.a.ReplacementReady(x.now) {
		t.Fatal("current new Task and serving backend evidence did not permit next wave")
	}
	if x.e.Health(x.now) != "Degraded" {
		t.Fatal("one serving backend represented full backend health")
	}
	x.keep(x.a.AdvanceReplacement(x.a.Revision(), x.f.c, x.now))
	retirement, _ = x.a.Retirement()
	if !retirement.Preserves(listener) {
		t.Fatal("second wave retired the unchanged listener")
	}
}

func closeReplacementWave(t *testing.T, x *inventoryFixture) {
	t.Helper()
	publishReplacementDrains(t, x)
	for attempt := 0; attempt < 1025; attempt++ {
		retirement, ok := x.a.Retirement()
		if !ok || !retirement.KeepExecution {
			t.Fatal("missing original wave retirement")
		}
		pending, ready := false, ""
		for _, target := range retirement.Targets {
			if !target.Closed {
				pending = true
				if x.a.CanRetire(target.Original.Step.Key) {
					ready = target.Original.Step.Key
					break
				}
			}
		}
		if !pending {
			x.keep(x.a.FinishRetirement(x.a.Revision()))
			x.e, _ = x.a.Execution()
			return
		}
		if ready == "" {
			t.Fatal("wave retirement blocked by an unexpected original consumer")
		}
		x.remove(ready)
	}
	t.Fatal("unbounded wave closure")
}

// Only the native owner/HTTP effects are fake. The signed observation and
// Inventory stop gate are the same core consumed by runtime and the reducer.
func publishReplacementDrains(t *testing.T, x *inventoryFixture) {
	t.Helper()
	retirement, _ := x.a.Retirement()
	for changed := true; changed; {
		changed = false
		for _, step := range x.e.Steps() {
			stage, _ := x.e.Stage(step.Key)
			if stage.Command != nil || !x.e.ReplacementAllows(step.Key) {
				continue
			}
			if _, _, err := x.e.Prepare(x.f.c, x.e.Revision(), step.Key, x.shared.Object(step.Key), x.now); err != nil {
				continue
			}
			x.completeStep(step.Key)
			x.sync()
			changed = true
		}
	}
	for _, step := range x.e.Steps() {
		if step.Kind != "ingress" || len(step.Identity) == 0 {
			continue
		}
		stage, _ := x.e.Stage(step.Key)
		if stage.Command == nil {
			x.completeStep(step.Key)
			x.sync()
		}
		o := x.observation(step.Key, true, false)
		for _, target := range retirement.Targets {
			if slices.Contains(step.Identity, target.Original.Step.Key) {
				s := target.Original
				o.IngressDrained = append(o.IngressDrained, ObjectRef{Key: s.Step.Key, Generation: s.Result.Generation, Revision: s.Result.Revision})
			}
		}
		for _, key := range step.Identity {
			if slices.ContainsFunc(o.IngressDrained, func(ref ObjectRef) bool { return ref.Key == key }) {
				continue
			}
			task, _ := x.e.Stage(key)
			if task.Held() {
				task, _ = task.HeldSource()
			}
			if task.Result != nil {
				o.IngressBackends = append(o.IngressBackends, ObjectRef{Key: key, Generation: task.Result.Generation, Revision: task.Result.Revision})
			}
		}
		private := x.f.na
		if step.Owner == public(x.f.nb) {
			private = x.f.nb
		}
		o.Signature = ed25519.Sign(private, ObservationBytes(o))
		x.save(x.e.Observe(x.e.Revision(), o, x.now))
		x.sync()
	}
}

func applyReplacementWave(t *testing.T, x *inventoryFixture) {
	t.Helper()
	for attempt := 0; attempt < 1025; attempt++ {
		changed := false
		for _, step := range x.b.Steps() {
			stage, _ := x.e.Stage(step.Key)
			if stage.Command != nil || !x.e.ReplacementAllows(step.Key) {
				continue
			}
			if _, _, err := x.e.Prepare(x.f.c, x.e.Revision(), step.Key, x.shared.Object(step.Key), x.now); err != nil {
				continue
			}
			x.completeStep(step.Key)
			x.sync()
			changed = true
		}
		if !changed {
			return
		}
	}
	t.Fatal("unbounded wave application")
}

func TestReplacementOneOperationClosesAndVerifiesOneNodeAtATime(t *testing.T) {
	x := runningReplacementFixture(t)
	first := ResourceKey("task", "tenant", "php-mysql", "web/node-a/r1")
	second := ResourceKey("task", "tenant", "php-mysql", "web/node-b/r1")
	before := x.a.d.Claims[x.a.claim(second)]
	firstStage, _ := x.e.Stage(first)
	secondStage, _ := x.e.Stage(second)
	if !firstStage.Held() || !secondStage.Held() || firstStage.Result != nil || secondStage.Result != nil || x.e.ActiveOperation() != "rolling" {
		t.Fatal("original native mislabeled as target Applied")
	}
	old, _ := secondStage.HeldSource()
	fact := Observation{Cluster: x.f.cluster, Plan: x.b.Digest(), Operation: "rolling", Key: second, Native: secondStage.Previous.Native, Owner: secondStage.Previous.Step.Owner, Command: state.Digest(*old.Command), Generation: old.Result.Generation, Revision: old.Result.Revision, Sequence: 1, At: x.now, Applied: true, Healthy: true}
	fact.Signature = ed25519.Sign(x.f.nb, ObservationBytes(fact))
	x.save(x.e.Observe(x.e.Revision(), fact, x.now))
	x.sync()
	stillHeld, _ := x.e.Stage(second)
	if !stillHeld.Held() || stillHeld.Result != nil || stillHeld.Observation == nil {
		t.Fatal("held native observation became the target's success")
	}
	if x.a.ReplacementReady(x.now) {
		t.Fatal("old successful app advanced the new wave")
	}
	closeReplacementWave(t, x)
	applyReplacementWave(t, x)
	firstStage, _ = x.e.Stage(first)
	if firstStage.Result == nil || firstStage.Result.Generation <= firstStage.Previous.Result.Generation || !x.a.ReplacementReady(x.now) {
		t.Fatal("first fresh target generation did not reach the real health gate")
	}
	// A signed new health failure halts; neither a second-node retirement nor
	// a fresh operation/request ID is generated to turn it into success.
	x.observe(first, false, false)
	x.sync()
	if x.a.ReplacementReady(x.now) {
		t.Fatal("failed first replica allowed the second node to stop")
	}
	if x.e.Health(x.now) != "Degraded" {
		t.Fatal("pending later replica hid a known first-wave failure")
	}
	if _, err := x.a.AdvanceReplacement(x.a.Revision(), x.f.c, x.now); err == nil {
		t.Fatal("unhealthy wave advanced")
	}
	after := x.a.d.Claims[x.a.claim(second)]
	if !bytes.Equal(goal(before), goal(after)) {
		t.Fatal("unselected node lost original native, claim or generation")
	}
	x.observe(first, true, false)
	x.sync()
	x.keep(x.a.AdvanceReplacement(x.a.Revision(), x.f.c, x.now))
	x.e, _ = x.a.Execution()
	retirement, ok := x.a.Retirement()
	if !ok || !retirement.KeepExecution || x.e.ActiveOperation() != "rolling" {
		t.Fatal("next wave became another app operation")
	}
	for _, target := range retirement.Targets {
		if target.Original.Step.Key == first {
			t.Fatal("healthy replacement was retired again")
		}
	}
	closeReplacementWave(t, x)
	applyReplacementWave(t, x)
	x.keep(x.a.AdvanceReplacement(x.a.Revision(), x.f.c, x.now))
	x.e, _ = x.a.Execution()
	x.save(x.e.Finish(x.e.Revision(), x.now))
	x.sync()
	if x.e.Status() != "Succeeded" || x.e.ActiveOperation() != "rolling" || len(x.a.d.History) != 1 || x.a.d.History[0].ID != "original" {
		t.Fatal("wave completion archived or replaced the original rollout identity")
	}
}

func TestReplacementUnknownAndCheckpointCannotSkipPositiveClosure(t *testing.T) {
	x := runningReplacementFixture(t)
	retirement, _ := x.a.Retirement()
	key := ""
	for _, target := range retirement.Targets {
		if x.a.CanRetire(target.Original.Step.Key) {
			key = target.Original.Step.Key
			break
		}
	}
	if key == "" {
		t.Fatal("no original drain")
	}
	x.keep(x.a.SendRemoval(x.a.Revision(), x.f.c, "alice", key, "drain"))
	x.keep(x.a.UnknownRemoval(x.a.Revision(), key, "drain"))
	original, _ := x.a.Removal(key, "drain")
	if _, err := x.a.AdvanceReplacement(x.a.Revision(), x.f.c, x.now); err == nil {
		t.Fatal("unknown was treated as native non-execution")
	}
	if next, _ := x.a.Removal(key, "drain"); next.Command != original.Command {
		t.Fatal("unknown request replaced")
	}
	raw, err := x.a.Encode()
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*inventoryRecord){
		func(d *inventoryRecord) { d.Active.Replacement.Previous = nil },
		func(d *inventoryRecord) { d.Active.Replacement.Previous.Operation = d.Active.Operation },
		func(d *inventoryRecord) { d.Active.Replacement.Phase = "complete" },
		func(d *inventoryRecord) { d.Active.Replacement.Wave++ },
		func(d *inventoryRecord) { d.Retirement = nil; d.Stopping = false },
		func(d *inventoryRecord) { d.Retirement.KeepExecution = false },
		func(d *inventoryRecord) {
			for index := range d.Active.Stages {
				if d.Active.Stages[index].Previous != nil {
					d.Active.Stages[index].Previous = nil
					return
				}
			}
		},
	} {
		var changed inventoryRecord
		_ = json.Unmarshal(raw, &changed)
		mutate(&changed)
		bad, _ := json.Marshal(changed)
		if _, err := DecodeInventory(bad); err == nil {
			t.Fatal("checkpoint erased original closure or skipped a wave")
		}
	}
}

func TestHeldExecutionPreservesOriginalRecipeAndActivationWithoutTargetReceipt(t *testing.T) {
	x := runningReplacementFixture(t)
	key := ResourceKey("task", "tenant", "php-mysql", "web/node-b/r1")
	old, held := x.e.HeldExecution(key)
	if !held || old.ActiveOperation() != "original" || !old.ActivationReady(key) || !x.e.ActivationReady(key) {
		t.Fatal("held native lost its exact original activation input")
	}
	original, _, err := old.Blueprint().TaskInput("web/node-b/r1")
	target, _, targetErr := x.e.Blueprint().TaskInput("web/node-b/r1")
	if err != nil || targetErr != nil || original.Image == target.Image {
		t.Fatal("held recipe became the new target recipe", err, targetErr)
	}
	old.d.Plan.Steps[0].Goal[0] ^= 1
	old.d.Stages[0].Command.Value = "caller-mutation"
	again, ok := x.e.HeldExecution(key)
	if !ok || again.d.Stages[0].Command.Value == "caller-mutation" || again.validate() != nil {
		t.Fatal("held execution view aliases rollout metadata")
	}
	stage, _ := x.e.Stage(key)
	if stage.Command != nil || stage.Result != nil || x.e.ReplacementAllows(key) {
		t.Fatal("original recipe access promoted a new Prepare/result")
	}
	retirement, _ := x.a.Retirement()
	if !retirement.Preserves(key) {
		t.Fatal("first-node wave fenced the unselected second node")
	}
	for _, selected := range retirement.Targets {
		if retirement.Preserves(selected.Original.Step.Key) {
			t.Fatal("selected source escaped its stop fence")
		}
	}
	retirement.Down = true
	if retirement.Preserves(key) {
		t.Fatal("whole-app down inherited wave exemption")
	}
}

func TestReplicaHealthDistinguishesPartialFreshnessFromOperationSuccess(t *testing.T) {
	x := runningReplacementFixture(t)
	key := ResourceKey("task", "tenant", "php-mysql", "web/node-a/r1")
	old, _ := x.e.HeldExecution(key)
	now := x.now + 51
	old = expired(old)
	if old.Health(now) != "Unknown" {
		t.Fatal("expired owner facts remained current health")
	}
	stage, _ := old.Stage(key)
	o := *stage.Observation
	o.Sequence++
	o.Expired = false
	o.At = now
	o.Signature = ed25519.Sign(x.f.na, ObservationBytes(o))
	refreshed, err := old.Observe(old.Revision(), o, now)
	if err != nil || refreshed.Health(now) != "Degraded" || refreshed.Status() != "Succeeded" {
		t.Fatal("partial availability hid a missing peer or rewrote historical success", err)
	}
}

func TestCompletedReplacementAllowsNewPartialRetirementWithoutLosingClosure(t *testing.T) {
	x := runningReplacementFixture(t)
	for wave := 0; wave < 2; wave++ {
		closeReplacementWave(t, x)
		applyReplacementWave(t, x)
		x.keep(x.a.AdvanceReplacement(x.a.Revision(), x.f.c, x.now))
		x.e, _ = x.a.Execution()
	}
	x.save(x.e.Finish(x.e.Revision(), x.now))
	x.sync()
	key := ResourceKey("task", "tenant", "php-mysql", "web/node-a/r1")
	stage, _ := x.e.Stage(key)
	if stage.Previous == nil || !stage.Previous.Removed || stage.Result == nil || x.e.d.Replacement.Phase != "complete" {
		t.Fatal("positive completed rollout required")
	}
	x.keep(x.a.Retire(x.a.Revision(), x.f.c, "alice", "explicit-clear", "submitter", 1, []string{key}, false))
	r, ok := x.a.Retirement()
	if !ok || r.Down || r.KeepExecution || len(r.Targets) == 0 {
		t.Fatal("new partial closure missing")
	}
	if _, err := x.a.FinishRetirement(x.a.Revision()); err == nil {
		t.Fatal("partial retirement skipped native closure")
	}
	for _, mode := range []string{"unfinished-wave", "no-completion", "keep-execution"} {
		bad, err := x.a.clone()
		if err != nil {
			t.Fatal(err)
		}
		switch mode {
		case "unfinished-wave":
			bad.d.Active.Replacement.Phase = "applying"
		case "no-completion":
			bad.d.Active.CompletedAt = 0
		case "keep-execution":
			bad.d.Retirement.KeepExecution = true
		}
		if _, err = bad.Encode(); err == nil {
			t.Fatal("forged completed retirement", mode)
		}
	}
	for tries := 0; tries < 16; tries++ {
		current, _ := x.a.Retirement()
		ready := ""
		pending := false
		for _, target := range current.Targets {
			if !target.Closed {
				pending = true
				if x.a.CanRetire(target.Original.Step.Key) {
					ready = target.Original.Step.Key
					break
				}
			}
		}
		if !pending {
			break
		}
		if ready == "" {
			t.Fatal("new original closure blocked")
		}
		x.remove(ready)
	}
	x.keep(x.a.FinishRetirement(x.a.Revision()))
	claim := x.a.d.Claims[x.a.claim(key)]
	if !claim.Removed || claim.Removal == nil || claim.Removal.ID != "explicit-clear" || claim.Result != *stage.Result {
		t.Fatal("new closure lost exact replacement generation")
	}
}

func TestCompletedReplacementAllowsExplicitDownWithOriginalNativePins(t *testing.T) {
	x := runningReplacementFixture(t)
	for wave := 0; wave < 2; wave++ {
		closeReplacementWave(t, x)
		applyReplacementWave(t, x)
		x.keep(x.a.AdvanceReplacement(x.a.Revision(), x.f.c, x.now))
		x.e, _ = x.a.Execution()
	}
	x.save(x.e.Finish(x.e.Revision(), x.now))
	x.sync()
	original := x.a.Claims()
	x.keep(x.a.Retire(x.a.Revision(), x.f.c, "alice", "explicit-down", "submitter", 1, nil, true))
	r, ok := x.a.Retirement()
	if !ok || !r.Down || r.KeepExecution {
		t.Fatal("original down closure missing")
	}
	for _, target := range r.Targets {
		found := false
		for _, claim := range original {
			if claim.Step.Key == target.Original.Step.Key && claim.Result == target.Original.Result && claim.Command == target.Original.Command {
				found = true
			}
		}
		if !found {
			t.Fatal("down adopted a different native generation")
		}
	}
	if _, err := x.a.FinishRetirement(x.a.Revision()); err == nil {
		t.Fatal("down skipped positive closure")
	}
	for _, mode := range []string{"unfinished", "missing-completion", "keep-execution"} {
		bad, err := x.a.clone()
		if err != nil {
			t.Fatal(err)
		}
		switch mode {
		case "unfinished":
			bad.d.Active.Replacement.Phase = "applying"
		case "missing-completion":
			bad.d.Active.CompletedAt = 0
		case "keep-execution":
			bad.d.Retirement.KeepExecution = true
		}
		if _, err = bad.Encode(); err == nil {
			t.Fatal("down admitted forged completion", mode)
		}
	}
}
