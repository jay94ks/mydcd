// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/engine"
)

func completionFixture(t *testing.T) *executionFixture {
	t.Helper()
	x := runFixture(t)
	c := smallCompose(t)
	web := c.Services["web"]
	web.DependsOn["db"] = ServiceDependency{Condition: "service_completed_successfully"}
	c.Services["web"] = web
	var err error
	x.b, err = Compile(c, x.f.c, contextFor(t, x.f))
	if err != nil {
		t.Fatal(err)
	}
	x.e, err = NewExecution(x.b, x.f.c, contextFor(t, x.f), "operation", "submitter", 1)
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func signCompletion(x *executionFixture, o Observation) Observation {
	key := x.f.na
	if o.Owner == public(x.f.nb) {
		key = x.f.nb
	}
	o.Signature = ed25519.Sign(key, ObservationBytes(o))
	return o
}

func TestCompletedDependencyUsesSignedOriginalExitAndRestoresCompletionWitness(t *testing.T) {
	x := completionFixture(t)
	db := ResourceKey("task", "tenant", "php-mysql", "db")
	web := ResourceKey("task", "tenant", "php-mysql", "web")
	steps := stepMap(x.b)
	if steps[db].Completion != Completed || !slices.Contains(steps[web].Dependencies, Dependency{db, Completed}) {
		t.Fatal("job completion was replaced with running/health")
	}
	x.before(db)
	x.completeStep(db) // Existing fixture supplies running/healthy, NOT an exit.
	x.completeStep(ResourceKey("inputs", "tenant", "php-mysql", "db"))
	if x.e.satisfies(x.e.index(db), Completed, x.now) {
		t.Fatal("running/healthy satisfies successful completion")
	}
	if _, _, err := x.e.Prepare(x.f.c, x.e.Revision(), web, state.Object{}, x.now); err == nil {
		t.Fatal("dependent started before positive exit")
	}
	o := x.observation(db, false, false)
	o.Exit = &engine.ContainerExit{Code: 0, StartedAt: 50_000_000_001, FinishedAt: 99_999_999_999}
	for _, change := range []func(*Observation){
		func(o *Observation) { o.Exit.Code = 7 },
		func(o *Observation) { o.Exit = nil },
		func(o *Observation) { o.At = 40 },
		func(o *Observation) { o.Released = true },
	} {
		copy := o
		exit := *o.Exit
		copy.Exit = &exit
		change(&copy)
		if successfulCompletion(copy) && validExitObservation(steps[db], copy) {
			t.Fatal("failed/missing/future/released exit became completion")
		}
	}
	x.save(x.e.Observe(x.e.Revision(), signCompletion(x, o), x.now))
	changedExecution, err := x.e.clone()
	if err != nil {
		t.Fatal(err)
	}
	rewritten := x.observation(db, false, false)
	rewritten.Exit = &engine.ContainerExit{Code: 17, StartedAt: o.Exit.StartedAt, FinishedAt: o.Exit.FinishedAt}
	rewritten = signCompletion(x, rewritten)
	changedExecution.d.Stages[x.e.index(db)].Observation = &rewritten
	if progress(x.e, changedExecution) {
		t.Fatal("inventory Advance rewrote the original exit with a newer signature")
	}
	if !x.e.satisfies(x.e.index(db), Completed, x.now) || expired(x.e).satisfies(x.e.index(db), Completed, x.now) {
		t.Fatal("positive exit freshness not enforced")
	}
	// The caller's pointer cannot mutate the accepted FSM state.
	o.Exit.Code = 9
	if !x.e.satisfies(x.e.index(db), Completed, x.now) {
		t.Fatal("caller retained ownership of accepted exit")
	}
	for _, step := range x.b.Steps() {
		s, _ := x.e.Stage(step.Key)
		if s.Result == nil {
			x.completeStep(step.Key)
		}
	}
	x.save(x.e.Finish(x.e.Revision(), x.now))
	if x.e.Status() != "Succeeded" || x.e.Health(x.now) != "Healthy" {
		t.Fatal("positive one-shot completion lost on encode/decode")
	}
	// A later report cannot rewrite the same original terminal execution.
	changed := x.observation(db, true, false)
	if _, err := x.e.Observe(x.e.Revision(), changed, x.now); err == nil {
		t.Fatal("same native resurrected as running/healthy")
	}
}

func TestExitFactsRejectWrongPhaseTimingSignatureAndPreserveLegacyBytes(t *testing.T) {
	x := completionFixture(t)
	db := ResourceKey("task", "tenant", "php-mysql", "db")
	x.before(db)
	x.completeStep(db)
	x.completeStep(ResourceKey("inputs", "tenant", "php-mysql", "db"))
	original := x.observation(db, false, false)
	legacy := ObservationBytes(original)
	if bytes.Contains(legacy, []byte(`"Exit"`)) {
		t.Fatal("nil optional exit changed legacy signed JSON")
	}
	for _, change := range []func(*Observation){
		func(o *Observation) { o.Healthy = true },
		func(o *Observation) { o.Applied = false },
		func(o *Observation) { o.Stopped = true },
		func(o *Observation) { o.Gone = true },
		func(o *Observation) { o.Exit.StartedAt = 0 },
		func(o *Observation) { o.Exit.FinishedAt = 101_000_000_000 },
		func(o *Observation) { o.Exit.Code = 256 },
	} {
		o := original
		o.Exit = &engine.ContainerExit{StartedAt: 50_000_000_000, FinishedAt: 99_000_000_000}
		change(&o)
		if _, err := x.e.Observe(x.e.Revision(), signCompletion(x, o), x.now); err == nil {
			t.Fatal("inconsistent exit was accepted")
		}
	}
	o := original
	o.Exit = &engine.ContainerExit{StartedAt: 50_000_000_000, FinishedAt: 99_000_000_000}
	o = signCompletion(x, o)
	o.Exit.Code = 1
	if _, err := x.e.Observe(x.e.Revision(), o, x.now); err == nil {
		t.Fatal("unsigned modification to exit accepted")
	}
	// A genuine nonzero exit is recorded, but never successful completion.
	o = signCompletion(x, o)
	x.save(x.e.Observe(x.e.Revision(), o, x.now))
	if x.e.satisfies(x.e.index(db), Completed, x.now) || x.e.satisfies(x.e.index(db), Applied, x.now) || x.e.Health(x.now) == "Healthy" {
		t.Fatal("failed job became successful/healthy")
	}
}

func TestComposeCompletionConditionAndBlueprintPhaseCannotBeDowngraded(t *testing.T) {
	raw := strings.ReplaceAll(composeFixture, "DIGEST", strings.Repeat("a", 64))
	raw = strings.ReplaceAll(raw, "condition: service_healthy", "condition: service_completed_successfully")
	if _, err := ParseCompose([]byte(raw)); err != nil {
		t.Fatal("compose-go completion condition not admitted", err)
	}
	x := completionFixture(t)
	copy := x.b.d
	copy.Steps = x.b.Steps()
	for i := range copy.Steps {
		if copy.Steps[i].Completion == Completed {
			copy.Steps[i].Completion = Applied
		}
	}
	b, _ := json.Marshal(copy)
	if _, err := DecodeBlueprint(b); err == nil {
		t.Fatal("job completion requirement removed from restored plan")
	}
}
