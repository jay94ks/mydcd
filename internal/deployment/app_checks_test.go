// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

// Existing planner/signatures/FSM/snapshot boundary; native checks are facts
// supplied by the fixture, not real interpreter or Docker success evidence.
func TestAppChecksGateApplicationWithoutChangingServiceHealth(t *testing.T) {
	x := restartingExecution(t, LifecycleCheck{ID: "all-ready", Phase: contract.Readiness, Interval: "10s", Timeout: "1s", LifecycleTemplate: LifecycleTemplate{Builtin: "depends_on", Parameters: LifecycleParameters(`{"services":["web"],"condition":"service_healthy"}`)}})
	for _, step := range x.b.Steps() {
		s, _ := x.e.Stage(step.Key)
		if s.Result == nil || s.Result.Code != state.Applied {
			x.completeStep(step.Key)
		}
	}
	key, required, _, maxFresh := x.e.appCheckCoordinator()
	if !required || key == "" {
		t.Fatal("app check coordinator missing")
	}
	if x.e.Health(x.now) != "Unknown" {
		t.Fatal("missing app results became healthy")
	}
	if _, err := x.e.Finish(x.e.Revision(), x.now); err == nil {
		t.Fatal("app completed without app checks")
	}
	o := x.observation(key, true, false)
	o.AppChecks = &AppCheckResult{Program: x.b.d.Checkers.Digest(), Status: contract.Fail, ValidUntil: int64(x.now)*1000 + maxFresh}
	o = signCompletion(x, o)
	x.save(x.e.Observe(x.e.Revision(), o, x.now))
	if x.e.Health(x.now) != "Degraded" || !x.e.satisfies(x.e.index(key), Healthy, x.now) {
		t.Fatal("app failure changed the coordinator's service health")
	}
	if _, err := x.e.Finish(x.e.Revision(), x.now); err == nil {
		t.Fatal("failed app check allowed completion")
	}
	pass := x.observation(key, true, false)
	pass.AppChecks = &AppCheckResult{Program: x.b.d.Checkers.Digest(), Status: contract.Pass, ValidUntil: int64(x.now)*1000 + maxFresh}
	for _, change := range []func(*Observation){
		func(o *Observation) { o.AppChecks.Program[0]++ },
		func(o *Observation) { o.AppChecks.ValidUntil = int64(o.At) * 1000 },
		func(o *Observation) { o.AppChecks.ValidUntil = 0 },
		func(o *Observation) { o.AppChecks.Status = "invalid" },
	} {
		bad := pass
		copy := *pass.AppChecks
		bad.AppChecks = &copy
		change(&bad)
		bad = signCompletion(x, bad)
		if _, err := x.e.Observe(x.e.Revision(), bad, x.now); err == nil {
			t.Fatal("invalid app result accepted", bad.AppChecks)
		}
	}
	for _, step := range x.b.Steps() {
		if step.Kind == "task" && step.Key != key {
			foreign := x.observation(step.Key, true, false)
			copy := *pass.AppChecks
			foreign.AppChecks = &copy
			foreign = signCompletion(x, foreign)
			if _, err := x.e.Observe(x.e.Revision(), foreign, x.now); err == nil {
				t.Fatal("non-coordinator app result accepted")
			}
		}
	}
	pass = signCompletion(x, pass)
	next, err := x.e.Observe(x.e.Revision(), pass, x.now)
	if err != nil {
		t.Fatal(err)
	}
	pass.AppChecks.Status = contract.Unknown // caller ownership must not alter it
	x.save(next, nil)
	if x.e.Health(x.now) != "Healthy" {
		t.Fatal("valid app pass not consumed")
	}
	x.save(x.e.Finish(x.e.Revision(), x.now))
	if x.e.Health(x.now+uint64(maxFresh/1000)+1) != "Unknown" {
		t.Fatal("expired app pass remained healthy")
	}
	legacy, _ := json.Marshal(Observation{})
	if bytes.Contains(legacy, []byte("AppChecks")) || bytes.Contains(legacy, []byte("OwnerBoot")) {
		t.Fatal("optional metadata changed old bytes")
	}
}
