// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/reconcile"
)

// Actual user authentication, SFCP, SDK Raft and durable FSM; no Docker or
// kernel adapters. The delivery step's send is recorded and then lost, so the
// deploy is Unknown; only an explicit resume-app-step sends the same command
// again, and the shared ledger answers it once.
func verifyRealStepReplay(t *testing.T, ctx context.Context, r *Runtime, read func() state.State, userOp func(string, string, uint64, any, ...state.Code) state.Result, revision func() uint64) {
	t.Helper()
	apps := func() control.Apps {
		a, e := r.controlPolicy.Apps(read())
		if e != nil {
			t.Fatal(e)
		}
		return a
	}
	execution := func() deployment.Execution {
		e, ok := apps().Execution("tenant", "app")
		if !ok {
			t.Fatal("missing execution")
		}
		return e
	}
	key := ""
	for _, step := range execution().Steps() {
		if step.Kind == "delivery" {
			key = step.Key
		}
	}
	stage := func() deployment.StageRecord {
		s, _ := execution().Stage(key)
		return s
	}
	if err := r.advanceCurrentApps(ctx); err != nil {
		t.Fatal("prepare", err)
	}
	if s := stage(); s.Command == nil || !s.Sendable() {
		t.Fatal("delivery step not prepared")
	}
	original := *stage().Command
	progress := func(action string) {
		t.Helper()
		var row control.AppView
		for _, v := range apps().Records() {
			if v.App == "app" {
				row = v
			}
		}
		if err := r.appProgress(ctx, cluster.View{State: read()}, row, action, key, nil); err != nil {
			t.Fatal(action, err)
		}
	}
	progress("send") // durable dispatch followed by no transmission
	progress("unknown")
	if s := stage(); s.Journal.Pending == nil || s.Journal.Pending.Phase != reconcile.RecoveryRequired || execution().Status() != "Unknown" {
		t.Fatal("lost send not Unknown")
	}
	for n := 0; n < 2; n++ {
		if err := r.advanceCurrentApps(ctx); err != nil {
			t.Fatal("unapproved pass", err)
		}
	}
	if s := stage(); s.Journal.Pending.Phase != reconcile.RecoveryRequired || s.Result != nil {
		t.Fatal("Unknown step resent without approval")
	}
	steps := execution().UnknownSteps()
	if len(steps) != 1 || steps[0].Key != key || steps[0].Command != state.Digest(original) {
		t.Fatal("unknown step not listed", steps)
	}
	q := control.AppStepReplay{Tenant: "tenant", App: "app", Operation: execution().ActiveOperation(), Key: key, Command: steps[0].Command}
	bad := q
	bad.Command[0]++
	userOp("bad-step-replay", "resume-app-step", revision(), bad, state.ConditionFailed)
	userOp("bad-step-replay-cas", "resume-app-step", revision()-1, q, state.ConditionFailed)
	userOp("step-replay", "resume-app-step", revision(), q)
	if !stage().ReplayDue() {
		t.Fatal("authorized replay not due")
	}
	for n := 0; n < 3 && stage().Result == nil; n++ {
		if err := r.advanceCurrentApps(ctx); err != nil {
			t.Fatal("replay pass", err)
		}
	}
	s := stage()
	if *s.Command != original || s.Result == nil || s.Result.Code != state.Applied || s.Replay == nil || !s.Replay.Dispatched {
		t.Fatal("replay did not send and collect the same command", s.Result, s.Replay)
	}
	if result, found := read().LookupResult(original); !found || result != *s.Result {
		t.Fatal("original durable receipt lost")
	}
	userOp("step-replay-again", "resume-app-step", revision(), q, state.ConditionFailed)
}
