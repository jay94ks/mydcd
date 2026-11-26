// SPDX-License-Identifier: Apache-2.0

package app

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/engine"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
	contract "github.com/jay94ks/mydcd/lifecycle/v1"
)

func appScopeState(t *testing.T, id string, phase contract.Phase, status contract.Status, fresh int64) appCheckerState {
	t.Helper()
	point, _, _ := checkerObservationFixture(t, checker.Prepared)
	d := point.Checkpoint.Definition
	d.Scope = ""
	d.Request.Checker = id
	d.Request.Phase = phase
	d.Timing = checker.Timing{IntervalMS: fresh - 100, TimeoutMS: 100, FreshForMS: fresh, Retries: 1}
	m, err := checker.New(d, 100)
	if err != nil {
		t.Fatal(err)
	}
	m, run, err := m.Plan(100)
	if err != nil {
		t.Fatal(err)
	}
	m, err = m.Dispatch(run.Request.RunID)
	if err != nil {
		t.Fatal(err)
	}
	m, _, err = m.Finish(checker.Completion{RunID: run.Request.RunID, RequestDigest: run.RequestDigest, Result: contract.Result{Schema: 1, Status: status, Reason: "observed"}, At: 101, HelperExited: true, ProbesClosed: true})
	if err != nil {
		t.Fatal(err)
	}
	return appCheckerState{check: checker.ResolvedCheck{ID: id, Phase: phase}, machine: m, point: checkerObservation{Checkpoint: m.Checkpoint()}}
}

func TestAppScopeAggregatesSameMachinesAndActualExpiry(t *testing.T) {
	program := [32]byte{3}
	ready := appScopeState(t, "ready", contract.Readiness, contract.Pass, 1100)
	live := appScopeState(t, "live", contract.Liveness, contract.Pass, 2100)
	got, err := aggregateAppCheckStates(program, []appCheckerState{ready, live}, 200)
	if err != nil || got.Status != contract.Pass || got.ValidUntil != 1201 || got.Program != program {
		t.Fatal(got, err)
	}
	got, err = aggregateAppCheckStates(program, []appCheckerState{ready, live}, 1300)
	if err != nil || got.Status != contract.Unknown || got.ValidUntil != 0 {
		t.Fatal("expired readiness passed", got, err)
	}
	fail := appScopeState(t, "failed", contract.Liveness, contract.Fail, 2100)
	got, err = aggregateAppCheckStates(program, []appCheckerState{ready, fail}, 1300)
	if err != nil || got.Status != contract.Fail || got.ValidUntil != 2201 {
		t.Fatal("confirmed failure lost to unknown peer", got, err)
	}
	startup := appScopeState(t, "started", contract.Startup, contract.Pass, 1100)
	got, err = aggregateAppCheckStates(program, []appCheckerState{startup}, 100000)
	if err != nil || got.Status != contract.Pass || got.ValidUntil != 0 {
		t.Fatal("startup success was not sticky for its binding", got, err)
	}
}

func TestAppDependencyReadsBoundServiceFactsAndIgnoresAppGate(t *testing.T) {
	owner := [32]byte{1}
	stamp := time.Unix(50, 0).UTC().Format(time.RFC3339Nano)
	target := contract.Target{Service: "web", TaskKey: "task/web", NativeID: "native", Owner: hex.EncodeToString(owner[:]), OwnerBoot: hex.EncodeToString(owner[:]), StartedAt: stamp, Generation: 3, Revision: 7}
	o := deployment.Observation{Native: target.NativeID, Owner: owner, OwnerBoot: target.OwnerBoot, StartedAt: 50_000_000_000, Generation: 3, Revision: 7, At: 100, Applied: true, Healthy: true, AppChecks: &deployment.AppCheckResult{Status: contract.Fail}}
	s := deployment.StageRecord{Observation: &o}
	if got := appTargetDependency(target, s, "service_healthy", 100); got.Status != contract.Pass {
		t.Fatal("app gate created a service dependency cycle", got)
	}
	for _, change := range []func(*deployment.Observation){func(o *deployment.Observation) { o.OwnerBoot = "changed" }, func(o *deployment.Observation) { o.StartedAt++ }, func(o *deployment.Observation) { o.Generation++ }, func(o *deployment.Observation) { o.Released = true }, func(o *deployment.Observation) { o.Expired = true }} {
		copy := o
		change(&copy)
		if got := appTargetDependency(target, deployment.StageRecord{Observation: &copy}, "service_healthy", 100); got.Status != contract.Unknown {
			t.Fatal("stale/foreign target accepted", got)
		}
	}
	// A stable task keeps its last fact time; renewals go over MyDCP. Only the
	// reducer's Expired mark makes it stale, never the stored At's age.
	if got := appTargetDependency(target, s, "service_healthy", 100+10*30); got.Status != contract.Pass {
		t.Fatal("stable task went stale by stored age", got)
	}
	o.Healthy = false
	o.Exit = &engine.ContainerExit{Code: 0, StartedAt: o.StartedAt, FinishedAt: 99_000_000_000}
	if got := appTargetDependency(target, s, "service_completed_successfully", 100); got.Status != contract.Pass {
		t.Fatal("one-shot exit ignored", got)
	}
}

func TestCheckerPeerObservationsStayLiveWhileUnchanged(t *testing.T) {
	owner := [32]byte{1}
	o := deployment.Observation{Native: "native", Owner: owner, OwnerBoot: "boot", Generation: 3, Revision: 7, At: 100, Applied: true, Healthy: true}
	later := o.At + 10*30
	if !liveTargetObservation(&o, owner, 3, 7, later) {
		t.Fatal("unchanged peer task stopped resolving as a checker target")
	}
	if got := taskDependencyReason(o, "service_healthy", later); got != "" {
		t.Fatal("unchanged dependency reported", got)
	}
	o.Expired = true
	if liveTargetObservation(&o, owner, 3, 7, later) {
		t.Fatal("expired peer task resolved")
	}
	if got := taskDependencyReason(o, "service_healthy", later); got != "owner-stopped-reporting" {
		t.Fatal("expired dependency reason", got)
	}
	o.Expired, o.Healthy = false, false
	if got := taskDependencyReason(o, "service_healthy", later); got != "dependency-not-ready" {
		t.Fatal("unhealthy dependency reason", got)
	}
}
