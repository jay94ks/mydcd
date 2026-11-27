// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"testing"

	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

func hashText(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func TestCheckerProgramChangeCannotReuseOldResultOrRunSequence(t *testing.T) {
	d := testDefinition()
	raw, _ := json.Marshal(d)
	if bytes.Contains(raw, []byte("ProgramDigest")) {
		t.Fatal("empty program binding changed existing schema1 bytes")
	}
	d.ProgramDigest = hashText("accepted-program")
	m, run := beginRun(t, newMachine(t, d), 100)
	m, _ = completeRun(t, m, run, 101, contract.Pass)
	m, _ = m.Retire()
	d.ProgramDigest = hashText("changed-action-policy")
	next, err := m.Replace(d, 102)
	if err != nil || next.Status(102) != contract.Unknown || next.Checkpoint().Sequence != 1 || next.Checkpoint().Last != nil {
		t.Fatal("changed program retained old observation or lost sequence", next.Checkpoint(), err)
	}
	_, fresh := beginRun(t, next, 102)
	if fresh.Sequence != 2 || fresh.Request.RunID == run.Request.RunID {
		t.Fatal("new policy reused original execution ID", fresh)
	}
	d.ProgramDigest = "not-a-digest"
	if d.Validate() == nil {
		t.Fatal("invalid program binding accepted")
	}
}

func TestCheckerBindingSeparatesAppAndServiceScopeAndKeepsLogicalReplacement(t *testing.T) {
	app := testDefinition()
	service := app
	service.Scope = "web"
	if app.Validate() != nil || service.Validate() != nil || app.Digest() == service.Digest() {
		t.Fatal("scope binding collision")
	}
	_, a := beginRun(t, newMachine(t, app), 100)
	_, b := beginRun(t, newMachine(t, service), 100)
	if a.Request.RunID == b.Request.RunID {
		t.Fatal("same-named app/service run collision")
	}
	raw, _ := json.Marshal(app)
	if bytes.Contains(raw, []byte("Scope")) {
		t.Fatal("absent scope changed old JSON shape")
	}
	retired, _ := newMachine(t, service).Retire()
	for _, change := range []func(*Definition){func(d *Definition) { d.Scope = "" }, func(d *Definition) { d.Request.Phase = contract.Liveness }} {
		next := service
		next.Request = ownRequest(service.Request)
		change(&next)
		if _, err := retired.Replace(next, 101); err == nil {
			t.Fatal("different logical scope/phase replaced original")
		}
	}
	bad := service
	bad.Scope = "db"
	if bad.Validate() == nil {
		t.Fatal("service scope references foreign target")
	}
}

func testDefinition() Definition {
	return Definition{Request: contract.Request{Schema: 1, Cluster: hashText("cluster"), Tenant: "tenant", App: "app", Checker: "http-ready", SourceDigest: hashText("original-source"), Phase: contract.Readiness, Targets: []contract.Target{{Service: "web", TaskKey: "apps/tenant/app/task/web", NativeID: hashText("original-container"), Owner: hashText("node-key"), OwnerBoot: hashText("node-boot"), Generation: 3, Revision: 7}}, Parameters: map[string]string{"path": "/readyz"}}, Timing: Timing{IntervalMS: 10, TimeoutMS: 5, FreshForMS: 30, Retries: 2}, PolicyRevision: 1}
}

func newMachine(t *testing.T, d Definition) Machine {
	t.Helper()
	m, err := New(d, 100)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func beginRun(t *testing.T, m Machine, at int64) (Machine, Run) {
	t.Helper()
	m, r, err := m.Plan(at)
	if err != nil {
		t.Fatal(err)
	}
	// Tests model the adapter's two durable checkpoints; they do not claim
	// a DB sync or actual helper launch by copying these values.
	m, err = Restore(m.Checkpoint())
	if err != nil {
		t.Fatal(err)
	}
	m, err = m.Dispatch(r.Request.RunID)
	if err != nil {
		t.Fatal(err)
	}
	m, err = Restore(m.Checkpoint())
	if err != nil {
		t.Fatal(err)
	}
	return m, r
}

func completeRun(t *testing.T, m Machine, r Run, at int64, status contract.Status) (Machine, Observation) {
	t.Helper()
	m, o, err := m.Finish(Completion{RunID: r.Request.RunID, RequestDigest: r.RequestDigest, Result: contract.Result{Schema: 1, Status: status, Reason: "sample-result"}, At: at, HelperExited: true, ProbesClosed: true})
	if err != nil || m.Validate() != nil {
		t.Fatal("completion", err, m.Validate())
	}
	return m, o
}

func TestCheckerDeadlineKeepsOriginalUntilHelperAndExecAreClosed(t *testing.T) {
	m, r := beginRun(t, newMachine(t, testDefinition()), 100)
	before := m.Checkpoint()
	if _, _, err := m.Plan(5000); !errors.Is(err, ErrPending) || m.Status(5000) != contract.Unknown {
		t.Fatal("timeout allowed another checker", err)
	}
	for _, closed := range []Completion{
		{RunID: r.Request.RunID, RequestDigest: r.RequestDigest, Result: contract.Result{Schema: 1, Status: contract.Pass, Reason: "late"}, At: 106, HelperExited: true},
		{RunID: r.Request.RunID, RequestDigest: r.RequestDigest, Result: contract.Result{Schema: 1, Status: contract.Pass, Reason: "late"}, At: 106, ProbesClosed: true},
	} {
		if _, _, err := m.Finish(closed); !errors.Is(err, ErrPending) || !reflect.DeepEqual(before, m.Checkpoint()) {
			t.Fatal("partial closure discarded original", err)
		}
	}
	retiring, err := m.Retire()
	if err != nil || retiring.Closed() {
		t.Fatal("retire claimed unknown process closure", err)
	}
	if _, err = retiring.CancelPrepared(r.Request.RunID, 106); !errors.Is(err, ErrPending) {
		t.Fatal("dispatched start became unsent", err)
	}
	retiring, observation := completeRun(t, retiring, r, 106, contract.Pass)
	if !retiring.Closed() || observation.Result.Status != contract.Unknown || observation.Result.Reason != "deadline-expired" || observation.Run.Request.RunID != r.Request.RunID {
		t.Fatal("late pass became current health or new run")
	}
	if _, _, err = retiring.Plan(1000); !errors.Is(err, ErrRetiring) {
		t.Fatal("retired binding restarted", err)
	}
}

func TestCheckerDuplicateAndOtherBindingCannotRefreshOriginalObservation(t *testing.T) {
	m, r := beginRun(t, newMachine(t, testDefinition()), 100)
	m, receipt := completeRun(t, m, r, 101, contract.Pass)
	before := m.Checkpoint()
	replayed, again, err := m.Finish(Completion{RunID: r.Request.RunID, RequestDigest: r.RequestDigest, Result: receipt.Result, At: 5000, HelperExited: true, ProbesClosed: true})
	if err != nil || again.At != 101 || !reflect.DeepEqual(before, replayed.Checkpoint()) || replayed.Status(5000) != contract.Unknown {
		t.Fatal("old completion renewed freshness", err)
	}
	changed := testDefinition()
	changed.Request.Targets[0].OwnerBoot = hashText("other-boot")
	other, run := beginRun(t, newMachine(t, changed), 100)
	if run.Request.RunID == r.Request.RunID {
		t.Fatal("run ID did not bind owner boot")
	}
	if _, _, err = other.Finish(Completion{RunID: r.Request.RunID, RequestDigest: r.RequestDigest, Result: receipt.Result, At: 101, HelperExited: true, ProbesClosed: true}); !errors.Is(err, ErrStale) {
		t.Fatal("previous target/boot pass adopted", err)
	}
	badDigest := run.RequestDigest
	badDigest[0] ^= 1
	if _, _, err = other.Finish(Completion{RunID: run.Request.RunID, RequestDigest: badDigest, Result: receipt.Result, At: 101, HelperExited: true, ProbesClosed: true}); !errors.Is(err, ErrStale) {
		t.Fatal("wrong request content adopted", err)
	}
}

func TestCheckerGraceRetriesUnknownAndFreshnessHaveDistinctMeaning(t *testing.T) {
	d := testDefinition()
	d.Timing.StartPeriodMS = 40
	m, r := beginRun(t, newMachine(t, d), 100)
	m, _ = completeRun(t, m, r, 101, contract.Fail)
	if m.Status(101) != contract.Unknown || m.Checkpoint().Failures != 0 {
		t.Fatal("grace failure was pass or counted failure")
	}
	m, r = beginRun(t, m, 111)
	m, _ = completeRun(t, m, r, 112, contract.Pass)
	if m.Status(112) != contract.Pass {
		t.Fatal("first pass not published")
	}
	m, r = beginRun(t, m, 122)
	m, _ = completeRun(t, m, r, 123, contract.Fail)
	if m.Status(123) != contract.Pass || m.Checkpoint().Failures != 1 {
		t.Fatal("success did not end grace / consecutive retry policy")
	}
	m, r = beginRun(t, m, 133)
	m, _ = completeRun(t, m, r, 134, contract.Fail)
	if m.Status(134) != contract.Fail {
		t.Fatal("retry exhaustion did not fail")
	}
	m, r = beginRun(t, m, 144)
	m, _ = completeRun(t, m, r, 145, contract.Unknown)
	if m.Status(145) != contract.Unknown || m.Checkpoint().Failures != 0 {
		t.Fatal("unknown counted as negative probe or retained pass")
	}
	m, r = beginRun(t, m, 155)
	m, _ = completeRun(t, m, r, 156, contract.Pass)
	if m.Status(186) != contract.Pass || m.Status(187) != contract.Unknown {
		t.Fatal("observation lifetime not enforced")
	}
}

func TestCheckerStalePassCannotBeRenewedBySubthresholdFailure(t *testing.T) {
	m, r := beginRun(t, newMachine(t, testDefinition()), 100)
	m, _ = completeRun(t, m, r, 101, contract.Pass)
	if m.Status(500) != contract.Unknown {
		t.Fatal("old pass did not expire")
	}
	m, r = beginRun(t, m, 500)
	m, _ = completeRun(t, m, r, 501, contract.Fail)
	if m.Status(501) != contract.Unknown || m.Checkpoint().Failures != 1 {
		t.Fatal("a negative sample renewed stale healthy state")
	}
}

func TestCheckerPreparedCancellationClockAndImmutableCopies(t *testing.T) {
	d := testDefinition()
	m := newMachine(t, d)
	d.Request.Parameters["path"] = "/changed"
	d.Request.Targets[0].NativeID = "changed"
	m, r, err := m.Plan(100)
	if err != nil || r.Request.Parameters["path"] != "/readyz" || r.Request.Targets[0].NativeID != hashText("original-container") {
		t.Fatal("caller changed frozen definition", err)
	}
	r.Request.Parameters["path"] = "/caller-mutated"
	cp := m.Checkpoint()
	cp.Active.Request.Targets[0].NativeID = "caller-mutated"
	if m.Checkpoint().Active.Request.Parameters["path"] != "/readyz" || m.Validate() != nil {
		t.Fatal("exported checkpoint aliases owned state")
	}
	m, err = m.CancelPrepared(r.Request.RunID, 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = m.Plan(109); !errors.Is(err, ErrNotDue) {
		t.Fatal(err)
	}
	next, second := beginRun(t, m, 110)
	if second.Sequence != 2 || second.Request.RunID == r.Request.RunID {
		t.Fatal("cancel reset run sequence floor")
	}
	if _, _, err = next.Finish(Completion{RunID: second.Request.RunID, RequestDigest: second.RequestDigest, Result: contract.Result{Schema: 1, Status: contract.Pass, Reason: "pass"}, At: 109, HelperExited: true, ProbesClosed: true}); !errors.Is(err, ErrClock) {
		t.Fatal("clock reversal replaced original pending run", err)
	}
	// StartPeriod=0 is representable, but its first run deadline cannot be.
	near, err := New(testDefinition(), math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = near.Plan(math.MaxInt64); !errors.Is(err, ErrClock) {
		t.Fatal("deadline overflow accepted", err)
	}
	grace := testDefinition()
	grace.Timing.StartPeriodMS = 1
	if _, err = New(grace, math.MaxInt64); !errors.Is(err, ErrClock) {
		t.Fatal("grace deadline overflow accepted", err)
	}
}

func TestCheckerStartupGateAndShutdownDoNotClaimNativeClosure(t *testing.T) {
	d := testDefinition()
	d.Request.Phase = contract.Startup
	m, r := beginRun(t, newMachine(t, d), 100)
	m, _ = completeRun(t, m, r, 101, contract.Pass)
	if m.Status(5000) != contract.Pass {
		t.Fatal("startup completion unnecessarily became a periodic check")
	}
	if _, _, err := m.Plan(5000); !errors.Is(err, ErrNotDue) {
		t.Fatal("one-shot startup reran", err)
	}
	status, err := Aggregate(contract.Readiness, []Sample{{Checker: "startup", Phase: contract.Startup, Status: contract.Unknown}, {Checker: "readiness", Phase: contract.Readiness, Status: contract.Pass}})
	if err != nil || status != contract.Unknown {
		t.Fatal("readiness bypassed startup", err)
	}
	shutdown, err := Aggregate(contract.Shutdown, []Sample{{Checker: "shutdown", Phase: contract.Shutdown, Status: contract.Pass}})
	if err != nil || shutdown != contract.Pass || m.Closed() {
		t.Fatal("checker result became native closure", err)
	}
	if _, err = Aggregate(contract.Readiness, []Sample{{"same", contract.Startup, contract.Pass}, {"same", contract.Readiness, contract.Pass}}); err == nil {
		t.Fatal("duplicate checker observations accepted")
	}
}

func TestCheckerRestoredOriginalRejectsCorruptOrReboundCheckpoint(t *testing.T) {
	m, r := beginRun(t, newMachine(t, testDefinition()), 100)
	for _, mutate := range []func(*Checkpoint){
		func(d *Checkpoint) { d.Schema = 2 },
		func(d *Checkpoint) { d.Active.Request.Targets[0].NativeID = "replacement" },
		func(d *Checkpoint) { d.Active.Request.Parameters["path"] = "/replacement" },
		func(d *Checkpoint) { d.Sequence++ },
		func(d *Checkpoint) { d.Active.RequestDigest[0] ^= 1 },
		func(d *Checkpoint) { d.Definition.Request.SourceDigest = hashText("replacement") },
		func(d *Checkpoint) { d.Definition.PolicyRevision++ },
		func(d *Checkpoint) { d.Definition.Timing.TimeoutMS++ },
		func(d *Checkpoint) { d.Published = contract.Pass; d.EverPassed = true },
	} {
		bad := m.Checkpoint()
		mutate(&bad)
		if _, err := Restore(bad); err == nil {
			t.Fatal("corrupt checkpoint restored")
		}
	}
	raw, _ := json.Marshal(m.Checkpoint())
	var disk Checkpoint
	if err := json.Unmarshal(raw, &disk); err != nil {
		t.Fatal(err)
	}
	restored, err := Restore(disk)
	if err != nil || restored.Checkpoint().Active.Request.RunID != r.Request.RunID {
		t.Fatal("same checkpoint lost original run", err)
	}
	if _, _, err = restored.Plan(9999); !errors.Is(err, ErrPending) {
		t.Fatal("restored original timeout authorized new run", err)
	}
	var zero Machine
	if _, _, err = zero.Plan(100); err == nil || zero.Closed() || zero.Status(100) != contract.Unknown {
		t.Fatal("uninitialized core created a run or closure")
	}
}

func TestCheckerReplacementWaitsOriginalClosureAndKeepsSequenceFloor(t *testing.T) {
	m, r := beginRun(t, newMachine(t, testDefinition()), 100)
	m, err := m.Retire()
	if err != nil {
		t.Fatal(err)
	}
	d := testDefinition()
	d.PolicyRevision++
	d.Request.SourceDigest = hashText("new-source")
	if _, err = m.Replace(d, 1000); !errors.Is(err, ErrPending) {
		t.Fatal("new source bypassed unknown original helper", err)
	}
	m, _ = completeRun(t, m, r, 106, contract.Pass)
	next, err := m.Replace(d, 107)
	if err != nil || next.Status(107) != contract.Unknown || next.Checkpoint().Last != nil {
		t.Fatal("replacement inherited previous health", err)
	}
	next, second := beginRun(t, next, 107)
	if second.Sequence != 2 || second.Request.RunID == r.Request.RunID {
		t.Fatal("replacement reset run floor")
	}
	if _, _, err = next.Finish(Completion{RunID: r.Request.RunID, RequestDigest: r.RequestDigest, Result: contract.Result{Schema: 1, Status: contract.Pass, Reason: "old-pass"}, At: 108, HelperExited: true, ProbesClosed: true}); !errors.Is(err, ErrStale) {
		t.Fatal("replacement adopted old helper's late pass", err)
	}
	next, _ = completeRun(t, next, second, 108, contract.Pass)
	next, err = next.Retire()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = next.Replace(d, 109); err == nil {
		t.Fatal("same binding reset its completed run/history")
	}
	back := testDefinition()
	if _, err = next.Replace(back, 109); err == nil {
		t.Fatal("old policy revision reactivated")
	}
	// An explicit policy update may choose old bytes; it still gets a new run.
	back.PolicyRevision = 3
	next, err = next.Replace(back, 109)
	if err != nil {
		t.Fatal(err)
	}
	_, third := beginRun(t, next, 109)
	if third.Sequence != 3 || third.Request.RunID == r.Request.RunID {
		t.Fatal("explicit source rollback reused old run identity")
	}
}
