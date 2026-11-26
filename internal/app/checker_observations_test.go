// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/eventlog"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/storage"
	"github.com/jay94ks/mydcd/internal/workload"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
	contract "github.com/jay94ks/mydcd/lifecycle/v1"
)

// Only journal Apply is simulated. Actual reports/journal DB reopen and the
// production recovery path are exercised; there is no working Docker client.
type checkerJournalApply struct{ calls int }

func (d *checkerJournalApply) Execute(context.Context, string, reconcile.Operation) (reconcile.Outcome, error) {
	d.calls++
	return reconcile.EffectApplied, nil
}
func (d *checkerJournalApply) Recover(context.Context, string, reconcile.Operation) (reconcile.Outcome, error) {
	d.calls++
	return reconcile.EffectApplied, nil
}

func checkerObservationFixture(t *testing.T, phase checker.RunPhase) (checkerObservation, [32]byte, [32]byte) {
	t.Helper()
	cluster, owner, program := sha256.Sum256([]byte("cluster")), sha256.Sum256([]byte("node")), sha256.Sum256([]byte("program"))
	text := func(v [32]byte) string { return hex.EncodeToString(v[:]) }
	task := deployment.ObjectRef{Key: "workload/task/tenant/app/web", Generation: 3, Revision: 7}
	native, boot, source := sha256.Sum256([]byte("native")), sha256.Sum256([]byte("boot")), sha256.Sum256([]byte("source"))
	d := checker.Definition{Scope: "web", ProgramDigest: text(program), PolicyRevision: 1, Timing: checker.Timing{IntervalMS: 100, TimeoutMS: 100, FreshForMS: 1000, Retries: 1}, Request: contract.Request{Schema: 1, Cluster: text(cluster), Tenant: "tenant", App: "app", Checker: "alive", SourceDigest: text(source), Phase: contract.Liveness, Targets: []contract.Target{{Service: "web", TaskKey: task.Key, NativeID: text(native), Owner: text(owner), OwnerBoot: text(boot), Generation: task.Generation, Revision: task.Revision}}}}
	now := time.Now().Add(-time.Minute).UnixMilli()
	m, err := checker.New(d, now)
	if err != nil {
		t.Fatal(err)
	}
	m, run, err := m.Plan(now)
	if err != nil {
		t.Fatal(err)
	}
	if phase == checker.Dispatched {
		m, err = m.Dispatch(run.Request.RunID)
		if err != nil {
			t.Fatal(err)
		}
	}
	return checkerObservation{Schema: 1, Task: task, Program: program, Checkpoint: m.Checkpoint()}, cluster, owner
}

func TestCheckerRecoveryKeepsOriginalRunAndReturnsOnlyItsReadConsumers(t *testing.T) {
	for _, phase := range []checker.RunPhase{checker.Prepared, checker.Dispatched} {
		t.Run(string(phase), func(t *testing.T) {
			ctx := context.Background()
			point, cluster, owner := checkerObservationFixture(t, phase)
			active := *point.Checkpoint.Active
			base := t.TempDir()
			reportPath, journalPath := filepath.Join(base, "observations.db"), filepath.Join(base, "workload.db")
			journal, err := reconcile.OpenJournal(journalPath)
			if err != nil {
				t.Fatal(err)
			}
			if err = journal.Desired(point.Task.Key, reconcile.Desired{Revision: point.Task.Revision, Resource: reconcile.Resource{Generation: point.Task.Generation, Present: true, Spec: "simulated-container"}}, 4); err != nil {
				t.Fatal(err)
			}
			driver := &checkerJournalApply{}
			if err = journal.Step(ctx, point.Task.Key, driver); err != nil {
				t.Fatal(err)
			}
			unrelated, err := journal.Borrow(point.Task.Key, "unrelated-read", point.Task.Generation)
			if err != nil {
				t.Fatal(err)
			}
			if phase == checker.Dispatched {
				if _, err = journal.Borrow(point.Task.Key, "checker-read/"+active.Request.RunID+"/"+strings.Repeat("a", 64), point.Task.Generation); err != nil {
					t.Fatal(err)
				}
			}
			if err = journal.Close(); err != nil {
				t.Fatal(err)
			}
			db, err := storage.Open(reportPath)
			if err != nil {
				t.Fatal(err)
			}
			r := &Runtime{Identity: &identity.Identity{Public: owner}, controlPolicy: control.Policy{Cluster: cluster}, reports: db, checkerObservationSizes: map[string]int{}}
			if err = r.saveCheckerObservation(point); err != nil {
				t.Fatal(err)
			}
			if err = db.Close(); err != nil {
				t.Fatal(err)
			}
			r.reports, err = storage.Open(reportPath)
			if err != nil {
				t.Fatal(err)
			}
			defer r.reports.Close()
			r.workload, err = workload.OpenManager(journalPath, &engine.Client{Owner: engine.Owner(cluster, owner)}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer r.workload.Close()
			r.checkerObservationSizes = nil
			if err = r.recoverCheckerObservations(ctx); err != nil {
				t.Fatal(err)
			}
			raw, err := r.reports.GetBounded(checkerObservationKey(point.Checkpoint.Definition), maxCheckerObservationBytes)
			if err != nil {
				t.Fatal(err)
			}
			restored, err := schema.Decode[checkerObservation](raw)
			if err != nil || restored.validate(cluster, owner) != nil || restored.Checkpoint.Active != nil || restored.Checkpoint.Sequence != active.Sequence || restored.Checkpoint.Published != contract.Unknown {
				t.Fatal("retained run was replayed or lost", restored, err)
			}
			if phase == checker.Dispatched && (restored.Checkpoint.Last == nil || restored.Checkpoint.Last.Run.Request.RunID != active.Request.RunID || restored.Checkpoint.Last.Result.Status != contract.Unknown) {
				t.Fatal("interrupted result did not keep original ID", restored.Checkpoint)
			}
			if phase == checker.Prepared && restored.Checkpoint.Last != nil {
				t.Fatal("prepared run was invented as executed")
			}
			record, err := r.workload.View(point.Task.Key)
			if err != nil || len(record.Consumers) != 1 || record.Consumers["unrelated-read"] != unrelated || driver.calls != 1 {
				t.Fatal("recovery changed unrelated pin/native state", record.Consumers, err, driver.calls)
			}
			r.checkerRecovered = false
			if err = r.recoverCheckerObservations(ctx); err != nil {
				t.Fatal("settled recovery failed", err)
			}
		})
	}
}

func TestCheckerObservationRejectsTaskAndProgramSubstitution(t *testing.T) {
	point, cluster, owner := checkerObservationFixture(t, checker.Prepared)
	for _, change := range []func(*checkerObservation){
		func(p *checkerObservation) { p.Task.Key += "-other" },
		func(p *checkerObservation) { p.Task.Generation++ },
		func(p *checkerObservation) { p.Task.Revision++ },
		func(p *checkerObservation) { p.Program[0]++ },
	} {
		copy := point
		change(&copy)
		if copy.validate(cluster, owner) == nil {
			t.Fatal("foreign Task/program accepted")
		}
	}
	owner[0]++
	if point.validate(cluster, owner) == nil {
		t.Fatal("foreign node accepted")
	}
}

func TestTaskCheckerShortFreshnessRunsLast(t *testing.T) {
	point, _, _ := checkerObservationFixture(t, checker.Prepared)
	var states []appCheckerState
	for i, name := range []string{"short", "compiled", "yaegi"} {
		d := point.Checkpoint.Definition
		d.Request.Checker = name
		d.Timing = checker.Timing{IntervalMS: 15000, TimeoutMS: 3000, FreshForMS: 18000, Retries: 1}
		if i == 0 {
			d.Timing.IntervalMS, d.Timing.FreshForMS = 1000, 4000
		}
		m, err := checker.New(d, int64(100000+i))
		if err != nil {
			t.Fatal(err)
		}
		states = append(states, appCheckerState{check: checker.ResolvedCheck{ID: name, Phase: contract.Liveness}, machine: m, point: checkerObservation{Checkpoint: m.Checkpoint()}})
	}
	selected, err := nextAppChecker(states, 100010, make([]bool, len(states)))
	if err != nil || selected != 1 {
		t.Fatal("short-freshness sample would expire while later due checks run", selected, err)
	}
}

func TestTaskCheckerFinitePassIncludesChecksBecomingDue(t *testing.T) {
	point, _, _ := checkerObservationFixture(t, checker.Prepared)
	var states []appCheckerState
	for i, name := range []string{"compiled", "yaegi", "short"} {
		d := point.Checkpoint.Definition
		d.Request.Checker = name
		d.Timing = checker.Timing{IntervalMS: 15000, TimeoutMS: 3000, FreshForMS: 18000, Retries: 1}
		if i == 2 {
			d.Timing.IntervalMS, d.Timing.FreshForMS = 1000, 4000
		}
		m, err := checker.New(d, 100000)
		if err != nil {
			t.Fatal(err)
		}
		states = append(states, appCheckerState{check: checker.ResolvedCheck{ID: name, Phase: contract.Liveness}, machine: m, point: checkerObservation{Checkpoint: m.Checkpoint()}})
	}
	// These successful durations fit each original request, but together exceed
	// the short check's freshness. On the second pass Yaegi only becomes due
	// while the first check is running. Neither case needs a longer deadline.
	for _, start := range []int64{100000, 118000} {
		now := start
		visited := make([]bool, len(states))
		for want, duration := range []int64{2941, 2804, 1263} {
			selected, err := nextAppChecker(states, now, visited)
			if err != nil || selected != want {
				t.Fatal("due checker order lost freshness or fairness", start, selected, want, err)
			}
			visited[selected] = true
			s := &states[selected]
			m, run, err := s.machine.Plan(now)
			if err != nil {
				t.Fatal(err)
			}
			m, err = m.Dispatch(run.Request.RunID)
			if err != nil {
				t.Fatal(err)
			}
			now += duration
			m, _, err = m.Finish(checker.Completion{RunID: run.Request.RunID, RequestDigest: run.RequestDigest, Result: contract.Result{Schema: 1, Status: contract.Pass, Reason: "alive"}, At: now, HelperExited: true, ProbesClosed: true})
			if err != nil {
				t.Fatal(err)
			}
			s.machine, s.point.Checkpoint = m, m.Checkpoint()
		}
		result, err := aggregateAppCheckStates(point.Program, states, now)
		if err != nil || result.Status != contract.Pass || result.ValidUntil != now+4000 {
			t.Fatal("finished pass did not retain genuinely fresh results", result, err)
		}
		if selected, err := nextAppChecker(states, now+20000, visited); err != nil || selected != -1 {
			t.Fatal("pass repeated an already completed checker", selected, err)
		}
		if result, err := aggregateAppCheckStates(point.Program, states, now+4000); err != nil || result.Status != contract.Unknown {
			t.Fatal("batch prolonged an expired success", result, err)
		}
	}
	if _, err := nextAppChecker(states, 200000, nil); !errors.Is(err, checker.ErrContract) {
		t.Fatal("invalid pass accounting accepted", err)
	}
}

func TestTaskCheckerPollingDoesNotStarveLaterChecks(t *testing.T) {
	point, _, _ := checkerObservationFixture(t, checker.Prepared)
	var states []appCheckerState
	for _, name := range []string{"first", "second", "third"} {
		d := point.Checkpoint.Definition
		d.Request.Checker = name
		d.Timing.IntervalMS, d.Timing.TimeoutMS = 5, 100
		m, err := checker.New(d, 100)
		if err != nil {
			t.Fatal(err)
		}
		states = append(states, appCheckerState{check: checker.ResolvedCheck{ID: name, Phase: contract.Liveness}, machine: m, point: checkerObservation{Checkpoint: m.Checkpoint()}})
	}
	// Polling is slower than every check's interval. Choosing the first due
	// item repeatedly would never reach second/third.
	for cycle, want := range []int{0, 1, 2, 0, 1, 2} {
		now := int64(100 + cycle*2000)
		selected, err := nextAppChecker(states, now, make([]bool, len(states)))
		if err != nil || selected != want {
			t.Fatal("check starved", cycle, selected, err)
		}
		s := &states[selected]
		m, run, err := s.machine.Plan(now)
		if err != nil {
			t.Fatal(err)
		}
		m, err = m.Dispatch(run.Request.RunID)
		if err != nil {
			t.Fatal(err)
		}
		m, _, err = m.Finish(checker.Completion{RunID: run.Request.RunID, RequestDigest: run.RequestDigest, Result: contract.Result{Schema: 1, Status: contract.Pass, Reason: "alive"}, At: now + 1, HelperExited: true, ProbesClosed: true})
		if err != nil {
			t.Fatal(err)
		}
		s.machine, s.point.Checkpoint = m, m.Checkpoint()
	}
	startup := point.Checkpoint.Definition
	startup.Request.Phase = contract.Startup
	m, err := checker.New(startup, 100)
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
	m, _, err = m.Finish(checker.Completion{RunID: run.Request.RunID, RequestDigest: run.RequestDigest, Result: contract.Result{Schema: 1, Status: contract.Pass, Reason: "started"}, At: 101, HelperExited: true, ProbesClosed: true})
	if err != nil {
		t.Fatal(err)
	}
	if selected, err := nextAppChecker([]appCheckerState{{machine: m, point: checkerObservation{Checkpoint: m.Checkpoint()}}}, 10000, []bool{false}); err != nil || selected != -1 {
		t.Fatal("completed startup scheduled again", selected, err)
	}
}

// The Machine's normalized result must not erase the local first phase, and
// observation must use the same persisted original run without issuing IO.
func TestCheckerDiagnosticSurvivesDeadlineNormalizationAndDBReopen(t *testing.T) {
	point, cluster, owner := checkerObservationFixture(t, checker.Dispatched)
	original := *point.Checkpoint.Active
	legacy, err := json.Marshal(point)
	if err != nil || strings.Contains(string(legacy), "Diagnostic") {
		t.Fatal("legacy checker row changed", err)
	}
	r := &Runtime{}
	result, closed, err := r.runAppCheck(context.Background(), deployment.Binding{}, point.Task, checker.TaskProgram{}, checker.ResolvedCheck{}, original.Request, workload.ContainerStatus{}, false, &point)
	if !errors.Is(err, context.DeadlineExceeded) || !closed || result.Status != contract.Unknown || point.Diagnostic == nil || point.Diagnostic.Phase != "request-deadline" || point.Diagnostic.Cause != "deadline" || point.Diagnostic.AuthorityCalls != 0 {
		t.Fatal("expired original check reached IO or lost first phase", result, closed, err, point.Diagnostic)
	}
	m, err := checker.Restore(point.Checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	m, _, err = m.Finish(checker.Completion{RunID: original.Request.RunID, RequestDigest: original.RequestDigest, Result: result, At: time.Now().UnixMilli(), HelperExited: true, ProbesClosed: closed})
	if err != nil {
		t.Fatal(err)
	}
	point.Checkpoint = m.Checkpoint()
	path := filepath.Join(t.TempDir(), "observations.db")
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	r.Identity = &identity.Identity{Public: owner}
	r.controlPolicy = control.Policy{Cluster: cluster}
	r.reports = db
	r.checkerObservationSizes = map[string]int{}
	if err = r.saveCheckerObservation(point); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	r.reports, err = storage.OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.reports.Close()
	rows, total, err := r.taskCheckerRuns(point.Task)
	if err != nil || total != 1 || len(rows) != 1 || rows[0].RunID != original.Request.RunID || rows[0].Reason != "deadline-expired" || rows[0].Diagnostic.Phase != "request-deadline" || rows[0].Diagnostic.AuthorityCalls != 0 {
		t.Fatal("normalized result erased original phase across DB reopen", rows, total, err)
	}
	otherGeneration := point.Task
	otherGeneration.Generation++
	otherGeneration.Revision++
	if rows, total, err = r.taskCheckerRuns(otherGeneration); err != nil || total != 0 || len(rows) != 0 {
		t.Fatal("older generation diagnostic appeared on the current Task", rows, total, err)
	}
	if rows, total, err = r.taskCheckerRuns(deployment.ObjectRef{Key: "workload/task/other/app/web", Generation: point.Task.Generation, Revision: point.Task.Revision}); err != nil || total != 0 || len(rows) != 0 {
		t.Fatal("foreign Task diagnostic leaked", rows, total, err)
	}
}

func TestNativeHealthReasonRequiresOriginalDispatchedControl(t *testing.T) {
	point, cluster, owner := checkerObservationFixture(t, checker.Prepared)
	d := point.Checkpoint.Definition
	now := time.Now().UnixMilli()
	d.Request.Targets[0].StartedAt = time.UnixMilli(now - 3600000).UTC().Format(time.RFC3339Nano)
	m, err := checker.New(d, now)
	if err != nil {
		t.Fatal(err)
	}
	m, run, err := m.Plan(now)
	if err != nil {
		t.Fatal(err)
	}
	m, err = m.Dispatch(run.Request.RunID)
	if err != nil {
		t.Fatal(err)
	}
	m, observation, err := m.Finish(checker.Completion{RunID: run.Request.RunID, RequestDigest: run.RequestDigest, Result: contract.Result{Schema: 1, Status: contract.Fail, Reason: "not-alive"}, At: now + 1, HelperExited: true, ProbesClosed: true})
	if err != nil {
		t.Fatal(err)
	}
	point.Checkpoint = m.Checkpoint()
	point.Control, err = checker.NewContainerControl(observation, checker.ActionPolicy{OnDead: checker.RestartContainer}, contract.Fail, true)
	if err != nil || point.Control == nil {
		t.Fatal(err)
	}
	db, err := storage.Open(filepath.Join(t.TempDir(), "observations.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	r := &Runtime{Identity: &identity.Identity{Public: owner}, controlPolicy: control.Policy{Cluster: cluster}, reports: db}
	target := eventlog.Target{Tenant: d.Request.Tenant, App: d.Request.App, Service: d.Scope, Task: point.Task.Key, Native: d.Request.Targets[0].NativeID, Generation: point.Task.Generation, Revision: point.Task.Revision}
	save := func() {
		t.Helper()
		if err := point.validate(cluster, owner); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(point)
		if err := db.Write(map[string][]byte{checkerObservationKey(d): raw}); err != nil {
			t.Fatal(err)
		}
	}
	save()
	detail := eventlog.Detail{Reason: "exit"}
	r.checkerEventReason(target, &detail, (now+2)*int64(time.Millisecond))
	if detail.Reason != "exit" {
		t.Fatal("prepared control invented an executed health stop")
	}
	sent, err := point.Control.Dispatch(checker.StopContainer)
	if err != nil {
		t.Fatal(err)
	}
	point.Control = &sent
	save()
	r.checkerEventReason(target, &detail, (now+2)*int64(time.Millisecond))
	if detail.Reason != "health" || detail.RunID != run.Request.RunID || detail.Checker != d.Request.Checker {
		t.Fatal("original health Stop dispatch was not linked")
	}
	detail = eventlog.Detail{Reason: "exit"}
	other := target
	other.Generation++
	r.checkerEventReason(other, &detail, (now+2)*int64(time.Millisecond))
	if detail.Reason != "exit" {
		t.Fatal("another generation borrowed health control")
	}
	point.Control.Phase = checker.ControlCompleted
	save()
	r.checkerEventReason(target, &detail, (now+2)*int64(time.Millisecond))
	if detail.Reason != "exit" {
		t.Fatal("retained old control classified an unrelated later exit")
	}
}
