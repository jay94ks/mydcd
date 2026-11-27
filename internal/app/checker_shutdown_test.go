// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/storage"
	"github.com/jay94ks/seafield/internal/workload"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

func TestShutdownAttemptIsNotRepeatedAfterPreparedRecoveryOrDBReopen(t *testing.T) {
	point, cluster, owner := checkerObservationFixture(t, checker.Prepared)
	d := point.Checkpoint.Definition
	d.Request.Phase = contract.Shutdown
	d.Stop = &checker.ShutdownScope{Operation: "original-down", Revision: 12}
	path := filepath.Join(t.TempDir(), "observations.db")
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	r := &Runtime{Identity: &identity.Identity{Public: owner}, controlPolicy: control.Policy{Cluster: cluster}, reports: db, checkerObservationSizes: map[string]int{}}
	point, m, needed, err := r.loadShutdownCheck(d, point.Task, point.Program)
	if err != nil || !needed {
		t.Fatal(point, needed, err)
	}
	m, run, err := m.Plan(time.Now().UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	point.Checkpoint = m.Checkpoint()
	if err = r.saveCheckerObservation(point); err != nil {
		t.Fatal(err)
	}
	if err = r.settleInterruptedChecker(t.Context(), &point); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	r.reports, err = storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.reports.Close()
	got, _, needed, err := r.loadShutdownCheck(d, point.Task, point.Program)
	if err != nil || needed || got.Checkpoint.Active != nil || got.Checkpoint.Sequence != run.Sequence || got.Checkpoint.Last != nil {
		t.Fatal("pre-dispatch interruption replayed shutdown", got, needed, err)
	}
	next := d
	next.Stop = &checker.ShutdownScope{Operation: "explicit-next-down", Revision: 14}
	got, m, needed, err = r.loadShutdownCheck(next, point.Task, point.Program)
	if err != nil || !needed || got.Checkpoint.Sequence != run.Sequence {
		t.Fatal("explicit new down lost floor", got, needed, err)
	}
	_, newRun, err := m.Plan(time.Now().UnixMilli())
	if err != nil || newRun.Request.RunID == run.Request.RunID || newRun.Sequence != run.Sequence+1 {
		t.Fatal("new stop reused old attempt", newRun, err)
	}
}

func TestShutdownScopeMappingDoesNotConfuseSameServiceAndAppCheckID(t *testing.T) {
	check := checker.ResolvedCheck{ID: "same-name", Phase: contract.Shutdown}
	p := checker.TaskProgram{Service: "web", Coordinator: "web", Checks: []checker.ResolvedCheck{check, {ID: "alive", Phase: contract.Liveness}}, AppChecks: []checker.ResolvedCheck{check}}
	got := taskShutdownChecks(p)
	if len(got) != 2 || got[0].appScope || !got[1].appScope {
		t.Fatal("service became app scope", got)
	}
	p.Service = "other"
	if got = taskShutdownChecks(p); len(got) != 1 || got[0].appScope {
		t.Fatal("non-coordinator ran app check", got)
	}
}

func TestUnavailableShutdownTargetDoesNotInventRunningOrNativeIdentity(t *testing.T) {
	if _, ok := shutdownRecordedTarget(deployment.Claim{}); ok {
		t.Fatal("no native witness became a target")
	}
	stamp := time.Now().Add(-time.Minute).UnixNano()
	c := deployment.Claim{Native: "original", Observation: &deployment.Observation{Native: "original", StartedAt: stamp, Applied: true, Healthy: true}}
	status, ok := shutdownRecordedTarget(c)
	if !ok || status.NativeID != "original" || status.Running || status.Ready || status.StartedAt != time.Unix(0, stamp).UTC().Format(time.RFC3339Nano) {
		t.Fatal("recorded fallback invented live state", status, ok)
	}
	c.Native = "foreign"
	if _, ok = shutdownRecordedTarget(c); ok {
		t.Fatal("mismatched original native accepted")
	}
}

func TestExpiredCheckerCannotIssueInitialShutdownOrActivationPermit(t *testing.T) {
	point, _, _ := checkerObservationFixture(t, checker.Dispatched)
	request := point.Checkpoint.Active.Request
	request.DeadlineUnixMilli = time.Now().Add(-time.Second).UnixMilli()
	for _, phase := range []contract.Phase{contract.Liveness, contract.Shutdown} {
		request.Phase = phase
		// No engine/mesh/DB: an expired request must stop before an authority IO.
		r := &Runtime{}
		result, closed, err := r.runAppCheck(context.Background(), deployment.Binding{}, point.Task, checker.TaskProgram{}, checker.ResolvedCheck{Phase: phase}, request, workload.ContainerStatus{}, false, &point)
		if !errors.Is(err, context.DeadlineExceeded) || !closed || result.Status != contract.Unknown {
			t.Fatal("expired request reached a grant/effect", result, closed, err)
		}
	}
}
