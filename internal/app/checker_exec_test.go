// SPDX-License-Identifier: Apache-2.0

package app

import (
	"crypto/sha256"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/storage"
	"github.com/jay94ks/mydcd/internal/workload"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
	contract "github.com/jay94ks/mydcd/lifecycle/v1"
)

func TestCheckerExecReceiptSurvivesDBReopenAndCannotFinishWhilePending(t *testing.T) {
	point, cluster, owner := checkerObservationFixture(t, checker.Prepared)
	d := point.Checkpoint.Definition
	d.Request.Targets[0].StartedAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	m, err := checker.New(d, point.Checkpoint.StartedAt)
	if err != nil {
		t.Fatal(err)
	}
	m, run, err := m.Plan(point.Checkpoint.StartedAt)
	if err != nil {
		t.Fatal(err)
	}
	m, err = m.Dispatch(run.Request.RunID)
	if err != nil {
		t.Fatal(err)
	}
	point.Checkpoint = m.Checkpoint()
	path := filepath.Join(t.TempDir(), "observations.db")
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	r := &Runtime{Identity: &identity.Identity{Public: owner}, controlPolicy: control.Policy{Cluster: cluster}, reports: db, checkerObservationSizes: map[string]int{}}
	if err = r.saveCheckerObservation(point); err != nil {
		t.Fatal(err)
	}
	p := workload.ProbeExecReceipt{Schema: 1, RunID: run.Request.RunID, Call: sha256.Sum256([]byte("exec-call")), Payload: sha256.Sum256([]byte("exec-payload")), Target: run.Request.Targets[0], Phase: workload.ProbeExecCreating}
	for _, phase := range []workload.ProbeExecPhase{workload.ProbeExecCreating, workload.ProbeExecCreated, workload.ProbeExecSent} {
		p.Phase = phase
		if phase == workload.ProbeExecCreated {
			p.ExecID = "original-exec"
		}
		if err = r.saveCheckerExec(&point, p); err != nil {
			t.Fatal(err)
		}
		if phase == workload.ProbeExecCreating {
			if err = r.saveCheckerExec(&point, p); !errors.Is(err, checker.ErrPending) {
				t.Fatal("same original Create intent admitted again", err)
			}
		}
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	r.reports, err = storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.reports.Close()
	raw, err := r.reports.GetBounded(checkerObservationKey(d), maxCheckerObservationBytes)
	if err != nil {
		t.Fatal(err)
	}
	point, err = schema.Decode[checkerObservation](raw)
	if err != nil || point.validate(cluster, owner) != nil || len(point.Executions) != 1 || point.Executions[0] != p || point.Checkpoint.Active == nil {
		t.Fatal("original exec dispatch lost", point, err)
	}
	changed := p
	changed.Payload[0]++
	if err = r.saveCheckerExec(&point, changed); !errors.Is(err, checker.ErrContract) {
		t.Fatal("payload rewrite accepted", err)
	}
	finished, _, err := m.Finish(checker.Completion{RunID: run.Request.RunID, RequestDigest: run.RequestDigest, Result: contract.Result{Schema: 1, Status: contract.Unknown, Reason: "interrupted"}, At: point.Checkpoint.StartedAt + 1, HelperExited: true, ProbesClosed: true})
	if err != nil {
		t.Fatal(err)
	}
	invalid := point
	invalid.Checkpoint = finished.Checkpoint()
	if err = r.saveCheckerObservation(invalid); !errors.Is(err, checker.ErrContract) {
		t.Fatal("pending exec reference was dropped by Finish", err)
	}
	for _, phase := range []workload.ProbeExecPhase{workload.ProbeExecStreamEnded, workload.ProbeExecCompleted} {
		p.Phase = phase
		if err = r.saveCheckerExec(&point, p); err != nil {
			t.Fatal(err)
		}
	}
	point.Checkpoint = finished.Checkpoint()
	if err = r.saveCheckerObservation(point); err != nil {
		t.Fatal("terminal receipt cannot finish same run", err)
	}
	if err = r.reports.Close(); err != nil {
		t.Fatal(err)
	}
	// A failed durable publication must not rewrite the caller's original state.
	point.Checkpoint = m.Checkpoint()
	p.Call = sha256.Sum256([]byte("second-exec-call"))
	p.Phase = workload.ProbeExecCreating
	p.ExecID = ""
	if err = r.saveCheckerExec(&point, p); err == nil || len(point.Executions) != 1 {
		t.Fatal("failed save changed caller", point, err)
	}
}
