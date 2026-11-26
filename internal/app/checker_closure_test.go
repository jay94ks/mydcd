// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/storage"
	"github.com/jay94ks/mydcd/internal/workload"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
	contract "github.com/jay94ks/mydcd/lifecycle/v1"
)

// Native Gone is the caller's prerequisite, not simulated as proof here.
// This exercises the actual checker DB/retirement core and original run state.
func TestCheckerClosureRetiresOnlyOriginalTaskAndPreservesRunFloor(t *testing.T) {
	ctx := context.Background()
	point, cluster, owner := checkerObservationFixture(t, checker.Prepared)
	original := *point.Checkpoint.Active
	path := filepath.Join(t.TempDir(), "observations.db")
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	r := &Runtime{Identity: &identity.Identity{Public: owner}, controlPolicy: control.Policy{Cluster: cluster}, reports: db, checkerObservationSizes: map[string]int{}}
	if err = r.saveCheckerObservation(point); err != nil {
		t.Fatal(err)
	}
	other := point.Task
	other.Generation++
	if err = r.retireTaskCheckers(ctx, other); err != nil {
		t.Fatal(err)
	}
	raw, err := db.GetBounded(checkerObservationKey(point.Checkpoint.Definition), maxCheckerObservationBytes)
	if err != nil {
		t.Fatal(err)
	}
	unchanged, err := schema.Decode[checkerObservation](raw)
	if err != nil || unchanged.Checkpoint.Active == nil || unchanged.Checkpoint.Retire {
		t.Fatal("different generation retired original checker", unchanged, err)
	}
	if err = r.retireTaskCheckers(ctx, point.Task); err != nil {
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
	raw, err = r.reports.GetBounded(checkerObservationKey(point.Checkpoint.Definition), maxCheckerObservationBytes)
	if err != nil {
		t.Fatal(err)
	}
	retired, err := schema.Decode[checkerObservation](raw)
	if err != nil || retired.validate(cluster, owner) != nil || retired.Checkpoint.Active != nil || !retired.Checkpoint.Retire || retired.Checkpoint.Sequence != original.Sequence || retired.Checkpoint.Last != nil {
		t.Fatal("prepared cancellation lost original floor or invented execution", retired, err)
	}
	m, err := checker.Restore(retired.Checkpoint)
	if err != nil || !m.Closed() {
		t.Fatal(err)
	}
	if _, _, err = m.Plan(retired.Checkpoint.Clock + 1); !errors.Is(err, checker.ErrRetiring) {
		t.Fatal("retired Task ran another checker", err)
	}
	if err = r.retireTaskCheckers(ctx, point.Task); err != nil {
		t.Fatal("same original closure failed", err)
	}
	rawAgain, err := r.reports.GetBounded(checkerObservationKey(point.Checkpoint.Definition), maxCheckerObservationBytes)
	if err != nil || string(rawAgain) != string(raw) {
		t.Fatal("terminal closure rewrote receipt", err)
	}
}

func TestCheckerClosureRefusesMissingKnownMetadata(t *testing.T) {
	_, cluster, owner := checkerObservationFixture(t, checker.Prepared)
	db, err := storage.Open(filepath.Join(t.TempDir(), "observations.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	r := &Runtime{Identity: &identity.Identity{Public: owner}, controlPolicy: control.Policy{Cluster: cluster}, reports: db, checkerObservationSizes: map[string]int{checkerObservationPrefix + "known": 1}}
	if err = r.retireTaskCheckers(context.Background(), deployment.ObjectRef{Key: "task", Generation: 1, Revision: 1}); !errors.Is(err, checker.ErrContract) {
		t.Fatal("missing record became settled closure", err)
	}
	r.workload = &workload.Manager{} // metadata denial must precede every SDK/journal use
	if err = r.recoverCheckerObservations(context.Background()); !errors.Is(err, checker.ErrContract) {
		t.Fatal("recovery forgot a known record and its original exec/run", err)
	}
}

func TestCheckerClosureKeepsUnsettledDispatchWithoutWorkload(t *testing.T) {
	point, cluster, owner := checkerObservationFixture(t, checker.Dispatched)
	db, err := storage.Open(filepath.Join(t.TempDir(), "observations.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	r := &Runtime{Identity: &identity.Identity{Public: owner}, controlPolicy: control.Policy{Cluster: cluster}, reports: db, checkerObservationSizes: map[string]int{}}
	if err = r.saveCheckerObservation(point); err != nil {
		t.Fatal(err)
	}
	key := checkerObservationKey(point.Checkpoint.Definition)
	before, err := db.GetBounded(key, maxCheckerObservationBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.retireTaskCheckers(context.Background(), point.Task); !errors.Is(err, checker.ErrPending) {
		t.Fatal("dispatch settled without original reader cleanup", err)
	}
	after, err := db.GetBounded(key, maxCheckerObservationBytes)
	if err != nil || string(after) != string(before) {
		t.Fatal("unsettled dispatch was rewritten", err)
	}
}

func TestCheckerClosurePreservesControlReceiptAfterOriginalNativeGone(t *testing.T) {
	for _, phase := range []checker.ControlPhase{checker.ControlPrepared, checker.ControlStopSent, checker.ControlStopped, checker.ControlStartSent, checker.ControlCompleted, checker.ControlCanceled} {
		t.Run(string(phase), func(t *testing.T) {
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
			m, observation, err := m.Finish(checker.Completion{RunID: run.Request.RunID, RequestDigest: run.RequestDigest, Result: contract.Result{Schema: 1, Status: contract.Fail, Reason: "dead"}, At: point.Checkpoint.StartedAt + 1, HelperExited: true, ProbesClosed: true})
			if err != nil {
				t.Fatal(err)
			}
			c, err := checker.NewContainerControl(observation, checker.ActionPolicy{OnDead: checker.RestartContainer}, contract.Fail, true)
			if err != nil || c == nil {
				t.Fatal(c, err)
			}
			c.Phase = phase // receipt-state fixture, not a claim of actual Docker IO
			point.Checkpoint = m.Checkpoint()
			point.setControl(*c)
			db, err := storage.Open(filepath.Join(t.TempDir(), "observations.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			// No workload/SDK exists: retirement must not retransmit an effect.
			r := &Runtime{Identity: &identity.Identity{Public: owner}, controlPolicy: control.Policy{Cluster: cluster}, reports: db, checkerObservationSizes: map[string]int{}}
			if err = r.saveCheckerObservation(point); err != nil {
				t.Fatal(err)
			}
			if err = r.retireTaskCheckers(context.Background(), point.Task); err != nil {
				t.Fatal(err)
			}
			raw, err := db.GetBounded(checkerObservationKey(d), maxCheckerObservationBytes)
			if err != nil {
				t.Fatal(err)
			}
			got, err := schema.Decode[checkerObservation](raw)
			want := *c
			if !want.Terminal() {
				want.Phase = checker.ControlCanceled
			}
			if err != nil || got.validate(cluster, owner) != nil || got.Control == nil || *got.Control != want || !got.Checkpoint.Retire || got.Checkpoint.Last == nil || got.Checkpoint.Last.Run.Request.RunID != run.Request.RunID || got.Checkpoint.Last.Result != observation.Result || got.Checkpoint.Sequence != point.Checkpoint.Sequence {
				t.Fatal("closure changed original control/result", got, err)
			}
			if phase == checker.ControlCompleted && (got.Previous == nil || got.Previous.Control != *c) {
				t.Fatal("completed start receipt was lost", got.Previous)
			}
		})
	}
}
