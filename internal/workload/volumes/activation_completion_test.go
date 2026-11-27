// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/moby/moby/api/types/container"
)

// Native state and permits are fixtures. The original activation core, real
// private DB, SDK dispatch and same-record recovery are used; this is not a
// real Engine/cgroup or writer-fencing result.
func TestFastExitSettlesOriginalStartingBatchWithoutRestartOrPinReturn(t *testing.T) {
	for _, lost := range []bool{false, true} {
		for _, code := range []int{0, 23} {
			f, refs := activationBatchTest(t)
			s := f.open(t)
			defer func() { _ = s.Close() }()
			ctx := context.Background()
			check := requireWholeStart(t, s, refs)
			f.http.startHook = func() error {
				if err := check(); err != nil {
					return err
				}
				f.http.exitState = &container.State{Status: container.StateExited, ExitCode: code, StartedAt: "2026-11-14T01:00:00Z", FinishedAt: "2026-11-14T01:00:01Z"}
				return nil
			}
			f.http.startRuns, f.http.loseStart = false, lost
			err := s.ActivateAll(ctx, refs)
			if lost && err == nil || !lost && err != nil {
				t.Fatal("unexpected first Start outcome", lost, code, err)
			}
			_ = s.Close()
			s = f.open(t)
			if err = s.ActivateAll(ctx, refs); err != nil {
				t.Fatal("same original fast exit did not settle", err)
			}
			if err = s.InspectAll(ctx, refs, f.http.value.ID); err != nil {
				t.Fatal("completed original lost input/Volume ownership", err)
			}
			for _, ref := range refs {
				raw, err := s.db.Get(activationRecordKey(ref.Consumer.Owner.Native))
				var disk activationRecord
				if err != nil || json.Unmarshal(raw, &disk) != nil {
					t.Fatal(err)
				}
				binding := disk.Bindings[bindingIndex(disk, ref)]
				if !binding.Started || binding.Closed || binding.Released || binding.Exit != nil || disk.Gate.Starting != nil || binding.Lease.Pin.Token == 0 {
					t.Fatal("process completion became writer closure or lost original pin")
				}
				native, err := f.native.View(ref.NativeKey)
				if err != nil || len(native.Consumers) != 1 {
					t.Fatal("native consumer was returned on process exit", err)
				}
			}
			if f.http.starts != 1 || f.calls != len(refs) || f.http.stops != 0 || f.http.removes != 0 {
				t.Fatal("original fast exit dispatched another native effect")
			}
		}
	}
}

func TestExitedWithoutOriginalStartingGrantDoesNotInventStart(t *testing.T) {
	f, refs := activationBatchTest(t)
	s := f.open(t)
	defer s.Close()
	f.http.exitState = &container.State{Status: container.StateExited, StartedAt: "2026-11-14T01:00:00Z", FinishedAt: "2026-11-14T01:00:01Z"}
	if err := s.ActivateAll(context.Background(), refs); err == nil {
		t.Fatal("external execution adopted without original grant")
	}
	if f.http.starts != 0 || f.calls != 0 {
		t.Fatal("foreign terminal execution restarted")
	}
}

func TestAmbiguousStoppedStartingBatchKeepsOriginalGrantAndNeverRestarts(t *testing.T) {
	f, refs := activationBatchTest(t)
	s := f.open(t)
	defer s.Close()
	f.http.startRuns, f.http.loseStart = false, true
	if err := s.ActivateAll(context.Background(), refs); err == nil {
		t.Fatal("lost Start reply was accepted")
	}
	f.http.exitState = &container.State{Status: container.StateExited} // NeverStarted/default exit0 is insufficient.
	if err := s.ActivateAll(context.Background(), refs); !errors.Is(err, reconcile.ErrPending) {
		t.Fatal("ambiguous stop did not retain original pending execution", err)
	}
	if f.http.starts != 1 || f.calls != len(refs) {
		t.Fatal("ambiguous original was sent again")
	}
}
