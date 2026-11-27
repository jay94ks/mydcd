// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"context"
	"errors"
	"testing"

	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/moby/moby/api/types/container"
)

// Same real DB/SDK-over-fixture boundary as initial activation. Native states
// and permits are simulated, not real Docker or authenticated quorum evidence.
func TestExistingVolumeStartRetainsOriginalGrantAcrossLostReply(t *testing.T) {
	for _, lost := range []bool{false, true} {
		f, refs := activationBatchTest(t)
		s := f.open(t)
		ctx := context.Background()
		before := "2026-11-15T01:00:00Z"
		f.http.startRuns = false
		f.http.startHook = func() error {
			f.http.exitState = &container.State{Status: container.StateExited, StartedAt: before, FinishedAt: "2026-11-15T01:00:01Z"}
			return nil
		}
		if err := s.ActivateAll(ctx, refs); err != nil {
			t.Fatal(err)
		}
		starts := f.http.starts
		f.http.startHook = func() error {
			f.http.exitState = &container.State{Status: container.StateExited, StartedAt: "2026-11-15T01:01:00Z", FinishedAt: "2026-11-15T01:01:01Z"}
			return nil
		}
		f.http.loseStart = lost
		markers := 0
		err := s.StartExisting(ctx, refs, f.http.value.ID, before, func() error { markers++; return nil })
		if lost && err == nil || !lost && err != nil || markers != 1 || f.http.starts != starts+1 {
			t.Fatal("unexpected repeated Start", lost, err, markers, f.http.starts)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		s = f.open(t)
		if lost {
			if err := s.ActivateAll(ctx, refs); !errors.Is(err, reconcile.ErrPending) {
				t.Fatal("initial recovery consumed repeated Start grant", err)
			}
		}
		if err := s.RecoverExistingStart(ctx, refs, f.http.value.ID, before); err != nil {
			t.Fatal(err)
		}
		if f.http.starts != starts+1 || markers != 1 {
			t.Fatal("recovery sent another Start")
		}
		if err := s.InspectAll(ctx, refs, f.http.value.ID); err != nil {
			t.Fatal("repeated Start lost original ownership", err)
		}
		for _, ref := range refs {
			cp, err := s.Checkpoint(ref)
			if err != nil || cp.Starting != nil {
				t.Fatal("original grant not settled", cp, err)
			}
			native, err := f.native.View(ref.NativeKey)
			if err != nil || len(native.Consumers) != 1 {
				t.Fatal("original pin changed", native.Consumers, err)
			}
		}
		// A failed start-sent save is positive no dispatch in this call.
		stamp := f.http.exitState.StartedAt
		injected := errors.New("marker sync failed")
		if err := s.StartExisting(ctx, refs, f.http.value.ID, stamp, func() error { return injected }); !errors.Is(err, injected) || f.http.starts != starts+1 {
			t.Fatal("SDK called before marker sync", err)
		}
		if err := s.InspectAll(ctx, refs, f.http.value.ID); err != nil {
			t.Fatal("unsent grant stranded original", err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
