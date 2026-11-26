// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/moby/moby/api/types/container"
)

func stopPolicyBatch(t *testing.T) (*activationFixture, []Activation) {
	t.Helper()
	f, refs := activationBatchTest(t)
	raw, _ := json.Marshal(struct {
		Schema  uint8
		Stop    engine.StopPolicy
		Process struct{ StopSignal string }
	}{Schema: 1, Stop: engine.StopPolicy{GraceSeconds: 120, Signal: "SIGQUIT"}, Process: struct{ StopSignal string }{"SIGQUIT"}})
	for i := range refs {
		refs[i].Task.Spec = string(raw)
	}
	id, err := f.docker.Identity("container", refs[0].TaskKey, refs[0].Task)
	if err != nil {
		t.Fatal(err)
	}
	f.http.value.Name, f.http.value.Config.Labels = "/"+id.Name, id.Labels
	f.http.value.Config.StopSignal = "SIGQUIT"
	grace := 120
	f.http.value.Config.StopTimeout = &grace
	return f, refs
}

func TestStopPolicyAndDispatchSurviveLostResponseWithoutReturningWriterPins(t *testing.T) {
	f, refs := stopPolicyBatch(t)
	s := f.open(t)
	defer func() { _ = s.Close() }()
	ctx := context.Background()
	if err := s.ActivateAll(ctx, refs); err != nil {
		t.Fatal(err)
	}
	f.http.stopHook = func() error {
		for _, ref := range refs {
			raw, err := s.db.Get(activationRecordKey(ref.Consumer.Owner.Native))
			var disk activationRecord
			if err != nil || json.Unmarshal(raw, &disk) != nil {
				return ErrActivation
			}
			b := disk.Bindings[bindingIndex(disk, ref)]
			if !b.StopSent || b.NativeID != f.http.value.ID || b.Closed || b.Released {
				return errors.New("Stop before all original dispatch markers")
			}
		}
		return nil
	}
	f.http.loseStop, f.http.keepRunningOnStop = true, true
	if err := s.RetireAll(ctx, refs); err == nil {
		t.Fatal("lost Stop response became closure")
	}
	if f.http.stops != 1 || f.http.stopGrace != "120" || f.http.stopSignal != "SIGQUIT" {
		t.Fatal("declared original Stop was not sent exactly once")
	}
	_ = s.Close()
	var err error
	s = f.open(t)
	if err = s.RetireAll(ctx, refs); !errors.Is(err, reconcile.ErrPending) || f.http.stops != 1 || f.http.removes != 0 {
		t.Fatal("Running original resent Stop/returned lifetime", err)
	}
	for _, ref := range refs {
		state, err := f.native.View(ref.NativeKey)
		if err != nil || len(state.Consumers) != 1 {
			t.Fatal("uncertain Stop returned writer/mount pin", err)
		}
	}
	f.http.running = false
	f.http.exitState = &container.State{Status: container.StateExited, StartedAt: "2026-11-14T01:00:00Z", FinishedAt: "2026-11-14T01:02:00Z"}
	if err = s.RetireAll(ctx, refs); err != nil || f.http.stops != 1 || f.http.removes != 1 {
		t.Fatal("late original exit did not settle same Stop", err)
	}
	for _, ref := range refs {
		state, err := f.native.View(ref.NativeKey)
		if err != nil || len(state.Consumers) != 0 {
			t.Fatal("positive closure did not return original consumer", err)
		}
	}
}

func TestShortOuterBudgetDoesNotDispatchStopOrRecordSent(t *testing.T) {
	f, refs := stopPolicyBatch(t)
	s := f.open(t)
	defer s.Close()
	if err := s.ActivateAll(context.Background(), refs); err != nil {
		t.Fatal(err)
	}
	short, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.RetireAll(short, refs); !errors.Is(err, engine.ErrStopBudget) || f.http.stops != 0 {
		t.Fatal("short parent truncated declared grace", err)
	}
	for _, ref := range refs {
		raw, err := s.db.Get(activationRecordKey(ref.Consumer.Owner.Native))
		var disk activationRecord
		if err != nil || json.Unmarshal(raw, &disk) != nil || disk.Bindings[bindingIndex(disk, ref)].StopSent {
			t.Fatal("no-request budget refusal became a sent Stop", err)
		}
	}
	// Same original operation may make its FIRST Stop with sufficient budget.
	if err := s.RetireAll(context.Background(), refs); err != nil || f.http.stops != 1 {
		t.Fatal("budget preflight consumed original Stop", err)
	}
}
