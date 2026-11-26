// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/moby/moby/api/types/container"
)

func sourceExitFixture() *container.State {
	return &container.State{Status: "exited", StartedAt: "2026-11-12T00:00:00.123456789Z", FinishedAt: "2026-11-12T00:00:03.987654321Z"}
}

func TestColdSourceExitBatchDurabilityAndLostRemove(t *testing.T) {
	f, refs := activationBatchTest(t)
	s := f.open(t)
	defer func() { _ = s.Close() }()
	ctx := context.Background()
	if err := s.ActivateAll(ctx, refs); err != nil {
		t.Fatal(err)
	}
	f.http.exitState = sourceExitFixture()
	f.http.loseRemove = true
	f.http.removeHook = func() error {
		for _, r := range refs {
			raw, err := s.db.Get(activationRecordKey(r.Consumer.Owner.Native))
			var d activationRecord
			if err != nil || json.Unmarshal(raw, &d) != nil {
				return errors.New("missing durable batch")
			}
			i := bindingIndex(d, r)
			if i < 0 || d.Bindings[i].Exit == nil || !d.Bindings[i].Exit.Clean() {
				return errors.New("Remove before durable exit for every original mount")
			}
		}
		return nil
	}
	if err := s.RetireAll(ctx, refs); err == nil {
		t.Fatal("lost Remove reply reported complete")
	}
	if f.http.removes != 1 {
		t.Fatal("Remove was blocked before evidence", f.http.removes)
	}
	_ = s.Close()
	s = f.open(t)
	if err := s.RetireAll(ctx, refs); err != nil {
		t.Fatal(err)
	}
	for _, r := range refs {
		ready, err := f.native.Ready(ctx, r.NativeKey, makeFixture(t).a)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := s.ColdSource(ctx, ready)
		if err != nil || proof.Writer != r || proof.NativeID != f.http.value.ID || !proof.Exit.Clean() {
			t.Fatal("lost original clean exit after DB reopen", proof, err)
		}
		proof.Exit.Code = 9
		again, err := s.ColdSource(ctx, ready)
		if err != nil || !again.Exit.Clean() {
			t.Fatal("returned proof aliases stored exit", err)
		}
	}
}

func TestColdSourceRefusesUnknownUncleanAndUnsyncedExit(t *testing.T) {
	for _, scenario := range []string{"legacy", "nonzero", "oom", "error", "invalid-time", "still-running", "sync"} {
		t.Run(scenario, func(t *testing.T) {
			f := activationTest(t)
			s := f.open(t)
			defer func() { _ = s.Close() }()
			ctx := context.Background()
			f.http.exists = true
			if err := s.Activate(ctx, f.ref); err != nil {
				t.Fatal(err)
			}
			exit := sourceExitFixture()
			switch scenario {
			case "legacy":
				exit = nil
			case "nonzero":
				exit.ExitCode = 137
			case "oom":
				exit.OOMKilled = true
			case "error":
				exit.Error = "private daemon error must not enter receipt"
			case "invalid-time":
				exit.FinishedAt = "0001-01-01T00:00:00Z"
			case "still-running":
				exit.Running = true
			case "sync":
				f.http.exitInspectHook = func() { _ = s.db.Close() }
			}
			f.http.exitState = exit
			err := s.Retire(ctx, f.ref)
			if scenario == "sync" || scenario == "still-running" {
				if err == nil || f.http.removes != 0 {
					t.Fatal("removed before synced terminal state", err, f.http.removes)
				}
				_ = s.Close()
				s = f.open(t)
				f.http.exitInspectHook = nil
				row := s.entries[f.ref.Consumer.Owner.Native].disk
				if row.Bindings[0].Closed || row.Bindings[0].Released || row.Bindings[0].Exit != nil {
					t.Fatal("failed observation published completion")
				}
				if _, err := s.ColdSource(ctx, NativeReady{}); err == nil {
					t.Fatal("accepted pending writer")
				}
				return
			}
			if err != nil {
				t.Fatal("cleanup must remain possible", err)
			}
			_ = s.Close()
			s = f.open(t)
			ready, err := f.native.Ready(ctx, f.ref.NativeKey, makeFixture(t).a)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.ColdSource(ctx, ready); err == nil {
				t.Fatal("absence fabricated clean source", scenario)
			}
		})
	}
}

func TestClosedWritersSurviveSourceDeletionAndSameDBReopen(t *testing.T) {
	f := activationTest(t)
	s := f.open(t)
	defer func() { _ = s.Close() }()
	ctx := context.Background()
	f.http.exists = true
	if err := s.Activate(ctx, f.ref); err != nil {
		t.Fatal(err)
	}
	ready, err := f.native.Ready(ctx, f.ref.NativeKey, makeFixture(t).a)
	if err != nil {
		t.Fatal(err)
	}
	if records, err := s.ClosedWriters(ready); err != nil || len(records) != 0 {
		t.Fatal("active writer became a historical cold fact", err)
	}
	f.http.exitState = sourceExitFixture()
	if err = s.Retire(ctx, f.ref); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s = f.open(t)
	// No historical lookup may consult native Inspect/list or require the
	// original Engine object to exist. The saved signed identity is sufficient
	// for selecting facts; it remains insufficient for cold source file access.
	f.sdk.mu.Lock()
	f.sdk.exists = false
	inspections := 0
	f.sdk.volumeInspectHook = func() { inspections++ }
	f.sdk.mu.Unlock()
	records, err := s.ClosedWriters(ready)
	if err != nil || len(records) != 1 || records[0].Writer != f.ref || !records[0].Exit.Clean() || inspections != 0 {
		t.Fatal("original historical writer unavailable", err, len(records))
	}
	records[0].Exit.Code = 9
	again, err := s.ClosedWriters(ready)
	if err != nil || !again[0].Exit.Clean() {
		t.Fatal("historical observation aliases disk", err)
	}
	if _, err = s.ColdSource(ctx, ready); err == nil {
		t.Fatal("historical lookup granted cold file access")
	}
}
