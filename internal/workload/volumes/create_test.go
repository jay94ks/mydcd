// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jay94ks/mydcd/internal/reconcile"
)

func TestCreatePreparedBatchOriginalDispatchAndClosure(t *testing.T) {
	for _, dispatched := range []bool{false, true} {
		t.Run(map[bool]string{false: "never-sent", true: "dispatched-absent"}[dispatched], func(t *testing.T) {
			f, refs := activationBatchTest(t)
			f.http.exists = false
			s := f.open(t)
			defer func() { _ = s.Close() }()
			ctx := context.Background()
			if err := s.PrepareCreateAll(ctx, refs); err != nil {
				t.Fatal(err)
			}
			_ = s.Close()
			s = f.open(t)
			if yes, err := s.CreatePreparedAll(refs); err != nil || !yes {
				t.Fatal("lost positive no-Create checkpoint", err)
			}
			for _, r := range refs {
				query := r
				query.Operation = 0
				got, err := s.Original(query)
				if err != nil || got != r {
					t.Fatal("new Remove ID substituted original", err)
				}
				query.TaskKey += "-other"
				if _, err = s.Original(query); err == nil {
					t.Fatal("other task resolved original binding")
				}
			}
			if dispatched {
				if err := s.DispatchCreateAll(refs); err != nil {
					t.Fatal(err)
				}
				if yes, err := s.CreatePreparedAll(refs); err != nil || yes {
					t.Fatal("dispatched request regained no-Create fact", err)
				}
				if err := s.DispatchCreateAll(refs); err == nil {
					t.Fatal("second SDK create dispatch authorized")
				}
				if err := s.PrepareCreateAll(ctx, refs); err == nil {
					t.Fatal("uncertain request re-prepared")
				}
				if err := s.RetireAll(ctx, refs); !errors.Is(err, reconcile.ErrPending) {
					t.Fatal("dispatched absence closed", err)
				}
				f.http.exists = true // Later positive original observation.
			}
			if err := s.RetireAll(ctx, refs); err != nil {
				t.Fatal(err)
			}
			for _, r := range refs {
				state, err := f.native.View(r.NativeKey)
				if err != nil || len(state.Consumers) != 0 {
					t.Fatal("original planned pin not returned", err)
				}
				if _, err = s.Gone(ctx, r, makeFixture(t).a); err != nil {
					t.Fatal(err)
				}
			}
			if f.http.starts != 0 || !dispatched && f.http.removes != 0 {
				t.Fatal("unneeded native effect for unsent request")
			}
		})
	}
}

func TestCreatePreparedReceiptSyncFailureReopensOriginal(t *testing.T) {
	f, refs := activationBatchTest(t)
	f.http.exists = false
	s := f.open(t)
	defer func() { _ = s.Close() }()
	ctx := context.Background()
	inspects := 0
	f.sdk.volumeInspectHook = func() {
		inspects++
		if inspects != 3 {
			return
		}
		for _, r := range refs {
			raw, err := s.db.Get(activationRecordKey(r.Consumer.Owner.Native))
			var disk activationRecord
			if err != nil || json.Unmarshal(raw, &disk) != nil || len(disk.Bindings) != 1 || disk.Bindings[0].Ref != r || !disk.Bindings[0].CreatePrepared {
				t.Error("Borrow before ALL original no-Create intents", err)
			}
		}
		_ = s.db.Close()
	}
	if err := s.PrepareCreateAll(ctx, refs); err == nil {
		t.Fatal("lost pin receipt sync accepted")
	}
	_ = s.Close()
	s = f.open(t)
	if yes, err := s.CreatePreparedAll(refs); err != nil || !yes {
		t.Fatal("lost original no-Create fact on reboot", err)
	}
	if err := s.PrepareCreateAll(ctx, refs); err != nil {
		t.Fatal("same original prepare/pin receipt recovery", err)
	}
	if err := s.DispatchCreateAll(refs); err != nil {
		t.Fatal(err)
	}
	f.http.exists = true
	f.http.startHook = requireWholeStart(t, s, refs)
	if err := s.ActivateAll(ctx, refs); err != nil {
		t.Fatal(err)
	}
	if f.http.starts != 1 {
		t.Fatal("lost prepare receipt retransmitted SDK Start")
	}
	if err := s.RetireAll(ctx, refs); err != nil {
		t.Fatal(err)
	}
}

func TestVolumeInspectionRequiresOriginalPinAndIdentity(t *testing.T) {
	f, refs := activationBatchTest(t)
	f.http.exists = false
	s := f.open(t)
	defer s.Close()
	ctx := context.Background()
	if err := s.PrepareCreateAll(ctx, refs); err != nil {
		t.Fatal(err)
	}
	if err := s.DispatchCreateAll(refs); err != nil {
		t.Fatal(err)
	}
	f.http.exists = true
	if err := s.ActivateAll(ctx, refs); err != nil {
		t.Fatal(err)
	}
	if err := s.InspectAll(ctx, refs, f.http.value.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.InspectAll(ctx, refs, "other-native-ID"); err == nil {
		t.Fatal("readiness accepted a different immutable native ID")
	}
	e, err := s.entry(refs[1], false)
	if err != nil {
		t.Fatal(err)
	}
	lease := e.disk.Bindings[bindingIndex(e.disk, refs[1])].Lease
	// Inject missing original local pin without changing the SDK process.
	if err = f.native.Return(lease); err != nil {
		t.Fatal(err)
	}
	if err = s.InspectAll(ctx, refs, f.http.value.ID); err == nil {
		t.Fatal("readiness borrowed a replacement for a missing original pin")
	}
	if f.http.starts != 1 || f.calls != 2 {
		t.Fatal("read-only inspection dispatched Start/permit")
	}
	if err = s.RetireAll(ctx, refs); err != nil {
		t.Fatal(err)
	}
}

// A retained volume keeps a terminal predecessor binding. That durable lower
// generation is distinct from an absent/unknown current SDK request.
func TestClosedPredecessorProvesNewCreateUnpreparedOnlyUntilBatchPrepare(t *testing.T) {
	f, refs := activationBatchTest(t)
	f.http.exists = false
	s := f.open(t)
	defer func() { _ = s.Close() }()
	ctx := context.Background()
	if err := s.PrepareCreateAll(ctx, refs); err != nil {
		t.Fatal(err)
	}
	if err := s.RetireAll(ctx, refs); err != nil {
		t.Fatal(err)
	}
	next := append([]Activation(nil), refs...)
	for i := range next {
		next[i].Task.Generation++
		next[i].Consumer.Generation++
		next[i].Operation++
	}
	_ = s.Close()
	s = f.open(t)
	yes, err := s.CreateUnpreparedAll(next)
	if err != nil || !yes {
		t.Fatal("durable terminal predecessor not recognized", err)
	}
	if yes, _ := s.CreateUnpreparedAll(refs); yes {
		t.Fatal("old operation declared unprepared")
	}
	wrong := append([]Activation(nil), next...)
	wrong[0].TaskKey += "-other"
	if yes, _ := s.CreateUnpreparedAll(wrong); yes {
		t.Fatal("different task used predecessor")
	}
	if err := s.PrepareCreateAll(ctx, next); err != nil {
		t.Fatal(err)
	}
	if yes, err := s.CreateUnpreparedAll(next); err != nil || yes {
		t.Fatal("prepared intent erased", err)
	}
	if err := s.DispatchCreateAll(next); err != nil {
		t.Fatal(err)
	}
	if yes, err := s.CreateUnpreparedAll(next); err != nil || yes {
		t.Fatal("unknown dispatched SDK request declared unsent", err)
	}
	if f.http.starts != 0 {
		t.Fatal("proof dispatched a native start")
	}
}
