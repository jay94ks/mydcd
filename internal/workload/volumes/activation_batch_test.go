// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/volume"
)

func activationBatchTest(t *testing.T) (*activationFixture, []Activation) {
	t.Helper()
	f := activationTest(t)
	f.sdk.mu.Lock()
	f.sdk.volumes = map[string]volume.Volume{f.sdk.value.Name: f.sdk.value}
	f.sdk.mu.Unlock()
	spec := f.spec
	spec.Scope.ID = "logs"
	key, err := f.native.Desired(spec, 2, 1, 4)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.native.Step(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	owner, scope, err := f.native.Owner(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	catalog := makeFixture(t).c
	second, err := New(catalog, "admin", scope, owner, 4)
	if err != nil {
		t.Fatal(err)
	}
	second, consumer, err := second.Acquire(catalog, "admin", second.Revision(), "database", 1, true)
	if err != nil {
		t.Fatal(err)
	}
	r := f.ref
	r.Scope, r.Consumer, r.NativeKey = scope, consumer, key
	f.http.mu.Lock()
	f.http.value.Mounts = append(f.http.value.Mounts, container.MountPoint{Type: mount.TypeVolume, Name: owner.Native, Destination: "/logs", RW: true})
	f.http.exists = true
	f.http.mu.Unlock()
	authority := f.authority
	f.authority = func(ctx context.Context, request StartRequest) (Permit, error) {
		if request.Scope == scope {
			f.calls++
			return second.PermitStart(catalog, "admin", request)
		}
		return authority(ctx, request)
	}
	refs, err := activationBatch([]Activation{f.ref, r})
	if err != nil {
		t.Fatal(err)
	}
	return f, refs
}

func requireWholeStart(t *testing.T, s *Activations, refs []Activation) func() error {
	t.Helper()
	return func() error {
		for _, r := range refs {
			raw, err := s.db.Get(activationRecordKey(r.Consumer.Owner.Native))
			var d activationRecord
			if err != nil || json.Unmarshal(raw, &d) != nil || d.Gate.Starting == nil || *d.Gate.Starting != r.Consumer {
				return errors.New("SDK Start before whole Starting transaction")
			}
			i := bindingIndex(d, r)
			if i < 0 || d.Bindings[i].Ref != r || d.Bindings[i].NativeID != strings.Repeat("a", 64) || d.Bindings[i].Lease.Pin.Token == 0 {
				return errors.New("SDK Start before whole original ID/pin transaction")
			}
		}
		return nil
	}
}

func TestActivationBatchRequiresEveryPermitAndSyncBeforeOneStart(t *testing.T) {
	for _, fail := range []string{"second-permit", "sync"} {
		t.Run(fail, func(t *testing.T) {
			f, refs := activationBatchTest(t)
			authority := f.authority
			var s *Activations
			var sequences []uint64
			deny := true
			f.authority = func(ctx context.Context, r StartRequest) (Permit, error) {
				sequences = append(sequences, r.Sequence)
				p, err := authority(ctx, r)
				if deny && r.Scope == refs[1].Scope {
					if fail == "sync" {
						_ = s.db.Close()
					} else {
						return Permit{}, errors.New("second volume denied")
					}
				}
				return p, err
			}
			s = f.open(t)
			defer func() { _ = s.Close() }()
			f.http.startHook = requireWholeStart(t, s, refs)
			if err := s.ActivateAll(context.Background(), refs); err == nil {
				t.Fatal("partial permission or unsynced batch started")
			}
			if f.http.starts != 0 || len(sequences) != 2 {
				t.Fatal("Start occurred before every permission", f.http.starts, sequences)
			}
			for _, r := range refs {
				cp, err := s.Checkpoint(r)
				if err != nil || cp.Starting != nil {
					t.Fatal("partially published Starting", err)
				}
			}
			deny = false
			if fail == "sync" {
				_ = s.Close()
				s = f.open(t)
				f.http.startHook = requireWholeStart(t, s, refs)
			}
			if err := s.ActivateAll(context.Background(), []Activation{refs[1], refs[0]}); err != nil {
				t.Fatal(err)
			}
			if f.http.starts != 1 || fail == "second-permit" && (sequences[2] <= sequences[0] || sequences[3] <= sequences[1]) {
				t.Fatal("duplicate Start or reused permit sequence", f.http.starts, sequences)
			}
			if err := s.RetireAll(context.Background(), refs); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestActivationBatchOriginalUnknownRecoveryAndClosure(t *testing.T) {
	for _, running := range []bool{true, false} {
		t.Run(map[bool]string{true: "running", false: "stopped"}[running], func(t *testing.T) {
			f, refs := activationBatchTest(t)
			s := f.open(t)
			defer func() { _ = s.Close() }()
			f.http.startHook = requireWholeStart(t, s, refs)
			f.http.startRuns, f.http.loseStart = running, true
			if err := s.ActivateAll(context.Background(), refs); err == nil {
				t.Fatal("lost SDK Start ACK reported successful")
			}
			for _, r := range refs {
				cp, err := s.Checkpoint(r)
				if err != nil || cp.Starting == nil || *cp.Starting != r.Consumer {
					t.Fatal("lost original whole Starting", err)
				}
				if _, err = s.Fence(r, r.Consumer.OwnerRevision); err == nil {
					t.Fatal("unknown Start passed a member Fence")
				}
			}
			_ = s.Close()
			s = f.open(t)
			s.authority = func(context.Context, StartRequest) (Permit, error) { return Permit{}, ErrVolume }
			err := s.ActivateAll(context.Background(), refs)
			if running && err != nil || !running && !errors.Is(err, reconcile.ErrPending) || f.http.starts != 1 || f.calls != 2 {
				t.Fatal("unknown original retransmitted or queried new permits", err, f.http.starts, f.calls)
			}
			f.http.loseRemove = true
			if err = s.RetireAll(context.Background(), refs); err == nil {
				t.Fatal("lost removal ACK reported complete")
			}
			_ = s.Close()
			s = f.open(t)
			if err = s.RetireAll(context.Background(), refs); err != nil {
				t.Fatal("same original terminal native ID", err)
			}
			for _, r := range refs {
				state, err := f.native.View(r.NativeKey)
				if err != nil || len(state.Consumers) != 0 {
					t.Fatal("orphaned mount pin", err)
				}
				if _, err = s.Gone(context.Background(), r, makeFixture(t).a); err != nil {
					t.Fatal("original member closure", err)
				}
			}
		})
	}
}

func TestActivationBatchRejectsUncoveredDuplicateAndOtherTask(t *testing.T) {
	f, refs := activationBatchTest(t)
	s := f.open(t)
	defer s.Close()
	ctx := context.Background()
	for _, bad := range [][]Activation{{refs[0]}, {refs[0], refs[0]}, nil} {
		if err := s.ActivateAll(ctx, bad); err == nil {
			t.Fatal("incomplete/duplicate mount set started")
		}
	}
	other := refs[1]
	other.Operation++
	if err := s.ActivateAll(ctx, []Activation{refs[0], other}); err == nil {
		t.Fatal("different original operation started")
	}
	if f.http.starts != 0 {
		t.Fatal("uncovered mount received Start")
	}
	if err := s.RetireAll(ctx, refs); err != nil {
		// The uncovered one-ref attempt may only have planned that ref. Plan
		// the other before observing/closing a positively present original.
		if err = s.Plan(ctx, refs[1]); err != nil {
			t.Fatal(err)
		}
		if err = s.RetireAll(ctx, refs); err != nil {
			t.Fatal(err)
		}
	}
}
