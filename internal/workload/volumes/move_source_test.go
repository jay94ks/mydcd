// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"context"
	"errors"
	"testing"
)

func TestMoveSourceFenceRequiresDurableClosureAndCurrentAuthority(t *testing.T) {
	for _, scenario := range []string{"normal", "sync", "revoked"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := context.Background()
			f := activationTest(t)
			s := f.open(t)
			defer func() { _ = s.Close() }()
			f.http.exists = true
			if err := s.Activate(ctx, f.ref); err != nil {
				t.Fatal(err)
			}
			fixture := makeFixture(t)
			ready, err := f.native.Ready(ctx, f.ref.NativeKey, fixture.a)
			if err != nil {
				t.Fatal(err)
			}
			b := Binding{Scope: ready.Spec.Scope, ID: "move", StartedRevision: 3, SourceOwnerRevision: f.ref.Consumer.OwnerRevision, Source: ready.Owner, Target: fixture.target, Compatibility: [32]byte{1}, MaxBytes: 128 << 10}
			calls := 0
			authority := func(context.Context, Binding) error {
				calls++
				if scenario == "sync" {
					_ = s.db.Close()
				}
				if scenario == "revoked" && calls == 2 {
					return errors.New("current move authorization revoked")
				}
				return nil
			}
			if proof, err := s.FenceSource(ctx, ready, b, func(context.Context, Binding) error { return nil }, fixture.a); err == nil || len(proof.Signature) != 0 {
				t.Fatal("active writer signed a fence", err)
			}
			f.http.exitState = sourceExitFixture()
			if err = s.Retire(ctx, f.ref); err != nil {
				t.Fatal(err)
			}
			proof, err := s.FenceSource(ctx, ready, b, authority, fixture.a)
			if scenario == "normal" {
				if err != nil || !validFence(proof, b) {
					t.Fatal("no original signed fence", err)
				}
			} else if err == nil || len(proof.Signature) != 0 {
				t.Fatal("failed sync/authorization signed a fence", err)
			}
			_ = s.Close()
			s = f.open(t)
			gate, err := s.Checkpoint(f.ref)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "sync" {
				if gate.FenceThrough != 0 {
					t.Fatal("failed write published fence")
				}
			} else {
				if gate.FenceThrough != b.SourceOwnerRevision {
					t.Fatal("same DB lost durable source fence")
				}
				if _, _, err = s.entries[ready.Owner.Native].gate.Request(f.ref.Consumer, [32]byte{7}); err == nil {
					t.Fatal("old writer escaped fence after reboot")
				}
			}
		})
	}
}

func TestSourceUnfencedDistinguishesOriginalRunningWriterFromLostFenceReport(t *testing.T) {
	f := activationTest(t)
	s := f.open(t)
	defer func() { _ = s.Close() }()
	ctx := context.Background()
	fixture := makeFixture(t)
	ready, err := f.native.Ready(ctx, f.ref.NativeKey, fixture.a)
	if err != nil {
		t.Fatal(err)
	}
	b := Binding{Scope: ready.Spec.Scope, ID: "move", StartedRevision: 3, SourceOwnerRevision: f.ref.Consumer.OwnerRevision, Source: ready.Owner, Target: fixture.target, Compatibility: [32]byte{1}, MaxBytes: 128 << 10}
	if unchanged, err := s.SourceUnfenced(ctx, ready, b); err != nil || !unchanged {
		t.Fatal("exact native with no activation was not observed", err)
	}
	f.http.exists = true
	if err = s.Activate(ctx, f.ref); err != nil {
		t.Fatal(err)
	}
	if unchanged, err := s.SourceUnfenced(ctx, ready, b); err != nil || !unchanged || f.http.removes != 0 {
		t.Fatal("checking early cancellation retired the original writer", err)
	}
	f.http.exitState = sourceExitFixture()
	if err = s.Retire(ctx, f.ref); err != nil {
		t.Fatal(err)
	}
	calls := 0
	_, err = s.FenceSource(ctx, ready, b, func(context.Context, Binding) error {
		calls++
		if calls == 2 {
			return errors.New("shared fence report lost authority")
		}
		return nil
	}, fixture.a)
	if err == nil {
		t.Fatal("late authorization failure was not injected")
	}
	_ = s.Close()
	s = f.open(t)
	if unchanged, err := s.SourceUnfenced(ctx, ready, b); err != nil || unchanged {
		t.Fatal("missing shared fence report hid a durable local fence", err)
	}
	foreign := b
	foreign.Source.Native = "foreign-native"
	if _, err = s.SourceUnfenced(ctx, ready, foreign); err == nil {
		t.Fatal("another native owner borrowed unchanged-source evidence")
	}
}
