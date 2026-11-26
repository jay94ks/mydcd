// SPDX-License-Identifier: Apache-2.0

package control

import (
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
)

func TestExplainVolumeMovePrepareAgreesWithPermit(t *testing.T) {
	f, q := moveCore(t)
	f.apply("move", "begin-volume-move", f.core().Revision(), q, state.Applied)
	j, _, _ := f.view().Move(VolumeMoveSelection{Scope: f.scope, ID: q.ID})
	cases := []struct {
		caller [32]byte
		at     int64
		want   string
	}{
		{j.Binding.Target.Key, j.Origin.At + 1, ""},
		{j.Binding.Target.Key, j.ExpiresAt, "MOVE_PLAN_EXPIRED"},
		{j.Binding.Target.Key, j.Origin.At - 1, "CLOCK_BEFORE_PLAN"},
		{j.Binding.Source.Key, j.Origin.At + 1, "TARGET_KEY_NOT_CALLER"},
	}
	for _, c := range cases {
		got := f.p.ExplainVolumeMovePrepare(f.s, c.caller, j.Selection(), c.at)
		_, err := f.p.VolumeMovePermit(f.s, c.caller, VolumeMovePermitRequest{Selection: j.Selection(), Kind: "prepare"}, c.at)
		if got != c.want || (got == "") != (err == nil) {
			t.Fatalf("at=%d: explain %q, want %q, permit err %v", c.at, got, c.want, err)
		}
	}
	if got := f.p.ExplainVolumeMovePrepare(f.s, j.Binding.Target.Key, VolumeMoveSelection{Scope: f.scope, ID: "missing"}, j.Origin.At+1); got != "MOVE_NOT_FOUND" {
		t.Fatal(got)
	}
}

func TestMoveAppSupersededWhenTheAppLeftTheMove(t *testing.T) {
	f, q := moveCore(t)
	f.apply("move", "begin-volume-move", f.core().Revision(), q, state.Applied)
	j, _, _ := f.view().Move(VolumeMoveSelection{Scope: f.scope, ID: q.ID})
	if f.p.moveAppSuperseded(f.s, j) {
		t.Fatal("a move without an app was superseded")
	}
	// The app record is gone: no retirement can belong to the move any more.
	j.App = &VolumeMoveApp{Operation: "run-app", Revision: 1}
	if !f.p.moveAppSuperseded(f.s, j) {
		t.Fatal("a move whose app is gone still waits for its quiescence")
	}
}

func TestExplainVolumeMoveActivateAgreesWithPermit(t *testing.T) {
	f, q := moveCore(t)
	f.apply("move", "begin-volume-move", f.core().Revision(), q, state.Applied)
	j, _, _ := f.view().Move(VolumeMoveSelection{Scope: f.scope, ID: q.ID})
	for _, c := range []struct {
		at   int64
		want string
	}{
		{j.ExpiresAt, "MOVE_PLAN_EXPIRED"},
		{j.Origin.At + 1, "NO_APP_TARGET"}, // this fixture moves a volume without an app
	} {
		got := f.p.ExplainVolumeMoveActivate(f.s, j.Binding.Target.Key, j.Selection(), c.at)
		_, err := f.p.VolumeMovePermit(f.s, j.Binding.Target.Key, VolumeMovePermitRequest{Selection: j.Selection(), Kind: "activate-app"}, c.at)
		if got != c.want || err == nil {
			t.Fatalf("at=%d: explain %q, want %q, permit err %v", c.at, got, c.want, err)
		}
	}
}
