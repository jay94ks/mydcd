// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/jay94ks/mydcd/internal/reconcile"
)

func TestRouteUnknownApplyRetiresSameIDWithoutInventingItsOutcome(t *testing.T) {
	f := routeCoreFixture(t)
	core, operation, err := f.a.Plan()
	if err != nil || operation == nil {
		t.Fatal(err)
	}
	if _, err := core.BeginNativeRetirement(); err == nil {
		t.Fatal("active/Prepared Apply entered irreversible retirement")
	}
	core, err = core.Dispatch(operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	core, err = core.Unknown(operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	policy, _ := f.f.n.Route("first", "sql")
	f.f.n, err = f.f.n.Withdraw(f.f.c, "admin", "first", "sql", "first", policy.Revision)
	if err != nil {
		t.Fatal(err)
	}
	core, err = core.Sync(f.f.c, f.f.n, f.f.a)
	if err != nil {
		t.Fatal(err)
	}
	core, err = core.BeginNativeRetirement()
	if err != nil || core.Journal().Pending.ID != operation.ID || core.Journal().Pending.Target != operation.Target || core.Journal().Pending.Phase != reconcile.Retiring || core.Journal().LastID != operation.ID {
		t.Fatal("retirement replaced the uncertain original Apply", err)
	}
	before := routeRaw(t, core)
	again, err := core.BeginNativeRetirement()
	if err != nil || !bytes.Equal(before, routeRaw(t, again)) {
		t.Fatal("same retirement was not stable", err)
	}
	restored, err := DecodeRouteRuntime(before)
	if err != nil {
		t.Fatal(err)
	}
	late := routeNative(t, restored, f.f.key)
	if _, err := restored.ObserveNative(late); err == nil {
		t.Fatal("late original Apply reopened retiring native")
	}
	closed := late
	closed.Kind, closed.Installed, closed.Gone = reconcile.Remove, false, true
	closed.Signature = ed25519.Sign(f.f.key, RouteNativeBytes(closed))
	for _, mutate := range []func(*RouteNativeProof){
		func(p *RouteNativeProof) { p.Operation++ },
		func(p *RouteNativeProof) { p.Boot[0]++ },
		func(p *RouteNativeProof) { p.Spec += "changed" },
		func(p *RouteNativeProof) { p.Gone = false },
		func(p *RouteNativeProof) { p.Reference.Lifetime.Token++ },
	} {
		other := closed
		mutate(&other)
		other.Signature = ed25519.Sign(f.f.key, RouteNativeBytes(other))
		if _, err := restored.FinishNativeRetirement(other); err == nil {
			t.Fatal("foreign or incomplete native closure consumed original retirement")
		}
	}
	finished, err := restored.FinishNativeRetirement(closed)
	if err != nil || finished.Journal().Pending != nil || finished.Journal().Applied.Present || finished.Journal().Desired.Present || finished.Journal().LastID != operation.ID || finished.FlowCount() != 0 {
		t.Fatal("positive native closure did not settle exact original retirement", err)
	}
	routeRaw(t, finished)
	if !bytes.Equal(before, routeRaw(t, restored)) {
		t.Fatal("rejected or successful candidates mutated original snapshot")
	}
}
