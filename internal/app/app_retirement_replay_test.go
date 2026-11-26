// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"testing"
)

// Actual user authentication, MYDCP, SDK Raft and durable FSM; no Docker/kernel
// adapters. The retained metadata command is the same boundary as E8's source
// Delete. Failure injection omits its first transmission after durable send.
func verifyRealRetirementReplay(t *testing.T, ctx context.Context, r *Runtime, read func() state.State, userOp func(string, string, uint64, any, ...state.Code) state.Result, late bool) {
	t.Helper()
	apps := func() control.Apps {
		a, e := r.controlPolicy.Apps(read())
		if e != nil {
			t.Fatal(e)
		}
		return a
	}
	a := apps()
	i, _ := a.Inventory("tenant", "app")
	userOp("original-down", "down-app", i.Revision(), control.AppDown{Tenant: "tenant", App: "app", Operation: "stop-original"})
	a = apps()
	i, _ = a.Inventory("tenant", "app")
	retirement, found := i.Retirement()
	if !found {
		t.Fatal("original retirement absent")
	}
	key := "workload/cd/tenant/app/source"
	original, found := i.Removal(key, "delete")
	if !found {
		t.Fatal("original source Delete absent", retirement)
	}
	progress := func(action string) {
		a := apps()
		i, _ := a.Inventory("tenant", "app")
		ret, _ := i.Retirement()
		row := a.Records()[0]
		if err := r.retirementProgress(ctx, cluster.View{State: read()}, row, ret, action, key, control.AppRetirementProgress{Phase: "delete"}); err != nil {
			t.Fatal(action, err)
		}
	}
	progress("retire-send") // durable dispatch followed by no transmission
	progress("retire-unknown")
	a = apps()
	i, _ = a.Inventory("tenant", "app")
	m, _ := i.Removal(key, "delete")
	if m.Journal.Pending == nil || m.Journal.Pending.Phase != reconcile.RecoveryRequired {
		t.Fatal("first failure not Unknown")
	}
	before := read().Index()
	if changed, err := r.reconcileAppRetirements(ctx, cluster.View{State: read()}, a); changed || err != nil {
		t.Fatal("unapproved replay", changed, err)
	}
	if read().Index() != before {
		t.Fatal("result-only reconciliation wrote a command")
	}
	pending := a.Records()[0].Retirement.Pending
	if pending == nil || pending.ReplayAuthorized || pending.Request != original.Command.RequestID || pending.Command != state.Digest(original.Command) {
		t.Fatal("public bounded recovery coordinates", pending)
	}
	q := control.AppRetirementReplay{Tenant: "tenant", App: "app", Retirement: pending.Retirement, Key: pending.Key, Phase: pending.Phase, Command: pending.Command}
	bad := q
	bad.Retirement = "another-retirement"
	userOp("bad-replay-target", "resume-app-retirement", i.Revision(), bad, state.ConditionFailed)
	userOp("bad-replay-cas", "resume-app-retirement", i.Revision()-1, q, state.ConditionFailed)
	userOp("explicit-original-replay", "resume-app-retirement", i.Revision(), q)
	if pending := apps().Records()[0].Retirement.Pending; pending == nil || !pending.ReplayAuthorized {
		t.Fatal("explicit grant not visible in status", pending)
	}
	if late {
		raw, _ := state.EncodeCommand(original.Command)
		reply, err := r.appCall(ctx, "app-command", raw)
		if err != nil || reply.Committed == nil || reply.Committed.Result.Code != state.Applied {
			t.Fatal("late original", err)
		}
	}
	// First pass consumes the grant and transmits the exact original, or
	// collects a late commit without consuming it. Second pass collects once.
	for n := 0; n < 2; n++ {
		if _, err := r.reconcileAppRetirements(ctx, cluster.View{State: read()}, apps()); err != nil {
			t.Fatal("original continuation", err)
		}
	}
	a = apps()
	i, _ = a.Inventory("tenant", "app")
	m, found = i.Removal(key, "delete")
	if !found { // completed whole retirement retains the same removal proof
		for _, claim := range i.Claims() {
			if claim.Step.Key == key && claim.Removal != nil && claim.Removal.Delete != nil {
				m = *claim.Removal.Delete
				found = true
			}
		}
	}
	if !found || m.Command != original.Command || m.Result == nil || m.Result.Code != state.Applied || m.Replay == nil || m.Replay.Dispatched == late {
		t.Fatal("original replay/result/late grant changed", m)
	}
	if result, found := read().LookupResult(original.Command); !found || result != *m.Result {
		t.Fatal("original durable receipt lost")
	}
	if read().Object(key).Present {
		t.Fatal("original metadata still present")
	}
	t.Log("same original ID/hash/Unknown, explicit authenticated CAS grant, one transmission, actual Raft dedup/result and late-original collection; no native closure claim")
}
