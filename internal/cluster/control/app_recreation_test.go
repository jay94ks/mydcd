// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
)

func TestLogClearAcceptancePinsConsentCASAndOriginalSourceThroughSnapshot(t *testing.T) {
	f, _, selection := logClearPlanFixture(t, "local")
	plan, err := f.p.PlanAppLogClear(f.s, f.session, 11, "tenant", selection)
	if err != nil {
		t.Fatal(err)
	}
	q := AppLogClear{Tenant: "tenant", App: "source-app", Operation: "clear-original", Target: plan.Target, Recreate: true}
	q.Selection.Service = "web"
	operation := func(id string, value AppLogClear) (UserOperation, state.Command) {
		t.Helper()
		payload, _ := json.Marshal(value)
		op := UserOperation{Schema: 1, Session: f.session, At: 11, Epoch: f.s.ModuleEpoch(), RequestID: id, RootRevision: f.s.Object(AppsKey).Revision, Change: Change{Schema: 1, Action: "clear-app-logs", Principal: f.session.User, Expected: plan.InventoryRevision, Payload: payload}}
		op.Signature = ed25519.Sign(f.admin, OperationBytes(op))
		cmd, err := op.Command()
		if err != nil {
			t.Fatal(err)
		}
		return op, cmd
	}
	apply := func(cmd state.Command, want state.Code) state.Result {
		t.Helper()
		next, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
		if err != nil || result.Code != want {
			t.Fatal("clear FSM", result, err)
		}
		f.s = next
		return result
	}
	before := f.s.Object(AppsKey)
	missing := q
	missing.Recreate = false
	_, cmd := operation("no-consent", missing)
	apply(cmd, state.Forbidden)
	stale := q
	stale.Target[0] ^= 1
	_, cmd = operation("wrong-target", stale)
	apply(cmd, state.ConditionFailed)
	if f.s.Object(AppsKey) != before {
		t.Fatal("rejected clear changed app state")
	}
	op, cmd := operation("original-clear", q)
	result := apply(cmd, state.Applied)
	a, err := f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	entry := a.entries[appKey("tenant", "source-app")]
	if entry.PendingSync == nil || entry.PendingSync.Recreate == nil || entry.Origin.Change.Action != "begin-app" || entry.Down != nil || a.Quiescent() {
		t.Fatal("clear replaced original ownership or lost request pin")
	}
	if !bytes.Equal(OperationBytes(*entry.PendingSync.User), OperationBytes(op)) {
		t.Fatal("accepted user operation was rewritten")
	}
	r, ok := entry.Inventory.Retirement()
	if !ok || r.Down || len(r.Targets) != len(plan.Impact) {
		t.Fatal("native closure differs from consent plan")
	}
	if apply(cmd, state.Applied) != result {
		t.Fatal("same original command did not return retained result")
	}
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = state.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	a, err = f.p.Apps(f.s)
	if err != nil || a.LogClearStatus("tenant", "source-app", "clear-original") == nil {
		t.Fatal("snapshot lost original clear", err)
	}
	if _, ready := a.LogClearContinuation("tenant", "source-app"); ready {
		t.Fatal("restart admitted before positive closure")
	}
}
