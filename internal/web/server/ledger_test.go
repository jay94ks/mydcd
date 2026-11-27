// SPDX-License-Identifier: Apache-2.0

package server

import (
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

func TestRotateLedger(t *testing.T) {
	f, fake := newFakeFixture(t)
	fakeLogin(t, f, "admin")
	epoch := func() float64 {
		t.Helper()
		code, out := f.do("GET", "/api/v1/nodes", nil)
		if code != 200 || out["ledgerRevision"] == nil {
			t.Fatalf("nodes: %d %v", code, out)
		}
		return out["ledgerEpoch"].(float64)
	}
	if epoch() != 1 {
		t.Fatal("first ledger epoch is not 1")
	}
	const op1, op2, op3, op4 = "c1b2c3d4-0000-4000-8000-000000000001", "c1b2c3d4-0000-4000-8000-000000000002", "c1b2c3d4-0000-4000-8000-000000000003", "c1b2c3d4-0000-4000-8000-000000000004"

	// work in progress: condition failed, epoch unchanged
	fake.SetLedgerBusy(true)
	if code, out := f.do("POST", "/api/v1/ledger/rotate", map[string]any{"opId": op1, "expected": 1}); code != 200 || opState(t, code, out) != "failed" || out["op"].(map[string]any)["resultCode"] != float64(sfc.ResultConditionFailed) {
		t.Fatalf("busy: %d %v", code, out)
	}
	if epoch() != 1 {
		t.Fatal("busy rotation changed the epoch")
	}
	fake.SetLedgerBusy(false)
	code, out := f.do("POST", "/api/v1/ledger/rotate", map[string]any{"opId": op2, "expected": 1})
	if code != 200 || opState(t, code, out) != "applied" || out["op"].(map[string]any)["action"] != "rotate-ledger" {
		t.Fatalf("rotate: %d %v", code, out)
	}
	var v control.LedgerWindow
	userPayload(t, f, "u-admin", op2, &v)
	if v.NextEpoch != 2 || epoch() != 2 {
		t.Fatalf("payload %+v, epoch %v", v, epoch())
	}
	// a stale epoch fails
	if code, out := f.do("POST", "/api/v1/ledger/rotate", map[string]any{"opId": op3, "expected": 1}); opState(t, code, out) != "failed" {
		t.Fatalf("stale: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/ledger/rotate", map[string]any{"opId": op4, "expected": 0}); code != 422 {
		t.Fatalf("zero: %d %v", code, out)
	}
	// not an administrator: refused by sfcd
	fakeLogin(t, f, "alice")
	if code, out := f.do("POST", "/api/v1/ledger/rotate", map[string]any{"opId": op4, "expected": 2}); opState(t, code, out) != "failed" || out["op"].(map[string]any)["resultCode"] != float64(sfc.ResultForbidden) {
		t.Fatalf("manager: %d %v", code, out)
	}
}
