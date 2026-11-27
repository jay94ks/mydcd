// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/web/sfc"
	"github.com/jay94ks/seafield/internal/web/store"
)

const (
	opVw3 = "c1b2c3d4-0000-4000-8000-000000000003"
)

// assertNowhere checks that a secret is in no stored op of alice: the row,
// its digest, its signed original or its job.
func assertNowhere(t *testing.T, f *fixture, secret string) {
	t.Helper()
	for _, state := range []string{store.OpPending, store.OpApplied, store.OpFailed, store.OpRejected, store.OpUnknown, store.OpRunning} {
		ops, err := f.store.ListOps("u-alice", state, 1000)
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range ops {
			raw, _ := json.Marshal(o)
			if strings.Contains(string(raw), secret) || strings.Contains(string(o.Signed), secret) {
				t.Fatalf("secret stored in op %s (%s)", o.ID, o.Action)
			}
		}
	}
}

func TestVaultValueInputLost(t *testing.T) {
	f, fake := newFakeFixture(t)
	fakeLogin(t, f, "alice")
	// the private input's call fails: the outcome is unknown and the values
	// are not kept, so they are never sent again
	fake.FailNext("secret-input", sfc.CodeTransport)
	code, out := f.do("POST", "/api/v1/t/shop/vault/value", map[string]any{"opId": opVw3, "path": "db/mysql", "values": map[string]string{"MYSQL_PASSWORD": "lost-pw", "MYSQL_ROOT_PASSWORD": "lost-root"}})
	if code != 202 || opState(t, code, out) != "unknown" || out["op"].(map[string]any)["errorCode"] != "input-unknown" {
		t.Fatalf("lost: %d %v", code, out)
	}
	// sending again recovers (no values): nothing arrived, so not applied
	code, out = f.do("POST", "/api/v1/t/shop/vault/value", map[string]any{"opId": opVw3, "path": "db/mysql", "values": map[string]string{"MYSQL_PASSWORD": "lost-pw", "MYSQL_ROOT_PASSWORD": "lost-root"}})
	if code != 200 || opState(t, code, out) != "failed" || out["op"].(map[string]any)["errorCode"] != "write-not-applied" {
		t.Fatalf("recover: %d %v", code, out)
	}
	if got := fake.VaultWriteReceived("shop", vaultWriteID(opVw3)); len(got) != 0 {
		t.Fatalf("values sent after an attempt: %v", got)
	}
	assertNowhere(t, f, "lost-")
}
