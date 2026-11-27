// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
)

func TestCDSyncJournalPreservesTargetStrictModeAndRejectedReceipt(t *testing.T) {
	for _, targetMode := range []bool{false, true} {
		home, c, session, _ := journalFixture(t)
		q := control.AppCDChange{Tenant: "tenant", App: "app", Choice: &control.AppDeliveryChoice{Operation: "rollout", Candidate: [32]byte{1}, Registration: [32]byte{2}}}
		if targetMode {
			target := [32]byte{3}
			q.Target = &target
		}
		op := journalOperation(t, c, session, "original-cd")
		op.Change.Action, op.Change.Expected = "sync-app", 17
		op.Change.Payload, _ = json.Marshal(q)
		op.Signature = ed25519.Sign(c.Self.Private, control.OperationBytes(op))
		command, err := op.Command()
		if err != nil || (command.Kind == state.ModuleAppCAS) != targetMode {
			t.Fatal("original mode", err)
		}
		if _, err := StageOperation(home, c, op); err != nil {
			t.Fatal(err)
		}
		// Persist an actual private journal receipt, including a definitive
		// rejection. Loading it never fetches/re-signs a newer source target.
		result := state.Result{Code: state.ConditionFailed, Index: 29, Revision: 28, Generation: 1}
		if err := RecordOperationResult(home, c, session, op, result); err != nil {
			t.Fatal(err)
		}
		record, err := LoadOperation(home, c, session, op.RequestID)
		if err != nil || record.Result == nil || *record.Result != result || !bytes.Equal(control.OperationBytes(record.Operation), control.OperationBytes(op)) || !bytes.Equal(record.Operation.Signature, op.Signature) {
			t.Fatal("original target/signature/result changed", err)
		}
		changed := op
		if targetMode {
			q.Target = nil
		} else {
			target := [32]byte{3}
			q.Target = &target
		}
		changed.Change.Payload, _ = json.Marshal(q)
		changed.Signature = ed25519.Sign(c.Self.Private, control.OperationBytes(changed))
		if _, err := StageOperation(home, c, changed); err == nil {
			t.Fatal("original request changed CAS mode")
		}
	}
}
