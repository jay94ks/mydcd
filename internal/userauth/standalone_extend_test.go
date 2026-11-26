// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
)

func TestStandaloneExtensionReplyKeepsOriginalBoundsAndConfirmedResult(t *testing.T) {
	_, c, session, _ := journalFixture(t)
	created := session.IssuedAt
	q := control.StandaloneExtendChange{Tenant: "tenant", Name: "debug", Scope: "scope", Operation: "extend", CreatedAt: created, PreviousExpiresAt: created + 3600, TTLSeconds: 3600, Target: [32]byte{7}}
	raw, _ := control.ChangeBytes("standalone-extend", session.User, 2, q)
	var change control.Change
	_ = json.Unmarshal(raw, &change)
	op, err := c.prepareOperation(session, "original-extend", change, Reply{AppsRootRevision: 7, ModuleEpoch: 1}, created+3000)
	if err != nil || !control.StandaloneCASAllowed(op.Change) || op.VerifyOriginal(c.Cluster) != nil {
		t.Fatal("extension did not use original signing path", err)
	}
	for _, code := range []state.Code{state.Applied, state.ConditionFailed} {
		r := Reply{Schema: 1, Code: "ok", Found: true, Result: &state.Result{Code: code, Index: 9}}
		addStandaloneExtensionOutcome(&r, op)
		if r.StandaloneExtension == nil || r.StandaloneExtension.ProposedExpiresAt != created+6600 || r.StandaloneExtension.RemainingExtensionSeconds != 79800 || r.StandaloneExtensionCode != "" || r.Result.Code != code {
			t.Fatal("receipt and original arithmetic were conflated", r)
		}
	}
	for _, r := range []Reply{{Code: "unknown"}, {Code: "denied"}, {Code: "ok", Found: false}, {Code: "ok", Found: true}} {
		addStandaloneExtensionOutcome(&r, op)
		if r.StandaloneExtension != nil {
			t.Fatal("unconfirmed proposal exposed as outcome")
		}
	}
	q.TTLSeconds = 86400
	op.Change.Payload, _ = json.Marshal(q)
	op.Signature = ed25519.Sign(c.Self.Private, control.OperationBytes(op))
	r := Reply{Schema: 1, Code: "ok", Found: true, Result: &state.Result{Code: state.ConditionFailed, Index: 10}}
	addStandaloneExtensionOutcome(&r, op)
	if r.StandaloneExtension == nil || r.StandaloneExtensionCode != "STANDALONE_TTL_LIMIT" || r.StandaloneExtension.AllowedTTLSeconds != 83400 || r.StandaloneExtension.RemainingExtensionSeconds != 82800 {
		t.Fatal("limit refusal lost original numeric allowance", r)
	}
	op.Signature[0] ^= 1
	r.StandaloneExtension = nil
	addStandaloneExtensionOutcome(&r, op)
	if r.StandaloneExtension != nil {
		t.Fatal("unverified original rendered as extension outcome")
	}
}
