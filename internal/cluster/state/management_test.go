// SPDX-License-Identifier: Apache-2.0

package state

import (
	"fmt"
	"testing"
)

func TestManagementPermissionsLedgerRotationAndSnapshot(t *testing.T) {
	s, _ := New("admin")
	grant := Command{Actor: "admin", Epoch: 1, RequestID: "grant", Kind: SetRights, Target: "operator", Rights: Network}
	if r := mustApply(t, &s, grant); r.Code != Applied {
		t.Fatal(r)
	}
	c := Command{Actor: "operator", Epoch: 1, RequestID: "net", Key: "network/tun", Value: "mtu=1400"}
	if r := mustApply(t, &s, c); r.Code != Applied {
		t.Fatal(r)
	}
	c.RequestID = "deny"
	c.Key = "ingress/app"
	denied := mustApply(t, &s, c)
	if denied.Code != Forbidden {
		t.Fatal(denied)
	}
	grant.RequestID = "expand"
	grant.Expected = 1
	grant.Rights = Network | Ingress
	if r := mustApply(t, &s, grant); r.Code != Applied {
		t.Fatal(r)
	}
	if r := mustApply(t, &s, c); r != denied {
		t.Fatal("permission change reevaluated old request", r)
	}
	for i := s.ReceiptCount(); i < LedgerLimit+2; i++ { // two admin receipts, fill operator ledger
		c.RequestID = fmt.Sprint(i)
		c.Key = "network/limit"
		c.Expected = s.Object(c.Key).Revision
		mustApply(t, &s, c)
	}
	c.RequestID = "overflow"
	if r := mustApply(t, &s, c); r.Code != LedgerFull {
		t.Fatal(r)
	}
	rotation := Command{Actor: "admin", Epoch: 1, RequestID: "rotate", Kind: RotateLedger, Target: "operator", Expected: 4}
	if r := mustApply(t, &s, rotation); r.Code != Applied {
		t.Fatal(r)
	}
	if r := mustApply(t, &s, c); r.Code != Expired {
		t.Fatal("old ledger replay became executable", r)
	}
	c.Epoch = 2
	c.Expected = s.Object(c.Key).Revision
	if r := mustApply(t, &s, c); r.Code != Applied {
		t.Fatal(r)
	}
	b, err := Encode(s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if r := mustApply(t, &restored, c); r.Code != Applied || r.Index == restored.Index() {
		t.Fatal("lost durable receipt", r)
	}
	c.Epoch = 1
	if r := mustApply(t, &restored, c); r.Code != Expired {
		t.Fatal(r)
	}
	for _, bad := range [][]byte{nil, append(b, 0), []byte(`{"Schema":1,"Schema":1}`)} {
		if _, err := Decode(bad); err == nil {
			t.Fatal("accepted malformed snapshot")
		}
	}
}

func TestPolicyCASLastAdminAndSelfRotation(t *testing.T) {
	s, _ := New("admin")
	c := Command{Actor: "admin", Epoch: 1, RequestID: "revoke", Kind: SetRights, Target: "admin", Rights: Network}
	if r := mustApply(t, &s, c); r.Code != ConditionFailed {
		t.Fatal("removed last administrator", r)
	}
	c.RequestID = "self"
	c.Kind = RotateLedger
	c.Rights = 0
	if r := mustApply(t, &s, c); r.Code != Applied {
		t.Fatal(r)
	}
	if s.ReceiptCount() != 0 {
		t.Fatal("old self receipt occupied new epoch")
	}
	if r := mustApply(t, &s, c); r.Code != Expired {
		t.Fatal(r)
	}
	c.Epoch = 2
	c.RequestID = "stale"
	c.Kind = SetRights
	c.Target = "other"
	c.Expected = 10
	if r := mustApply(t, &s, c); r.Code != ConditionFailed {
		t.Fatal(r)
	}
	c.Actor = "unknown"
	if r := mustApply(t, &s, c); r.Code != Forbidden {
		t.Fatal(r)
	}
	if _, err := New(""); err == nil {
		t.Fatal("empty genesis identity")
	}
}
