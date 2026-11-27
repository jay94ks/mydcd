// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/json"
	"github.com/jay94ks/seafield/internal/access"
	"strings"
	"testing"
)

func TestOperationReasonIsSignedOwnedDisplayMetadataAndNeverApproval(t *testing.T) {
	f := newBackupCore(t)
	raw, e := ChangeBytes("put-user", "admin", 0, access.User{ID: "bot", Username: "bot", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: [32]byte{9}, Enabled: true}}})
	if e != nil {
		t.Fatal(e)
	}
	var change Change
	if json.Unmarshal(raw, &change) != nil {
		t.Fatal("change")
	}
	op := UserOperation{Schema: 1, Session: f.session, At: 2, Epoch: 1, RequestID: "with-reason", Change: change, Reason: &OperationReason{Text: "autofix", IncidentID: "incident-1", ApprovedBy: "other-admin"}}
	op.Signature = ed25519.Sign(f.admin, OperationBytes(op))
	if op.VerifyOriginal(f.p.Cluster) != nil {
		t.Fatal("signed reason rejected")
	}
	original, _ := op.Command()
	op.Reason.IncidentID = "incident-2"
	if op.VerifyOriginal(f.p.Cluster) == nil {
		t.Fatal("reason changed outside immutable signature")
	}
	if changed, _ := op.Command(); changed == original {
		t.Fatal("ledger identity did not bind reason")
	}
	for _, reason := range []OperationReason{{Text: strings.Repeat("a", 513)}, {IncidentID: "bad\nlabel"}, {ApprovedBy: "not an account id"}} {
		op.Reason = &reason
		if _, e = op.Command(); e == nil {
			t.Fatal("unbounded/invalid reason allowed")
		}
	}
	op.Reason = &OperationReason{Text: "autofix", IncidentID: "incident-1", ApprovedBy: "other-admin"}
	op.Signature = ed25519.Sign(f.admin, OperationBytes(op))
	current, err := f.p.Current(f.s)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := current.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	if current.authorizeChange(f.s, catalog, op) != nil {
		t.Fatal("ordinary authenticated fixture lost authority before independent-approval policy")
	}
	catalog, err = catalog.SetNodeCLI("admin", 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if current.authorizeChange(f.s, catalog, op) == nil {
		t.Fatal("claimed approved-by bypassed independent user approval")
	}
	// A claimed approver never adds a role or an independent management proof.
	if f.session.Approval != nil {
		t.Fatal("fixture must have no independent user approval")
	}
}
