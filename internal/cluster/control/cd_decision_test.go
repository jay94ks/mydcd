// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"testing"
)

func signedCDDecision(t *testing.T, f *backupCoreFixture, action, id string, strict bool) (UserOperation, state.Command) {
	t.Helper()
	apps, err := f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	entry := apps.entries[appKey("tenant", "source-app")]
	selection, ok := entry.Delivery.CandidateSelection()
	if !ok {
		t.Fatal("missing candidate")
	}
	q := AppCDDecisionChange{Tenant: "tenant", App: "source-app", Candidate: selection.Candidate, Target: appSyncTarget(entry), Strict: strict}
	raw, _ := json.Marshal(q)
	op := UserOperation{Schema: 1, Session: f.session, At: 10, Epoch: f.s.ModuleEpoch(), RequestID: id, RootRevision: f.s.Object(AppsKey).Revision, Reason: &OperationReason{Text: "release review", IncidentID: "gate-1"}, Change: Change{Schema: 1, Principal: f.session.User, Action: action, Expected: entry.Delivery.Revision(), Payload: raw}}
	op.Signature = ed25519.Sign(f.admin, OperationBytes(op))
	cmd, err := op.Command()
	if err != nil {
		t.Fatal(err)
	}
	return op, cmd
}
func TestCDCandidateDecisionUsesManageCDGrantAndOriginalReasonWithoutSecretPermission(t *testing.T) {
	f, _ := fieldCASFixture(t)
	f.session.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read, access.ManageCD}}}
	f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
	op, cmd := signedCDDecision(t, f, "cd-approve", "approve-candidate", false)
	fieldCASObservation(t, f)
	applyRestartCore(t, f, cmd, state.Applied)
	apps, err := f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	entry := apps.entries[appKey("tenant", "source-app")]
	if entry.CDDecision == nil || entry.CDDecision.Origin.Reason.Text != op.Reason.Text || entry.CDDecision.Origin.RequestID != op.RequestID {
		t.Fatal("original decision/reason lost")
	}
	public, _ := json.Marshal(entry.CDDecision.view())
	if bytes.Contains(public, []byte("Signature")) || bytes.Contains(public, []byte("Session")) {
		t.Fatal("public decision exposed grant")
	}
	users, _ := f.p.Catalog(f.s)
	if users.AuthorizeSession(f.session, f.p.Cluster, f.p.Issuer(f.session.Issuer), 10, "tenant", access.Deploy, "") == nil {
		t.Fatal("ManageCD became Secret/Vault approval authority")
	}
	applyRestartCore(t, f, cmd, state.Applied)
	_, other := signedCDDecision(t, f, "cd-reject", "reject-candidate", true)
	fieldCASObservation(t, f)
	applyRestartCore(t, f, other, state.ConditionFailed)
}
func TestCDRejectSurvivesRootRestoreAndWrongTenantDecisionDenied(t *testing.T) {
	f, _ := fieldCASFixture(t)
	_, cmd := signedCDDecision(t, f, "cd-reject", "reject-candidate", false)
	applyRestartCore(t, f, cmd, state.Applied)
	apps, err := f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	entry := apps.entries[appKey("tenant", "source-app")]
	if !entry.Delivery.Rejected() {
		t.Fatal("typed reject not applied")
	}
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	apps, err = f.p.Apps(restored)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := apps.Delivery("tenant", "source-app")
	if !d.Rejected() {
		t.Fatal("restore resurrected candidate")
	}
	f.session.Scopes = []access.Scope{{Tenant: "other", Actions: []access.Action{access.ManageCD}}}
	f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
	_, denied := signedCDDecision(t, f, "cd-approve", "foreign-approval", false)
	applyRestartCore(t, f, denied, state.Forbidden)
}
