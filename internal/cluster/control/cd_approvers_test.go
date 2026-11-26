// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/json"
	"slices"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
)

func signedAs(t *testing.T, f *backupCoreFixture, session access.Session, id, action string, expected uint64, payload any) state.Command {
	t.Helper()
	raw, _ := json.Marshal(payload)
	op := UserOperation{Schema: 1, Session: session, At: 10, Epoch: f.s.ModuleEpoch(), RequestID: id, RootRevision: f.s.Object(AppsKey).Revision, Change: Change{Schema: 1, Principal: session.User, Action: action, Expected: expected, Payload: raw}}
	op.Signature = ed25519.Sign(f.admin, OperationBytes(op))
	cmd, err := op.Command()
	if err != nil {
		t.Fatal(err)
	}
	return cmd
}

func TestCDApproverMayDecideOnlyThatApp(t *testing.T) {
	f, _ := fieldCASFixture(t)
	key := [32]byte(f.admin.Public().(ed25519.PublicKey))
	f.session.Scopes = append(f.session.Scopes, access.Scope{Tenant: "tenant", Actions: []access.Action{access.Read, access.ManageCD, access.ManageMembers}})
	f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
	f.apply("reviewer-user", "put-user", 0, access.User{ID: "reviewer", Username: "reviewer", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: key, Enabled: true}}}, state.Applied)
	f.apply("reviewer-member", "set-membership", 0, access.Membership{Tenant: "tenant", User: "reviewer", Role: access.Viewer, Enabled: true}, state.Applied)
	users, _ := f.p.Catalog(f.s)
	u, _ := users.User("reviewer")
	reviewer := f.session
	reviewer.User, reviewer.AccountRevision = "reviewer", u.Revision
	reviewer.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}}
	reviewer.Signature = ed25519.Sign(f.node, access.SessionBytes(reviewer))

	apps, _ := f.p.Apps(f.s)
	entry := apps.entries[appKey("tenant", "source-app")]
	selection, _ := entry.Delivery.CandidateSelection()
	reject := func(id string) state.Command {
		apps, _ := f.p.Apps(f.s)
		entry := apps.entries[appKey("tenant", "source-app")]
		return signedAs(t, f, reviewer, id, "cd-reject", entry.Delivery.Revision(), AppCDDecisionChange{Tenant: "tenant", App: "source-app", Candidate: selection.Candidate, Target: appSyncTarget(entry)})
	}
	// Without the grant a viewer cannot decide.
	fieldCASObservation(t, f)
	applyRestartCore(t, f, reject("reject-before"), state.ConditionFailed)
	// A viewer cannot grant itself.
	applyRestartCore(t, f, signedAs(t, f, reviewer, "self-grant", "grant-cd-approver", entry.Delivery.Revision(), AppCDApproverChange{Tenant: "tenant", App: "source-app", User: "reviewer"}), state.Forbidden)
	// The manager grants; the CD record shows the approver.
	apps, _ = f.p.Apps(f.s)
	entry = apps.entries[appKey("tenant", "source-app")]
	applyRestartCore(t, f, signedAs(t, f, f.session, "grant", "grant-cd-approver", entry.Delivery.Revision(), AppCDApproverChange{Tenant: "tenant", App: "source-app", User: "reviewer"}), state.Applied)
	apps, _ = f.p.Apps(f.s)
	entry = apps.entries[appKey("tenant", "source-app")]
	if !slices.Equal(appCDView(entry).Approvers, []string{"reviewer"}) {
		t.Fatal("approver view", appCDView(entry).Approvers)
	}
	applyRestartCore(t, f, signedAs(t, f, f.session, "grant-again", "grant-cd-approver", entry.Delivery.Revision(), AppCDApproverChange{Tenant: "tenant", App: "source-app", User: "reviewer"}), state.ConditionFailed)
	fieldCASObservation(t, f)
	applyRestartCore(t, f, reject("reject-granted"), state.Applied)
	apps, _ = f.p.Apps(f.s)
	if !apps.entries[appKey("tenant", "source-app")].Delivery.Rejected() {
		t.Fatal("approver rejection not recorded")
	}
	// Revoked: decisions stop.
	entry = apps.entries[appKey("tenant", "source-app")]
	applyRestartCore(t, f, signedAs(t, f, f.session, "revoke", "revoke-cd-approver", entry.Delivery.Revision(), AppCDApproverChange{Tenant: "tenant", App: "source-app", User: "reviewer"}), state.Applied)
	apps, _ = f.p.Apps(f.s)
	if v := appCDView(apps.entries[appKey("tenant", "source-app")]); v.Approvers != nil {
		t.Fatal("approver kept", v.Approvers)
	}
	if CommandKey("grant-cd-approver") != AppsKey {
		t.Fatal("command key")
	}
}

func TestCDApproverApprovalIsAccepted(t *testing.T) {
	f, _ := fieldCASFixture(t)
	key := [32]byte(f.admin.Public().(ed25519.PublicKey))
	f.session.Scopes = append(f.session.Scopes, access.Scope{Tenant: "tenant", Actions: []access.Action{access.Read, access.ManageCD, access.ManageMembers}})
	f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
	f.apply("reviewer-user", "put-user", 0, access.User{ID: "reviewer", Username: "reviewer", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: key, Enabled: true}}}, state.Applied)
	f.apply("reviewer-member", "set-membership", 0, access.Membership{Tenant: "tenant", User: "reviewer", Role: access.Viewer, Enabled: true}, state.Applied)
	users, _ := f.p.Catalog(f.s)
	u, _ := users.User("reviewer")
	reviewer := f.session
	reviewer.User, reviewer.AccountRevision = "reviewer", u.Revision
	reviewer.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}}
	reviewer.Signature = ed25519.Sign(f.node, access.SessionBytes(reviewer))
	entry := func() appEntry {
		apps, _ := f.p.Apps(f.s)
		return apps.entries[appKey("tenant", "source-app")]
	}
	applyRestartCore(t, f, signedAs(t, f, f.session, "grant", "grant-cd-approver", entry().Delivery.Revision(), AppCDApproverChange{Tenant: "tenant", App: "source-app", User: "reviewer"}), state.Applied)
	fieldCASObservation(t, f)
	e := entry()
	selection, _ := e.Delivery.CandidateSelection()
	applyRestartCore(t, f, signedAs(t, f, reviewer, "approve-granted", "cd-approve", e.Delivery.Revision(), AppCDDecisionChange{Tenant: "tenant", App: "source-app", Candidate: selection.Candidate, Target: appSyncTarget(e)}), state.Applied)
	e = entry()
	users, _ = f.p.Catalog(f.s)
	if e.CDDecision == nil || e.CDDecision.Origin.Session.User != "reviewer" || !acceptedCDApproval(users, e) {
		t.Fatal("approver approval not accepted", e.CDDecision)
	}
	// Revoked, the same recorded approval no longer counts.
	applyRestartCore(t, f, signedAs(t, f, f.session, "revoke", "revoke-cd-approver", e.Delivery.Revision(), AppCDApproverChange{Tenant: "tenant", App: "source-app", User: "reviewer"}), state.Applied)
	users, _ = f.p.Catalog(f.s)
	if e = entry(); acceptedCDApproval(users, e) {
		t.Fatal("revoked approver's approval still accepted")
	}
}
