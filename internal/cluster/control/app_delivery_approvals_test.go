// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
)

func TestCDApprovalSelectorCannotAdoptAnotherCandidateOrOperation(t *testing.T) {
	f := deliveryControlFixture(t)
	a, _ := f.p.Apps(f.s)
	entry := a.entries[appKey("tenant", "source-app")]
	before, _ := json.Marshal(entry.Origin)
	request := AppCDApprovalRequest{App: "source-app", Selection: AppApprovalSelection{Operation: "run-source-app"}}
	registration, err := f.p.AppDeliveryApprovalRegistration(f.s, f.session, 10, "tenant", request)
	if err != nil || !registration.Selection.Equal(request.Selection) || len(registration.Realms) != 0 {
		t.Fatal("accepted no-Secret app required unrelated Vault state", registration.Realms, err)
	}
	after, _ := json.Marshal(registration.Origin)
	if !bytes.Equal(before, after) {
		t.Fatal("approval changed original requester")
	}
	for _, selected := range []AppApprovalSelection{
		{}, {Operation: "not-accepted"}, {Candidate: &[32]byte{77}},
		{Operation: "run-source-app", Candidate: &[32]byte{77}}, {Candidate: &[32]byte{}},
	} {
		request.Selection = selected
		if _, err := f.p.AppDeliveryApprovalRegistration(f.s, f.session, 10, "tenant", request); err == nil {
			t.Fatal("unselected input obtained approval authority", selected)
		}
	}
	if _, err := f.p.AppDeliveryApprovalRegistration(f.s, f.session, 10, "other", AppCDApprovalRequest{App: "source-app", Selection: AppApprovalSelection{Operation: "run-source-app"}}); err == nil {
		t.Fatal("tenant scope changed")
	}
	f.apply("replan-before-candidate-approval", "replan-app", entry.Delivery.Revision(), AppCDChange{Tenant: "tenant", App: "source-app"}, state.Applied)
	a, _ = f.p.Apps(f.s)
	entry = a.entries[appKey("tenant", "source-app")]
	current, _ := entry.Delivery.CandidateSelection()
	request.Selection = AppApprovalSelection{Candidate: &current.Candidate}
	registration, err = f.p.AppDeliveryApprovalRegistration(f.s, f.session, 10, "tenant", request)
	if err != nil || !registration.Selection.Equal(request.Selection) {
		t.Fatal("explicit current candidate could not be approved before destructive sync", err)
	}
	request.Selection.Candidate[0] ^= 1
	if registration.Selection.Candidate == nil || *registration.Selection.Candidate == *request.Selection.Candidate {
		t.Fatal("returned selector retained caller-owned memory")
	}
}

func TestCDCandidateApprovalSurvivesSameIntentHealthObservation(t *testing.T) {
	f, _ := fieldCASFixture(t)
	a, _ := f.p.Apps(f.s)
	entry := a.entries[appKey("tenant", "source-app")]
	f.apply("fresh-approval-plan", "replan-app", entry.Delivery.Revision(), AppCDChange{Tenant: "tenant", App: "source-app"}, state.Applied)
	a, _ = f.p.Apps(f.s)
	entry = a.entries[appKey("tenant", "source-app")]
	candidate, _ := entry.Delivery.CandidateSelection()
	request := AppCDApprovalRequest{App: "source-app", Selection: AppApprovalSelection{Candidate: &candidate.Candidate}}
	before, ok := entry.Delivery.CandidateBlueprint()
	if !ok {
		t.Fatal("initial candidate blueprint")
	}
	fieldCASObservation(t, f)
	a, _ = f.p.Apps(f.s)
	entry = a.entries[appKey("tenant", "source-app")]
	_, ctx, err := f.p.appDeliveryAccess(f.s, entry)
	catalog, _ := f.p.Catalog(f.s)
	fresh, replanErr := entry.Delivery.Replan(entry.Delivery.Revision(), catalog, ctx)
	changed, ok := fresh.CandidateSelection()
	if err != nil || replanErr != nil || !ok || changed.Candidate == candidate.Candidate || changed.Intent != candidate.Intent || changed.Artifact != candidate.Artifact {
		t.Fatal("health counterexample did not preserve intent while changing plan", err, replanErr)
	}
	registration, err := f.p.AppDeliveryApprovalRegistration(f.s, f.session, 10, "tenant", request)
	if err != nil || !registration.Selection.Equal(request.Selection) {
		t.Fatal("same current candidate denied solely by health plan bases", err)
	}
	currentPolicy, err := f.p.Current(f.s)
	if err != nil {
		t.Fatal(err)
	}
	after, err := currentPolicy.appApprovalBlueprintFor(f.s, f.session, 10, &entry.Origin, &request.Selection)
	if err != nil || after.IntentDigest() != before.IntentDigest() || after.AppInputDigest() != before.AppInputDigest() {
		t.Fatal("approval adopted different input", err)
	}
	f.apply("pause-approval", "pause-app-cd", func() uint64 { a, _ := f.p.Apps(f.s); d, _ := a.Delivery("tenant", "source-app"); return d.Revision() }(), AppCDChange{Tenant: "tenant", App: "source-app"}, state.Applied)
	if _, err := f.p.AppDeliveryApprovalRegistration(f.s, f.session, 10, "tenant", request); err == nil {
		t.Fatal("paused candidate approved")
	}
}

func TestCDCandidateApprovalRejectsPolicyChangeAfterSelection(t *testing.T) {
	f, _ := fieldCASFixture(t)
	a, _ := f.p.Apps(f.s)
	entry := a.entries[appKey("tenant", "source-app")]
	candidate, _ := entry.Delivery.CandidateSelection()
	policy := entry.Delivery.Policy()
	policy.Poll++
	f.apply("new-policy-before-approval", "configure-app-cd", entry.Delivery.Revision(), AppCDChange{Tenant: "tenant", App: "source-app", Policy: &policy, PolicyRevision: entry.Delivery.PolicyRevision()}, state.Applied)
	_, err := f.p.AppDeliveryApprovalRegistration(f.s, f.session, 10, "tenant", AppCDApprovalRequest{App: "source-app", Selection: AppApprovalSelection{Candidate: &candidate.Candidate}})
	if err == nil {
		t.Fatal("stale candidate gained approval under a different policy")
	}
}
