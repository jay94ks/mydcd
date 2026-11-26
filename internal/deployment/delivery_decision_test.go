// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"strings"
	"testing"
)

func TestCDRejectedCommitSurvivesFetchRebaseRestoreAndRequiresExplicitReconsider(t *testing.T) {
	f := newDeliveryFixture(t, "automatic")
	commit := f.receive(f.body)
	id, _ := f.d.Candidate()
	f.saveDelivery(f.d.Reject(f.d.Revision(), f.f.c, f.ctx, "alice", id, "upstream validation failed"))
	original := deliveryRaw(t, f.d)
	for _, action := range []string{"approve", "automatic", "manual"} {
		var err error
		switch action {
		case "approve":
			_, err = f.d.ApproveDecision(f.d.Revision(), f.f.c, f.ctx, "alice", id, "")
		case "automatic":
			_, err = f.d.SyncAutomatic(f.d.Revision(), f.f.c, f.ctx, "denied-auto", "submitter", 1)
		case "manual":
			_, err = f.d.Sync(f.d.Revision(), f.f.c, f.ctx, "alice", "denied-manual", "submitter", 1, false)
		}
		if err == nil || !bytes.Equal(original, deliveryRaw(t, f.d)) {
			t.Fatal("rejected source executed or mutated", action, err)
		}
	}
	ticket := f.fetch()
	input, err := ReadDeliveryInput(f.repo, ticket, commit, "app.yaml", 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	f.saveDelivery(f.d.Received(f.d.Revision(), f.f.c, f.ctx, input))
	f.saveDelivery(f.d.RebaseCandidate(f.d.Revision(), f.f.c, f.ctx))
	restored, err := DecodeDelivery(deliveryRaw(t, f.d))
	if err != nil || !restored.Rejected() {
		t.Fatal("source fetch/rebase/restore resurrected rejection", err)
	}
	f.d = restored
	f.saveDelivery(f.d.Reconsider(f.d.Revision(), f.f.c, f.ctx, "alice"))
	if f.d.Rejected() {
		t.Fatal("explicit reconsider did not lift same-source rejection")
	}
	f.saveDelivery(f.d.Replan(f.d.Revision(), f.f.c, f.ctx))
	f.saveDelivery(f.d.SyncAutomatic(f.d.Revision(), f.f.c, f.ctx, "human-replanned", "submitter", 1))
}
func TestCDExplicitCandidateApprovalUsesManualPolicyWithoutGrantingSecretApproval(t *testing.T) {
	f := newDeliveryFixture(t, "manual")
	f.receive(f.body)
	id, _ := f.d.Candidate()
	f.saveDelivery(f.d.ApproveDecision(f.d.Revision(), f.f.c, f.ctx, "alice", id, "release gate passed"))
	if !f.d.ExplicitApprovalReady(f.f.c) {
		t.Fatal("explicit candidate approval not available")
	}
	f.saveDelivery(f.d.RebaseCandidate(f.d.Revision(), f.f.c, f.ctx))
	status, err := f.d.Status(f.f.c, f.ctx, 100)
	if err != nil || status.ApprovalActor != "alice" || status.ApprovalReason != "release gate passed" {
		t.Fatal("public approval metadata missing", err)
	}
	f.saveDelivery(f.d.SyncAutomatic(f.d.Revision(), f.f.c, f.ctx, "approved-manual", "submitter", 1))
	selected, ok := f.d.Selection()
	if !ok || selected.Operation != "approved-manual" {
		t.Fatal("approved candidate did not use original inventory")
	}
}
func TestCDDecisionReasonRuneBoundAndNewCommitDoesNotClearOldRejection(t *testing.T) {
	if !ValidCDReason(strings.Repeat("값", 512)) || ValidCDReason(strings.Repeat("값", 513)) || ValidCDReason("bad\x00reason") || ValidCDReason(string([]byte{0xff})) {
		t.Fatal("invalid public reason bound")
	}
	f := newDeliveryFixture(t, "manual")
	old := f.receive(f.body)
	id, _ := f.d.Candidate()
	f.saveDelivery(f.d.Reject(f.d.Revision(), f.f.c, f.ctx, "alice", id, "rejected"))
	f.receive(append([]byte("# new commit\n"), f.body...))
	if f.d.Rejected() {
		t.Fatal("new source inherited old rejection")
	}
	ticket := f.fetch()
	input, err := ReadDeliveryInput(f.repo, ticket, old, "app.yaml", 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	f.saveDelivery(f.d.Received(f.d.Revision(), f.f.c, f.ctx, input))
	if !f.d.Rejected() {
		t.Fatal("return to old commit forgot its rejection")
	}
}
