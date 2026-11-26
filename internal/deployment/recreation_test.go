// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"testing"
)

func TestExplicitRecreationUsesRunningSourceAndKeepsQueuedCandidate(t *testing.T) {
	f := newTransitionFixture(t, false, false)
	old, active := f.d.Inventory().Execution()
	if !active {
		t.Fatal("missing completed original")
	}
	// A different queued source must not be smuggled into an explicit restart.
	f.receive(f.imageChange("9"))
	queued, _ := f.d.Candidate()
	oldPolicy, oldOverrides := goal(f.d.d.Policy), goal(f.d.d.Overrides)
	key := ResourceKey("task", "tenant", "php-mysql", "db")
	f.saveDelivery(f.d.BeginRecreation(f.d.Revision(), f.f.c, "alice", "clear-logs", old.d.Submitter, old.d.Epoch, []string{key}))
	transition, _ := f.d.Transition()
	if transition.Mode != DeliveryRecreate || transition.Selection.Plan != old.Blueprint().Digest() {
		t.Fatal("recreation selected a new source instead of the running app")
	}
	if _, err := f.d.ContinueTransition(f.d.Revision(), f.f.c, f.ctx, "alice"); err == nil {
		t.Fatal("recreation began before positive original closure")
	}
	f.closeTargets()
	f.finishRetirement()
	f.continueTransition()
	next, found := f.d.Inventory().Execution()
	if !found || next.ActiveOperation() != "clear-logs" || !sameDeliveryIntent(old.Blueprint(), next.Blueprint()) {
		t.Fatal("recreation changed the accepted app goal")
	}
	if current, _ := f.d.Candidate(); current != queued || !bytes.Equal(oldPolicy, goal(f.d.d.Policy)) || !bytes.Equal(oldOverrides, goal(f.d.d.Overrides)) {
		t.Fatal("recreation reset Git candidate/policy/override metadata")
	}
}
