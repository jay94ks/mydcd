// SPDX-License-Identifier: Apache-2.0

package control

import (
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
)

func TestNodeRemovalPlanAndDurableRejectionUseSameCode(t *testing.T) {
	f := newNodeStorageFixture(t)
	plan, err := f.p.PlanNodeRemoval(f.s, f.sessions["admin"], 2, "node-a")
	if err != nil || plan.Removable || plan.VotersBefore != 1 || plan.VotersAfter != 0 || plan.Rejection() != state.NodeLastVoter {
		t.Fatal(plan, err)
	}
	cmd := f.apply("admin", "remove-node", plan.Expected, NodeLifecycleChange{ID: "node-a", Operation: "remove-last", Epoch: plan.Epoch}, state.NodeLastVoter)
	original, found := f.s.LookupResult(cmd)
	if !found || original.Reason != "LAST_VOTER" {
		t.Fatal("missing retained refusal", original)
	}
	f.apply("admin", "cordon-node", 0, NodeSelection{ID: "node-a"}, state.Applied)
	encoded, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	result, found := restored.LookupResult(cmd)
	if !found || result != original {
		t.Fatal("original reason was lost or re-evaluated", result, original)
	}
	if _, err = f.p.PlanNodeRemoval(f.s, f.sessions["manager"], 2, "node-a"); err == nil {
		t.Fatal("tenant manager read global removal plan")
	}
}

func TestNodeRemovalPlanShowsFixedVolumeAndRegisteredRoot(t *testing.T) {
	f, q := fixedRegistrationFixture(t)
	f.apply("manager", "register-fixed-volume", 0, q, state.Applied)
	f.creationReport(q.Scope, true, nil, nil, state.Applied)
	ready := f.fixedReady(q.Scope, 7)
	f.creationReport(q.Scope, false, &ready, nil, state.Applied)
	plan, err := f.p.PlanNodeRemoval(f.s, f.sessions["admin"], 2, "node-a")
	if err != nil || len(plan.Storage) != 1 || plan.Storage[0].ID != "hdd" || plan.Storage[0].Path != "/mnt/hdd" || plan.Storage[0].Volumes != 1 || len(plan.Volumes) != 1 || plan.Volumes[0].ID != q.Scope.ID || !plan.Volumes[0].Fixed {
		t.Fatal("fixed original data omitted", plan, err)
	}
	fixed := false
	for _, b := range plan.Blockers {
		if b.Code == "FIXED_VOLUME_PRESENT" {
			fixed = true
		}
	}
	if !fixed || plan.Removable {
		t.Fatal("fixed data did not block normal removal", plan)
	}
}
