// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
)

// node-remove-plan and remove-node / isolate / restore with the
// real NodeLifecycleChange payload.
func TestNodeRemovePlan(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	admin := passwordLogin(t, f, "admin", "admin")
	alice := passwordLogin(t, f, "alice", "alice")
	member := func(id string) liveMember { return liveMemberOf(t, admin, id) }
	codes := func(p control.NodeRemovePlan) map[string]string {
		out := map[string]string{}
		for _, b := range p.Blockers {
			out[b.Code] = b.Detail
		}
		return out
	}
	lifecycle := func(c Conn, action, node string, p control.NodeRemovePlan) Result {
		_, res := submit(t, c, action, p.Expected, control.NodeLifecycleChange{ID: node, Operation: "op-" + action + "-" + node, Epoch: p.Epoch}, root(t, c))
		return res
	}

	_, err := alice.PlanNodeRemoval(ctx, "node-c")
	wantCode(t, err, CodeDenied)

	// One of three voters: 2 left, quorum 2, tolerates 0. node-c holds a
	// fixed volume on an undrained storage root.
	p, err := admin.PlanNodeRemoval(ctx, "node-c")
	if err != nil {
		t.Fatal(err)
	}
	bc := codes(p)
	if p.Removable || p.VotersBefore != 3 || p.VotersAfter != 2 || p.QuorumAfter != 2 || p.FaultToleranceAfter != 0 || p.Epoch != fakeNodeEpoch || p.Expected != member("node-c").Revision {
		t.Fatalf("plan %+v", p)
	}
	if bc[NodeFixedVolumeStays] != "payments/ledger-data" || bc[NodeStorageNotDrained] != "hdd" || len(p.Storage) != 1 || p.Storage[0].Volumes != 1 {
		t.Fatalf("blockers %+v storage %+v", p.Blockers, p.Storage)
	}
	if len(p.Tasks) == 0 {
		t.Fatalf("tasks %+v", p.Tasks)
	}
	if res := lifecycle(admin, ActionRemoveNode, "node-c", p); res.Code != ResultFixedVolumePresent || ResultErrorCode(res.Code) != NodeFixedVolumeStays {
		t.Fatalf("remove with fixed volume %+v", res)
	}

	// Self and pending operation.
	if pa, _ := admin.PlanNodeRemoval(ctx, "node-a"); codes(pa)[NodeSelfRemoval] == "" {
		t.Fatalf("node-a %+v", pa)
	}
	if pd, _ := admin.PlanNodeRemoval(ctx, "node-d"); pd.PendingOperation != "op-invite-node-d" || codes(pd)[NodeOperationPending] != "op-invite-node-d" || pd.VotersAfter != 3 {
		t.Fatalf("node-d %+v", pd)
	}

	// Clear node-c's storage, then it can go.
	f.mu.Lock()
	f.w.volumes = f.w.volumes[:0:0]
	for i := range f.w.nodeStorage {
		f.w.nodeStorage[i].Draining, f.w.nodeStorage[i].Closed = true, true
	}
	f.mu.Unlock()
	p, _ = admin.PlanNodeRemoval(ctx, "node-c")
	if !p.Removable {
		t.Fatalf("cleared plan %+v", p.Blockers)
	}
	stale := p
	stale.Epoch++
	if res := lifecycle(admin, ActionRemoveNode, "node-c", stale); res.Code != ResultConditionFailed {
		t.Fatalf("stale epoch %+v", res)
	}
	if res := lifecycle(alice, ActionRemoveNode, "node-c", p); res.Code != ResultForbidden {
		t.Fatalf("remove by manager %+v", res)
	}
	if res := lifecycle(admin, ActionRemoveNode, "node-c", p); res.Code != ResultApplied {
		t.Fatalf("remove %+v", res)
	}
	if m := member("node-c"); m.Phase != NodePhaseRemoved || m.Voter {
		t.Fatalf("removed %+v", m)
	}
	_, err = admin.PlanNodeRemoval(ctx, "node-c")
	wantCode(t, err, CodeMissing)

	// Two voters left: node-b may go (1 voter, quorum 1), unless node-a
	// stops answering.
	pb, _ := admin.PlanNodeRemoval(ctx, "node-b")
	if !pb.Removable || pb.VotersAfter != 1 || pb.QuorumAfter != 1 {
		t.Fatalf("node-b %+v", pb)
	}
	f.SetNodeStatus("node-a", "unreachable")
	pb, _ = admin.PlanNodeRemoval(ctx, "node-b")
	if pb.Removable || pb.Blockers[0].Code != NodeQuorumLoss {
		t.Fatalf("node-b quorum %+v", pb)
	}
	if res := lifecycle(admin, ActionRemoveNode, "node-b", pb); res.Code != ResultQuorumLoss || ResultErrorCode(res.Code) != NodeQuorumLoss {
		t.Fatalf("remove node-b %+v", res)
	}
	f.SetNodeStatus("node-a", "ready")

	// Isolate / restore take the same payload.
	pb, _ = admin.PlanNodeRemoval(ctx, "node-b")
	if res := lifecycle(admin, ActionIsolateNode, "node-b", pb); res.Code != ResultApplied || member("node-b").Phase != NodePhaseIsolated {
		t.Fatalf("isolate %+v", res)
	}
	if _, res := submit(t, admin, ActionRestoreNode, member("node-b").Revision, NodeSelection{Node: "node-b"}, rootFor(t, admin, ActionRestoreNode)); res.Code != ResultInvalid {
		t.Fatalf("old payload %+v", res)
	}
	pb, _ = admin.PlanNodeRemoval(ctx, "node-b")
	if res := lifecycle(admin, ActionRestoreNode, "node-b", pb); res.Code != ResultApplied || member("node-b").Phase != NodePhaseActive {
		t.Fatalf("restore %+v", res)
	}
}

// Last voter: demote the others, then node-a is refused with LAST_VOTER.
func TestNodeRemoveLastVoter(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	admin := passwordLogin(t, f, "admin", "admin")
	f.mu.Lock()
	for i := range f.w.members {
		if f.w.members[i].ID != "node-a" {
			f.w.members[i].Voter = false
		}
	}
	f.mu.Unlock()
	p, err := admin.PlanNodeRemoval(ctx, "node-a")
	if err != nil || p.Removable || len(p.Blockers) == 0 || p.Blockers[0].Code != NodeLastVoter || p.VotersAfter != 0 {
		t.Fatalf("plan %+v %v", p, err)
	}
	_, res := submit(t, admin, ActionRemoveNode, p.Expected, control.NodeLifecycleChange{ID: "node-a", Operation: "op-rm-a", Epoch: p.Epoch}, rootFor(t, admin, ActionRemoveNode))
	if res.Code != ResultLastVoter || ResultErrorCode(res.Code) != NodeLastVoter {
		t.Fatalf("remove %+v", res)
	}
}
