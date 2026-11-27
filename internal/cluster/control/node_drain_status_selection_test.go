// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
)

// Plans/progress are retained model inputs, not native migration evidence.
// Signatures, Directory.BeginDrain, checkpoint validation, current authority
// and the production status projection/selection are the real product core.
func nodeDrainStatusRecord(t *testing.T, f *nodeStorageFixture, operation, status string) {
	t.Helper()
	d, err := f.p.Members(f.s)
	if err != nil {
		t.Fatal(err)
	}
	plan := NodeDrainPlan{Schema: 1, At: 2, Node: "node-a", Operation: operation, Expected: d.Cordon("node-a").Revision, RootRevision: f.s.Object(MembersKey).Revision, AppsRoot: f.s.Object(AppsKey).Revision, Index: f.s.Index(), Jobs: []NodeDrainJob{}, Tasks: []NodePlanTask{}, Blockers: []NodeBlocker{}}
	if status != "Succeeded" {
		plan.Tasks = []NodePlanTask{{Tenant: "tenant", App: "app", Service: "web", Task: "task/app/tenant/app/web/0", Node: "node-a", Generation: 1, Revision: 1, Movable: status == "Draining"}}
		if status == "Draining" {
			plan.Jobs = []NodeDrainJob{{Tenant: "tenant", App: "app", Operation: drainAppOperation(operation, "tenant", "app"), Tasks: []deployment.ObjectRef{{Key: plan.Tasks[0].Task, Generation: 1, Revision: 1}}}}
		} else {
			plan.Tasks[0].Reason = "FIXED_VOLUME_PRESENT"
			plan.Blockers = []NodeBlocker{{Code: plan.Tasks[0].Reason, Detail: plan.Tasks[0].Task}}
		}
	}
	plan.Digest = drainPlanDigest(plan)
	payload := NodeDrainChange{At: 2, ID: plan.Node, Operation: operation, LeaveBlocked: true, AppsRoot: plan.AppsRoot, Plan: plan.Digest, Jobs: plan.Jobs}
	raw, _ := ChangeBytes("drain-node", "admin", plan.Expected, payload)
	var change Change
	if err = json.Unmarshal(raw, &change); err != nil {
		t.Fatal(err)
	}
	op := UserOperation{Schema: 1, Session: f.sessions["admin"], At: 2, Epoch: f.s.ModuleEpoch(), RootRevision: plan.RootRevision, RequestID: "original-" + operation, Change: change}
	op.Signature = ed25519.Sign(f.admin, OperationBytes(op))
	origin, _ := json.Marshal(op)
	frozen, _ := json.Marshal(plan)
	d, err = d.BeginDrain(plan.Node, operation, plan.Expected, origin, frozen)
	if err != nil {
		t.Fatal("retained original drain", err)
	}
	writes, code := f.p.memberCheckpoint(f.s, d)
	if code != state.Applied {
		t.Fatal("retained drain checkpoint", code)
	}
	f.checkpoint(MembersKey, writes)
	if _, err = f.p.Members(f.s); err != nil {
		t.Fatal("invalid retained model input", err)
	}
}

func TestNodeDrainStatusSelectsCurrentThenLatestCommittedOriginal(t *testing.T) {
	f := newNodeStorageFixture(t)
	query := func(operation, wantOperation, wantState string) NodeDrainStatus {
		t.Helper()
		before, _ := state.Encode(f.s)
		status, err := f.p.NodeDrainStatus(f.s, f.sessions["admin"], 2, NodeDrainQuery{Node: "node-a", Operation: operation})
		after, _ := state.Encode(f.s)
		if err != nil || status.Schema != 1 || status.Node != "node-a" || status.Operation != wantOperation || status.State != wantState || !bytes.Equal(before, after) {
			t.Fatal("status selection changed the original or read state", status, err)
		}
		return status
	}
	for _, q := range []NodeDrainQuery{{Node: "node-a"}, {Node: "node-a", Operation: "missing-original"}, {Node: "node-b"}} {
		if _, err := f.p.NodeDrainStatus(f.s, f.sessions["admin"], 2, q); !errors.Is(err, access.ErrInvalid) {
			t.Fatal("empty history must fail explicitly", q, err)
		}
	}
	nodeDrainStatusRecord(t, f, "z-historical", "Succeeded")
	query("", "z-historical", "Succeeded")
	nodeDrainStatusRecord(t, f, "a-historical", "Partial")
	query("", "a-historical", "Partial") // append order, not lexical ID
	query("z-historical", "z-historical", "Succeeded")
	nodeDrainStatusRecord(t, f, "z-active", "Draining")
	nodeDrainStatusRecord(t, f, "a-active", "Draining")
	nodeDrainStatusRecord(t, f, "latest-terminal", "Succeeded")
	active := query("", "a-active", "Draining")
	if active.Total != 1 || active.Moved != 0 || active.Blocked != 0 || len(active.Jobs) != 1 || active.Jobs[0].State != "Queued" {
		t.Fatal("active status did not consume original derived progress", active)
	}
	query("z-active", "z-active", "Draining")
	query("latest-terminal", "latest-terminal", "Succeeded")
	partial := query("a-historical", "a-historical", "Partial")
	if partial.Total != 1 || partial.Blocked != 1 || partial.Moved != 0 {
		t.Fatal("terminal original blocker status changed", partial)
	}
	// Public response ownership must not mutate the stored signed plan.
	active.Jobs[0].Operation = "caller-mutated"
	query("", "a-active", "Draining")
	before, _ := state.Encode(f.s)
	for _, operation := range []string{"", "a-active", "missing-original"} {
		if _, err := f.p.NodeDrainStatus(f.s, f.sessions["manager"], 2, NodeDrainQuery{Node: "node-a", Operation: operation}); !errors.Is(err, access.ErrDenied) {
			t.Fatal("non-admin selected or probed drain history", operation, err)
		}
	}
	for _, mutate := range []struct {
		edit func(*access.Session)
		sign bool
	}{
		{func(s *access.Session) { s.Signature[0] ^= 1 }, false},
		{func(s *access.Session) { s.AccountRevision++ }, true},
		{func(s *access.Session) { s.ExpiresAt = 2 }, true},
	} {
		session := f.sessions["admin"]
		session.Signature = bytes.Clone(session.Signature)
		mutate.edit(&session)
		if mutate.sign {
			session.Signature = ed25519.Sign(f.node, access.SessionBytes(session))
		}
		if _, err := f.p.NodeDrainStatus(f.s, session, 2, NodeDrainQuery{Node: "node-a"}); !errors.Is(err, access.ErrDenied) {
			t.Fatal("invalid current signed authority selected history", err)
		}
	}
	after, _ := state.Encode(f.s)
	if !bytes.Equal(before, after) {
		t.Fatal("denied status query mutated shared state")
	}
}

func TestNodeDrainStatusValidationDoesNotRelaxPlanOrDrain(t *testing.T) {
	for _, q := range []NodeDrainQuery{{Node: "node-a"}, {Node: "node-a", Operation: "original"}} {
		if !q.ValidStatus() || q.Valid() != (q.Operation != "") {
			t.Fatal("status/plan operation boundary", q)
		}
	}
	for _, q := range []NodeDrainQuery{{}, {Node: "../node"}, {Node: "node-a", Operation: "../operation"}} {
		if q.ValidStatus() || q.Valid() {
			t.Fatal("malformed status selector accepted", q)
		}
	}
	f := newNodeStorageFixture(t)
	if _, err := f.p.PlanNodeDrain(f.s, f.sessions["admin"], 2, NodeDrainQuery{Node: "node-a"}); !errors.Is(err, access.ErrDenied) {
		t.Fatal("plan accepted missing operation", err)
	}
	f.apply("admin", "drain-node", 0, NodeDrainChange{At: 2, ID: "node-a"}, state.Invalid)
	plan, err := f.p.PlanNodeDrain(f.s, f.sessions["admin"], 2, NodeDrainQuery{Node: "node-a", Operation: "actual-empty-drain"})
	if err != nil {
		t.Fatal("ordinary exact drain plan", err)
	}
	f.apply("admin", "drain-node", plan.Expected, NodeDrainChange{At: plan.At, ID: plan.Node, Operation: plan.Operation, AppsRoot: plan.AppsRoot, Plan: plan.Digest, Jobs: plan.Jobs}, state.Applied)
	status, err := f.p.NodeDrainStatus(f.s, f.sessions["admin"], 2, NodeDrainQuery{Node: "node-a"})
	if err != nil || status.Operation != plan.Operation || status.State != "Succeeded" || status.Total != 0 || status.Moved != 0 || status.Blocked != 0 {
		t.Fatal("status did not resolve the actual reducer's empty drain", status, err)
	}
}
