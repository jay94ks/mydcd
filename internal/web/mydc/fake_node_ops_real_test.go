// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
)

// RQ12 in the real shape: plans, drain status, demote / rotate / force
// with the control payloads, the bundle's limits and the refusal reasons.
func TestNodeOpsReal(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	admin := passwordLogin(t, f, "admin", "admin")
	alice := passwordLogin(t, f, "alice", "alice")
	rev := func(id string) uint64 { return liveMemberOf(t, admin, id).Revision }

	if _, err := alice.PlanNodeDrain(ctx, control.NodeDrainQuery{Node: "node-b", Operation: "drain-b"}); err == nil {
		t.Fatal("manager reads the drain plan")
	}
	// Drain node-b with the plan as it was read.
	dp, err := admin.PlanNodeDrain(ctx, control.NodeDrainQuery{Node: "node-b", Operation: "drain-b"})
	if err != nil || dp.Schema != 1 || dp.Expected != rev("node-b") || dp.Digest == ([32]byte{}) || len(dp.Jobs) == 0 || len(dp.Tasks) == 0 {
		t.Fatalf("drain plan %+v %v", dp, err)
	}
	blocked := 0
	for _, task := range dp.Tasks {
		if !task.Movable {
			blocked++
		} else if task.Target == "" {
			t.Fatalf("movable without target %+v", task)
		}
	}
	change := control.NodeDrainChange{At: dp.At, ID: "node-b", Operation: "drain-b", LeaveBlocked: blocked > 0, AppsRoot: dp.AppsRoot, Plan: dp.Digest, Jobs: dp.Jobs}
	bad := change
	bad.Plan[0] ^= 1
	if _, res := submit(t, admin, ActionDrainNode, dp.Expected, bad, rootFor(t, admin, ActionDrainNode)); res.Code != ResultConditionFailed {
		t.Fatalf("stale plan %+v", res)
	}
	if _, res := submit(t, admin, ActionDrainNode, dp.Expected, change, rootFor(t, admin, ActionDrainNode)); res.Code != ResultApplied {
		t.Fatalf("drain %+v", res)
	}
	st, err := admin.NodeDrainStatus(ctx, control.NodeDrainQuery{Node: "node-b", Operation: "drain-b"})
	if err != nil || st.Total != len(dp.Tasks) || st.Blocked != blocked || st.Moved+st.Blocked != st.Total || (blocked > 0) != (st.State == "Partial") {
		t.Fatalf("status %+v %v", st, err)
	}
	if _, err := admin.NodeDrainStatus(ctx, control.NodeDrainQuery{Node: "node-b", Operation: "other"}); err == nil {
		t.Fatal("status of an unknown drain")
	}
	// an Operation-less status names the drain.
	f.SetNodeDrainState("node-b", "drain-b", "Draining")
	if last, err := admin.NodeDrainStatus(ctx, control.NodeDrainQuery{Node: "node-b"}); err != nil || last.Operation != "drain-b" || last.State != "Draining" {
		t.Fatalf("last status %+v %v", last, err)
	}
	if _, err := admin.NodeDrainStatus(ctx, control.NodeDrainQuery{Node: "node-c"}); err == nil {
		t.Fatal("last status without a drain")
	}
	if _, err := alice.NodeDrainStatus(ctx, control.NodeDrainQuery{Node: "node-b"}); err == nil {
		t.Fatal("last status by a non-admin")
	}

	// Demote node-c (a voter) with NodeSelection{ID}.
	vp, err := admin.PlanNodeDemotion(ctx, "node-c")
	if err != nil || !vp.Demotable || vp.VotersAfter != vp.VotersBefore-1 || vp.Expected != rev("node-c") {
		t.Fatalf("demote plan %+v %v", vp, err)
	}
	if _, res := submit(t, admin, ActionDemoteNode, vp.Expected, control.NodeSelection{ID: "node-c"}, rootFor(t, admin, ActionDemoteNode)); res.Code != ResultApplied {
		t.Fatalf("demote %+v", res)
	}

	// Rotate node-b's identity.
	if _, res := submit(t, admin, ActionRotateNodeIdentity, rev("node-b"), control.NodeIdentityChange{ID: "node-b", Operation: "rotate-b"}, rootFor(t, admin, ActionRotateNodeIdentity)); res.Code != ResultApplied {
		t.Fatalf("rotate %+v", res)
	}

	// Diagnostics: a valid allowlist bundle within 64 KiB.
	b, err := admin.ReadNodeDiagnostics(ctx, "node-b")
	if err != nil || !b.Valid("node-b") {
		t.Fatalf("bundle %+v %v", b, err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(b.Data))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	var names []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
	}
	if len(names) != 3 || names[0] != "config-summary.json" || names[2] != "mydcd-events.json" {
		t.Fatalf("bundle files %v", names)
	}

	// Force remove: a responding server is refused; an unreachable one
	// (node-c, demoted above) goes with its signed probe; node-d's pending
	// join blocks it.
	fp, err := admin.PlanNodeForceRemoval(ctx, control.NodeForceQuery{Node: "node-b", Operation: "force-b"})
	if err != nil || fp.Forceable || fp.Probe == nil || !fp.Probe.Responding {
		t.Fatalf("force plan b %+v %v", fp, err)
	}
	res := func(node, opID string) Result {
		t.Helper()
		p, err := admin.PlanNodeForceRemoval(ctx, control.NodeForceQuery{Node: node, Operation: opID})
		if err != nil || p.Probe == nil {
			t.Fatalf("force plan %v", err)
		}
		_, r := submit(t, admin, ActionForceRemoveNode, p.Expected, control.NodeForceChange{ID: node, Operation: opID, Epoch: p.Epoch, Probe: *p.Probe}, rootFor(t, admin, ActionForceRemoveNode))
		return r
	}
	if r := res("node-b", "force-b"); r.Code != ResultNodeResponding || r.Reason != NodeResponding || ResultErrorCode(r.Code) != NodeResponding {
		t.Fatalf("force responding %+v", r)
	}
	if r := res("node-d", "force-d"); r.Code != ResultNodeOperationPending || r.Reason != NodeOperationPending {
		t.Fatalf("force pending d %+v", r)
	}
	f.SetNodeStatus("node-c", "unreachable")
	fc, err := admin.PlanNodeForceRemoval(ctx, control.NodeForceQuery{Node: "node-c", Operation: "force-c"})
	if err != nil || fc.Probe == nil || fc.Probe.Responding || !fc.Probe.Valid() || !fc.Forceable {
		t.Fatalf("force plan c %+v %v", fc, err)
	}
	if r := res("node-c", "force-c"); r.Code != ResultApplied {
		t.Fatalf("force c %+v", r)
	}
	if _, err := admin.PlanNodeRemoval(ctx, "node-c"); err == nil {
		t.Fatal("plan of a retired server")
	}
	rp, err := admin.PlanNodeRemoval(ctx, "node-b")
	if err != nil || rp.Schema != 1 || rp.Removable || len(rp.Blockers) == 0 || rp.ConfigurationIndex == 0 || rp.RootRevision == 0 {
		t.Fatalf("remove plan %+v %v", rp, err)
	}
}
