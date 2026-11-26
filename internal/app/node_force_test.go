// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/cluster/membership"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
)

// This source connects the existing real N3 fixture. The target mydcd stops;
// the remaining pair must commit one original SDK effect after a fresh MYDCP
// probe. Native workload modules are disabled, so this proves no Task stop or
// Volume writer fence. Those pins are covered separately by the core input.
func verifyRuntimeForceRemoval(t *testing.T, ctx context.Context, controls []*Runtime, user userauth.Client, session access.Session, policy control.Policy, wait func(string, func() bool)) {
	t.Helper()
	var stopped *Runtime
	current := func() (*Runtime, membership.Directory, bool) {
		for _, runtime := range controls {
			if runtime == stopped || !runtime.Engine().IsLeader() {
				continue
			}
			view, err := runtime.Engine().Read(ctx, false)
			if err != nil {
				continue
			}
			d, err := policy.Members(view.State)
			if err == nil {
				return runtime, d, true
			}
		}
		return nil, membership.Directory{}, false
	}
	peerFor := func(runtime *Runtime) mydcp.Peer {
		for _, peer := range user.Peers {
			if [32]byte(peer.Key) == runtime.Identity.Public {
				return peer
			}
		}
		t.Fatal("missing pinned control")
		return mydcp.Peer{}
	}
	wait("N3 installed before force removal", func() bool {
		_, d, ok := current()
		if !ok {
			return false
		}
		topology, err := d.Topology()
		return err == nil && len(topology.Configuration().Members) == 3 && topology.Configuration().Voters() == 3
	})
	leader, d, _ := current()
	var target *Runtime
	for _, candidate := range controls[1:] {
		if candidate != leader {
			target = candidate
			break
		}
	}
	if target == nil {
		t.Fatal("missing non-genesis follower")
	}
	id := target.installation.record.Root.Self.ID
	oldKey := target.Identity.Public
	removal, err := user.NodeRemovePlan(ctx, peerFor(leader), session, id)
	if err != nil || removal.VotersBefore != 3 || removal.VotersAfter != 2 || removal.QuorumAfter != 2 || removal.FaultToleranceAfter != 0 {
		t.Fatal("public N3 removal plan", removal, err)
	}
	plan, err := user.NodeForceRemovePlan(ctx, peerFor(leader), session, control.NodeForceQuery{Node: id, Operation: "responding-force"})
	if err != nil || plan.Forceable || plan.Probe == nil || !plan.Probe.Responding {
		t.Fatal("responding node force plan", plan, err)
	}
	prepare := func(request string, plan control.NodeForcePlan) control.UserOperation {
		t.Helper()
		payload, _ := json.Marshal(control.NodeForceChange{ID: id, Operation: plan.Operation, Epoch: plan.Epoch, Probe: *plan.Probe})
		op, err := user.Prepare(ctx, peerFor(leader), session, request, control.Change{Schema: 1, Action: "force-remove-node", Principal: session.User, Expected: plan.Expected, Payload: payload})
		if err != nil {
			t.Fatal(err)
		}
		return op
	}
	rejectedOp := prepare("reject-responding-force", plan)
	rejected, err := user.Operation(ctx, peerFor(leader), rejectedOp, false)
	if err != nil || rejected.Result == nil || rejected.Result.Code != state.NodeStillResponding || rejected.Result.Reason != "NODE_RESPONDING" {
		t.Fatal("force response refusal", rejected, err)
	}
	before, _ := d.Entry(id)
	stopped = target
	if err = target.Close(); err != nil {
		t.Fatal("stop original target mydcd", err)
	}
	wait("surviving installed quorum", func() bool { _, _, ok := current(); return ok })
	leader, d, _ = current()
	plan, err = user.NodeForceRemovePlan(ctx, peerFor(leader), session, control.NodeForceQuery{Node: id, Operation: "force-unreachable"})
	if err != nil || !plan.Forceable || plan.Probe == nil || plan.Probe.Responding || plan.VotersAfter != 2 || plan.QuorumAfter != 2 {
		t.Fatal("authenticated failed probe plan", plan, err)
	}
	op := prepare("force-unreachable-original", plan)
	accepted, err := user.Operation(ctx, peerFor(leader), op, false)
	if err != nil || accepted.Result == nil || accepted.Result.Code != state.Applied {
		t.Fatal("force original acceptance", accepted, err)
	}
	wait("actual original force RemoveServer", func() bool {
		_, d, ok := current()
		if !ok {
			return false
		}
		v, found := d.NodeView(id)
		return found && v.Node.Phase == lifecycle.Retired && v.Node.Closure == nil && v.Node.Retirement != nil && v.Native != nil && v.Native.ObservedIndex > v.Native.BaseIndex
	})
	leader, d, _ = current()
	after, _ := d.Entry(id)
	if after.Peer != before.Peer || d.MemberKey(oldKey) || d.ReplicationKey(oldKey) || !d.HistoricalMemberKey(oldKey) {
		t.Fatal("force retirement replaced history or leaked current authority")
	}
	if _, approved := leader.Mesh.Peer(mydcp.Identity(oldKey)); approved {
		t.Fatal("retired TLS key fell back into public user authentication")
	}
	actual, err := leader.Engine().InstalledConfiguration(ctx, true)
	if err != nil || len(actual.Configuration.Servers) != 2 {
		t.Fatal("actual forced native membership", actual, err)
	}
	retained, err := user.Result(ctx, peerFor(leader), session, rejectedOp)
	if err != nil || retained.Result == nil || *retained.Result != *rejected.Result {
		t.Fatal("original refusal was recomputed after target disappeared", retained, err)
	}
	retained, err = user.Result(ctx, peerFor(leader), session, op)
	if err != nil || retained.Result == nil || *retained.Result != *accepted.Result {
		t.Fatal("force original operation result changed", retained, err)
	}
	if err = leader.Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
}
