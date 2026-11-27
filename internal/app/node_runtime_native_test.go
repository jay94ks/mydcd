// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
)

// This actual SDK/SFCP/FSM boundary uses the shared join fixture with native
// workload/network modules disabled. Owner proofs must come from the runtime;
// the test supplies no fabricated zero counts or readiness signatures. Full
// service/flow/writer retirement remains the resource-bearing E6 input.
func verifyRuntimeNodeLifecycle(t *testing.T, ctx context.Context, controls []*Runtime, user userauth.Client, session access.Session, admin ed25519.PrivateKey, policy control.Policy, submit func(string, string, uint64, any), wait func(string, func() bool)) {
	t.Helper()
	current := func() (*Runtime, membership.Directory, bool) {
		for _, runtime := range controls {
			if !runtime.Engine().IsLeader() {
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
	selectPeer := func(runtime *Runtime) sfcp.Peer {
		for _, peer := range user.Peers {
			if [32]byte(peer.Key) == runtime.Identity.Public {
				return peer
			}
		}
		t.Fatal("missing original trusted peer")
		return sfcp.Peer{}
	}
	wait("actual N3 runtime prefix", func() bool {
		_, d, found := current()
		if !found {
			return false
		}
		topology, err := d.Topology()
		return err == nil && len(topology.Configuration().Members) == 3 && topology.Configuration().Voters() == 3
	})
	_, d, _ := current()
	// Exercise the same public method and actual SDK DemoteVoter before the
	// existing lifecycle scenario; restore N3 with the original installed key.
	demoted := controls[2]
	demotedID := demoted.installation.record.Root.Self.ID
	entry, _ := d.Entry(demotedID)
	leaderBefore, _, _ := current()
	plan, err := user.NodeDemotePlan(ctx, selectPeer(leaderBefore), session, demotedID)
	if err != nil || !plan.Demotable || plan.VotersAfter != 2 || plan.FaultToleranceAfter != 0 {
		t.Fatal("public demotion plan", plan, err)
	}
	submit("demote-installed-voter", "demote-node", entry.Revision, control.NodeSelection{ID: demotedID})
	wait("actual installed nonvoter retains native identity", func() bool {
		_, d, found := current()
		if !found {
			return false
		}
		entry, found := d.Entry(demotedID)
		topology, err := d.Topology()
		return found && err == nil && entry.Phase == membership.Ready && !entry.Peer.Voter && entry.Job.Pending == nil && topology.Configuration().Voters() == 2 && d.MemberKey(demoted.Identity.Public) && d.WorkKey(demoted.Identity.Public)
	})
	leaderBefore, d, _ = current()
	entry, _ = d.Entry(demotedID)
	// The demoted node no longer issues sessions; it relays the login to the
	// leader, which issues it.
	if relayed, err := user.Login(ctx, selectPeer(demoted), "admin", admin); err != nil || relayed.Issuer != leaderBefore.Identity.Public || relayed.Issuer == demoted.Identity.Public {
		t.Fatal("demoted node must relay login to the leader, not mint a grant", err)
	}
	submit("restore-installed-voter", "promote-node", entry.Revision, control.NodeSelection{ID: demotedID})
	wait("actual re-promotion uses original installed key", func() bool {
		_, d, ok := current()
		if !ok {
			return false
		}
		entry, found := d.Entry(demotedID)
		topology, err := d.Topology()
		return found && err == nil && entry.Phase == membership.Active && entry.Job.Pending == nil && topology.Configuration().Voters() == 3
	})
	_, d, _ = current()
	topology, _ := d.Topology()
	isolatedControl := controls[1]
	leader, _, _ := current()
	if leader != isolatedControl {
		peer := selectPeer(isolatedControl)
		if err := leader.Engine().TransferLeadership(ctx, peer.ID, peer.Endpoint); err != nil {
			t.Fatal("actual leadership handoff before ingress isolation", err)
		}
		wait("actual selected isolation leader", func() bool { return isolatedControl.Engine().IsLeader() })
	}
	isolatedID := controls[1].installation.record.Root.Self.ID
	excludedGrant, err := user.Login(ctx, selectPeer(isolatedControl), "admin", admin)
	if err != nil || excludedGrant.Issuer != isolatedControl.Identity.Public {
		t.Fatal("grant before issuer isolation", err)
	}
	receiptPayload, _ := json.Marshal(control.TenantID{ID: "issuer-original-receipt"})
	originalReceipt, err := user.Prepare(ctx, selectPeer(isolatedControl), excludedGrant, "issuer-original-receipt", control.Change{Schema: 1, Principal: excludedGrant.User, Action: "create-tenant", Payload: receiptPayload})
	if err != nil {
		t.Fatal(err)
	}
	acceptedReceipt, err := user.Operation(ctx, selectPeer(isolatedControl), originalReceipt, false)
	if err != nil || acceptedReceipt.Result == nil || acceptedReceipt.Result.Code != state.Applied {
		t.Fatal("original accepted operation before issuer isolation", err)
	}
	node, _ := topology.Node(isolatedID)
	submit("isolate-live-control", "isolate-node", node.Revision, control.NodeLifecycleChange{ID: isolatedID, Operation: "isolate-control", Epoch: topology.Epoch()})
	wait("actual owner zero census and Isolated", func() bool {
		_, d, ok := current()
		if !ok {
			return false
		}
		view, found := d.NodeView(isolatedID)
		return found && view.Node.Phase == lifecycle.Isolated && view.Node.Closure != nil
	})
	leader, d, _ = current()
	topology, _ = d.Topology()
	view, _ := d.NodeView(isolatedID)
	if d.WorkKey(controls[1].Identity.Public) || !d.MemberKey(controls[1].Identity.Public) || !d.ReplicationKey(controls[1].Identity.Public) || topology.Configuration().Voters() != 3 || view.Node.Closure.ConfigurationIndex != topology.Configuration().Index || !ed25519.Verify(ed25519.PublicKey(controls[1].Identity.Public[:]), lifecycle.ProofBytes(*view.Node.Closure), view.Node.Closure.Signature) {
		t.Fatal("isolation changed quorum, lost consensus or used a fabricated owner proof")
	}
	actual, err := leader.Engine().InstalledConfiguration(ctx, true)
	if err != nil || len(actual.Configuration.Servers) != 3 {
		t.Fatal("isolation changed actual Raft configuration", err)
	}
	// Isolation closes the user Work ingress while the same member remains a
	// consensus leader. An Active ingress can attest and relay the same signed
	// operation without changing its ID, session, target, CAS or authority.
	if leader != isolatedControl {
		t.Fatal("isolated control ceased being the actual consensus leader")
	}
	activePeer := selectPeer(controls[0])
	isolatedPeer := selectPeer(isolatedControl)
	payload, err := json.Marshal(control.TenantID{ID: "node-ingress-probe"})
	if err != nil {
		t.Fatal(err)
	}
	op, err := user.Prepare(ctx, activePeer, session, "original-isolation-ingress", control.Change{Schema: 1, Principal: session.User, Action: "create-tenant", Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	_, err = user.Operation(ctx, isolatedPeer, op, false)
	var denied *userauth.Error
	if !errors.As(err, &denied) || denied.Code != "denied" {
		t.Fatal("isolated actual ingress accepted new management work", err)
	}
	command, err := op.Command()
	if err != nil {
		t.Fatal(err)
	}
	beforeRelay, err := isolatedControl.Engine().Read(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, found := beforeRelay.State.LookupResult(command); found {
		t.Fatal("isolated ingress dispatched the denied operation into A1")
	}
	relayed, err := user.Operation(ctx, activePeer, op, false)
	if err != nil || !relayed.Found || relayed.Result == nil || relayed.Result.Code != state.Applied {
		t.Fatal("active ingress could not relay original to isolated consensus leader", relayed, err)
	}
	afterRelay, err := isolatedControl.Engine().Read(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := policy.Catalog(afterRelay.State)
	if _, found := catalog.Tenant("node-ingress-probe"); err != nil || !found {
		t.Fatal("active relay did not reach the original control FSM", err)
	}
	_, err = user.Login(ctx, isolatedPeer, "admin", admin)
	denied = nil
	if !errors.As(err, &denied) || denied.Code != "not-session-issuer" {
		t.Fatal("isolated issuer must refuse even administrator login", err)
	}
	recoverySession, err := user.Login(ctx, activePeer, "admin", admin)
	if err != nil || recoverySession.User != session.User || recoverySession.Issuer != controls[0].Identity.Public || recoverySession.Approval == nil {
		t.Fatal("active follower recovery login with credentials kept at that issuer", err)
	}
	if _, err = user.Whoami(ctx, activePeer, excludedGrant); err == nil {
		t.Fatal("excluded issuer's old grant admitted a new request")
	}
	retained, err := user.Result(ctx, activePeer, recoverySession, originalReceipt)
	if err != nil || !retained.Found || retained.Result == nil || retained.Result.Code != state.Applied || *retained.Result != *acceptedReceipt.Result {
		t.Fatal("re-login could not recover the unchanged original result", err)
	}
	submit("restore-live-control", "restore-node", view.Node.Revision, control.NodeLifecycleChange{ID: isolatedID, Operation: "restore-control", Epoch: topology.Epoch()})
	wait("fresh owner readiness and Active", func() bool {
		_, d, ok := current()
		if !ok {
			return false
		}
		view, found := d.NodeView(isolatedID)
		return found && view.Node.Phase == lifecycle.Active && view.Node.Closure != nil && view.Node.Closure.Ready && d.WorkKey(controls[1].Identity.Public)
	})
	// Remove the ACTUAL current leader, so the production scheduling path must
	// transfer leadership before the one original SDK removal dispatch.
	leader, d, _ = current()
	removedID, removedKey := leader.installation.record.Root.Self.ID, leader.Identity.Public
	topology, _ = d.Topology()
	node, _ = topology.Node(removedID)
	submit("remove-current-leader", "remove-node", node.Revision, control.NodeLifecycleChange{ID: removedID, Operation: "remove-leader", Epoch: topology.Epoch()})
	wait("original self-removal and successor native configuration", func() bool {
		_, d, ok := current()
		if !ok {
			return false
		}
		view, found := d.NodeView(removedID)
		return found && view.Node.Phase == lifecycle.Removed && view.Native != nil && view.Native.ObservedIndex > view.Native.BaseIndex
	})
	successor, d, _ := current()
	if successor == leader || leader.Engine().IsLeader() || d.MemberKey(removedKey) || d.ReplicationKey(removedKey) || !d.HistoricalMemberKey(removedKey) {
		t.Fatal("self-removal did not hand off original authority/history")
	}
	actual, err = successor.Engine().InstalledConfiguration(ctx, true)
	if err != nil || len(actual.Configuration.Servers) != 2 {
		t.Fatal("actual RemoveServer did not preserve N2", err)
	}
	for _, server := range actual.Configuration.Servers {
		if string(server.ID) == removedID {
			t.Fatal("removed server still present in SDK configuration")
		}
	}
	if err := successor.Engine().Snapshot(ctx); err != nil {
		t.Fatal("runtime node metadata Snapshot", err)
	}
	// A removed issuer cannot issue the replacement session. Authenticate the
	// same system account at the still-installed successor using original pins.
	fresh, err := user.Login(ctx, selectPeer(successor), "admin", admin)
	if err != nil || fresh.User != session.User || fresh.Issuer != successor.Identity.Public {
		t.Fatal("successor current user login", err)
	}
	reply, err := user.Query(ctx, selectPeer(successor), fresh, "members", "")
	if err != nil || reply.NodeVoters != 2 || reply.NodeQuorum != 2 || reply.NodeConfigurationIndex != actual.Index {
		t.Fatal("current public runtime node view", reply, err)
	}
	var stopped *Runtime
	for _, runtime := range controls {
		if runtime != leader && runtime != successor {
			stopped = runtime
			break
		}
	}
	if stopped == nil {
		t.Fatal("missing second surviving voter")
	}
	if err := stopped.Close(); err != nil {
		t.Fatal("stop actual second voter", err)
	}
	probe, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	_, err = user.Query(probe, selectPeer(successor), fresh, "members", "")
	cancel()
	if err == nil {
		t.Fatal("N2 quorum read succeeded with only one surviving voter")
	}
	actual, err = successor.Engine().InstalledConfiguration(ctx, false)
	if err != nil || len(actual.Configuration.Servers) != 2 {
		t.Fatal("quorum loss silently shrank membership", err)
	}
	topology, _ = d.Topology()
	if topology.Configuration().Quorum() != 2 || topology.Configuration().Standalone(successor.installation.record.Root.Self.ID) {
		t.Fatal("one reachable node became standalone")
	}
	t.Logf("actual QUIC/FSM/A2/SDK: N3 isolated leader/denied ingress versus same signed operation via Active relay/recovery login, restoration with runtime owner proofs, leader %s removal/transfer, original history and indexed Snapshot, successor login, N2/Q2 loss refusal; no Docker/kernel/resource-bearing success claim", removedID)
}
