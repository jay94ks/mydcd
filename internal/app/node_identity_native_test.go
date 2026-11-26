// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/membership"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
)

// Actual MYDCP/Raft/FSM/local installation restart, with workload/network native
// modules disabled by the existing N3 fixture. Resource-bearing original Task,
// Volume and sealed-input settlement require their native fixture separately.
func verifyRuntimeIdentityRotation(t *testing.T, ctx context.Context, nodes []*Runtime, client userauth.Client, session access.Session, policy control.Policy, submit func(string, string, uint64, any), wait func(string, func() bool)) {
	t.Helper()
	target := nodes[2]
	id := target.installation.record.Root.Self.ID
	original := target.Identity.Public
	config := target.installation.config
	current := func() (*Runtime, membership.Directory, bool) {
		for _, runtime := range nodes {
			if runtime.installation.record.Root.Self.ID == id || !runtime.Engine().IsLeader() {
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
	var d membership.Directory
	wait("unchanged leader before installed identity replacement", func() bool {
		for _, runtime := range nodes {
			if runtime.Engine().IsLeader() {
				view, err := runtime.Engine().Read(ctx, false)
				if err != nil {
					return false
				}
				d, err = policy.Members(view.State)
				return err == nil && d.Runtime != nil
			}
		}
		return false
	})
	entry, _ := d.Entry(id)
	// Freeze another node's latest SDK configuration before the key-only
	// transition. Reopening it later must retain this installation evidence at
	// the same SDK index while authenticating the replaced peer by its new key.
	observerIndex := -1
	for i, runtime := range nodes {
		if runtime != target && !runtime.Engine().IsLeader() {
			observerIndex = i
			break
		}
	}
	if observerIndex < 0 {
		t.Fatal("missing other installed nonleader for same-configuration restart")
	}
	observer := nodes[observerIndex]
	observerConfig := observer.installation.config
	observerRecord, installErr := observer.InstallConfiguration(ctx)
	if installErr != nil {
		t.Fatal("install latest configuration before another member key replacement", installErr)
	}
	priorMember, present := observerRecord.Root.Installed.Member(id)
	if !present || priorMember.Key != original {
		t.Fatal("other-node original installation did not freeze the original member key")
	}
	submit("replace-installed-node-key", "rotate-node-identity", entry.Revision, control.NodeIdentityChange{ID: id, Operation: "replace-installed"})
	wait("durable local identity restart request", func() bool {
		select {
		case <-target.IdentityRestart():
			return true
		default:
			return false
		}
	})
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	restored, err := Open(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restored.Close() })
	if restored.Identity.Public == original || restored.Mesh.LocalKey() != mydcp.Identity(restored.Identity.Public) || restored.installation.record.Root.OriginalKey() != original {
		t.Fatal("restart did not select actual new TLS identity and historic root")
	}
	if _, err = restored.ResumeInstallation(ctx); err != nil {
		t.Fatal(err)
	}
	nodes[2] = restored
	wait("new TLS identity installation observation", func() bool {
		leader, d, ok := current()
		if !ok {
			return false
		}
		row, ok := d.IdentityRotation(id, "replace-installed")
		if !ok || row.Phase != "Installed" || !d.MemberKey(restored.Identity.Public) || d.MemberKey(original) || d.ReplicationKey(original) || !d.HistoricalMemberKey(original) {
			return false
		}
		_ = leader
		return true
	})
	leader, _, ok := current()
	if !ok {
		t.Fatal("missing unchanged leader")
	}
	if _, admitted := leader.Mesh.Peer(mydcp.Identity(original)); admitted {
		t.Fatal("historic key leaked into current TLS/user fallback")
	}
	var peer mydcp.Peer
	for _, candidate := range client.Peers {
		if [32]byte(candidate.Key) == leader.Identity.Public {
			peer = candidate
			break
		}
	}
	page, err := client.MemberPage(ctx, peer, session, "")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, row := range page.NodeLifecycle {
		if row.Node.Member.ID == id {
			found = row.Identity != nil && row.Identity.Operation == "replace-installed" && row.Identity.Phase == "Installed"
		}
	}
	if !found {
		t.Fatal("public node status omitted original replacement progress")
	}
	wait("other node applies new member key without a new SDK configuration", func() bool {
		_, directory, readErr := observer.members(ctx, false)
		installed, configErr := observer.Engine().InstalledConfiguration(ctx, false)
		return readErr == nil && configErr == nil && installed.Index == observerRecord.Root.Installed.Index && directory.MemberKey(restored.Identity.Public) && !directory.MemberKey(original)
	})
	repeatedObserver, err := observer.InstallConfiguration(ctx)
	if err != nil || repeatedObserver.Root.Installed.Index != observerRecord.Root.Installed.Index {
		t.Fatal("same running node could not reuse its original signed installation record", err)
	}
	if err = observer.Close(); err != nil {
		t.Fatal(err)
	}
	reopenedObserver, err := Open(observerConfig)
	if err != nil {
		t.Fatal("reopen other original node after member identity replacement", err)
	}
	t.Cleanup(func() { _ = reopenedObserver.Close() })
	resumedObserver, err := reopenedObserver.ResumeInstallation(ctx)
	if err != nil {
		t.Fatal("resume other node at same SDK configuration index", err)
	}
	nodes[observerIndex] = reopenedObserver
	retainedMember, present := resumedObserver.Root.Installed.Member(id)
	if !present || resumedObserver.Root.Installed.Index != observerRecord.Root.Installed.Index || retainedMember.Key != priorMember.Key || resumedObserver.Root.Self != observerRecord.Root.Self {
		t.Fatal("same-configuration resume rewrote original member/self installation evidence")
	}
	wait("reopened other node admits only the replaced peer's current TLS key", func() bool {
		_, directory, readErr := reopenedObserver.members(ctx, false)
		_, oldAdmitted := reopenedObserver.Mesh.Peer(mydcp.Identity(original))
		newPeer, newAdmitted := reopenedObserver.Mesh.Peer(mydcp.Identity(restored.Identity.Public))
		return readErr == nil && directory.MemberKey(restored.Identity.Public) && !directory.MemberKey(original) && !oldAdmitted && newAdmitted && (newPeer.Member || newPeer.Replicate)
	})
	_, d, _ = current()
	entry, _ = d.Entry(id)
	submit("demote-replaced-installed-node", "demote-node", entry.Revision, control.NodeSelection{ID: id})
	wait("actual demotion after installed key replacement", func() bool {
		_, directory, ok := current()
		if !ok {
			return false
		}
		entry, found := directory.Entry(id)
		topology, err := directory.Topology()
		return found && err == nil && entry.Phase == membership.Ready && entry.Job.Pending == nil && !entry.Peer.Voter && topology.Configuration().Voters() == 2 && directory.MemberKey(restored.Identity.Public) && directory.WorkKey(restored.Identity.Public) && !directory.MemberKey(original)
	})
}
