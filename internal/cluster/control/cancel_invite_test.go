// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/membership"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
)

func TestCancelNodeInviteLetsTheNameBeAddedAgain(t *testing.T) {
	f := newNodeStorageFixture(t)
	peer := func(seed byte) config.Peer {
		k := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
		return config.Peer{ID: "edge-9", Key: hex.EncodeToString(k.Public().(ed25519.PublicKey)), Endpoint: "198.51.100.9:7443"}
	}
	f.apply("admin", "invite-node", 0, NodeInvitation{Peer: peer(41), JoinID: "join-edge-9"}, state.Applied)
	d, _ := f.p.Members(f.s)
	e, _ := d.Entry("edge-9")

	// Adding the name again is refused while the invitation stands.
	f.apply("admin", "invite-node", 0, NodeInvitation{Peer: peer(42), JoinID: "join-edge-9b"}, state.ConditionFailed)
	f.apply("manager", "cancel-node-invite", e.Revision, NodeSelection{ID: "edge-9"}, state.Forbidden)
	f.apply("admin", "cancel-node-invite", e.Revision+1, NodeSelection{ID: "edge-9"}, state.ConditionFailed)
	f.apply("admin", "cancel-node-invite", 1, NodeSelection{ID: "node-a"}, state.ConditionFailed) // a member
	f.apply("admin", "cancel-node-invite", e.Revision, NodeSelection{ID: "edge-9"}, state.Applied)
	if d, _ = f.p.Members(f.s); func() bool { _, ok := d.Entry("edge-9"); return ok }() {
		t.Fatal("invitation kept")
	}
	// The name is free again, with another key.
	f.apply("admin", "invite-node", 0, NodeInvitation{Peer: peer(42), JoinID: "join-edge-9b"}, state.Applied)
	d, _ = f.p.Members(f.s)
	if again, _ := d.Entry("edge-9"); again.Peer.Key != peer(42).Key || again.Address != e.Address {
		t.Fatalf("again = %+v", again)
	}
}

func (f *nodeStorageFixture) memberReportAs(r MemberReport, want state.Code) {
	f.t.Helper()
	f.next++
	r.Schema, r.Cluster, r.Reporter, r.Epoch = 1, f.p.Cluster, [32]byte(f.node.Public().(ed25519.PublicKey)), f.s.ModuleEpoch()
	r.RequestID, r.RootRevision = fmt.Sprintf("report-%d", f.next), f.s.Object(MembersKey).Revision
	r.Signature = ed25519.Sign(f.node, MemberReportBytes(r))
	cmd, err := r.Command()
	if err != nil {
		f.t.Fatal(err)
	}
	n, result, err := state.ApplyAdmitted(f.s, f.s.Index()+1, cmd, f.p.Validate, f.p.Reduce, f.p.AdmitModule)
	if err != nil || result.Code != want {
		f.t.Fatal(r.Action, result.Code, want, err)
	}
	f.s = n
}

func TestStuckJoinsCanBeGivenUpAndTheNameReused(t *testing.T) {
	f := newNodeStorageFixture(t)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{43}, 32))
	peer := config.Peer{ID: "edge-9", Key: hex.EncodeToString(key.Public().(ed25519.PublicKey)), Endpoint: "198.51.100.9:7443"}
	f.apply("admin", "invite-node", 0, NodeInvitation{Peer: peer, JoinID: "join-edge-9"}, state.Applied)
	entry := func() membership.Entry {
		d, _ := f.p.Members(f.s)
		e, _ := d.Entry("edge-9")
		return e
	}
	// The server ran join; the add's result is unknown.
	e := entry()
	f.memberReportAs(MemberReport{Action: "dispatch", Node: "edge-9", Expected: e.Revision, JobID: e.Job.Pending.ID, ConfigurationIndex: 5}, state.Applied)
	e = entry()
	f.memberReportAs(MemberReport{Action: "unknown", Node: "edge-9", Expected: e.Revision, JobID: e.Job.Pending.ID}, state.Applied)
	e = entry()
	f.apply("admin", "cancel-node-invite", e.Revision, NodeSelection{ID: "edge-9"}, state.ConditionFailed) // not settled
	// The leader saw the committed configuration without it: never added.
	f.memberReportAs(MemberReport{Action: "absent", Node: "edge-9", Expected: e.Revision, JobID: e.Job.Pending.ID, ConfigurationIndex: 4}, state.ConditionFailed)
	f.memberReportAs(MemberReport{Action: "absent", Node: "edge-9", Expected: e.Revision, JobID: e.Job.Pending.ID, ConfigurationIndex: 5}, state.Applied)
	e = entry()
	f.apply("admin", "cancel-node-invite", e.Revision, NodeSelection{ID: "edge-9"}, state.Applied)
	f.apply("admin", "invite-node", 0, NodeInvitation{Peer: peer, JoinID: "join-edge-9b"}, state.Applied)

	// Now it is added to Raft (a learner) but never confirms its install.
	e = entry()
	f.memberReportAs(MemberReport{Action: "dispatch", Node: "edge-9", Expected: e.Revision, JobID: e.Job.Pending.ID, ConfigurationIndex: 6}, state.Applied)
	e = entry()
	f.memberReportAs(MemberReport{Action: "observe", Node: "edge-9", Expected: e.Revision, JobID: e.Job.Pending.ID, ConfigurationIndex: 7, Peer: peer}, state.Applied)
	e = entry()
	if e.Phase != membership.Learner {
		t.Fatal("not a learner", e.Phase)
	}
	f.apply("admin", "cancel-node-invite", e.Revision, NodeSelection{ID: "edge-9"}, state.ConditionFailed)
	f.memberReportAs(MemberReport{Action: "join-aborted", Node: "edge-9", Expected: e.Revision, ConfigurationIndex: 8}, state.ConditionFailed) // not aborting
	f.apply("manager", "abort-node-join", e.Revision, NodeSelection{ID: "edge-9"}, state.Forbidden)
	f.apply("admin", "abort-node-join", e.Revision, NodeSelection{ID: "edge-9"}, state.Applied)
	e = entry()
	if e.Abort == nil {
		t.Fatal("abort not recorded")
	}
	f.memberReportAs(MemberReport{Action: "join-aborted", Node: "edge-9", Expected: e.Revision, ConfigurationIndex: 7}, state.ConditionFailed) // not after it
	f.memberReportAs(MemberReport{Action: "join-aborted", Node: "edge-9", Expected: e.Revision, ConfigurationIndex: 8}, state.Applied)
	if d, _ := f.p.Members(f.s); func() bool { _, ok := d.Entry("edge-9"); return ok }() {
		t.Fatal("learner kept")
	}
	f.apply("admin", "invite-node", 0, NodeInvitation{Peer: peer, JoinID: "join-edge-9c"}, state.Applied)
}
