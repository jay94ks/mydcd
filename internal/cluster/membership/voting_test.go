// SPDX-License-Identifier: Apache-2.0

package membership

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/reconcile"
)

func TestVotingDemotionKeepsInstalledIdentityAndOriginalUnknown(t *testing.T) {
	d, ak, bk := runtimeMembers(t)
	before, _ := d.Entry("b")
	plan, err := d.PlanNodeChange("b", false)
	if err != nil || len(plan.Blockers) != 0 || plan.VotersBefore != 2 || plan.VotersAfter != 1 || plan.QuorumAfter != 1 || plan.FaultToleranceAfter != 0 {
		t.Fatal(plan, err)
	}
	origin := json.RawMessage(`{"original":"demote-b"}`)
	n, err := d.ChangeVote("b", before.Revision, false, origin)
	d = checked(t, n, err)
	origin[2] = 'X'
	e, _ := d.Entry("b")
	if e.Peer != before.Peer || e.Ack.Key != before.Ack.Key || e.Phase != Demoting || !bytes.Equal(e.Voting.Origin, []byte(`{"original":"demote-b"}`)) {
		t.Fatal("prepared demotion changed installed identity")
	}
	d = dispatch(t, d, "b", ak, 14)
	e, _ = d.Entry("b")
	original := *e.Job.Pending
	n, err = d.Unknown("b", e.Revision, original.ID)
	d = checked(t, n, err)
	e, _ = d.Entry("b")
	if e.Job.Pending.Phase != reconcile.RecoveryRequired || *e.Job.Pending == original {
		t.Fatal("unknown outcome lost its original effect")
	}
	n, err = d.Dispatch("b", e.Revision, original.ID, 14, memberKey(ak))
	assertRejected(t, d, n, err)
	plan, err = d.PlanNodeChange("a", false)
	if err != nil || !containsBlocker(plan.Blockers, "NODE_OPERATION_PENDING") {
		t.Fatal("concurrent voting effect not reported", plan, err)
	}
	target := before.Peer
	target.Voter = false
	d = observe(t, d, "b", 15, target)
	topology, _ := d.Topology()
	c := topology.Configuration()
	c.Index = 15
	c.Members[1].Voter = false
	n, err = d.InstallConfiguration(c)
	d = checked(t, n, err)
	e, _ = d.Entry("b")
	if e.Peer.Key != before.Peer.Key || e.Phase != Ready || e.Peer.Voter || !reflect.DeepEqual(e.Ack, before.Ack) || !d.MemberKey(memberKey(bk)) || !d.WorkKey(memberKey(bk)) {
		t.Fatal("demotion removed native identity or installation evidence")
	}
	if len(d.SessionIssuers()) != 1 {
		t.Fatal("demoted nonvoter can issue current sessions")
	}
	n, err = d.ChangeVote("b", e.Revision, true, json.RawMessage(`{"original":"promote-b-again"}`))
	d = checked(t, n, err)
	d = dispatch(t, d, "b", ak, 15)
	target.Voter = true
	d = observe(t, d, "b", 16, target)
	topology, _ = d.Topology()
	c = topology.Configuration()
	c.Index = 16
	c.Members[1].Voter = true
	n, err = d.InstallConfiguration(c)
	d = checked(t, n, err)
	if len(d.SessionIssuers()) != 2 {
		t.Fatal("original installed nonvoter could not be promoted again")
	}
}
func containsBlocker(blockers []string, want string) bool {
	for _, code := range blockers {
		if code == want {
			return true
		}
	}
	return false
}

func TestSharedNodePlanLastVoterReservationsAndMissingConfiguration(t *testing.T) {
	d, _, ak, _ := fixture(t)
	plan, err := d.PlanNodeChange("a", true)
	if err != nil || !containsBlocker(plan.Blockers, "LAST_VOTER") || !containsBlocker(plan.Blockers, "CONFIGURATION_NOT_INSTALLED") {
		t.Fatal(plan, err)
	}
	n, err := d.InstallConfiguration(lifecycle.Configuration{Index: 10, Members: []lifecycle.Member{{ID: "a", Key: memberKey(ak), Voter: true}}})
	d = checked(t, n, err)
	e, _ := d.Entry("a")
	n, err = d.ChangeVote("a", e.Revision, false, json.RawMessage(`{}`))
	assertRejected(t, d, n, err)
	d, _, _ = runtimeMembers(t)
	d = beginRuntimeNode(t, d, "b", "remove-b", lifecycle.Remove)
	plan, err = d.PlanNodeChange("a", true)
	if err != nil || !containsBlocker(plan.Blockers, "QUORUM_LOSS") {
		t.Fatal("reserved removal consumed the last remaining voter", plan, err)
	}
	topology, _ := d.Topology()
	a, _ := topology.Node("a")
	n, err = d.BeginNode("a", "remove-a", lifecycle.Remove, a.Revision, topology.Epoch(), json.RawMessage(`{}`))
	assertRejected(t, d, n, err)
}

func TestInstalledThreeVoterRemovalPlanHasTwoVotersAndZeroFaultTolerance(t *testing.T) {
	d, ak, _ := runtimeMembers(t)
	c, ck := testPeer("c", 23, false)
	n, err := d.Invite(c, "join-c")
	d = checked(t, n, err)
	d = dispatch(t, d, "c", ak, 14)
	d = observe(t, d, "c", 15, c)
	d = installed(t, d, "c", ck, 15)
	topology, _ := d.Topology()
	configuration := topology.Configuration()
	configuration.Index = 15
	configuration.Members = append(configuration.Members, lifecycle.Member{ID: "c", Key: memberKey(ck)})
	n, err = d.InstallConfiguration(configuration)
	d = checked(t, n, err)
	e, _ := d.Entry("c")
	n, err = d.Promote("c", e.Revision)
	d = checked(t, n, err)
	d = dispatch(t, d, "c", ak, 15)
	c.Voter = true
	d = observe(t, d, "c", 16, c)
	configuration.Index = 16
	configuration.Members[2].Voter = true
	n, err = d.InstallConfiguration(configuration)
	d = checked(t, n, err)
	for _, remove := range []bool{false, true} {
		plan, err := d.PlanNodeChange("b", remove)
		if err != nil || len(plan.Blockers) != 0 || plan.VotersBefore != 3 || plan.VotersAfter != 2 || plan.QuorumAfter != 2 || plan.FaultToleranceAfter != 0 {
			t.Fatal(plan, err)
		}
	}
}
