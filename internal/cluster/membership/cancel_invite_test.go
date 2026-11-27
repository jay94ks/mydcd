// SPDX-License-Identifier: Apache-2.0

package membership

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
)

func TestCancelInviteFreesTheNameKeyAndAddress(t *testing.T) {
	d, b, ak, bk := fixture(t)
	d = invite(t, d, b)
	first, _ := d.Entry("b")
	if _, err := d.CancelInvite("b", first.Revision+1); err == nil {
		t.Fatal("stale revision accepted")
	}
	if _, err := d.CancelInvite("a", 1); !errors.Is(err, ErrNotInvited) {
		t.Fatal("a member was cancelled", err)
	}
	n, err := d.CancelInvite("b", first.Revision)
	n = checked(t, n, err)
	if _, ok := n.Entry("b"); ok || n.Revision != d.Revision+1 {
		t.Fatal("entry kept", n.Entries)
	}
	// The same name, key and endpoint register again and get the address back.
	again := invite(t, n, b)
	if e, _ := again.Entry("b"); e.Address != first.Address || e.Phase != Invited {
		t.Fatalf("again = %+v, first address %v", e, first.Address)
	}
	// Another key under the same name (the key-change case).
	other, _ := testPeer("b", 23, false)
	other.Endpoint = b.Endpoint
	if _, err := n.Invite(other, "join-b2", nil); err != nil {
		t.Fatal("new key refused after cancel", err)
	}

	// Once the join is dispatched to Raft, it is no longer an invitation
	// that can be cancelled.
	joining := dispatch(t, again, "b", ak, 10)
	e, _ := joining.Entry("b")
	if _, err := joining.CancelInvite("b", e.Revision); !errors.Is(err, ErrJoinStarted) {
		t.Fatal("dispatched join cancelled", err)
	}
	learner := observe(t, joining, "b", 12, b)
	e, _ = learner.Entry("b")
	if _, err := learner.CancelInvite("b", e.Revision); err == nil {
		t.Fatal("learner cancelled")
	}
	_ = bk
}

func TestAbsentJoinIsSettledAndCanBeCancelled(t *testing.T) {
	d, b, ak, _ := fixture(t)
	d = invite(t, d, b)
	d = dispatch(t, d, "b", ak, 10)
	e, _ := d.Entry("b")
	n, err := d.Unknown("b", e.Revision, e.Job.Pending.ID)
	d = checked(t, n, err)
	e, _ = d.Entry("b")
	if _, err := d.CancelInvite("b", e.Revision); !errors.Is(err, ErrJoinStarted) {
		t.Fatal("unknown join cancelled before it is settled", err)
	}
	if _, err := d.Absent("b", e.Revision, e.Job.Pending.ID, 9); err == nil {
		t.Fatal("absence before the dispatch index accepted")
	}
	if _, err := d.Absent("b", e.Revision, e.Job.Pending.ID+1, 10); err == nil {
		t.Fatal("another job accepted")
	}
	n, err = d.Absent("b", e.Revision, e.Job.Pending.ID, 10)
	d = checked(t, n, err)
	e, _ = d.Entry("b")
	if e.Phase != Invited || e.Job.Pending == nil || e.BaseIndex != 0 {
		t.Fatalf("not planned again: %+v", e)
	}
	// It can join again (a new dispatch) or be cancelled.
	retry := dispatch(t, d, "b", ak, 11)
	if r, _ := retry.Entry("b"); r.BaseIndex != 11 {
		t.Fatal("retry dispatch", r)
	}
	n, err = d.CancelInvite("b", e.Revision)
	n = checked(t, n, err)
	if _, ok := n.Entry("b"); ok {
		t.Fatal("not cancelled")
	}
	// A learner is not absent.
	learner := observe(t, retry, "b", 12, b)
	l, _ := learner.Entry("b")
	if _, err := learner.Absent("b", l.Revision, 1, 20); err == nil {
		t.Fatal("learner settled as absent")
	}
}

func TestAbortedLearnerLeavesRaftAndFreesTheName(t *testing.T) {
	d, b, ak, bk := fixture(t)
	a := lifecycle.Member{ID: "a", Key: memberKey(ak), Voter: true}
	n, err := d.InstallConfiguration(lifecycle.Configuration{Index: 10, Members: []lifecycle.Member{a}})
	d = checked(t, n, err)
	d = invite(t, d, b)
	d = dispatch(t, d, "b", ak, 10)
	d = observe(t, d, "b", 12, b)
	n, err = d.InstallConfiguration(lifecycle.Configuration{Index: 12, Members: []lifecycle.Member{a, {ID: "b", Key: memberKey(bk)}}})
	d = checked(t, n, err)
	e, _ := d.Entry("b")
	if e.Phase != Learner {
		t.Fatal("fixture is not a learner", e.Phase)
	}
	origin := json.RawMessage(`{"abort":true}`)
	if _, err := d.BeginAbortJoin("a", 1, origin); err == nil {
		t.Fatal("a member's join aborted")
	}
	n, err = d.BeginAbortJoin("b", e.Revision, origin)
	d = checked(t, n, err)
	e, _ = d.Entry("b")
	// The server can no longer finish the join.
	ack := Ack{Schema: 1, Cluster: d.Cluster, Node: "b", JoinID: e.JoinID, Key: memberKey(bk), ConfigurationIndex: 12, AppliedIndex: 13}
	if _, err := d.Installed(ack, e.Revision); err == nil {
		t.Fatal("ack accepted while aborting")
	}
	if _, err := d.FinishAbortJoin("b", e.Revision, 12); err == nil {
		t.Fatal("finished without a later configuration")
	}
	n, err = d.FinishAbortJoin("b", e.Revision, 13)
	d = checked(t, n, err)
	if _, ok := d.Entry("b"); ok {
		t.Fatal("entry kept")
	}
	topology, _ := d.Topology()
	if _, ok := topology.Node("b"); ok {
		t.Fatal("topology still has b")
	}
	// The real configuration without b installs, and the name joins anew.
	n, err = d.InstallConfiguration(lifecycle.Configuration{Index: 13, Members: []lifecycle.Member{a}})
	d = checked(t, n, err)
	d = invite(t, d, b)
	d = dispatch(t, d, "b", ak, 13)
	d = observe(t, d, "b", 14, b)
	if e, _ := d.Entry("b"); e.Phase != Learner {
		t.Fatal("rejoin", e.Phase)
	}
}
