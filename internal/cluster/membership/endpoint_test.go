// SPDX-License-Identifier: Apache-2.0

package membership

import (
	"encoding/json"
	"testing"
)

// installAt publishes the current configuration at index (the moved
// server's vote and key do not change).
func installAt(t *testing.T, d Directory, index uint64) Directory {
	t.Helper()
	topology, _ := d.Topology()
	c := topology.Configuration()
	c.Index = index
	n, err := d.InstallConfiguration(c)
	return checked(t, n, err)
}

func TestEndpointChangeMovesJoinedVoterAndKeepsItsVote(t *testing.T) {
	d, ak, _ := runtimeMembers(t)
	before, _ := d.Entry("b")
	const moved = "192.0.2.20:8002"
	n, err := d.ChangeEndpoint("b", before.Revision, moved, json.RawMessage(`{"original":"move-b"}`))
	d = checked(t, n, err)
	e, _ := d.Entry("b")
	if e.Phase != Moving || e.Peer != before.Peer || e.Voting.Endpoint != moved || !FullMember(e) {
		t.Fatal("prepared move changed the recorded peer", e.Phase, e.Peer)
	}
	if !e.EndpointMatches(before.Peer.Endpoint) || !e.EndpointMatches(moved) || e.EndpointMatches("192.0.2.21:8002") {
		t.Fatal("endpoint match during the move")
	}
	// Nothing else changes membership while the move is open.
	n, err = d.ChangeVote("b", e.Revision, false, json.RawMessage(`{}`))
	assertRejected(t, d, n, err)
	d = dispatch(t, d, "b", ak, 14)
	target := before.Peer
	target.Endpoint = moved
	wrong := before.Peer
	e, _ = d.Entry("b")
	n, err = d.Observe("b", e.Revision, e.Job.Pending.ID, 15, wrong)
	assertRejected(t, d, n, err)
	d = observe(t, d, "b", 15, target)
	d = installAt(t, d, 15)
	e, _ = d.Entry("b")
	if e.Peer != target || e.Phase != Active || !e.Peer.Voter || e.EndpointMatches(before.Peer.Endpoint) || len(d.SessionIssuers()) != 2 {
		t.Fatal("settled move", e.Phase, e.Peer)
	}
	// The old endpoint is free again; a later vote change still works.
	n, err = d.ChangeVote("b", e.Revision, false, json.RawMessage(`{"original":"demote-b"}`))
	d = checked(t, n, err)
	d = dispatch(t, d, "b", ak, 15)
	target.Voter = false
	d = observe(t, d, "b", 16, target)
	e, _ = d.Entry("b")
	if e.Peer.Endpoint != moved || e.Phase != Ready {
		t.Fatal("demotion after the move", e.Phase, e.Peer)
	}
}

func TestEndpointChangeMovesGenesisServer(t *testing.T) {
	d, ak, _ := runtimeMembers(t)
	a, _ := d.Entry("a")
	const moved = "198.51.100.7:8001"
	n, err := d.ChangeEndpoint("a", a.Revision, moved, json.RawMessage(`{"original":"move-a"}`))
	d = checked(t, n, err)
	d = dispatch(t, d, "a", ak, 14)
	target := a.Peer
	target.Endpoint = moved
	d = observe(t, d, "a", 15, target)
	e, _ := d.Entry("a")
	if e.Peer.Endpoint != moved || e.Phase != Active || d.Genesis.Endpoint == moved {
		t.Fatal("genesis move", e.Peer, d.Genesis)
	}
}

func TestEndpointChangeRefusals(t *testing.T) {
	d, _, _ := runtimeMembers(t)
	b, _ := d.Entry("b")
	a, _ := d.Entry("a")
	for name, tc := range map[string]struct {
		revision uint64
		endpoint string
	}{
		"same endpoint":  {b.Revision, b.Peer.Endpoint},
		"another's":      {b.Revision, a.Peer.Endpoint},
		"not host:port":  {b.Revision, "192.0.2.1"},
		"stale revision": {b.Revision - 1, "192.0.2.1:8002"},
		"empty endpoint": {b.Revision, ""},
	} {
		n, err := d.ChangeEndpoint("b", tc.revision, tc.endpoint, json.RawMessage(`{}`))
		if err == nil {
			t.Fatal(name, "accepted")
		}
		assertRejected(t, d, n, err)
	}
	n, err := d.ChangeEndpoint("b", b.Revision, "192.0.2.1:8002", nil)
	assertRejected(t, d, n, err)
	// A pending move's new endpoint is taken.
	n, err = d.ChangeEndpoint("b", b.Revision, "192.0.2.1:8002", json.RawMessage(`{}`))
	d = checked(t, n, err)
	n, err = d.ChangeEndpoint("a", a.Revision, "192.0.2.1:8002", json.RawMessage(`{}`))
	assertRejected(t, d, n, err)
	// A server that never joined is changed with `node add --replace`.
	d, _, _, _ = fixture(t)
	c, _ := testPeer("c", 23, false)
	d = invite(t, d, c)
	e, _ := d.Entry("c")
	n, err = d.ChangeEndpoint("c", e.Revision, "192.0.2.3:8003", json.RawMessage(`{}`))
	assertRejected(t, d, n, err)
}
