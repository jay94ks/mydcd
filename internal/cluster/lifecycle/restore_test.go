// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"crypto/ed25519"
	"testing"
)

// A signed restore retires every member, makes the new server the only
// voter, survives encoding, counts generations and refuses mismatches.
func TestRestoreClusterRetiresEveryMember(t *testing.T) {
	top, _, _, _ := recoveryFixture(t)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	r := ClusterRestore{Schema: 1, Cluster: top.Cluster(), RequestID: "restore-1", Node: "node-z", Key: [32]byte(pub), Endpoint: "127.0.0.1:7000", Backup: "backup-1", RaftIndex: 20, Term: 4, StateIndex: 12, Generation: 1, CreatedAt: 1}
	sign := func(r ClusterRestore) ClusterRestore {
		r.Signature = ed25519.Sign(priv, ClusterRestoreBytes(r))
		return r
	}
	r = sign(r)
	c := Configuration{Index: 21, Members: []Member{{ID: "node-z", Key: r.Key, Voter: true}}}
	next, err := top.RestoreCluster(r, c)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"node-a", "node-b", "node-c"} {
		if n, _ := next.Node(id); n.Phase != Retired || n.Restored != 1 {
			t.Fatal("not retired", id, n)
		}
	}
	if n, _ := next.Node("node-z"); n.Phase != Active || next.Generation() != 1 || !next.Configuration().Standalone("node-z") {
		t.Fatal("restored server", n)
	}
	raw, err := next.Encode()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(raw)
	if err != nil || decoded.Generation() != 1 {
		t.Fatal("decode", err)
	}

	again := r
	again.Generation = 2
	if _, err = top.RestoreCluster(sign(again), c); err == nil {
		t.Fatal("generation skipped")
	}
	taken := r
	taken.Node = "node-b"
	if _, err = top.RestoreCluster(sign(taken), Configuration{Index: 21, Members: []Member{{ID: "node-b", Key: r.Key, Voter: true}}}); err == nil {
		t.Fatal("existing name reused")
	}
	forged := r
	forged.RequestID = "other"
	if _, err = top.RestoreCluster(forged, c); err == nil {
		t.Fatal("unsigned restore accepted")
	}
	wrong := c
	wrong.Index = 20
	if _, err = top.RestoreCluster(r, wrong); err == nil {
		t.Fatal("index other than RaftIndex+1 accepted")
	}
	second := r
	second.RequestID, second.Node, second.RaftIndex, second.Generation = "restore-2", "node-y", 30, 2
	second = sign(second)
	if _, err = next.RestoreCluster(second, Configuration{Index: 31, Members: []Member{{ID: "node-y", Key: r.Key, Voter: true}}}); err != nil {
		t.Fatal("second generation", err)
	}
}
