// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"crypto/ed25519"
	"testing"
)

func recoveryFixture(t *testing.T) (Topology, Recovery, Configuration, ed25519.PrivateKey) {
	t.Helper()
	cluster := [32]byte{7}
	var members []Member
	var self ed25519.PrivateKey
	for i, id := range []string{"node-a", "node-b", "node-c"} {
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			self = priv
		}
		members = append(members, Member{ID: id, Key: [32]byte(pub), Voter: true})
	}
	top, err := New(cluster, Configuration{Index: 5, Members: members})
	if err != nil {
		t.Fatal(err)
	}
	plan := Recovery{Schema: 1, Cluster: cluster, RequestID: "recover-1", Node: "node-a", Key: members[0].Key, Voters: []string{"node-a"}, PreviousIndex: 5, LastIndex: 9, Term: 3, CreatedAt: 1}
	plan.Signature = ed25519.Sign(self, RecoveryBytes(plan))
	return top, plan, Configuration{Index: 10, Members: members[:1]}, self
}

// The signed plan retires every member it dropped, survives encoding, and
// a plan that does not match the change is refused.
func TestRecoverRetiresDroppedMembers(t *testing.T) {
	top, plan, c, self := recoveryFixture(t)
	next, err := top.Recover(plan, c)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"node-b", "node-c"} {
		n, _ := next.Node(id)
		if n.Phase != Retired || n.Recovery == nil || n.Recovery.RequestID != "recover-1" {
			t.Fatal("not retired", id, n)
		}
	}
	raw, err := next.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Decode(raw); err != nil {
		t.Fatal("decode", err)
	}

	bad := plan
	bad.Voters = []string{"node-a", "node-b"}
	bad.Signature = ed25519.Sign(self, RecoveryBytes(bad))
	if _, err = top.Recover(bad, c); err == nil {
		t.Fatal("voters differ from the change")
	}
	forged := plan
	forged.RequestID = "other"
	if _, err = top.Recover(forged, c); err == nil {
		t.Fatal("unsigned change accepted")
	}
	wrong := c
	wrong.Index = 9
	if _, err = top.Recover(plan, wrong); err == nil {
		t.Fatal("index other than LastIndex+1 accepted")
	}
	if _, err = next.Recover(plan, c); err == nil {
		t.Fatal("recovery applied twice")
	}
}
