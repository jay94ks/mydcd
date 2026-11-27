// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestJoiningReplicationNeverGrantsInstalledMemberRights(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{51}, 32))
	var public Identity
	copy(public[:], key.Public().(ed25519.PublicKey))
	cluster, challenge := [32]byte{71}, [32]byte{72}
	g, _ := NewGate(cluster, challenge)
	if err := g.Authenticate(Binding{Key: public, TLSKey: public, Cluster: cluster, Challenge: challenge, Signature: ed25519.Sign(key, ProofBytes(public, cluster, challenge))}, true); err != nil {
		t.Fatal(err)
	}
	provisional := Policy{Key: public, Replicate: true, Snapshot: true}
	for _, p := range []Purpose{Raft, Snapshot} {
		if err := g.Admit(Frame{Purpose: p, Kind: 1}, provisional, false, false); err != nil {
			t.Fatal("approved replication denied", p, err)
		}
	}
	for _, test := range []struct {
		p Purpose
		k uint8
	}{{Management, 1}, {Management, 3}, {Management, 4}, {User, 3}, {Observation, 1}, {Packet, 1}, {PathControl, 1}} {
		if g.Admit(Frame{Purpose: test.p, Kind: test.k}, provisional, false, test.p == Packet) == nil {
			t.Fatal("joining key obtained installed privilege", test)
		}
	}
	provisional.UserAuth = true
	if g.Admit(Frame{Purpose: User, Kind: 3}, provisional, false, false) == nil {
		t.Fatal("public user-auth enabled member relay")
	}
	provisional.Replicate = false
	for _, p := range []Purpose{Raft, Snapshot} {
		if g.Admit(Frame{Purpose: p, Kind: 1}, provisional, false, false) == nil {
			t.Fatal("revoked replication remained enabled", p)
		}
	}
}
