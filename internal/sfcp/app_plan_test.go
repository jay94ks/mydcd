// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestAppPlanChunkBoundedPurposeAndCurrentAdmission(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{61}, 32))
	var public Identity
	copy(public[:], key.Public().(ed25519.PublicKey))
	cluster, challenge := [32]byte{62}, [32]byte{63}
	gate, _ := NewGate(cluster, challenge)
	b := Binding{Key: public, TLSKey: public, Cluster: cluster, Challenge: challenge, Signature: ed25519.Sign(key, ProofBytes(public, cluster, challenge))}
	if err := gate.Authenticate(b, true); err != nil {
		t.Fatal(err)
	}
	f := Frame{Purpose: User, Kind: 4, Request: 5, Fields: []Field{{Tag: 1, Required: true, Value: make([]byte, 8)}, {Tag: 2, Required: true, Value: make([]byte, 24<<10)}, {Tag: 3, Required: true, Value: make([]byte, 32)}}}
	if _, err := Encode(f); err != nil {
		t.Fatal(err)
	}
	for _, policy := range []Policy{{Key: public, UserAuth: true}, {Key: public, Member: true}} {
		if gate.Admit(f, policy, false, false) != nil {
			t.Fatal("current user/member chunk denied")
		}
		if gate.AdmitOn(Management, f, policy, false, false) == nil || gate.Admit(f, policy, true, false) == nil || gate.Admit(f, policy, false, true) == nil {
			t.Fatal("purpose/early data/datagram bypass")
		}
	}
	for _, policy := range []Policy{{Key: public}, {Key: public, Respond: true}, {Key: public, Replicate: true}, {Key: public, Manage: true}} {
		if gate.Admit(f, policy, false, false) == nil {
			t.Fatal("chunk grants user/member right", policy)
		}
	}
	f.Fields[1].Value = make([]byte, (24<<10)+9)
	if _, err := Encode(f); err == nil {
		t.Fatal("chunk frame budget widened")
	}
}
