// SPDX-License-Identifier: Apache-2.0

package mydcp

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

func TestSecretInputPurposeIsBoundedUserOnlyAndCannotRelay(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	identity := Identity(pub)
	cluster, challenge := [32]byte{41}, [32]byte{42}
	gate, err := NewGate(cluster, challenge)
	if err != nil {
		t.Fatal(err)
	}
	proof := Binding{Key: identity, TLSKey: identity, Cluster: cluster, Challenge: challenge}
	proof.Signature = ed25519.Sign(key, ProofBytes(identity, cluster, challenge))
	if err = gate.Authenticate(proof, true); err != nil {
		t.Fatal(err)
	}
	body := []byte("private")
	digest := sha256.Sum256(body)
	frame := Frame{Purpose: SecretInput, Kind: 1, Request: 1, Fields: []Field{{Tag: 1, Required: true, Value: body}, {Tag: 2, Required: true, Value: digest[:]}}}
	user := Policy{Key: identity, UserAuth: true}
	if gate.Admit(frame, user, false, false) != nil {
		t.Fatal("dedicated user input denied")
	}
	for _, policy := range []Policy{{Key: identity, Manage: true}, {Key: identity, Read: true}, {Key: identity, Member: true}, {Key: identity, Replicate: true}} {
		if gate.Admit(frame, policy, false, false) == nil {
			t.Fatal("node/legacy permission admitted private input")
		}
	}
	if gate.AdmitOn(User, frame, user, false, false) == nil || gate.Admit(frame, user, true, false) == nil || gate.Admit(frame, user, false, true) == nil {
		t.Fatal("purpose/early/datagram bypass")
	}
	frame.Kind = 3
	if _, err = Encode(frame); err == nil {
		t.Fatal("private relay admitted")
	}
	frame.Kind = 1
	frame.Fields[0].Value = make([]byte, 64<<10)
	if _, err = Encode(frame); err == nil {
		t.Fatal("private budget exceeded")
	}
}
