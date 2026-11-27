// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
)

func TestUserPurposeNeverGrantsNodeOrLegacyRights(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{31}, 32))
	var public Identity
	copy(public[:], key.Public().(ed25519.PublicKey))
	cluster, challenge := [32]byte{71}, [32]byte{72}
	g, _ := NewGate(cluster, challenge)
	binding := Binding{Key: public, TLSKey: public, Cluster: cluster, Challenge: challenge, Signature: ed25519.Sign(key, ProofBytes(public, cluster, challenge))}
	if err := g.Authenticate(binding, true); err != nil {
		t.Fatal(err)
	}
	policy := Policy{Key: public, UserAuth: true}
	body := []byte("{}")
	digest := sha256.Sum256(body)
	frame := Frame{Purpose: User, Kind: 1, Request: 2, Fields: []Field{{Tag: 1, Required: true, Value: body}, {Tag: 2, Required: true, Value: digest[:]}}}
	if err := g.Admit(frame, policy, false, false); err != nil {
		t.Fatal(err)
	}
	wire, err := Encode(frame)
	decoder, _ := NewDecoder(MaxBody)
	decoded, _, decodeErr := decoder.Feed(wire)
	if err != nil || decodeErr != nil || decoded == nil || decoded.Purpose != User {
		t.Fatal(err, decodeErr)
	}
	for _, test := range []struct {
		p Purpose
		k uint8
	}{{User, 3}, {Management, 1}, {Management, 3}, {Management, 4}, {Raft, 1}, {Snapshot, 1}, {Observation, 1}, {Packet, 1}, {PathControl, 1}} {
		if g.Admit(Frame{Purpose: test.p, Kind: test.k}, policy, false, test.p == Packet) == nil {
			t.Fatal("user purpose widened into node/legacy rights", test)
		}
	}
	member := policy
	member.UserAuth = false
	member.Member = true
	frame.Kind = 3
	if err := g.Admit(frame, member, false, false); err != nil {
		t.Fatal("approved member cannot relay", err)
	}
	wire, err = Encode(frame)
	decoder, _ = NewDecoder(MaxBody)
	decoded, _, decodeErr = decoder.Feed(wire)
	if err != nil || decodeErr != nil || decoded == nil || decoded.Kind != 3 {
		t.Fatal("relay codec", err, decodeErr)
	}
	frame.Kind = 1
	if g.Admit(frame, policy, true, false) == nil || g.Admit(frame, Policy{Key: public}, false, false) == nil {
		t.Fatal("early data or disabled User policy admitted")
	}
}
