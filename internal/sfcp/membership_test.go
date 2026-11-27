// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
)

func TestMembershipPurposeBoundsAndCurrentReplicationAdmission(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{61}, 32))
	var pub Identity
	copy(pub[:], key.Public().(ed25519.PublicKey))
	cluster, ch := [32]byte{71}, [32]byte{72}
	gate, _ := NewGate(cluster, ch)
	if err := gate.Authenticate(Binding{Key: pub, TLSKey: pub, Cluster: cluster, Challenge: ch, Signature: ed25519.Sign(key, ProofBytes(pub, cluster, ch))}, true); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"Schema":1}`)
	digest := sha256.Sum256(body)
	for _, kind := range []uint8{1, 2} {
		f := Frame{Purpose: Membership, Kind: kind, Request: 1, Fields: []Field{{Tag: 1, Required: true, Value: body}, {Tag: 2, Required: true, Value: digest[:]}}}
		raw, err := Encode(f)
		if err != nil {
			t.Fatal(err)
		}
		d, _ := NewDecoder(MaxBody)
		round, _, err := d.Feed(raw)
		if err != nil || round == nil || round.Purpose != Membership || round.Kind != kind {
			t.Fatal("membership codec", err)
		}
		if err = gate.Admit(f, Policy{Key: pub, Replicate: true, Respond: true}, false, false); err != nil {
			t.Fatal("approved join purpose denied", err)
		}
		if gate.Admit(f, Policy{Key: pub, UserAuth: true, Respond: true}, false, false) == nil {
			t.Fatal("user key gained join purpose")
		}
		if gate.Admit(f, Policy{Key: pub, Replicate: true, Respond: true}, true, false) == nil {
			t.Fatal("early-data join accepted")
		}
	}
	big := bytes.Repeat([]byte{'x'}, 128<<10)
	f := Frame{Purpose: Membership, Kind: 1, Request: 1, Fields: []Field{{Tag: 1, Required: true, Value: big}, {Tag: 2, Required: true, Value: digest[:]}}}
	if _, err := Encode(f); err == nil {
		t.Fatal("membership body cap not enforced")
	}
}
