// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

func TestCertificateMaterialRequiresCurrentMemberAndDedicatedBoundedPurpose(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	id := Identity(pub)
	cluster, challenge := [32]byte{51}, [32]byte{52}
	g, err := NewGate(cluster, challenge)
	if err != nil {
		t.Fatal(err)
	}
	proof := Binding{Key: id, TLSKey: id, Cluster: cluster, Challenge: challenge, Signature: ed25519.Sign(key, ProofBytes(id, cluster, challenge))}
	if err = g.Authenticate(proof, true); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"Schema":1}`)
	digest := sha256.Sum256(body)
	for _, kind := range []uint8{1, 2} {
		f := Frame{Purpose: CertificateMaterial, Kind: kind, Request: 1, Fields: []Field{{Tag: 1, Required: true, Value: body}, {Tag: 2, Required: true, Value: digest[:]}}}
		if g.Admit(f, Policy{Key: id, Member: true}, false, false) != nil {
			t.Fatal("current member denied")
		}
		for _, p := range []Policy{{Key: id, UserAuth: true}, {Key: id, Read: true, Respond: true}, {Key: id, Manage: true}, {Key: id, Replicate: true}} {
			if g.Admit(f, p, false, false) == nil {
				t.Fatal("nonmember granted private read")
			}
		}
		if g.Admit(f, Policy{Key: id, Member: true}, true, false) == nil || g.Admit(f, Policy{Key: id, Member: true}, false, true) == nil || g.AdmitOn(Management, f, Policy{Key: id, Member: true}, false, false) == nil {
			t.Fatal("purpose/early/datagram bypass")
		}
		if _, err = Encode(f); err != nil {
			t.Fatal(err)
		}
		f.Kind = 3
		if _, err = Encode(f); err == nil {
			t.Fatal("private relay allowed")
		}
		f.Kind = kind
		f.Fields[0].Value = make([]byte, 64<<10)
		if _, err = Encode(f); err == nil {
			t.Fatal("private response bound bypass")
		}
	}
}

func TestVaultValueIsMemberOnlyAndBounded(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	id := Identity(pub)
	cluster, challenge := [32]byte{61}, [32]byte{62}
	g, err := NewGate(cluster, challenge)
	if err != nil {
		t.Fatal(err)
	}
	if err = g.Authenticate(Binding{Key: id, TLSKey: id, Cluster: cluster, Challenge: challenge, Signature: ed25519.Sign(key, ProofBytes(id, cluster, challenge))}, true); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, 150<<10)
	digest := sha256.Sum256(body)
	for _, kind := range []uint8{1, 2} {
		f := Frame{Purpose: VaultValue, Kind: kind, Request: 1, Fields: []Field{{Tag: 1, Required: true, Value: body}, {Tag: 2, Required: true, Value: digest[:]}}}
		if g.Admit(f, Policy{Key: id, Member: true}, false, false) != nil {
			t.Fatal("member denied")
		}
		for _, p := range []Policy{{Key: id, UserAuth: true}, {Key: id, Read: true, Respond: true}, {Key: id, Manage: true}, {Key: id, Replicate: true}} {
			if g.Admit(f, p, false, false) == nil {
				t.Fatal("nonmember admitted")
			}
		}
		if _, err = Encode(f); err != nil {
			t.Fatal("sealed value does not fit", err)
		}
		f.Fields[0].Value = make([]byte, 193<<10)
		if _, err = Encode(f); err == nil {
			t.Fatal("bound bypass")
		}
	}
}
