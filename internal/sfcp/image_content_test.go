// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestImageContentFramesKeepBodyBoundAndSeparateUserFromOwnerRelay(t *testing.T) {
	if ImageContent != 16 {
		t.Fatal("existing purpose numbers changed")
	}
	frame := Frame{Purpose: ImageContent, Kind: 4, Request: 42, Fields: []Field{{Tag: 1, Required: true, Value: make([]byte, 8)}, {Tag: 2, Required: true, Value: make([]byte, 24<<10)}, {Tag: 3, Required: true, Value: make([]byte, 32)}}}
	raw, err := Encode(frame)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadFrame(bytes.NewReader(raw), 32<<10)
	if err != nil || decoded.Purpose != ImageContent || decoded.Request != 42 {
		t.Fatal(decoded, err)
	}
	frame.Fields[1].Value = make([]byte, 32<<10)
	if _, err = Encode(frame); err == nil {
		t.Fatal("unbounded content frame accepted")
	}
	private := ed25519.NewKeyFromSeed(make([]byte, 32))
	key := Identity(private.Public().(ed25519.PublicKey))
	cluster, challenge := [32]byte{1}, [32]byte{2}
	gate, err := NewGate(cluster, challenge)
	if err != nil {
		t.Fatal(err)
	}
	if err = gate.Authenticate(Binding{Key: key, TLSKey: key, Cluster: cluster, Challenge: challenge, Signature: ed25519.Sign(private, ProofBytes(key, cluster, challenge))}, true); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		kind    uint8
		policy  Policy
		allowed bool
	}{
		{1, Policy{Key: key, UserAuth: true}, true},
		{3, Policy{Key: key, UserAuth: true}, false},
		{4, Policy{Key: key, UserAuth: true}, false},
		{3, Policy{Key: key, Member: true}, true},
		{KindImageSourceRead, Policy{Key: key, Member: true}, true},
		{KindImageSourceRead, Policy{Key: key, UserAuth: true}, false},
		{KindImageSourceRead, Policy{Key: key, Respond: true}, false},
		{KindImageEngineRead, Policy{Key: key, Member: true}, true},
		{KindImageEngineRead, Policy{Key: key, UserAuth: true}, false},
		{5, Policy{Key: key, Member: true}, false},
		{4, Policy{Key: key, Respond: true}, true},
	} {
		if allowed := gate.Admit(Frame{Purpose: ImageContent, Kind: tc.kind}, tc.policy, false, false) == nil; allowed != tc.allowed {
			t.Fatal(tc, allowed)
		}
	}
}
