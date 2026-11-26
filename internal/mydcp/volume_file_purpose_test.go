// SPDX-License-Identifier: Apache-2.0

package mydcp

import (
	"bytes"
	"testing"
)

func TestVolumeFilePurposePreservesCertificateAndImageSchemas(t *testing.T) {
	if ImageContent != 16 || CertificateMaterial != 17 || VolumeFile != 18 {
		t.Fatal("existing schema-one purposes were renumbered")
	}
	for _, p := range []Purpose{ImageContent, CertificateMaterial, VolumeFile} {
		frame := Frame{Purpose: p, Kind: 1, Request: 1, Fields: []Field{{1, true, []byte(`{"Schema":1}`)}, {2, true, bytes.Repeat([]byte{1}, 32)}}}
		wire, err := Encode(frame)
		if err != nil {
			t.Fatal(p, err)
		}
		decoder, _ := NewDecoder(MaxBody)
		got, n, err := decoder.Feed(wire)
		if err != nil || got == nil || n != len(wire) || got.Purpose != p {
			t.Fatal("distinct purpose did not round-trip", p, err)
		}
	}
	chunk := Frame{Purpose: VolumeFile, Kind: 4, Request: 1, Fields: []Field{{1, true, make([]byte, 8)}, {2, true, bytes.Repeat([]byte{1}, 24<<10)}, {3, true, make([]byte, 32)}}}
	if _, err := Encode(chunk); err != nil {
		t.Fatal("bounded file chunk rejected", err)
	}
	chunk.Purpose = CertificateMaterial
	if _, err := Encode(chunk); err == nil {
		t.Fatal("file chunks entered certificate material protocol")
	}
}

func TestVolumeFilePurposeRequiresCurrentRoleForEachDirection(t *testing.T) {
	key := Identity{1}
	gate := Gate{key: key, authenticated: true}
	for _, tc := range []struct {
		policy Policy
		kind   uint8
		allow  bool
	}{
		{Policy{Key: key, UserAuth: true}, 1, true},
		{Policy{Key: key, UserAuth: true}, 3, false},
		{Policy{Key: key, Member: true}, 3, true},
		{Policy{Key: key, Member: true}, 1, false},
		{Policy{Key: key, Respond: true}, 2, true},
		{Policy{Key: key, UserAuth: true}, 2, false},
		{Policy{Key: key, Read: true, Manage: true}, 4, false},
		{Policy{Key: key, Replicate: true}, 3, false},
		{Policy{Key: key, Member: true}, 4, true},
		{Policy{Key: key, UserAuth: true}, 4, true},
		{Policy{Key: key, Respond: true}, 4, true},
	} {
		err := gate.Admit(Frame{Purpose: VolumeFile, Kind: tc.kind}, tc.policy, false, false)
		if (err == nil) != tc.allow {
			t.Fatal("file direction acquired another role", tc.kind, tc.policy, err)
		}
	}
	if gate.Admit(Frame{Purpose: CertificateMaterial, Kind: 1}, Policy{Key: key, UserAuth: true}, false, false) == nil {
		t.Fatal("file user authentication acquired certificate material")
	}
	if gate.Admit(Frame{Purpose: VolumeFile, Kind: 1}, Policy{Key: key}, false, false) == nil {
		t.Fatal("revoked role reused previous file admission")
	}
}
