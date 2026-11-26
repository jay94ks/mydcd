// SPDX-License-Identifier: Apache-2.0

package wallet

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

func TestEnvelopeHeaderRejectsCostAmplificationBeforeKDF(t *testing.T) {
	h := Header{Salt: [16]byte{1}, Nonce: [12]byte{2}, CipherLength: 20}
	header, err := h.Encode()
	if err != nil || len(header) != 50 {
		t.Fatal(err)
	}
	envelope := append(bytes.Clone(header), make([]byte, 20)...)
	decoded, err := DecodeHeader(envelope)
	if err != nil || decoded != h {
		t.Fatal(decoded, err)
	}
	for _, n := range []int{0, 7, 8, 17, 49, 50, 69} {
		if _, err := DecodeHeader(envelope[:n]); err == nil {
			t.Fatal("truncated envelope", n)
		}
	}
	for _, offset := range []int{0, 7, 8, 9, 12, 13, 16, 17, 46, 49} {
		mut := bytes.Clone(envelope)
		mut[offset] ^= 0xff
		if _, err := DecodeHeader(mut); err == nil {
			t.Fatal("accepted corrupt header/cost", offset)
		}
	}
	for _, mut := range [][]byte{append(bytes.Clone(envelope), 0), bytes.Repeat([]byte{0}, MaxFileBytes+1)} {
		if _, err := DecodeHeader(mut); err == nil {
			t.Fatal("bad file length")
		}
	}
	// All four size bytes can be attacker-controlled; reject before conversion or
	// allocation, rather than interpreting a huge ciphertext as a valid envelope.
	mut := bytes.Clone(envelope)
	binary.BigEndian.PutUint32(mut[46:], ^uint32(0))
	if _, err := DecodeHeader(mut); err == nil {
		t.Fatal("integer length overflow")
	}
}
func TestPayloadCanonicalKeysAndLosslessAliases(t *testing.T) {
	entries := []Entry{{Name: "operator", Seed: [32]byte{2}}, {Name: "default", Seed: [32]byte{1}}, {Name: "same-key", Seed: [32]byte{2}}}
	original := append([]Entry(nil), entries...)
	defer Clear(entries)
	defer Clear(original)
	encoded, err := EncodePayload(entries)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	if !reflect.DeepEqual(entries, original) {
		t.Fatal("encoder mutated caller keys")
	}
	decoded, err := DecodePayload(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer Clear(decoded)
	if len(decoded) != 3 || decoded[0].Name != "default" || decoded[0].Seed != entries[1].Seed || decoded[1].Public() != decoded[2].Public() {
		t.Fatal("keys/names changed")
	}
	encoded2, err := EncodePayload(decoded)
	if err != nil || !bytes.Equal(encoded, encoded2) {
		t.Fatal("not canonical", err)
	}
	clear(encoded2)
	if _, err := json.Marshal(entries[0]); err == nil || fmt.Sprintf("%+v", entries[0]) != "[redacted wallet entry]" {
		t.Fatal("private key formatted")
	}
	empty, err := EncodePayload(nil)
	if err != nil || !bytes.Equal(empty, make([]byte, 4)) {
		t.Fatal(err)
	}
	if got, err := DecodePayload(empty); err != nil || len(got) != 0 {
		t.Fatal(err)
	}
}
func TestPayloadMalformedInputReturnsNoPartialKeys(t *testing.T) {
	good, err := EncodePayload([]Entry{{Name: "a", Seed: [32]byte{1}}, {Name: "b", Seed: [32]byte{2}}})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(good)
	for n := 0; n < len(good); n++ {
		if entries, err := DecodePayload(good[:n]); err == nil || entries != nil {
			t.Fatal("truncated payload exposed keys", n)
		}
	}
	mutations := []func([]byte){
		func(b []byte) { binary.BigEndian.PutUint32(b, MaxEntries+1) },
		func(b []byte) { binary.BigEndian.PutUint16(b[4:], 129) },
		func(b []byte) { b[6] = '/' },
		func(b []byte) { b[7] = 2 },
		func(b []byte) { b[42] = 'a' }, // second name duplicates first
	}
	for i, mut := range mutations {
		b := bytes.Clone(good)
		mut(b)
		entries, err := DecodePayload(b)
		clear(b)
		if err == nil || entries != nil {
			t.Fatal("invalid payload exposed keys", i)
		}
	}
	if entries, err := DecodePayload(append(bytes.Clone(good), 0)); err == nil || entries != nil {
		t.Fatal("trailing bytes")
	}
	if _, err := EncodePayload([]Entry{{Name: "a"}, {Name: "a"}}); err == nil {
		t.Fatal("duplicate name")
	}
	if _, err := EncodePayload([]Entry{{Name: "../key"}}); err == nil {
		t.Fatal("name escape")
	}
}
