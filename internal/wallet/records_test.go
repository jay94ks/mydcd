// SPDX-License-Identifier: Apache-2.0

package wallet

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"
)

func TestU0WalletCredentialPayloadAndInputOwnership(t *testing.T) {
	record := []byte(`{"Schema":1,"Username":"alice","Session":"private-issued-grant"}`)
	entries := []Entry{{Name: "proof", Seed: [32]byte{7}}, {Name: "login-record", Record: bytes.Clone(record)}}
	defer Clear(entries)
	raw, err := EncodePayload(entries)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	if !bytes.Equal(entries[1].Record, record) {
		t.Fatal("encoding cleared caller-owned credentials")
	}
	decoded, err := DecodePayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer Clear(decoded)
	if len(decoded) != 2 || !bytes.Equal(decoded[0].Record, record) || decoded[1].Seed != entries[0].Seed {
		t.Fatal("key/credential decoding")
	}
	clear(decoded[0].Record)
	if !bytes.Contains(raw, record) || !bytes.Equal(entries[1].Record, record) {
		t.Fatal("decoder returned shared private storage")
	}
	for _, invalid := range [][]Entry{
		{{Name: "empty", Record: []byte{}}},
		{{Name: "mixed", Seed: [32]byte{1}, Record: []byte("x")}},
		{{Name: "large", Record: make([]byte, MaxRecordBytes+1)}},
		{{Name: "duplicate"}, {Name: "duplicate", Record: []byte("x")}},
	} {
		if _, err := EncodePayload(invalid); err == nil {
			t.Fatal("invalid private payload accepted")
		}
		Clear(invalid)
	}
	// A hostile record size is checked before allocating/copying that length.
	bad := []byte{0, 0, 0, 1, 0, 1, 'a', 2, 0xff, 0xff, 0xff, 0xff}
	if entries, err := DecodePayload(bad); err == nil || entries != nil {
		t.Fatal("unbounded record accepted")
	}
	unknown := bytes.Clone(bad)
	unknown[7] = 3
	if entries, err := DecodePayload(unknown); err == nil || entries != nil {
		t.Fatal("unknown type accepted")
	}
	var seedOnly []byte
	seedOnly = binary.BigEndian.AppendUint32(seedOnly, 1)
	seedOnly = binary.BigEndian.AppendUint16(seedOnly, 1)
	seedOnly = append(seedOnly, 'a', 1)
	seedOnly = append(seedOnly, bytes.Repeat([]byte{7}, 32)...)
	keys, err := DecodePayload(seedOnly)
	if err != nil {
		t.Fatal("original type1 compatibility", err)
	}
	defer Clear(keys)
	encoded, err := EncodePayload(keys)
	if err != nil || !bytes.Equal(seedOnly, encoded) {
		t.Fatal("original key bytes changed", err)
	}
}

func TestU0WalletCredentialRecordCASAndEncryptedReadback(t *testing.T) {
	home := t.TempDir()
	password := []byte("private wallet passphrase")
	disk, err := OpenDisk(home, true)
	if err != nil {
		t.Fatal(err)
	}
	defer disk.Close()
	if err := disk.Init(password); err != nil {
		t.Fatal(err)
	}
	key := Entry{Name: "proof", Seed: [32]byte{9}}
	if _, err := disk.Put(key); err != nil {
		t.Fatal(err)
	}
	first, next := []byte("first-private-login-grant"), []byte("next-private-login-grant")
	if err := disk.PutRecord("login-alice", first, nil); err != nil {
		t.Fatal(err)
	}
	if err := disk.Save(password); err != nil {
		t.Fatal(err)
	}
	back, err := disk.ReadBackRecord("login-alice", password)
	if err != nil || !bytes.Equal(first, back) {
		t.Fatal(err)
	}
	clear(back)
	if err := disk.PutRecord("login-alice", next, nil); !errors.Is(err, ErrExists) {
		t.Fatal("record overwritten without CAS", err)
	}
	wrong := sha256.Sum256([]byte("wrong"))
	if err := disk.PutRecord("login-alice", next, &wrong); err == nil {
		t.Fatal("wrong CAS accepted")
	}
	expected := sha256.Sum256(first)
	if err := disk.PutRecord("login-alice", next, &expected); err != nil {
		t.Fatal(err)
	}
	if err := disk.PutRecord("proof", next, nil); !errors.Is(err, ErrExists) {
		t.Fatal("private key replaced by credential", err)
	}
	if _, err := disk.Get("login-alice"); err == nil {
		t.Fatal("credential accepted as signing key")
	}
	if _, err := disk.Put(Entry{Name: "login-alice"}); !errors.Is(err, ErrExists) {
		t.Fatal("credential replaced by signing key", err)
	}
	if err := disk.Save(password); err != nil {
		t.Fatal(err)
	}
	back, err = disk.ReadBackRecord("login-alice", password)
	defer clear(back)
	if err != nil || !bytes.Equal(next, back) {
		t.Fatal(err)
	}
	listed, err := disk.List()
	if err != nil || len(listed) != 1 || listed[0].Name != "proof" {
		t.Fatal("public key list exposed credential data", listed, err)
	}
}
