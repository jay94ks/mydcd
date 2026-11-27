// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/storage"
)

func builtinWrite(t *testing.T) (fixture, WriteRecord) {
	t.Helper()
	f := writable(t)
	n, err := f.t.Create(f.c, "alice", f.t.Revision(), Object{ID: "token", Parent: "common", Kind: Secret, Reference: Reference{Profile: BuiltinProfile, Object: "token", Keys: []string{"TOKEN"}}})
	f.t = mustTree(t, n, err)
	request := valueRequest(f, "write-token", "token")
	f = prepare(t, f, request)
	f = dispatch(t, f, request.ID)
	w, _ := f.t.Write(request.ID)
	return f, w
}

func TestBuiltinValueSealsBoundToItsWrite(t *testing.T) {
	f, w := builtinWrite(t)
	master := bytes.Repeat([]byte{9}, 32)
	sealer := public(f.na)
	if _, err := SealBuiltinValue(master, f.t.cluster, f.t.tenant, w, sealer, map[string][]byte{"OTHER": []byte("x")}); err == nil {
		t.Fatal("sealed keys the write does not name")
	}
	if _, err := SealBuiltinValue(master, f.t.cluster, f.t.tenant, w, sealer, map[string][]byte{"TOKEN": make([]byte, BuiltinMaxBytes+1)}); err == nil {
		t.Fatal("sealed past the size bound")
	}
	private := []byte("private-token")
	v, err := SealBuiltinValue(master, f.t.cluster, f.t.tenant, w, sealer, map[string][]byte{"TOKEN": private})
	if err != nil || !v.Binds(f.t.cluster, f.t.tenant, w) || v.Revision != 1 || bytes.Contains(v.Sealed, private) {
		t.Fatal("seal", err)
	}
	got, err := OpenBuiltinValue(master, v)
	if err != nil || !bytes.Equal(got["TOKEN"], private) {
		t.Fatal("open", err)
	}
	if _, err = OpenBuiltinValue(bytes.Repeat([]byte{8}, 32), v); err == nil {
		t.Fatal("opened with another master key")
	}
	moved := v
	moved.Object = "other"
	if _, err = OpenBuiltinValue(master, moved); err == nil || moved.Binds(f.t.cluster, f.t.tenant, w) {
		t.Fatal("value moved to another object")
	}
	other := w
	other.Request.ID = "another-write"
	if v.Binds(f.t.cluster, f.t.tenant, other) || v.Binds(f.t.cluster, "other-tenant", w) {
		t.Fatal("value bound to another write or realm")
	}
	// A holder's statement is the one the reducer checks.
	holder := ed25519.Sign(f.na, v.HolderBytes(sealer))
	p := WriteObservation{Cluster: f.t.cluster, Tenant: f.t.tenant, Request: w.Request, ProviderRevision: v.Revision, Digest: v.Digest()}
	if !ed25519.Verify(ed25519.PublicKey(sealer[:]), HolderBytes(p, sealer), holder) {
		t.Fatal("holder statement differs from the observation's")
	}
}

func TestBuiltinStoreHoldsOneValuePerWrite(t *testing.T) {
	f, w := builtinWrite(t)
	master := make([]byte, 32)
	_, _ = rand.Read(master)
	path := filepath.Join(t.TempDir(), "builtin.db")
	s, err := OpenBuiltinStore(path, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	key := BuiltinWriteKey(f.t.cluster, f.t.tenant, w)
	if _, err = s.ForWrite(key); !errors.Is(err, storage.ErrMissing) {
		t.Fatal("empty store", err)
	}
	private := []byte("private-token")
	v, _ := SealBuiltinValue(master, f.t.cluster, f.t.tenant, w, public(f.na), map[string][]byte{"TOKEN": private})
	if err = s.Put(key, v); err != nil {
		t.Fatal(err)
	}
	if err = s.Put(key, v); err != nil {
		t.Fatal("same value again", err)
	}
	second, _ := SealBuiltinValue(master, f.t.cluster, f.t.tenant, w, public(f.na), map[string][]byte{"TOKEN": private})
	if err = s.Put(key, second); err == nil {
		t.Fatal("a second value for one write")
	}
	if got, err := s.ForWrite(key); err != nil || got.Digest() != v.Digest() {
		t.Fatal("for write", err)
	}
	if got, err := s.Get(v.Digest()); err != nil || got.Digest() != v.Digest() {
		t.Fatal("by digest", err)
	}
	other := w
	other.Request.ID = "big"
	big, err := SealBuiltinValue(master, f.t.cluster, f.t.tenant, w, public(f.na), map[string][]byte{"TOKEN": make([]byte, BuiltinMaxBytes)})
	if err != nil {
		t.Fatal(err)
	}
	small, err := OpenBuiltinStore(filepath.Join(t.TempDir(), "small.db"), 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer small.Close()
	if err = small.Put(BuiltinWriteKey(f.t.cluster, f.t.tenant, other), big); err == nil {
		t.Fatal("stored past the store limit")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || bytes.Contains(raw, private) {
		t.Fatal("plain value on disk", err)
	}
}
