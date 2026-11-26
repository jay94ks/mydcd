// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
)

func fixedFixture(t *testing.T) *fixture {
	t.Helper()
	f := makeFixture(t)
	scope := f.s.Scope()
	scope.App = ""
	var err error
	f.s, err = NewFixed(f.c, "admin", scope, f.source, 3)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestFixedVolumeUsesOriginalSharedWriterAndReaderCore(t *testing.T) {
	f := fixedFixture(t)
	a := f.acquire("app-a-db", 1, false)
	b := f.acquire("app-b-reader", 1, false)
	if _, _, err := f.s.Acquire(f.c, "admin", f.s.Revision(), "writer", 1, true); err == nil {
		t.Fatal("writer bypassed existing readers")
	}
	if _, err := f.s.BeginUnregister(f.c, "admin", f.s.Revision()); err == nil {
		t.Fatal("unregistered live/unknown reader")
	}
	f.set(f.s.Release(f.gone(a)))
	f.set(f.s.Release(f.gone(b)))
	writer := f.acquire("app-a-db", 2, true)
	if _, _, err := f.s.Acquire(f.c, "admin", f.s.Revision(), "other", 2, true); err == nil {
		t.Fatal("two fixed writers admitted")
	}
	if _, _, err := f.s.Acquire(f.c, "admin", f.s.Revision(), "reader", 2, false); err == nil {
		t.Fatal("reader bypassed fixed writer")
	}
	original, _ := f.s.Encode()
	round, err := Decode(original)
	if err != nil || !round.Fixed() || round.Scope().App != "" || len(round.Consumers()) != 1 || round.Consumers()[0] != writer {
		t.Fatal("same snapshot lost original fixed consumer", err)
	}
	f.s = round
	f.set(f.s.Release(f.gone(writer)))
	if _, _, err = f.s.Acquire(f.c, "admin", f.s.Revision(), "app-a-db", 1, true); err == nil {
		t.Fatal("fixed consumer generation floor reset")
	}
}

func TestFixedVolumeMoveAndManagedDeleteRefusedBeforeAnyTransition(t *testing.T) {
	f := fixedFixture(t)
	before, _ := f.s.Encode()
	_, owner := f.s.Owner()
	if _, err := f.s.Prepare(f.c, "admin", f.s.Revision(), owner, "move", f.target, [32]byte{1}, 1<<20); !errors.Is(err, ErrNotMovable) {
		t.Fatal("fixed move not refused", err)
	}
	if _, err := f.s.BeginDelete(f.c, "admin", f.s.Revision()); !errors.Is(err, ErrUnregisterRequired) {
		t.Fatal("fixed source deletion allowed", err)
	}
	after, _ := f.s.Encode()
	if !bytes.Equal(before, after) {
		t.Fatal("fixed move/delete changed original")
	}
	if _, err := New(f.c, "admin", f.s.Scope(), f.source, 3); err == nil {
		t.Fatal("generic managed create accepted tenant fixed namespace")
	}
	managed := makeFixture(t)
	if _, err := NewFixed(managed.c, "admin", managed.s.Scope(), managed.source, 3); err == nil {
		t.Fatal("fake app scope accepted as tenant fixed")
	}
	if f.s.Scope().Key() == managed.s.Scope().Key() || FixedNativeKey(f.s.Scope()) == "" {
		t.Fatal("tenant/app/native namespaces collide")
	}
}

func TestFixedVolumeUnregisterRequiresOriginalDataRetainedProof(t *testing.T) {
	f := fixedFixture(t)
	f.set(f.s.BeginUnregister(f.c, "admin", f.s.Revision()))
	proof := NativeRemoved{Schema: 1, Scope: f.s.Scope(), Owner: f.source, Key: FixedNativeKey(f.s.Scope()), Generation: f.s.Scope().Generation, DeleteRevision: f.s.DeleteRevision(), DataRetained: true}
	for _, name := range []string{"data-deleted", "wrong-key", "wrong-generation", "wrong-owner"} {
		t.Run(name, func(t *testing.T) {
			bad := proof
			switch name {
			case "data-deleted":
				bad.DataRetained = false
			case "wrong-key":
				bad.Key = "volume/tenant/app/data/original"
			case "wrong-generation":
				bad.Generation++
			case "wrong-owner":
				bad.Owner = f.target
			}
			bad.Signature = ed25519.Sign(f.a, NativeRemovedBytes(bad))
			if _, err := f.s.CompleteDelete(bad); err == nil {
				t.Fatal("unsafe unregister proof accepted")
			}
		})
	}
	proof.Signature = ed25519.Sign(f.a, NativeRemovedBytes(proof))
	f.set(f.s.CompleteDelete(proof))
	if !f.s.Deleted() || !f.s.Fixed() {
		t.Fatal("registration did not close")
	}
	gone, ok := f.s.Removal()
	if !ok || !gone.DataRetained {
		t.Fatal("original data preservation receipt missing")
	}
	if _, _, err := f.s.Acquire(f.c, "admin", f.s.Revision(), "late", 2, true); err == nil {
		t.Fatal("unregistered directory started a writer")
	}
}

func TestFixedVolumeKeepsLegacySchemaOneOptionalFieldsAbsent(t *testing.T) {
	f := makeFixture(t)
	raw, err := f.s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(`"Fixed"`)) {
		t.Fatal("legacy snapshot bytes gained fixed mode")
	}
	scope := f.s.Scope()
	scope.App = ""
	f.s.d.Scope = scope
	if _, err = f.s.Encode(); err == nil {
		t.Fatal("empty-app legacy snapshot adopted as fixed")
	}
	f = fixedFixture(t)
	f.s.d.Fixed = false
	if _, err = f.s.Encode(); err == nil {
		t.Fatal("fixed namespace lost explicit fixed mode")
	}
}
