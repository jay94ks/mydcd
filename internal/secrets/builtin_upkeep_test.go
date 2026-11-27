// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"crypto/rand"
	"path/filepath"
	"testing"
)

func publishBuiltin(t *testing.T, f fixture, id string) fixture {
	t.Helper()
	request := valueRequest(f, id, "token")
	f = prepare(t, f, request)
	f = dispatch(t, f, request.ID)
	f = observe(t, f, builtinObservation(f, request.ID, f.na, f.na))
	o, _ := f.t.Object("token")
	n, err := f.t.PublishStored(f.c, "alice", request.ID, request.Epoch, o.Revision, f.t.Revision())
	f.t = mustTree(t, n, err)
	return f
}

func TestBuiltinHoldingsArePrunedAndRefilled(t *testing.T) {
	f := writable(t)
	n, err := f.t.Create(f.c, "alice", f.t.Revision(), Object{ID: "token", Parent: "common", Kind: Secret, Reference: Reference{Profile: BuiltinProfile, Keys: []string{"TOKEN"}}})
	f.t = mustTree(t, n, err)
	f = publishBuiltin(t, f, "first")
	f = publishBuiltin(t, f, "second")
	if len(f.t.BuiltinHoldings()) != 2 {
		t.Fatal("both published revisions recorded before pruning")
	}
	a, _ := NewApprovals(f.t.cluster)
	pruned := f.t.PruneBuiltin(a)
	hs := pruned.BuiltinHoldings()
	if len(hs) != 1 || hs[0].Revision != 2 || pruned.Revision() != f.t.Revision() {
		t.Fatal("superseded revision kept, or pruning moved the tree revision", hs)
	}
	// A retained usage pins the old revision.
	a.usages["pin"] = Usage{Grant: Grant{Realm: f.t.tenant}, Plan: UsePlan{Leaves: []Leaf{{Secret: "token", Reference: Reference{Profile: BuiltinProfile, Object: "token", Revision: 1, Keys: []string{"TOKEN"}}}}}}
	if len(f.t.PruneBuiltin(a).BuiltinHoldings()) != 2 {
		t.Fatal("pinned revision pruned")
	}

	h := hs[0]
	voter, gone := public(f.nb), public(f.na)
	current := func(k [32]byte) bool { return k == voter }
	added, err := pruned.AddBuiltinHolder(h.Kind, h.Object, h.Revision, h.Digest, voter, current)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := added.BuiltinHolding(h.Kind, h.Object, h.Revision); len(got.Holders) != 1 || got.Holders[0] != voter {
		t.Fatal("holder that left was kept, or the new holder missing", got.Holders, gone)
	}
	if _, err = pruned.AddBuiltinHolder(h.Kind, h.Object, h.Revision, [32]byte{9}, voter, current); err == nil {
		t.Fatal("holder for another digest")
	}
	if _, err = pruned.AddBuiltinHolder(h.Kind, h.Object, h.Revision, h.Digest, gone, current); err == nil {
		t.Fatal("non-voter holder")
	}
}

func TestBuiltinStoreRetainDeletesUnreadValues(t *testing.T) {
	f, w := builtinWrite(t)
	master := make([]byte, 32)
	_, _ = rand.Read(master)
	s, err := OpenBuiltinStore(filepath.Join(t.TempDir(), "b.db"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	v, _ := SealBuiltinValue(master, f.t.cluster, f.t.tenant, w, public(f.na), map[string][]byte{"TOKEN": []byte("x")})
	other := w
	other.Request.ID = "other"
	u, _ := SealBuiltinValue(master, f.t.cluster, f.t.tenant, other, public(f.na), map[string][]byte{"TOKEN": []byte("y")})
	if s.Put(BuiltinWriteKey(f.t.cluster, f.t.tenant, w), v) != nil {
		t.Fatal("put")
	}
	// A value stored after the mark (replicated while the keep set was being
	// read from older state) survives that Retain, and only that one.
	mark := s.Mark()
	if s.Put(BuiltinWriteKey(f.t.cluster, f.t.tenant, other), u) != nil {
		t.Fatal("put")
	}
	if n, err := s.Retain(map[[32]byte]bool{v.Digest(): true}, mark); err != nil || n != 0 || !s.Has(u.Digest()) {
		t.Fatal("deleted a value stored after the mark", n, err)
	}
	if n, err := s.Retain(map[[32]byte]bool{v.Digest(): true}, s.Mark()); err != nil || n != 1 || !s.Has(v.Digest()) || s.Has(u.Digest()) {
		t.Fatal("retain", n, err)
	}
	if _, err = s.ForWrite(BuiltinWriteKey(f.t.cluster, f.t.tenant, other)); err == nil {
		t.Fatal("index of a deleted value kept")
	}
	if n, err := s.Retain(nil, s.Mark()); err != nil || n != 1 || s.Has(v.Digest()) {
		t.Fatal("wipe", n, err)
	}
}
