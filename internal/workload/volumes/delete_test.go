// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"crypto/ed25519"
	"testing"
)

func TestVolumeDeletionFencesNewUsersAndPreservesSignedTombstone(t *testing.T) {
	f := makeFixture(t)
	writer := f.acquire("writer", 1, true)
	if _, err := f.s.BeginDelete(f.c, "admin", f.s.Revision()); err == nil {
		t.Fatal("live writer deleted")
	}
	f.set(f.s.Release(f.gone(writer)))
	before := f.s
	if _, err := f.s.BeginDelete(f.c, "admin", f.s.Revision()-1); err == nil {
		t.Fatal("stale deletion CAS accepted")
	}
	if _, err := f.s.BeginDelete(f.c, "foreign", f.s.Revision()); err == nil {
		t.Fatal("foreign deletion accepted")
	}
	f.set(f.s.BeginDelete(f.c, "admin", f.s.Revision()))
	if before.Deleting() || !f.s.Deleting() || f.s.Deleted() {
		t.Fatal("published deletion mutated old state")
	}
	for _, writable := range []bool{true, false} {
		if _, _, err := f.s.Acquire(f.c, "admin", f.s.Revision(), "new-user", 2, writable); err == nil {
			t.Fatal("deleting volume acquired", writable)
		}
	}
	if _, err := f.s.Prepare(f.c, "admin", f.s.Revision(), 1, "move", f.target, [32]byte{1}, 4096); err == nil {
		t.Fatal("deleting volume migration accepted")
	}
	proof := NativeRemoved{Schema: 1, Scope: f.s.Scope(), Owner: f.source, Key: "volume/tenant/app/mysql/initial", Generation: 1, DeleteRevision: f.s.DeleteRevision()}
	proof.Signature = ed25519.Sign(f.a, NativeRemovedBytes(proof))
	for _, mutate := range []func(*NativeRemoved){
		func(p *NativeRemoved) { p.Scope.Generation++ },
		func(p *NativeRemoved) { p.Owner = f.target },
		func(p *NativeRemoved) { p.DeleteRevision++ },
		func(p *NativeRemoved) { p.Signature = nil },
	} {
		bad := proof
		mutate(&bad)
		if _, err := f.s.CompleteDelete(bad); err == nil {
			t.Fatal("wrong Gone completed deletion")
		}
	}
	f.set(f.s.CompleteDelete(proof))
	if !f.s.Deleted() || f.s.RetainsData() {
		t.Fatal("positive Gone did not finish deletion")
	}
	if _, _, err := f.s.Acquire(f.c, "admin", f.s.Revision(), "new-user", 2, true); err == nil {
		t.Fatal("deleted tombstone reactivated")
	}
}
