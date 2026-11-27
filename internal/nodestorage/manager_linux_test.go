// SPDX-License-Identifier: Apache-2.0

package nodestorage

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/reconcile"
)

func TestRootJournalMissingOriginalNeverAdoptsPublishedFact(t *testing.T) {
	f := observedRoot(t)
	r, _ := f.book.Root("node-a", "hdd")
	path := filepath.Join(t.TempDir(), "roots.db")
	m, err := OpenRoots(path, f.book.Cluster(), "node-a", f.key)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Desired(r); err == nil {
		t.Fatal("lost local original checkpoint adopted published root")
	}
	if len(m.Keys()) != 0 {
		t.Fatal("failed adoption wrote a new root intent")
	}
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRootNeverDispatchedDrainPreservesSameDBFloorAndOwner(t *testing.T) {
	f := newRootFixture(t)
	var err error
	f.book, err = f.book.Add(f.users, "admin", 0, f.definition)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := f.book.Root("node-a", "hdd")
	f.book, err = f.book.Drain(f.users, "admin", "node-a", "hdd", r.Revision)
	if err != nil {
		t.Fatal(err)
	}
	r, _ = f.book.Root("node-a", "hdd")
	db := filepath.Join(t.TempDir(), "roots.db")
	m, err := OpenRoots(db, f.book.Cluster(), "node-a", f.key)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Desired(r); err != nil {
		t.Fatal(err)
	}
	key := RootNativeKey(r.Reference(f.book.Cluster()))
	if err = m.Step(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	closed, err := m.Closed(r)
	if err != nil || closed.Verify() != nil {
		t.Fatal("never-dispatched registration closure", err)
	}
	if _, err = m.Fact(context.Background(), r); err == nil {
		t.Fatal("tombstone fabricated native directory Ready")
	}
	before, err := m.View(key)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	if foreign, err := OpenRoots(db, f.book.Cluster(), "node-b", f.key); err == nil {
		_ = foreign.Close()
		t.Fatal("other node adopted original storage journal")
	}
	m, err = OpenRoots(db, f.book.Cluster(), "node-a", f.key)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	after, err := m.View(key)
	a, _ := json.Marshal(before)
	b, _ := json.Marshal(after)
	if err != nil || !bytes.Equal(a, b) {
		t.Fatal("same DB reopen changed original tombstone/floor", err)
	}
	if _, err = m.Closed(r); err != nil {
		t.Fatal(err)
	}
	if before.State.GenerationFloor != r.Generation || before.State.LastID != 0 || before.State.Applied.Present {
		t.Fatal("closure invented an Apply/native operation")
	}
}

func TestRootReadOnlyRecoveryDoesNotInventCheckpoint(t *testing.T) {
	f := newRootFixture(t)
	m, err := OpenRoots(filepath.Join(t.TempDir(), "roots.db"), f.book.Cluster(), "node-a", f.key)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ref := Reference{Cluster: f.book.Cluster(), Node: "node-a", Key: [32]byte(f.key.Public().(ed25519.PublicKey)), ID: "hdd", Generation: 1, Path: "/not-created-by-this-test"}
	raw, _ := json.Marshal(ref)
	op := reconcile.Operation{ID: 1, Kind: reconcile.Apply, Phase: reconcile.RecoveryRequired, Target: reconcile.Resource{Generation: 1, Present: true, Spec: string(raw)}}
	d := rootDriver{m: m}
	outcome, err := d.Recover(context.Background(), RootNativeKey(ref), op)
	if err != nil || outcome != reconcile.EffectNotApplied {
		t.Fatal("read-only pre-checkpoint recovery invented native proof", outcome, err)
	}
	if len(m.Keys()) != 0 {
		t.Fatal("Recover wrote a replacement original")
	}
	// Once a durable fact exists, absence/cancellation may not become a
	// fresh proof or NotApplied. No actual filesystem is asserted here.
	f.book, err = f.book.Add(f.users, "admin", 0, f.definition)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := f.book.Root("node-a", "hdd")
	fact := signedRoot(f, r, 2)
	d.original = &fact
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	outcome, err = d.Recover(ctx, RootNativeKey(ref), op)
	if err == nil || outcome != reconcile.EffectUnknown {
		t.Fatal("cancelled inspection erased original uncertainty")
	}
}

func TestSettledRootObservesOriginalDirectoryWithoutNewWork(t *testing.T) {
	f := newRootFixture(t)
	base := t.TempDir()
	f.definition.Path = filepath.Join(base, "root")
	if err := os.Mkdir(f.definition.Path, 0750); err != nil {
		t.Fatal(err)
	}
	handle, err := OpenDirectory(f.definition.Path)
	if errors.Is(err, ErrUnsupported) {
		t.Skip("actual host filesystem lacks required ext4 native identity")
	}
	if err != nil {
		t.Fatal(err)
	}
	_ = handle.Close()
	f.book, err = f.book.Add(f.users, "admin", 0, f.definition)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := f.book.Root("node-a", "hdd")
	m, err := OpenRoots(filepath.Join(t.TempDir(), "roots.db"), f.book.Cluster(), "node-a", f.key)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if ok, err := m.Settled(context.Background(), root); err != nil || ok {
		t.Fatal("unregistered root was settled", ok, err)
	}
	if err := m.Desired(root); err != nil {
		t.Fatal(err)
	}
	key := RootNativeKey(root.Reference(f.book.Cluster()))
	if err := m.Step(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	fact, err := m.Fact(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	f.book, err = f.book.Observe(fact, f.definition.Key)
	if err != nil {
		t.Fatal(err)
	}
	root, _ = f.book.Root("node-a", "hdd")
	if err := m.Desired(root); err != nil {
		t.Fatal(err)
	}
	before, err := m.View(key)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := m.Settled(context.Background(), root); err != nil || !ok {
		t.Fatal("settled native root", ok, err)
	}
	for _, kind := range []string{"unpublished", "draining", "revision", "pending"} {
		t.Run(kind, func(t *testing.T) {
			next := root
			row := before
			switch kind {
			case "unpublished":
				next.Attestation = nil
			case "draining":
				next.Draining = true
			case "revision":
				next.Revision++
			case "pending":
				row.State.Pending = &reconcile.Operation{}
			}
			if settledRootRecord(next, row) {
				t.Fatal("unsettled work bypassed current permit")
			}
		})
	}
	if err := os.Rename(f.definition.Path, filepath.Join(base, "original")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(f.definition.Path, 0750); err != nil {
		t.Fatal(err)
	}
	if ok, err := m.Settled(context.Background(), root); err == nil || ok {
		t.Fatal("replacement inode accepted", ok, err)
	}
	after, err := m.View(key)
	a, _ := json.Marshal(before)
	b, _ := json.Marshal(after)
	if err != nil || !bytes.Equal(a, b) {
		t.Fatal("read changed original checkpoint/operation/pins", err)
	}
}
