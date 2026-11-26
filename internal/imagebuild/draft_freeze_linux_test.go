// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/jay94ks/mydcd/internal/reconcile"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/sys/unix"
)

func frozenDraftFixture(t *testing.T) (*DraftStore, *Spool, DraftFreezePlan) {
	t.Helper()
	store, spool := draftStoreFixture(t)
	if _, err := store.Edit(context.Background(), draftFileEdit("dockerfile", "Dockerfile", "FROM scratch\n", 1), bytes.NewBufferString("FROM scratch\n")); err != nil {
		t.Fatal(err)
	}
	draft, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	plan := DraftFreezePlan{Schema: 1, Scope: store.scope, ID: "save-one", Creator: "manager", Revision: draft.Revision, Draft: draft.Digest(), CreatedAt: 100, ExpiresAt: 1000}
	return store, spool, plan
}

func TestFrozenDraftUsesOneOriginalArchiveAndExistingReaderReclaimFence(t *testing.T) {
	store, spool, plan := frozenDraftFixture(t)
	ctx := context.Background()
	scope, err := store.PrepareFreeze(ctx, plan)
	if err != nil {
		t.Fatal(err)
	}
	spool.mu.Lock()
	original, _, err := store.loadFreeze(plan)
	spool.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	_, key := testScope(1, [32]byte{1})
	frozen, err := store.AdoptFreeze(ctx, plan, key)
	if err != nil || !frozen.Valid() || frozen.Scope != scope {
		t.Fatal("owner evidence", frozen, err)
	}
	spool.mu.Lock()
	imported, err := spool.header(scope)
	spool.mu.Unlock()
	if err != nil || !matchesGenerated(imported, original, plan) || imported.Inode != original.Inode {
		t.Fatal("archive was copied/replaced", imported, err)
	}
	name := filepath.Join(plan.Scope.Root.Path, ".mydc-imagebuild", string(store.key), freezeName(plan))
	if _, err := os.Stat(name); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("original archive was not handed to Spool", err)
	}
	reader, err := spool.Open(ctx, scope, frozen.Fact)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := InspectZIP(ctx, bytes.NewReader(body), int64(len(body)), scope.Dockerfile, scope.ExpandedLimit)
	if err != nil || tree.Digest() != frozen.Fact.Tree {
		t.Fatal("existing archive reader diverged", err)
	}
	if err := spool.Begin(ctx, scope); err == nil {
		t.Fatal("generated archive reopened as raw upload")
	}
	if _, err := spool.Put(ctx, scope, 0, body[:scope.PartLength(0)], key); err == nil {
		t.Fatal("generated archive admitted uploaded bytes")
	}
	u := Upload{Scope: scope, Revision: 1, Closed: true, Version: VersionID(frozen.Fact)}
	if err := spool.Reclaim(u, false); !errors.Is(err, ErrUsed) {
		t.Fatal("active reader reclaimed", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := spool.Reclaim(u, true); !errors.Is(err, ErrUsed) {
		t.Fatal("retained version reclaimed", err)
	}
	if err := spool.Reclaim(u, false); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PrepareFreeze(ctx, plan); err == nil {
		t.Fatal("reclaimed original silently regenerated")
	}
}

func TestFrozenDraftRecoversCompleteOriginalAndUnfinishedAdoption(t *testing.T) {
	store, spool, plan := frozenDraftFixture(t)
	ctx := context.Background()
	scope, err := store.PrepareFreeze(ctx, plan)
	if err != nil {
		t.Fatal(err)
	}
	spool.mu.Lock()
	h, _, err := store.loadFreeze(plan)
	if err == nil {
		h.Scope = nil
		err = store.saveFreeze(h)
	}
	spool.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	// The mutable editor changes, but the completed old archive still proves
	// its original scope/revision/entry digest and must never be rebuilt.
	if _, err := store.Edit(ctx, DraftEdit{ID: "next", Kind: "mkdir", Path: "later", Expected: plan.Revision}, nil); err != nil {
		t.Fatal(err)
	}
	if got, err := store.PrepareFreeze(ctx, plan); err != nil || got != scope {
		t.Fatal("lost complete record did not recover original", got, err)
	}
	_, key := testScope(1, [32]byte{1})
	frozen, err := store.AdoptFreeze(ctx, plan, key)
	if err != nil {
		t.Fatal(err)
	}
	spool.mu.Lock()
	err = spool.db.Update(func(tx *bolt.Tx) error {
		b := spool.bucket(tx, scope)
		var header localUpload
		if json.Unmarshal(b.Get(spoolHeader), &header) != nil {
			return ErrStorage
		}
		header.Seal = nil
		header.Received = 0
		raw, _ := json.Marshal(header)
		return b.Put(spoolHeader, raw)
	})
	spool.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenDraftStore(spool, plan.Scope, false)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if got, err := store.PrepareFreeze(ctx, plan); err != nil || got != scope {
		t.Fatal("moved original file was treated as missing", got, err)
	}
	again, err := store.AdoptFreeze(ctx, plan, key)
	if err != nil || !again.Valid() || !bytes.Equal(FrozenDraftBytes(again), FrozenDraftBytes(frozen)) {
		t.Fatal("adoption recovery changed original evidence", err)
	}
	changed := plan
	changed.Revision++
	if _, err := store.PrepareFreeze(ctx, changed); !errors.Is(err, ErrConflict) {
		t.Fatal("freeze ID reused for another plan", err)
	}
}

func TestFrozenDraftDoesNotOverwriteForeignDestination(t *testing.T) {
	store, _, plan := frozenDraftFixture(t)
	ctx := context.Background()
	scope, err := store.PrepareFreeze(ctx, plan)
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(scope.Root.Path, ".mydc-imagebuild", scopeName(scope)+".zip")
	if err := os.WriteFile(destination, []byte("foreign original"), 0600); err != nil {
		t.Fatal(err)
	}
	_, key := testScope(1, [32]byte{1})
	if _, err := store.AdoptFreeze(ctx, plan, key); err == nil {
		t.Fatal("foreign target adopted/overwritten")
	}
	if body, err := os.ReadFile(destination); err != nil || string(body) != "foreign original" {
		t.Fatal("foreign bytes changed", err)
	}
	if _, err := store.PrepareFreeze(ctx, plan); err != nil {
		t.Fatal("source original lost after target rejection", err)
	}
}

func TestFrozenDraftPartialArchiveIsRetainedWithoutTruncateOrRebuild(t *testing.T) {
	store, spool, plan := frozenDraftFixture(t)
	name := filepath.Join(plan.Scope.Root.Path, ".mydc-imagebuild", string(store.key), freezeName(plan))
	if err := os.WriteFile(name, []byte("partial ZIP"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	spool.mu.Lock()
	err = store.saveFreeze(nativeDraftFreeze{Plan: plan, Device: uint64(stat.Dev), Inode: stat.Ino})
	spool.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PrepareFreeze(context.Background(), plan); !errors.Is(err, reconcile.ErrPending) {
		t.Fatal("partial original treated as complete", err)
	}
	if body, err := os.ReadFile(name); err != nil || string(body) != "partial ZIP" {
		t.Fatal("partial original rewritten", err)
	}
}
