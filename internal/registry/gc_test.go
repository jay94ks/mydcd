// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestNativeGCReclaimsRetiredAndExpiredUnpublishedWithOriginalResult(t *testing.T) {
	ctx := context.Background()
	s, _, _, _, _, _, image, digest := nativeImageFixture(t)
	defer s.Close()
	if _, err := s.DeleteImage(ctx, deleteRequest("delete", digest, digest), allowNativeImage); err != nil {
		t.Fatal(err)
	}
	// A completed upload whose original finite grant has ended is abandoned
	// data, not a permanent reservation. Its original upload receipt still
	// proves exact ownership; active/fresh grants are tested separately.
	orphan := storeBlob(t, s, "pending/app", []byte("expired unpublished image bytes"))
	if err := s.RegisterPushLease(ctx, "pending/app", 100, 200, 100, true); err != nil {
		t.Fatal(err)
	}
	q := GCRequest{Operation: "collect", Authority: "registry.example"}
	calls := 0
	done, err := s.GarbageCollect(ctx, q, func(_ context.Context, refs []string) error {
		calls++
		if len(refs) != 1 || refs[0] != "registry.example/team/app@"+digest {
			t.Fatal(refs)
		}
		return nil
	})
	expected := image.Config.Size + image.Layers[0].Size + orphan.Size
	if err != nil || !done.Valid() || done.State != "done" || done.ReclaimedBytes != expected || calls != 1 {
		t.Fatal(done, err)
	}
	latest, ok, err := s.Metadata.LatestGC(ctx)
	if err != nil || !ok || latest.Request != q || latest.ReclaimedBytes != expected {
		t.Fatal(latest, ok, err)
	}
	_ = storeBlob(t, s, "team/app", []byte("layer"))
	repeated, err := s.GarbageCollect(ctx, q, func(context.Context, []string) error { t.Fatal("completed GC original re-executed"); return nil })
	if err != nil || repeated.CompletedAt != done.CompletedAt || repeated.ReclaimedBytes != done.ReclaimedBytes {
		t.Fatal(repeated, err)
	}
	if _, err = s.Blobs.Stat(ctx, "team/app", image.Layers[0].Digest); err != nil {
		t.Fatal("old GC receipt removed a new upload", err)
	}
}

func TestNativeGCIntentRecoveryFinishesOnlyOriginalDetachedFiles(t *testing.T) {
	ctx := context.Background()
	s, path, scope, meta, limits, _, image, digest := nativeImageFixture(t)
	defer func() { _ = s.Close() }()
	if _, err := s.DeleteImage(ctx, deleteRequest("delete-original", digest, digest), allowNativeImage); err != nil {
		t.Fatal(err)
	}
	q := GCRequest{Operation: "cut-after-detach", Authority: "registry.example"}
	// Cut at the product helper's own transaction boundary. No replacement GC
	// implementation or guessed absence is used by this fixture.
	release, err := s.gate.acquire(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.Metadata.mu.Lock()
	s.Blobs.mu.Lock()
	pending, err := s.beginGC(ctx, q, allowNativeImage)
	s.Blobs.mu.Unlock()
	s.Metadata.mu.Unlock()
	s.mu.Unlock()
	release()
	if err != nil || pending.State != "deleting" || len(pending.Blobs) != 2 {
		t.Fatal(pending, err)
	}
	// One unlink reached the filesystem but its acknowledgement/DB progress did
	// not. The persisted original intent is what authorizes positive recovery.
	first, _ := blobPath(pending.Blobs[0].Digest)
	if err = s.Blobs.root.Remove(first); err != nil {
		t.Fatal(err)
	}
	if err = s.Blobs.syncDir("blobs"); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = OpenStore(ctx, path, scope, meta, limits)
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.GarbageCollect(ctx, q, func(context.Context, []string) error {
		t.Fatal("recovered original needs no replacement intent")
		return nil
	})
	if err != nil || r.State != "done" || r.ReclaimedBytes != image.Config.Size+image.Layers[0].Size {
		t.Fatal(r, err)
	}
	for _, blob := range r.Blobs {
		path, _ := blobPath(blob.Digest)
		if _, err = s.Blobs.root.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("original detached file retained", path, err)
		}
	}
}

func TestNativeGCRejectsUnfinishedUploadsAndUnwitnessedRetirement(t *testing.T) {
	ctx := context.Background()
	s, _, _, _, _, _, _, digest := nativeImageFixture(t)
	defer s.Close()
	u, err := s.Blobs.Begin(ctx, "team/app")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.GarbageCollect(ctx, GCRequest{Operation: "busy", Authority: "registry.example"}, allowNativeImage); !errors.Is(err, ErrUploadsInProgress) {
		t.Fatal("active upload collected", err)
	}
	if err = s.Blobs.Cancel(ctx, "team/app", u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DeleteImage(ctx, deleteRequest("delete", digest, digest), allowNativeImage); err != nil {
		t.Fatal(err)
	}
	if _, err = s.GarbageCollect(ctx, GCRequest{Operation: "shared-held", Authority: "registry.example"}, func(context.Context, []string) error { return ErrImageInUse }); !errors.Is(err, ErrImageInUse) {
		t.Fatal("shared references ignored", err)
	}
	// Corrupt a positive retirement witness rather than letting GC synthesize it.
	if err = s.db.Write(map[string][]byte{actionReceiptKey(imageDeletePrefix, "delete"): nil}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.GarbageCollect(ctx, GCRequest{Operation: "missing-witness", Authority: "registry.example"}, allowNativeImage); err == nil {
		t.Fatal("unwitnessed flags authorized deletion")
	}
}

func TestGCRecoveryRefusesLiveReferenceContradictingDetachedIntent(t *testing.T) {
	ctx := context.Background()
	s, path, scope, meta, limits, _, _, digest := nativeImageFixture(t)
	if _, err := s.DeleteImage(ctx, deleteRequest("delete", digest, digest), allowNativeImage); err != nil {
		t.Fatal(err)
	}
	// Keep the original blob receipt bytes solely to inject a contradictory DB
	// row after the genuine detach transaction, never to repair/adopt a file.
	var key string
	var blob blobRecord
	for k, v := range s.Blobs.blobs {
		key, blob = k, v
		break
	}
	release, err := s.gate.acquire(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.Metadata.mu.Lock()
	s.Blobs.mu.Lock()
	_, err = s.beginGC(ctx, GCRequest{Operation: "cut", Authority: "registry.example"}, allowNativeImage)
	s.Blobs.mu.Unlock()
	s.Metadata.mu.Unlock()
	s.mu.Unlock()
	release()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(blob)
	if err = s.db.Write(map[string][]byte{key: raw}); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if opened, err := OpenStore(ctx, path, scope, meta, limits); err == nil {
		_ = opened.Close()
		t.Fatal("live reference was removed during GC recovery")
	}
	physical, _ := blobPath(blob.Digest)
	if info, err := os.Stat(filepath.Join(path, "objects", physical)); err != nil || info.Size() != blob.Size {
		t.Fatal("contradictory GC modified live bytes", info, err)
	}
}
