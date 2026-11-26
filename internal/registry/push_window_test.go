// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/storage"
)

func TestPushFenceRetainsFiniteOldGrantAndRejectsNewIssueAcrossRestart(t *testing.T) {
	ctx := context.Background()
	s, path, scope, meta, limits, _, _, _ := nativeImageFixture(t)
	defer func() { _ = s.Close() }()
	if err := s.RegisterPushLease(ctx, "team/app", 100, 200, 100, true); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(path, "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.RegisterPushLease(ctx, "team/app", 100, 200, 110, false); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(path, "registry.db"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("covered HEAD token caused another native DB commit", err)
	}
	if err := s.RegisterPushLease(ctx, "another/app", 100, 250, 100, false); err != nil {
		t.Fatal(err)
	}
	until, err := s.BeginWriteFence(ctx, "gc-original", 110)
	if err != nil || until != 250 {
		t.Fatal(until, err)
	}
	for _, tc := range []struct {
		repo            string
		issued, expires int64
		issuing         bool
	}{
		{"team/app", 100, 200, true},  // new issuance is always stopped
		{"team/app", 111, 200, false}, // an uncovered newer token cannot extend the fence
		{"foreign/app", 100, 190, false},
		{"team/app", 100, 201, false},
	} {
		if err = s.RegisterPushLease(ctx, tc.repo, tc.issued, tc.expires, 120, tc.issuing); !errors.Is(err, ErrMaintenanceFence) {
			t.Fatal("uncovered/new token admitted", tc, err)
		}
	}
	if err = s.RegisterPushLease(ctx, "team/app", 100, 200, 120, false); err != nil {
		t.Fatal("already covered finite push/HEAD denied", err)
	}
	if _, err = s.BeginWriteFence(ctx, "replacement", 120); !errors.Is(err, ErrMaintenanceFence) {
		t.Fatal("original maintenance replaced", err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = OpenStore(ctx, path, scope, meta, limits)
	if err != nil {
		t.Fatal(err)
	}
	until, err = s.BeginWriteFence(ctx, "gc-original", 260)
	if err != nil || until != 250 {
		t.Fatal("restart renewed/forgot old expiry", until, err)
	}
	if err = s.EndWriteFence(ctx, "gc-original"); err != nil {
		t.Fatal(err)
	}
	if err = s.RegisterPushLease(ctx, "team/app", 260, 300, 260, true); err != nil {
		t.Fatal("settled no-effect fence not released", err)
	}
}

func TestNativeGCWaitsForIssuedPushLeaseBeforeDetach(t *testing.T) {
	ctx := context.Background()
	s, _, _, _, _, _, _, digest := nativeImageFixture(t)
	defer s.Close()
	if _, err := s.DeleteImage(ctx, deleteRequest("delete", digest, digest), allowNativeImage); err != nil {
		t.Fatal(err)
	}
	_ = storeBlob(t, s, "team/app", []byte("unpublished blob"))
	now := time.Now().Unix()
	if err := s.RegisterPushLease(ctx, "team/app", now, now+60, now, true); err != nil {
		t.Fatal(err)
	}
	q := GCRequest{Operation: "gc-wait", Authority: "registry.example"}
	if _, err := s.GarbageCollect(ctx, q, allowNativeImage); !errors.Is(err, ErrPushLeaseActive) {
		t.Fatal("GC raced a finite existing push lease", err)
	}
	if _, err := s.db.Get(actionReceiptKey(gcPrefix, q.Operation)); !errors.Is(err, storage.ErrMissing) {
		t.Fatal("waiting GC detached/settled before lease closure", err)
	}
	if len(s.Blobs.blobs) != 3 {
		t.Fatal("waiting GC removed original associations")
	}
	if err := s.RegisterPushLease(ctx, "team/app", now, now+60, now, true); !errors.Is(err, ErrMaintenanceFence) {
		t.Fatal("new push issued during wait", err)
	}
	if err := s.RegisterPushLease(ctx, "team/app", now, now+60, now, false); err != nil {
		t.Fatal("already covered push could not finish", err)
	}
	if err := s.EndWriteFence(ctx, q.Operation); err != nil {
		t.Fatal("unsent GC could not be positively canceled", err)
	}
}

func TestLegacyPushWarmupIsPersistedOnceAndNewStoreHasNoWarmup(t *testing.T) {
	ctx := context.Background()
	s, path, scope, meta, limits, _, _, _ := nativeImageFixture(t)
	state, err := s.Metadata.pushState()
	if err != nil || state.WarmUntil != 0 {
		_ = s.Close()
		t.Fatal("fresh store fabricated historical token window", state, err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	// Exact legacy boundary: retained original owner/data, no new maintenance
	// receipt and no sidecar from the earlier token-issuance implementation.
	db, err := storage.Open(filepath.Join(path, "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Write(map[string][]byte{pushStateKey: nil}); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	before := time.Now().Unix()
	s, err = OpenStore(ctx, path, scope, meta, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	state, err = s.Metadata.pushState()
	if err != nil || state.WarmUntil < before+MaxGrantSeconds {
		t.Fatal("legacy token lifetime was guessed empty", state, err)
	}
	floor := state.WarmUntil
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = OpenStore(ctx, path, scope, meta, limits)
	if err != nil {
		t.Fatal(err)
	}
	state, err = s.Metadata.pushState()
	if err != nil || state.WarmUntil != floor {
		t.Fatal("restart reset one-time legacy warmup", state, err)
	}
}

func TestLostPushSidecarDoesNotResumeNativeGCOrDiscardOriginalFence(t *testing.T) {
	ctx := context.Background()
	s, path, scope, meta, limits, _, _, digest := nativeImageFixture(t)
	if _, err := s.DeleteImage(ctx, deleteRequest("delete", digest, digest), allowNativeImage); err != nil {
		_ = s.Close()
		t.Fatal(err)
	}
	if err := s.db.Write(map[string][]byte{pushStateKey: nil}); err != nil {
		_ = s.Close()
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if opened, err := OpenStore(ctx, path, scope, meta, limits); err == nil {
		_ = opened.Close()
		t.Fatal("known sidecar loss was initialized as a legacy DB")
	}
}

func TestMismatchedPushFenceCannotAuthorizePendingGCRecovery(t *testing.T) {
	ctx := context.Background()
	s, path, scope, meta, limits, _, _, digest := nativeImageFixture(t)
	if _, err := s.DeleteImage(ctx, deleteRequest("delete", digest, digest), allowNativeImage); err != nil {
		t.Fatal(err)
	}
	release, err := s.gate.acquire(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.Metadata.mu.Lock()
	s.Blobs.mu.Lock()
	pending, err := s.beginGC(ctx, GCRequest{Operation: "original", Authority: "registry.example"}, allowNativeImage)
	s.Blobs.mu.Unlock()
	s.Metadata.mu.Unlock()
	s.mu.Unlock()
	release()
	if err != nil {
		t.Fatal(err)
	}
	value, err := s.Metadata.pushState()
	if err != nil {
		t.Fatal(err)
	}
	value.Fence.Operation = "different-original"
	raw, _ := json.Marshal(value)
	if err = s.db.Write(map[string][]byte{pushStateKey: raw}); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if opened, err := OpenStore(ctx, path, scope, meta, limits); err == nil {
		_ = opened.Close()
		t.Fatal("different fence authorized original unlink")
	}
	for _, blob := range pending.Blobs {
		physical, _ := blobPath(blob.Digest)
		if info, err := os.Stat(filepath.Join(path, "objects", physical)); err != nil || info.Size() != blob.Size {
			t.Fatal("unproved fence recovery changed original file", info, err)
		}
	}
}
