// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/types"
)

func TestNativeOriginalMaintenanceReadSurvivesReopenWithoutRepeatingEffect(t *testing.T) {
	ctx := context.Background()
	s, path, scope, metadata, blobs, handler, image, digest := nativeImageFixture(t)
	q := deleteRequest("read-original-delete", digest, digest)
	if _, found, err := s.DeleteReceipt(ctx, q); err != nil || found {
		t.Fatal("unsubmitted native intent invented a result", found, err)
	}
	deleted, err := s.DeleteImage(ctx, q, allowNativeImage)
	if err != nil || deleted.State != "deleted" {
		t.Fatal(deleted, err)
	}
	gc := GCRequest{Operation: "read-original-gc", Authority: "registry.example"}
	done, err := s.GarbageCollect(ctx, gc, allowNativeImage)
	if err != nil || done.State != "done" {
		t.Fatal(done, err)
	}
	// A later upload/publication has a different lifetime. Looking up either
	// original operation must not run its effect against this new publication.
	storeBlob(t, s, "team/app", []byte(`{"architecture":"amd64","os":"linux"}`))
	storeBlob(t, s, "team/app", []byte("layer"))
	putHandlerManifest(t, handler, "team/app", "stable", image, types.OCIManifestSchema1, 201)
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = OpenStore(ctx, path, scope, metadata, blobs)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	originalDelete, found, err := s.DeleteReceipt(ctx, q)
	if err != nil || !found || originalDelete.At != deleted.At || originalDelete.Request != deleted.Request || originalDelete.State != deleted.State {
		t.Fatal("original delete receipt changed", originalDelete, found, err)
	}
	originalGC, found, err := s.GCReceipt(ctx, gc)
	if err != nil || !found || originalGC.CompletedAt != done.CompletedAt || originalGC.ReclaimedBytes != done.ReclaimedBytes || originalGC.Sequence != done.Sequence {
		t.Fatal("original GC receipt changed", originalGC, found, err)
	}
	if _, err = s.Metadata.GetManifest(ctx, "team/app", "stable"); err != nil {
		t.Fatal("result lookup removed a new manifest", err)
	}
	if _, err = s.Blobs.Stat(ctx, "team/app", image.Layers[0].Digest); err != nil {
		t.Fatal("result lookup removed a new blob", err)
	}
	changed := q
	changed.Reference = "stable"
	if _, _, err = s.DeleteReceipt(ctx, changed); err == nil {
		t.Fatal("same original ID silently retargeted")
	}
	changedGC := gc
	changedGC.Authority = "different.example"
	if _, _, err = s.GCReceipt(ctx, changedGC); err == nil {
		t.Fatal("same original GC ID silently retargeted")
	}
	s.Metadata.mu.Lock()
	s.Metadata.failed = true
	s.Metadata.mu.Unlock()
	if _, _, err = s.DeleteReceipt(ctx, q); !errors.Is(err, ErrStorage) {
		t.Fatal("failed writer substituted memory for durable recovery", err)
	}
	if _, _, err = s.GCReceipt(ctx, gc); !errors.Is(err, ErrStorage) {
		t.Fatal("failed writer acknowledged GC without original DB recovery", err)
	}
}
