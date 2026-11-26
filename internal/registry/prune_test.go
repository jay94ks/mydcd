// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/jay94ks/mydcd/internal/registryclient"
)

// Actual retained Store/HTTP metadata and local native files. Shared user/Raft
// authorization is injected at the existing guard and is not claimed here.
func TestNativePrunePreviewBorrowsStoreAndPerItemReceiptsSurviveOriginalRecovery(t *testing.T) {
	ctx := context.Background()
	s, path, scope, metadata, limits, _, image, digest := nativeImageFixture(t)
	before, err := os.ReadFile(filepath.Join(path, "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	preview, err := s.PrunePreview(ctx, "registry.example", registryclient.PruneConditions{GC: true}, nil)
	if err != nil || !preview.Valid() || len(preview.Items) != 1 || preview.Items[0].Image.Digest != digest || preview.EstimatedReclaimedBytes != image.Config.Size+image.Layers[0].Size {
		t.Fatal("native graph/physical preview", preview, err)
	}
	after, err := os.ReadFile(filepath.Join(path, "registry.db"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("preview wrote native state", err)
	}
	q, err := PruneImageDelete("original-prune", "registry.example", preview.Items[0])
	if err != nil || q.Item == "" || q.Aliases == "" {
		t.Fatal(q, err)
	}
	removed, err := s.DeleteImage(ctx, q, allowNativeImage)
	if err != nil || removed.State != "deleted" || removed.Request != q {
		t.Fatal(removed, err)
	}
	// A public/single-item operation whose literal ID equals the parent cannot
	// adopt an internal child receipt and claim a different request succeeded.
	public := q
	public.Item, public.Aliases = "", ""
	if _, found, err := s.DeleteReceipt(ctx, public); err != nil || found {
		t.Fatal("child receipt crossed native namespace", found, err)
	}
	done, err := s.GarbageCollect(ctx, GCRequest{Operation: q.Operation, Authority: q.Authority}, allowNativeImage)
	if err != nil || done.ReclaimedBytes != preview.EstimatedReclaimedBytes {
		t.Fatal(done, err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = OpenStore(ctx, path, scope, metadata, limits)
	if err != nil {
		t.Fatal("child native receipt invalidated original recovery", err)
	}
	defer s.Close()
	again, found, err := s.DeleteReceipt(ctx, q)
	if err != nil || !found || again.At != removed.At || again.Request != q {
		t.Fatal("same parent/item original receipt", again, found, err)
	}
}

func TestNativePruneRefusesNewAliasAndNeverChangesOriginalRefusal(t *testing.T) {
	ctx := context.Background()
	s, _, _, _, _, handler, image, digest := nativeImageFixture(t)
	defer s.Close()
	preview, err := s.PrunePreview(ctx, "registry.example", registryclient.PruneConditions{}, nil)
	if err != nil || len(preview.Items) != 1 {
		t.Fatal(preview, err)
	}
	q, err := PruneImageDelete("frozen-preview", "registry.example", preview.Items[0])
	if err != nil {
		t.Fatal(err)
	}
	putHandlerManifest(t, handler, "team/app", "newly-published", image, types.OCIManifestSchema1, 201)
	refused, err := s.DeleteImage(ctx, q, func(context.Context, []string) error { t.Fatal("expanded alias set reached effect guard"); return nil })
	if err != nil || refused.Code != "REFERENCE_CHANGED" || refused.State != "rejected" {
		t.Fatal(refused, err)
	}
	for _, ref := range []string{digest, "stable", "newly-published"} {
		if _, err = s.Metadata.GetManifest(ctx, "team/app", ref); err != nil {
			t.Fatal("preview swept a new alias/current manifest", ref, err)
		}
	}
	removeAlias := deleteRequest("explicit-alias-removal", "newly-published", digest)
	if _, err = s.DeleteImage(ctx, removeAlias, allowNativeImage); err != nil {
		t.Fatal(err)
	}
	again, err := s.DeleteImage(ctx, q, func(context.Context, []string) error { t.Fatal("known original refusal re-executed"); return nil })
	if err != nil || again.Code != "REFERENCE_CHANGED" || again.At != refused.At {
		t.Fatal(again, err)
	}
}

func TestNativePruneIndexParentOrderAndCurrentSharedGuardReuseOriginalDelete(t *testing.T) {
	ctx := context.Background()
	s, _, _, _, _, handler, _, digest := nativeImageFixture(t)
	defer s.Close()
	body, err := s.Metadata.GetManifest(ctx, "team/app", digest)
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := v1.NewHash(digest)
	index := v1.IndexManifest{SchemaVersion: 2, MediaType: types.OCIImageIndex, Manifests: []v1.Descriptor{{Digest: hash, MediaType: types.OCIManifestSchema1, Size: int64(len(body.Body))}}}
	raw := putHandlerManifest(t, handler, "team/app", "multi", index, types.OCIImageIndex, 201)
	indexDigest := blobDigest(raw)
	protected, err := s.PrunePreview(ctx, "registry.example", registryclient.PruneConditions{}, []registryclient.PruneProtection{{Repository: "team/app", Digest: indexDigest, Code: "IMAGE_IN_USE"}})
	if err != nil || len(protected.Items) != 1 || protected.Items[0].Image.Reference != "stable" || protected.EstimatedReclaimedBytes != 0 {
		t.Fatal("kept index child preservation", protected, err)
	}
	preview, err := s.PrunePreview(ctx, "registry.example", registryclient.PruneConditions{}, nil)
	if err != nil || len(preview.Items) != 2 || preview.Items[0].Image.Digest != indexDigest || preview.Items[1].Image.Digest != digest {
		t.Fatal("native parent-before-child preview", preview, err)
	}
	first, err := PruneImageDelete("index-cleanup", "registry.example", preview.Items[0])
	if err != nil {
		t.Fatal(err)
	}
	refused, err := s.DeleteImage(ctx, first, func(context.Context, []string) error { return ErrImageInUse })
	if err != nil || refused.Code != "IMAGE_IN_USE" {
		t.Fatal("effect-time shared reference ignored", refused, err)
	}
	// A different explicitly requested parent operation is a new user intent,
	// not a replacement of the refusal. Its children still use the same core.
	for _, item := range preview.Items {
		q, err := PruneImageDelete("explicit-index-cleanup", "registry.example", item)
		if err != nil {
			t.Fatal(err)
		}
		result, err := s.DeleteImage(ctx, q, allowNativeImage)
		if err != nil || result.State != "deleted" {
			t.Fatal(result, err)
		}
	}
}

func TestNativeMaintenanceQuotaRefusalPreservesManifestAndDoesNotPoisonWriter(t *testing.T) {
	ctx := context.Background()
	s, _, _, _, _, handler, image, digest := nativeImageFixture(t)
	defer s.Close()
	for i := 0; i < 20; i++ {
		putHandlerManifest(t, handler, "team/app", fmt.Sprintf("retained-%02d", i), image, types.OCIManifestSchema1, 201)
	}
	s.Metadata.mu.Lock()
	rows, err := s.Metadata.inventory()
	original := s.Metadata.limits
	var total int
	for key, size := range rows {
		total += len(key) + int(size)
	}
	if err == nil {
		s.Metadata.limits.TotalBytes = total
	}
	s.Metadata.mu.Unlock()
	if err != nil || total < original.ManifestBytes {
		t.Fatal("valid full-budget fixture", total, err)
	}
	if _, err = s.BeginWriteFence(ctx, "no-space-for-fence", time.Now().Unix()); !errors.Is(err, ErrBudget) {
		t.Fatal("pre-effect fence budget became ambiguous storage failure", err)
	}
	if err = s.EndWriteFence(ctx, "no-space-for-fence"); err != nil {
		t.Fatal("known unsent fence could not settle", err)
	}
	s.Metadata.mu.Lock()
	s.Metadata.limits = original
	s.Metadata.limits.Records = len(rows)
	s.Metadata.mu.Unlock()
	_, err = s.GarbageCollect(ctx, GCRequest{Operation: "no-space-for-gc-result", Authority: "registry.example"}, allowNativeImage)
	if !errors.Is(err, ErrBudget) {
		t.Fatal("pre-detach receipt budget became ambiguous storage failure", err)
	}
	if err = s.EndWriteFence(ctx, "no-space-for-gc-result"); err != nil {
		t.Fatal("known pre-detach refusal lost original fence", err)
	}
	if _, found, err := s.GCReceipt(ctx, GCRequest{Operation: "no-space-for-gc-result", Authority: "registry.example"}); err != nil || found {
		t.Fatal("budget refusal invented native GC success", found, err)
	}
	if _, err = s.Metadata.GetManifest(ctx, "team/app", digest); err != nil {
		t.Fatal("pre-effect refusal changed/poisoned native manifest", err)
	}
	s.Metadata.mu.Lock()
	s.Metadata.limits = original
	s.Metadata.mu.Unlock()
}
