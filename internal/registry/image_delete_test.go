// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"testing"

	oci "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

func nativeImageFixture(t *testing.T) (*Store, string, Scope, MetadataLimits, BlobLimits, http.Handler, v1.Manifest, string) {
	t.Helper()
	ctx := context.Background()
	path := privateRegistryRoot(t)
	scope := metadataScope("tenant")
	meta := MetadataLimits{ManifestBytes: 4096, Records: 128, TotalBytes: 1 << 20}
	blobs := smallBlobLimits()
	s, err := OpenStore(ctx, path, scope, meta, blobs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	h, err := s.Handler(ctx, log.New(io.Discard, "", 0))
	if err != nil {
		_ = s.Close()
		t.Fatal(err)
	}
	config := storeBlob(t, s, "team/app", []byte(`{"architecture":"amd64","os":"linux"}`))
	layer := storeBlob(t, s, "team/app", []byte("layer"))
	layer.MediaType = types.OCILayer
	image := v1.Manifest{SchemaVersion: 2, MediaType: types.OCIManifestSchema1, Config: config, Layers: []v1.Descriptor{layer}}
	raw := putHandlerManifest(t, h, "team/app", "stable", image, types.OCIManifestSchema1, 201)
	return s, path, scope, meta, blobs, h, image, blobDigest(raw)
}
func deleteRequest(id, ref, digest string) ImageDelete {
	return ImageDelete{Operation: id, Authority: "registry.example", Repository: "team/app", Reference: ref, ExpectedDigest: digest}
}
func allowNativeImage(context.Context, []string) error { return nil }

// Actual retained Store/HTTP manifest writes, synchronous DB and local files.
// The shared policy callback is injected; this is not user/Raft authorization
// or real network Docker deployment evidence.
func TestNativeDeleteTagCASGuardAndOriginalReceiptPreserveDigest(t *testing.T) {
	ctx := context.Background()
	s, _, _, _, _, handler, image, digest := nativeImageFixture(t)
	defer s.Close()
	putHandlerManifest(t, handler, "team/app", "other", image, types.OCIManifestSchema1, 201)
	calls := 0
	rejected, err := s.DeleteImage(ctx, deleteRequest("in-use", "stable", digest), func(_ context.Context, refs []string) error {
		calls++
		if len(refs) != 2 || refs[0] != "registry.example/team/app@"+digest || refs[1] != "registry.example/team/app:stable" {
			t.Fatal(refs)
		}
		return ErrImageInUse
	})
	if err != nil || rejected.State != "rejected" || rejected.Code != "IMAGE_IN_USE" || calls != 1 {
		t.Fatal(rejected, err)
	}
	again, err := s.DeleteImage(ctx, rejected.Request, func(context.Context, []string) error { t.Fatal("final rejected original re-executed"); return nil })
	if err != nil || again.At != rejected.At {
		t.Fatal(again, err)
	}
	q := deleteRequest("tag-only", "stable", digest)
	removed, err := s.DeleteImage(ctx, q, allowNativeImage)
	if err != nil || removed.State != "deleted" || len(removed.Blobs) != 0 {
		t.Fatal(removed, err)
	}
	if _, err = s.Metadata.GetManifest(ctx, "team/app", "stable"); !errors.Is(err, oci.ErrNotFound) {
		t.Fatal("tag still present", err)
	}
	for _, ref := range []string{"other", digest} {
		if _, err = s.Metadata.GetManifest(ctx, "team/app", ref); err != nil {
			t.Fatal("tag deletion removed immutable/shared image", ref, err)
		}
	}
	bad := deleteRequest("tag-cas", "other", "sha256:"+strings.Repeat("c", 64))
	receipt, err := s.DeleteImage(ctx, bad, allowNativeImage)
	if err != nil || receipt.State != "rejected" || receipt.Code != "REFERENCE_CHANGED" {
		t.Fatal(receipt, err)
	}
	q.ExpectedDigest = bad.ExpectedDigest
	if _, err = s.DeleteImage(ctx, q, allowNativeImage); err == nil {
		t.Fatal("operation ID retargeted")
	}
}

func TestNativeDigestDeleteChecksIndexDependencyAndRetainsBlobUntilGC(t *testing.T) {
	ctx := context.Background()
	s, _, _, _, _, h, image, digest := nativeImageFixture(t)
	defer s.Close()
	raw, err := s.Metadata.GetManifest(ctx, "team/app", digest)
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := v1.NewHash(digest)
	index := v1.IndexManifest{SchemaVersion: 2, MediaType: types.OCIImageIndex, Manifests: []v1.Descriptor{{Digest: hash, MediaType: types.OCIManifestSchema1, Size: int64(len(raw.Body))}}}
	indexRaw := putHandlerManifest(t, h, "team/app", "multi", index, types.OCIImageIndex, 201)
	indexDigest := blobDigest(indexRaw)
	blocked, err := s.DeleteImage(ctx, deleteRequest("child-used", digest, digest), allowNativeImage)
	if err != nil || blocked.Code != "IMAGE_IN_USE" {
		t.Fatal("index dependency removed", blocked, err)
	}
	if r, err := s.DeleteImage(ctx, deleteRequest("index-delete", indexDigest, indexDigest), allowNativeImage); err != nil || r.State != "deleted" {
		t.Fatal(r, err)
	}
	removed, err := s.DeleteImage(ctx, deleteRequest("digest-delete", digest, digest), allowNativeImage)
	if err != nil || removed.State != "deleted" || len(removed.Blobs) != 2 {
		t.Fatal(removed, err)
	}
	if _, err = s.Metadata.GetManifest(ctx, "team/app", "stable"); !errors.Is(err, oci.ErrNameUnknown) {
		t.Fatal("last repository aliases survived", err)
	}
	reader, err := s.Blobs.Get(ctx, "team/app", image.Layers[0].Digest)
	if err != nil {
		t.Fatal("manifest removal destroyed native bytes before GC", err)
	}
	defer reader.Close()
	if _, err = s.GarbageCollect(ctx, GCRequest{Operation: "open-reader", Authority: "registry.example"}, allowNativeImage); !errors.Is(err, ErrReaders) {
		t.Fatal("open blob reader not protected", err)
	}
}
