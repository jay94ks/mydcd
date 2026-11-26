// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	oci "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/jay94ks/mydcd/internal/storage"
)

func catalogueManifest(t *testing.T, version string) (oci.ManifestData, string) {
	t.Helper()
	manifest := v1.Manifest{SchemaVersion: 2, MediaType: types.OCIManifestSchema1, Config: v1.Descriptor{MediaType: types.OCIConfigJSON, Digest: v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("a", 64)}, Size: 10}, Layers: []v1.Descriptor{{MediaType: types.OCILayer, Digest: v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("b", 64)}, Size: 20}}, Annotations: map[string]string{"revision": version}}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return oci.ManifestData{ContentType: string(types.OCIManifestSchema1), Body: raw}, fmt.Sprintf("sha256:%x", sha256.Sum256(raw))
}

// Actual bbolt and original Metadata publication/query/recovery. Descriptors
// are fixture data; this is not a claim of real blob upload or Docker pull.
func TestManagedCataloguePublicationIsAtomicIdempotentAndLegacyTimeUnknown(t *testing.T) {
	ctx := context.Background()
	scope := metadataScope("tenant")
	limits := MetadataLimits{ManifestBytes: 4096, Records: 128, TotalBytes: 1 << 20}
	m, db, path := metadataFixture(t, scope, limits)
	data, digest := catalogueManifest(t, "one")
	if err := m.PutManifest(ctx, "team/app", "stable", digest, data); err != nil {
		t.Fatal(err)
	}
	page, err := m.Catalogue(ctx, "registry.example", "team/app", [32]byte{1}, "")
	if err != nil || !page.Valid("registry.example", "team/app", "") || !page.UntaggedComplete || page.Live || len(page.Images) != 2 {
		t.Fatal(page, err)
	}
	for _, image := range page.Images {
		if image.ImageBytes != 30 || !image.UploadedAtKnown || image.UploadedAt == 0 || image.Digest != digest {
			t.Fatal(image)
		}
	}
	before, err := db.ScanBounded(manifestPrefix, 128, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.PutManifest(ctx, "team/app", "stable", digest, data); err != nil {
		t.Fatal(err)
	}
	again, err := m.Catalogue(ctx, "registry.example", "team/app", [32]byte{1}, "")
	after, _ := db.ScanBounded(manifestPrefix, 128, 1<<20)
	a, _ := json.Marshal(before)
	b, _ := json.Marshal(after)
	if err != nil || again.Root != page.Root || !bytes.Equal(a, b) {
		t.Fatal("retry fabricated publication metadata", again, err)
	}
	data2, digest2 := catalogueManifest(t, "two")
	if err = m.PutManifest(ctx, "team/app", "stable", digest2, data2); err != nil {
		t.Fatal(err)
	}
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	m, err = OpenMetadata(db, scope, limits)
	if err != nil {
		t.Fatal(err)
	}
	page, err = m.Catalogue(ctx, "registry.example", "team/app", [32]byte{1}, "")
	if err != nil || len(page.Images) != 3 {
		t.Fatal("repoint/reopen lost immutable digest", page, err)
	}
	for _, image := range page.Images {
		if image.Reference == "stable" && image.Digest != digest2 {
			t.Fatal("stale tag", image)
		}
	}
	// Retain the old schema-1 data/aliases but no publication facts. Recovery and
	// reads must preserve absence, never infer upload time from DB mtime/Created.
	rows, _ := db.ScanBounded(manifestPrefix+"published/", 128, 1<<20)
	deletes := map[string][]byte{}
	for key := range rows {
		deletes[key] = nil
	}
	if err = db.Write(deletes); err != nil {
		t.Fatal(err)
	}
	_ = m.Close()
	m, err = OpenMetadata(db, scope, limits)
	if err != nil {
		t.Fatal(err)
	}
	before, _ = db.ScanBounded(manifestPrefix, 128, 1<<20)
	page, err = m.Catalogue(ctx, "registry.example", "team/app", [32]byte{1}, "")
	after, _ = db.ScanBounded(manifestPrefix, 128, 1<<20)
	a, _ = json.Marshal(before)
	b, _ = json.Marshal(after)
	if err != nil || !bytes.Equal(a, b) {
		t.Fatal("legacy query changed original metadata", err)
	}
	for _, image := range page.Images {
		if image.UploadedAtKnown || image.UploadedAt != 0 {
			t.Fatal("invented legacy upload time", image)
		}
	}
}

func TestManagedCatalogueCursorDetectsTagRepointAndRejectsOrphanPublication(t *testing.T) {
	ctx := context.Background()
	scope := metadataScope("tenant")
	limits := MetadataLimits{ManifestBytes: 4096, Records: 128, TotalBytes: 1 << 20}
	m, db, _ := metadataFixture(t, scope, limits)
	data, digest := catalogueManifest(t, "one")
	for i := 0; i < 9; i++ {
		if err := m.PutManifest(ctx, "team/app", fmt.Sprintf("tag%d", i), digest, data); err != nil {
			t.Fatal(err)
		}
	}
	first, err := m.Catalogue(ctx, "registry.example", "team/app", [32]byte{1}, "")
	if err != nil || len(first.Images) != 8 || first.Next == "" {
		t.Fatal(first, err)
	}
	next, err := m.Catalogue(ctx, "registry.example", "team/app", [32]byte{1}, first.Next)
	if err != nil || len(next.Images) != 2 || next.Root != first.Root || !next.Valid("registry.example", "team/app", first.Next) {
		t.Fatal(next, err)
	}
	changed, newDigest := catalogueManifest(t, "two")
	if err = m.PutManifest(ctx, "team/app", "tag0", newDigest, changed); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Catalogue(ctx, "registry.example", "team/app", [32]byte{1}, first.Next); err == nil {
		t.Fatal("old cursor accepted changed tag mapping")
	}
	id, _ := repoID("team/app")
	raw, _ := json.Marshal(manifestPublication{Schema: 1, Digest: digest, At: 1000})
	if err = db.Write(map[string][]byte{manifestPrefix + "published/" + id + "/orphan": raw}); err != nil {
		t.Fatal(err)
	}
	_ = m.Close()
	if _, err = OpenMetadata(db, scope, limits); err == nil {
		t.Fatal("orphan publication repaired/accepted")
	}
}
