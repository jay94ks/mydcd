// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	oci "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

func storeBlob(t *testing.T, s *Store, repo string, data []byte) v1.Descriptor {
	t.Helper()
	ctx := context.Background()
	u, err := s.Blobs.Begin(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Blobs.Append(ctx, repo, u.ID, 0, int64(len(data)), bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	digest := blobDigest(data)
	if _, err = s.Blobs.Commit(ctx, repo, u.ID, digest); err != nil {
		t.Fatal(err)
	}
	h, _ := v1.NewHash(digest)
	return v1.Descriptor{MediaType: types.OCIConfigJSON, Digest: h, Size: int64(len(data))}
}

func putHandlerManifest(t *testing.T, h http.Handler, repo, target string, content any, media types.MediaType, want int) []byte {
	t.Helper()
	raw, err := json.Marshal(content)
	if err != nil {
		t.Fatal(err)
	}
	q := httptest.NewRequest(http.MethodPut, "/v2/"+repo+"/manifests/"+target, bytes.NewReader(raw))
	q.Header.Set("Content-Type", string(media))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, q)
	if w.Code != want {
		t.Fatal("manifest publication", w.Code, want, w.Body.String())
	}
	return raw
}

// Actual upstream HTTP handler + original disk/DB. This is not authenticated
// TLS push or an Engine pull; those belong to the final native E5 fixture.
func TestRegistryHandlerPublishesOnlySameRepoCompleteImageGraphAndReopens(t *testing.T) {
	ctx := context.Background()
	path := privateRegistryRoot(t)
	owner := metadataScope("alpha")
	meta := MetadataLimits{ManifestBytes: 4096, Records: 64, TotalBytes: 1 << 20}
	s, err := OpenStore(ctx, path, owner, meta, smallBlobLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	logger := log.New(io.Discard, "", 0)
	h, err := s.Handler(ctx, logger)
	if err != nil {
		t.Fatal(err)
	}
	config := storeBlob(t, s, "team/app", []byte(`{"architecture":"amd64","os":"linux"}`))
	layer := storeBlob(t, s, "team/app", []byte("layer"))
	layer.MediaType = types.OCILayer
	image := v1.Manifest{SchemaVersion: 2, MediaType: types.OCIManifestSchema1, Config: config, Layers: []v1.Descriptor{layer}}
	// Identical physical digest in another repo is not a repo association.
	putHandlerManifest(t, h, "another/app", "stable", image, types.OCIManifestSchema1, 400)
	if _, err = s.Metadata.GetManifest(ctx, "another/app", "stable"); !errors.Is(err, oci.ErrNameUnknown) {
		t.Fatal("failed publication wrote alias", err)
	}
	wrong := image
	wrong.Config.Size++
	putHandlerManifest(t, h, "team/app", "stable", wrong, types.OCIManifestSchema1, 400)
	external := image
	external.Config.URLs = []string{"https://foreign.example/config"}
	putHandlerManifest(t, h, "team/app", "stable", external, types.OCIManifestSchema1, 400)
	raw := putHandlerManifest(t, h, "team/app", "stable", image, types.OCIManifestSchema1, 201)
	digest, _ := v1.NewHash(blobDigest(raw))
	index := v1.IndexManifest{SchemaVersion: 2, MediaType: types.OCIImageIndex, Manifests: []v1.Descriptor{{MediaType: types.OCIManifestSchema1, Digest: digest, Size: int64(len(raw))}}}
	wrongIndex := index
	wrongIndex.Manifests = append([]v1.Descriptor(nil), index.Manifests...)
	wrongIndex.Manifests[0].Size++
	putHandlerManifest(t, h, "team/app", "multi", wrongIndex, types.OCIImageIndex, 400)
	putHandlerManifest(t, h, "team/app", "multi", index, types.OCIImageIndex, 201)
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = OpenStore(ctx, path, owner, meta, smallBlobLimits())
	if err != nil {
		t.Fatal(err)
	}
	h, err = s.Handler(ctx, logger)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"stable", digest.String()} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v2/team/app/manifests/"+target, nil))
		if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), raw) {
			t.Fatal("original manifest lost", w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/v2/team/app/manifests/stable", nil))
	if w.Code < 400 {
		t.Fatal("delete enabled")
	}
}

func TestRegistryHandlerRejectsStoredGraphWithMissingRepoReferences(t *testing.T) {
	ctx := context.Background()
	path := privateRegistryRoot(t)
	owner := metadataScope("alpha")
	meta := MetadataLimits{ManifestBytes: 4096, Records: 64, TotalBytes: 1 << 20}
	s, err := OpenStore(ctx, path, owner, meta, smallBlobLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	hash, _ := v1.NewHash(blobDigest([]byte("never uploaded")))
	image := v1.Manifest{SchemaVersion: 2, MediaType: types.OCIManifestSchema1, Config: v1.Descriptor{MediaType: types.OCIConfigJSON, Digest: hash, Size: 14}}
	raw, _ := json.Marshal(image)
	data := oci.ManifestData{ContentType: string(types.OCIManifestSchema1), Body: raw}
	// Deliberately inject through the low-level immutable metadata adapter.
	// Recovery must not silently publish readiness or repair this image.
	if err = s.Metadata.PutManifest(ctx, "app", "broken", blobDigest(raw), data); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = OpenStore(ctx, path, owner, meta, smallBlobLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Handler(ctx, log.New(io.Discard, "", 0)); !errors.Is(err, ErrStorage) {
		t.Fatal("incomplete image became serving handler", err)
	}
	kept, err := s.Metadata.GetManifest(ctx, "app", "broken")
	if err != nil || !bytes.Equal(kept.Body, raw) {
		t.Fatal("constructor repaired/dropped original", err)
	}
}
