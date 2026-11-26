// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/jay94ks/mydcd/internal/registryclient"
)

func TestNativeGraphContentHoldsOriginalStoreUntilBodyClose(t *testing.T) {
	s, _, _, _, _, handler, image, digest := nativeImageFixture(t)
	manifest, err := s.Metadata.GetManifest(context.Background(), "team/app", digest)
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := v1.NewHash(digest)
	index := v1.IndexManifest{SchemaVersion: 2, MediaType: types.OCIImageIndex, Manifests: []v1.Descriptor{{Digest: hash, MediaType: types.OCIManifestSchema1, Size: int64(len(manifest.Body))}}}
	raw := putHandlerManifest(t, handler, "team/app", "index", index, types.OCIImageIndex, 201)
	q := registryclient.GraphContentQuery{Root: "registry.example/team/app@" + blobDigest(raw), Path: []string{digest}, Kind: "layer", Digest: image.Layers[0].Digest.String()}
	info, body, err := s.OpenGraphContent(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	payload, err := io.ReadAll(body)
	if err != nil || !info.Valid(q.Selected()) || !bytes.Equal(payload, []byte("layer")) {
		t.Fatal("original index/manifest/blob not used", info, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	_, err = s.GarbageCollect(ctx, GCRequest{Operation: "graph-overlap", Authority: "registry.example"}, allowNativeImage)
	cancel()
	if err == nil {
		t.Fatal("graph body EOF released original native gate")
	}
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
	q.Path = []string{"sha256:" + strings.Repeat("f", 64)}
	if _, body, err := s.OpenGraphContent(context.Background(), q); err == nil || body != nil {
		t.Fatal("unrelated native manifest/blob opened", err)
	}
}
