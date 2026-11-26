// SPDX-License-Identifier: Apache-2.0

package registryclient

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

func TestImageMetadataUsesImmutableIndexGraphAndUniqueBlobSizes(t *testing.T) {
	image := v1.Manifest{SchemaVersion: 2, MediaType: types.OCIManifestSchema1, Config: v1.Descriptor{Digest: v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("a", 64)}, MediaType: types.OCIConfigJSON, Size: 10}, Layers: []v1.Descriptor{{Digest: v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("b", 64)}, MediaType: types.OCILayer, Size: 20}}}
	raw, _ := json.Marshal(image)
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(raw))
	hash, _ := v1.NewHash(digest)
	child := v1.Descriptor{Digest: hash, MediaType: types.OCIManifestSchema1, Size: int64(len(raw))}
	index := v1.IndexManifest{SchemaVersion: 2, MediaType: types.OCIImageIndex, Manifests: []v1.Descriptor{child, child}}
	body, _ := json.Marshal(index)
	reads := 0
	read := func(got string) (string, []byte, error) {
		reads++
		if got != digest {
			t.Fatal(got)
		}
		return string(types.OCIManifestSchema1), raw, nil
	}
	metadata, err := DescribeManifest("registry.example", "team/app", "stable", string(types.OCIImageIndex), body, read)
	if err != nil || !metadata.Valid() || metadata.ImageBytes != 30 || reads != 1 || metadata.UploadedAtKnown {
		t.Fatal(metadata, err, reads)
	}
	index.Manifests[1].Size++
	bad, _ := json.Marshal(index)
	if _, err = DescribeManifest("registry.example", "team/app", "stable", string(types.OCIImageIndex), bad, read); err == nil {
		t.Fatal("inconsistent duplicate child accepted")
	}
	if _, err = DescribeManifest("registry.example", "team/app", "sha256:"+strings.Repeat("c", 64), string(types.OCIManifestSchema1), raw, nil); err == nil {
		t.Fatal("requested digest changed")
	}
	image.Layers[0].URLs = []string{"https://foreign.example/layer"}
	bad, _ = json.Marshal(image)
	if _, err = DescribeManifest("registry.example", "team/app", "stable", string(types.OCIManifestSchema1), bad, nil); err == nil {
		t.Fatal("foreign layer descriptor accepted")
	}
}
