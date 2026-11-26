// SPDX-License-Identifier: Apache-2.0

package registryclient

import (
	"encoding/json"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

func TestManifestResolutionSharedParserBindsRootDigestAndPlatformDescriptors(t *testing.T) {
	image, err := random.Image(1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	body, err := image.RawManifest()
	if err != nil {
		t.Fatal(err)
	}
	media, err := image.MediaType()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := image.Digest()
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := ResolveManifest("ghcr.io/team/app:current", string(media), body)
	if err != nil || resolved.Digest != digest.String() || !resolved.Valid("ghcr.io/team/app:current") {
		t.Fatal("root content identity", resolved, err)
	}
	if _, err = ResolveManifest("ghcr.io/team/app@sha256:"+strings.Repeat("a", 64), string(media), body); err == nil {
		t.Fatal("requested immutable digest substituted")
	}
	index := v1.IndexManifest{SchemaVersion: 2, MediaType: types.OCIImageIndex, Manifests: []v1.Descriptor{{Digest: digest, Size: int64(len(body)), MediaType: media, Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}}}}
	encoded, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	multi, err := ResolveManifest("ghcr.io/team/app:multi", string(types.OCIImageIndex), encoded)
	if err != nil || len(multi.Platforms) != 1 || multi.Platforms[0].Digest != digest.String() || multi.Platforms[0].Platform.OS != "linux" || multi.Digest == digest.String() {
		t.Fatal("index flattened or platform pin lost", multi, err)
	}
	for _, test := range []struct {
		media string
		body  []byte
	}{
		{string(types.OCIImageIndex), body},
		{string(media), []byte(`{"schemaVersion":1}`)},
		{"application/octet-stream", body},
		{string(media), []byte(strings.Repeat(" ", int(MaxMetadataBytes)+1))},
	} {
		if _, err = ResolveManifest("ghcr.io/team/app:current", test.media, test.body); err == nil {
			t.Fatal("invalid or oversized metadata accepted")
		}
	}
}
