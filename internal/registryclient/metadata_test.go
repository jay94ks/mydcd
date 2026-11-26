// SPDX-License-Identifier: Apache-2.0

package registryclient

import (
	"context"
	"encoding/pem"
	"io"
	"log"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	oci "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func TestNormalizeImageForResolutionRejectsLocalIDsAndKeepsDigestPins(t *testing.T) {
	for _, test := range []struct{ raw, normalized, authority, repository string }{
		{"alpine", "docker.io/library/alpine:latest", "docker.io", "library/alpine"},
		{"docker.io/team/app:release", "docker.io/team/app:release", "docker.io", "team/app"},
		{"ghcr.io/team/app@sha256:" + strings.Repeat("a", 64), "ghcr.io/team/app@sha256:" + strings.Repeat("a", 64), "ghcr.io", "team/app"},
	} {
		n, a, r, err := Normalize(test.raw)
		if err != nil || n != test.normalized || a != test.authority || r != test.repository {
			t.Fatal(test.raw, n, a, r, err)
		}
	}
	for _, raw := range []string{"sha256:" + strings.Repeat("a", 64), strings.Repeat("a", 64), "https://registry.example/team/app", "ghcr.io/team/app\n", "ghcr.io/team/app@sha256:abc"} {
		if _, _, _, err := Normalize(raw); err == nil {
			t.Fatal("invalid resolution target", raw)
		}
	}
}

// Actual index/tag protocol and per-platform digest projection. No Docker
// execution or deploy trust is asserted by this metadata-only fixture.
func TestResolveManifestListPreservesRootAndPlatformDigests(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server := httptest.NewTLSServer(oci.New(oci.Logger(log.New(io.Discard, "", 0))))
	defer server.Close()
	authority := strings.TrimPrefix(server.URL, "https://")
	image, err := random.Image(1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	config, err := image.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	copy := *config
	copy.Architecture = "arm64"
	copy.OS = "linux"
	arm, err := mutate.ConfigFile(image, &copy)
	if err != nil {
		t.Fatal(err)
	}
	index := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: image, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}}},
		mutate.IndexAddendum{Add: arm, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "arm64"}}})
	tag, err := name.NewTag(authority+"/team/multi:latest", name.StrictValidation)
	if err != nil {
		t.Fatal(err)
	}
	if err = remote.WriteIndex(tag, index, remote.WithContext(ctx), remote.WithTransport(server.Client().Transport), remote.WithJobs(1)); err != nil {
		t.Fatal(err)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	a, err := New(authority, nil, nil, ca)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	result, err := a.Resolve(ctx, tag.String())
	if err != nil {
		t.Fatal(err)
	}
	digest, err := index.Digest()
	if err != nil {
		t.Fatal(err)
	}
	amdDigest, err := image.Digest()
	if err != nil {
		t.Fatal(err)
	}
	armDigest, err := arm.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if result.Digest != digest.String() || len(result.Platforms) != 2 || result.Platforms[0].Digest != amdDigest.String() || result.Platforms[1].Digest != armDigest.String() || result.Platforms[1].Platform == nil || result.Platforms[1].Platform.Architecture != "arm64" {
		t.Fatal("index flattened or platform pin lost", result)
	}
}
