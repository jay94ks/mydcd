// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/registryclient"
	bkclient "github.com/moby/buildkit/client"
)

func TestSDKOptionsUseOriginalReferenceFrozenSourcesAndExplicitFDStores(t *testing.T) {
	spec, _ := testJobSpec(t)
	input, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	inputs := []FrozenSource{{Source: Source{Reference: "docker.io/library/alpine:latest", Platform: "linux/amd64", Kind: "from", Stage: 0}, Image: "docker.io/library/alpine@sha256:" + strings.Repeat("a", 64)}}
	auth, err := NewBuildKitPullAuth(spec, inputs, func(context.Context) error { return nil }, func(context.Context, []Source, registryclient.PullTokenChallenge) (registryclient.PullToken, error) {
		return registryclient.PullToken{}, ErrSourceFetch
	})
	if err != nil {
		t.Fatal(err)
	}
	defer auth.Close()
	options, err := buildKitSolveOptions(context.Background(), spec, inputs, input, input, output, auth, false)
	if err != nil {
		t.Fatal(err)
	}
	id := spec.Digest()
	if options.Ref != hex.EncodeToString(id[:]) || options.Frontend != "dockerfile.v0" || options.FrontendAttrs["filename"] != spec.Scope.Dockerfile || options.FrontendAttrs["build-arg:PUBLIC"] != "value" || options.SourcePolicy == nil || len(options.SourcePolicy.Rules) != 3 || len(options.Session) != 2 || len(options.AllowedEntitlements) != 0 || options.LocalMounts["context"] == nil || options.LocalMounts["dockerfile"] == nil {
		t.Fatal("SDK options broadened sources or lost original solve identity")
	}
	if len(options.Exports) != 1 || options.Exports[0].Type != bkclient.ExporterOCI || options.Exports[0].Attrs["tar"] != "false" || !strings.HasPrefix(options.Exports[0].OutputDir, "/proc/self/fd/") {
		t.Fatal("SDK OCI output escaped held original directory")
	}
}

func TestSDKSourceContentOptionsKeepFrontendAndBindOriginalStores(t *testing.T) {
	spec, _ := testJobSpec(t)
	input, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	inputs := []FrozenSource{{Source: Source{Reference: "registry.example/team/app:latest", Platform: "linux/amd64", Kind: "from"}, Image: "registry.example/team/app@sha256:" + strings.Repeat("b", 64)}}
	reads := 0
	auth, err := NewBuildKitSourceAuth(spec, inputs, func(context.Context) error { return nil }, func(context.Context, []Source, registryclient.PullTokenChallenge) (registryclient.PullToken, error) {
		return registryclient.PullToken{}, ErrSourceFetch
	}, func(context.Context, Source, registryclient.GraphContentQuery, io.Writer) (registryclient.ContentInfo, error) {
		reads++
		return registryclient.ContentInfo{}, ErrSourceFetch
	})
	if err != nil {
		t.Fatal(err)
	}
	defer auth.Close()
	options, err := buildKitSolveOptions(context.Background(), spec, inputs, input, input, output, auth, true)
	if err != nil {
		t.Fatal(err)
	}
	defer closeSourceStores(options.OCIStores)
	if options.Frontend != "dockerfile.v0" || len(options.OCIStores) != 1 || options.OCIStores[sourceContentStoreID(inputs[0].Image)] == nil || len(options.SourcePolicy.Rules) != 5 || len(options.Session) != 2 || len(options.FrontendAttrs) != 3 || reads != 0 {
		t.Fatal("owner stores rewrote frontend, fetched early or lost exact policy")
	}
	legacy, err := buildKitSolveOptions(context.Background(), spec, inputs, input, input, output, auth, false)
	if err != nil || len(legacy.OCIStores) != 0 || len(legacy.SourcePolicy.Rules) != 3 {
		t.Fatal("original SDK mode changed", err)
	}
}

func TestSDKReadinessRequiresPinnedServerBeforeSendingSourcePolicy(t *testing.T) {
	if buildKitCompatible(nil) || buildKitCompatible(&bkclient.Info{}) || buildKitCompatible(&bkclient.Info{BuildkitVersion: bkclient.BuildkitVersion{Package: "github.com/moby/buildkit", Version: "v0.10.0"}}) || buildKitCompatible(&bkclient.Info{BuildkitVersion: bkclient.BuildkitVersion{Package: "foreign", Version: "v0.35.1"}}) {
		t.Fatal("unidentified server could ignore source-policy fields")
	}
	if !buildKitCompatible(&bkclient.Info{BuildkitVersion: bkclient.BuildkitVersion{Package: "github.com/moby/buildkit", Version: "v0.35.1"}}) {
		t.Fatal("pinned server rejected")
	}
}
