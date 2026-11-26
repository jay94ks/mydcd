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
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func TestExternalPruneUsesLiveAuthenticatedCatalogueAndRefusesChangedAliases(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	server := httptest.NewTLSServer(oci.New(oci.Logger(log.New(io.Discard, "", 0))))
	defer server.Close()
	authority := strings.TrimPrefix(server.URL, "https://")
	image, err := random.Image(64, 1)
	if err != nil {
		t.Fatal(err)
	}
	options := []remote.Option{remote.WithContext(ctx), remote.WithTransport(server.Client().Transport), remote.WithJobs(1)}
	write := func(repo, tag string) {
		t.Helper()
		ref, err := name.NewTag(authority+"/"+repo+":"+tag, name.StrictValidation)
		if err != nil {
			t.Fatal(err)
		}
		if err = remote.Write(ref, image, options...); err != nil {
			t.Fatal(err)
		}
	}
	write("team/app", "old")
	write("foreign/app", "hidden")
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	client, err := New(authority, nil, nil, ca)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	allow := func(repo string) bool { return repo == "team/app" }
	in, err := client.PruneInventory(ctx, PruneConditions{}, allow, nil)
	if err != nil || !in.Live || in.UntaggedComplete || in.PhysicalComplete || len(in.Images) != 1 || in.Images[0].Repository != "team/app" {
		t.Fatal(in, err)
	}
	preview, err := BuildPrunePreview(in, PruneConditions{})
	if err != nil || len(preview.Items) != 1 || preview.EstimateKnown || !preview.Live {
		t.Fatal(preview, err)
	}
	if same, err := client.CheckPruneAliases(ctx, preview.Items[0]); err != nil || !same {
		t.Fatal("original aliases changed", same, err)
	}
	write("team/app", "new")
	if same, err := client.CheckPruneAliases(ctx, preview.Items[0]); err != nil || same {
		t.Fatal("new alias silently adopted", same, err)
	}
	if _, err = client.PruneInventory(ctx, PruneConditions{IncludeUntagged: true}, allow, nil); err == nil || ResultCode(err) != "UNSUPPORTED" {
		t.Fatal("partial untagged success", err)
	}
	if _, err = client.PruneInventory(ctx, PruneConditions{Repositories: []string{"foreign/app"}}, allow, nil); err == nil || ResultCode(err) != "DENIED" {
		t.Fatal("foreign repo admitted", err)
	}
	in, err = client.PruneInventory(ctx, PruneConditions{}, allow, func(ImageMetadata) string { return "IMAGE_IN_USE" })
	if err != nil {
		t.Fatal(err)
	}
	preview, err = BuildPrunePreview(in, PruneConditions{})
	if err != nil || len(preview.Items) != 0 || len(preview.Retained) != 2 {
		t.Fatal("common protection lost", preview, err)
	}
	client.Close()
	if _, err = client.PruneInventory(ctx, PruneConditions{}, allow, nil); err == nil || ResultCode(err) != "CLOSED" {
		t.Fatal("closed source issued fresh enumeration", err)
	}
}
