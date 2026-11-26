// SPDX-License-Identifier: Apache-2.0

package registryclient

import (
	"context"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	oci "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// Real TLS/OCI requests with in-memory storage; this is not Docker unpack or a
// live tenant Vault test. Layer bodies must not be downloaded by a rights probe.
func TestPullProbeChecksPinnedConfigAndBlobHeadsWithoutDownloadingLayers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	backend := oci.New(oci.Logger(log.New(io.Discard, "", 0)))
	var denyHeads atomic.Bool
	var layerGets, heads atomic.Int32
	var layerPath string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/blobs/") && r.Method == http.MethodHead {
			heads.Add(1)
			if denyHeads.Load() {
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}
		if r.Method == http.MethodGet && r.URL.Path == layerPath {
			layerGets.Add(1)
		}
		backend.ServeHTTP(w, r)
	}))
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
	config.OS, config.Architecture = "linux", "amd64"
	image, err = mutate.ConfigFile(image, config)
	if err != nil {
		t.Fatal(err)
	}
	layers, err := image.Layers()
	if err != nil {
		t.Fatal(err)
	}
	layerDigest, err := layers[0].Digest()
	if err != nil {
		t.Fatal(err)
	}
	layerPath = "/v2/team/app/blobs/" + layerDigest.String()
	tag, err := name.NewTag(authority+"/team/app:current", name.StrictValidation)
	if err != nil {
		t.Fatal(err)
	}
	if err = remote.Write(tag, image, remote.WithContext(ctx), remote.WithTransport(server.Client().Transport), remote.WithJobs(1)); err != nil {
		t.Fatal(err)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	client, err := New(authority, nil, nil, ca)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	resolved, err := client.Resolve(ctx, tag.String())
	if err != nil {
		t.Fatal(err)
	}
	before := heads.Load()
	result, err := client.CheckPull(ctx, resolved, v1.Platform{OS: "linux", Architecture: "amd64"})
	if err != nil || !result.Valid(resolved) || result.Blobs != 2 || heads.Load() != before+1 || layerGets.Load() != 0 {
		t.Fatal("incomplete or excessive rights probe", result, err, heads.Load(), layerGets.Load())
	}
	wrong := resolved
	wrong.Digest = "sha256:" + strings.Repeat("a", 64)
	wrong.Pinned = authority + "/team/app@" + wrong.Digest
	if wrong.Valid(resolved.Pinned) {
		t.Fatal("requested digest substituted")
	}
	denyHeads.Store(true)
	if _, err = client.CheckPull(ctx, resolved, v1.Platform{OS: "linux", Architecture: "amd64"}); err == nil || err.Error() != "DENIED" {
		t.Fatal("manifest access concealed layer denial", err)
	}
	if layerGets.Load() != 0 {
		t.Fatal("permission test downloaded layer body")
	}
}
