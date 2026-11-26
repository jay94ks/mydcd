// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	oci "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/jay94ks/mydcd/internal/registryclient"
)

// Actual HTTPS and Docker SDK UDS streaming, with a fake Engine load/inspect.
// Does not claim real Docker layer unpacking or a MyDC deployed container.
func TestExternalCAImageStreamsOriginalGraphAndInspectsVerifiedNativeID(t *testing.T) {
	for _, test := range []struct {
		name               string
		oci, native, index bool
	}{{"legacy-docker", false, false, false}, {"legacy-oci", true, false, false}, {"containerd-docker", false, true, false}, {"containerd-oci", true, true, false}, {"containerd-oci-index", true, true, true}} {
		t.Run(test.name, func(t *testing.T) { testExternalCAImageNativeID(t, test.oci, test.native, test.index) })
	}
}

func testExternalCAImageNativeID(t *testing.T, ociMedia, manifestID, sourceIndex bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	backend := oci.New(oci.Logger(log.New(io.Discard, "", 0)))
	var holdLayer, unauthorized, breakLayer atomic.Bool
	var layerDigest string
	var layerLength int
	layerEntered, layerEnded := make(chan struct{}), make(chan struct{})
	var enteredOnce, endedOnce sync.Once
	registry := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if unauthorized.Load() {
			w.Header().Set("WWW-Authenticate", `Basic realm="private"`)
			http.Error(w, "private-test-password-echo", http.StatusUnauthorized)
			return
		}
		if holdLayer.Load() && strings.Contains(r.URL.Path, "/blobs/") && strings.HasSuffix(r.URL.Path, layerDigest) {
			enteredOnce.Do(func() { close(layerEntered) })
			<-r.Context().Done()
			endedOnce.Do(func() { close(layerEnded) })
			return
		}
		if breakLayer.Load() && strings.Contains(r.URL.Path, "/blobs/") && strings.HasSuffix(r.URL.Path, layerDigest) {
			w.Header().Set("Content-Length", fmt.Sprint(layerLength))
			fmt.Fprint(w, "private-test-password-echo")
			return
		}
		backend.ServeHTTP(w, r)
	}))
	defer registry.Close()
	authority := strings.TrimPrefix(registry.URL, "https://")
	image, err := random.Image(1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	if ociMedia {
		layer, err := random.Layer(1024, types.OCILayer)
		if err != nil {
			t.Fatal(err)
		}
		image, err = mutate.AppendLayers(empty.Image, layer)
		if err != nil {
			t.Fatal(err)
		}
		image = mutate.ConfigMediaType(mutate.MediaType(image, types.OCIManifestSchema1), types.OCIConfigJSON)
	}
	tag, err := name.NewTag(authority+"/team/app:source", name.StrictValidation)
	if err != nil {
		t.Fatal(err)
	}
	if err = remote.Write(tag, image, remote.WithContext(ctx), remote.WithTransport(registry.Client().Transport), remote.WithJobs(1)); err != nil {
		t.Fatal(err)
	}
	digest, err := image.Digest()
	if err != nil {
		t.Fatal(err)
	}
	config, err := image.ConfigName()
	if err != nil {
		t.Fatal(err)
	}
	layers, err := image.Layers()
	if err != nil {
		t.Fatal(err)
	}
	layer, err := layers[0].Digest()
	if err != nil {
		t.Fatal(err)
	}
	layerDigest = layer.String()
	rawManifest, err := image.RawManifest()
	if err != nil {
		t.Fatal(err)
	}
	rawConfig, err := image.RawConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	layerBody, err := layers[0].Compressed()
	if err != nil {
		t.Fatal(err)
	}
	rawLayer, err := io.ReadAll(layerBody)
	closed := layerBody.Close()
	if err != nil || closed != nil {
		t.Fatal(err, closed)
	}
	layerLength = len(rawLayer)
	manifestMedia, err := image.MediaType()
	if err != nil {
		t.Fatal(err)
	}
	nativeID := config.String()
	if manifestID {
		nativeID = digest.String()
	}
	blobPath := func(h v1.Hash) string { return "blobs/sha256/" + h.Hex }
	expectedBlobs := map[string][]byte{blobPath(digest): rawManifest, blobPath(config): rawConfig, blobPath(layer): rawLayer}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: registry.Certificate().Raw})
	ref := authority + "/team/app@" + digest.String()
	if sourceIndex {
		index := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: image, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: runtime.GOOS, Architecture: runtime.GOARCH}}})
		if err := remote.WriteIndex(tag, index, remote.WithContext(ctx), remote.WithTransport(registry.Client().Transport), remote.WithJobs(1)); err != nil {
			t.Fatal(err)
		}
		indexDigest, err := index.Digest()
		if err != nil {
			t.Fatal(err)
		}
		if indexDigest == digest {
			t.Fatal("index fixture did not distinguish selected platform manifest")
		}
		ref = authority + "/team/app@" + indexDigest.String()
	}
	var loaded atomic.Bool
	var loadFailure atomic.Bool
	var wrongID, brokenResponse atomic.Bool
	var loads, pulls, afterLoad atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_ping" {
			w.Header().Set("API-Version", "1.56")
			fmt.Fprint(w, "OK")
			return
		}
		if strings.HasSuffix(r.URL.Path, "/images/create") {
			pulls.Add(1)
			http.Error(w, "daemon pull forbidden", 500)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/images/load") {
			loads.Add(1)
			if r.Header.Get("X-Registry-Auth") != "" {
				t.Error("credential sent to Docker load")
			}
			archive := tar.NewReader(r.Body)
			found := map[string]bool{}
			for {
				header, err := archive.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					if holdLayer.Load() || breakLayer.Load() {
						return
					}
					t.Error("archive", err)
					http.Error(w, "archive", 400)
					return
				}
				if found[header.Name] || header.Typeflag != tar.TypeReg {
					t.Error("duplicate or non-regular archive entry", header.Name)
					http.Error(w, "archive", 400)
					return
				}
				found[header.Name] = true
				body, err := io.ReadAll(archive)
				if err != nil {
					if holdLayer.Load() || breakLayer.Load() {
						return
					}
					t.Error("archive entry", err)
					return
				}
				if want, ok := expectedBlobs[header.Name]; ok {
					h := sha256.Sum256(body)
					if !bytes.Equal(body, want) || header.Size != int64(len(want)) || header.Name != fmt.Sprintf("blobs/sha256/%x", h) {
						t.Error("archive changed verified blob", header.Name)
						http.Error(w, "blob", 400)
						return
					}
					continue
				}
				switch header.Name {
				case "manifest.json":
					var manifest tarball.Manifest
					if json.Unmarshal(body, &manifest) != nil || len(manifest) != 1 || manifest[0].Config != blobPath(config) || len(manifest[0].RepoTags) != 0 || len(manifest[0].Layers) != 1 || manifest[0].Layers[0] != blobPath(layer) {
						t.Error("archive changed config or added mutable tags")
						http.Error(w, "manifest", 400)
						return
					}
				case "index.json":
					var index v1.IndexManifest
					if json.Unmarshal(body, &index) != nil || index.SchemaVersion != 2 || index.MediaType != types.OCIImageIndex || len(index.Manifests) != 1 || index.Manifests[0].Digest != digest || index.Manifests[0].Size != int64(len(rawManifest)) || index.Manifests[0].MediaType != manifestMedia || len(index.Manifests[0].Annotations) != 0 {
						t.Error("archive lost original platform manifest or introduced tag")
						http.Error(w, "index", 400)
						return
					}
				case "oci-layout":
					var layout struct {
						ImageLayoutVersion string `json:"imageLayoutVersion"`
					}
					if json.Unmarshal(body, &layout) != nil || layout.ImageLayoutVersion != "1.0.0" {
						t.Error("invalid OCI layout")
						return
					}
				default:
					t.Error("unrelated archive entry", header.Name)
					return
				}
			}
			if len(found) != 6 {
				t.Error("incomplete verified archive")
				http.Error(w, "incomplete", 400)
				return
			}
			if _, err := io.Copy(io.Discard, r.Body); err != nil {
				return
			}
			if loadFailure.Load() {
				fmt.Fprintln(w, `{"error":"private-test-password-echo","errorDetail":{"message":"private-test-password-echo"}}`)
				return
			}
			if brokenResponse.Load() {
				fmt.Fprintln(w, `{"stream":`)
				return
			}
			loaded.Store(true)
			// This deliberately unrelated ID must never select a local image.
			fmt.Fprintln(w, `{"stream":"Loaded image ID: sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}`)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/json") {
			if loaded.Load() && strings.HasSuffix(r.URL.Path, "/images/"+nativeID+"/json") {
				afterLoad.Add(1)
				id := nativeID
				if wrongID.Load() {
					id = "sha256:" + strings.Repeat("f", 64)
				}
				fmt.Fprintf(w, `{"Id":%q,"Config":{},"RepoDigests":[%q]}`, id, ref)
				return
			}
			w.WriteHeader(404)
			fmt.Fprint(w, `{"message":"not present"}`)
			return
		}
		http.NotFound(w, r)
	})
	root, err := os.MkdirTemp("", "mydc-external-image-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	listener, err := net.Listen("unix", filepath.Join(root, "engine.sock"))
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler}
	done := make(chan struct{})
	go func() { _ = server.Serve(listener); close(done) }()
	defer func() { _ = server.Close(); <-done }()
	engine, err := open(ctx, "unix://"+listener.Addr().String(), "external-ca-fixture", 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	auth, err := NewExternalRegistryAuth(authority, nil, nil, ca)
	if err != nil {
		t.Fatal(err)
	}
	var outcomes []registryclient.PullOutcome
	observe := func(event registryclient.PullOutcome) { outcomes = append(outcomes, event) }
	got, err := engine.ImageWithAuth(ctx, ref, true, auth.WithPullObserver(observe))
	if err != nil || got.ID != nativeID || loads.Load() != 1 || pulls.Load() != 0 || afterLoad.Load() == 0 {
		t.Fatal("verified import/native ID edge", got.ID, err, loads.Load(), pulls.Load(), afterLoad.Load())
	}
	if len(outcomes) != 1 || outcomes[0] != (registryclient.PullOutcome{Stage: "load", Code: "OK"}) {
		t.Fatal("successful actual load observation", outcomes)
	}
	// No canonical RepoDigest was fabricated by load. A fresh current input
	// reproves origin, finds the exact native ID and performs no second load.
	auth, err = NewExternalRegistryAuth(authority, nil, nil, ca)
	if err != nil {
		t.Fatal(err)
	}
	if got, err = engine.ImageWithAuth(ctx, ref, false, auth.WithPullObserver(observe)); err != nil || got.ID != nativeID || loads.Load() != 1 {
		t.Fatal("verified native cache not reused", got.ID, err, loads.Load())
	}
	if len(outcomes) != 1 {
		t.Fatal("cached image fabricated a pull success", outcomes)
	}
	wrongID.Store(true)
	auth, err = NewExternalRegistryAuth(authority, nil, nil, ca)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = engine.ImageWithAuth(ctx, ref, false, auth); !errors.Is(err, ErrOwnership) || loads.Load() != 1 {
		t.Fatal("different native ID with matching RepoDigest accepted", err, loads.Load())
	}
	wrongID.Store(false)
	loaded.Store(false)
	auth, err = NewExternalRegistryAuth(authority, nil, nil, ca)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = engine.ImageWithAuth(ctx, ref, false, auth); err == nil || loads.Load() != 1 {
		t.Fatal("pull=false imported missing native image", err, loads.Load())
	}
	loaded.Store(true)
	unauthorized.Store(true)
	auth, err = NewExternalRegistryAuth(authority, nil, nil, ca)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = engine.ImageWithAuth(ctx, ref, true, auth.WithPullObserver(observe)); err == nil || len(outcomes) != 2 || outcomes[1] != (registryclient.PullOutcome{Stage: "resolve", Code: "UNAUTHORIZED"}) {
		t.Fatal("actual pull authentication failure", err, outcomes)
	}
	unauthorized.Store(false)
	loaded.Store(false)
	wrongID.Store(true)
	auth, err = NewExternalRegistryAuth(authority, nil, nil, ca)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = engine.ImageWithAuth(ctx, ref, true, auth); !errors.Is(err, ErrOwnership) {
		t.Fatal("load log or RepoDigest accepted a different post-load native ID", err)
	}
	wrongID.Store(false)
	loaded.Store(false)
	loadFailure.Store(true)
	auth, err = NewExternalRegistryAuth(authority, nil, nil, ca)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = engine.ImageWithAuth(ctx, ref, true, auth.WithPullObserver(observe)); err == nil || err.Error() != "IMAGE_LOAD_FAILED" || strings.Contains(err.Error(), "private-test-password") {
		t.Fatal("Engine load error was ignored or exposed", err)
	}
	if len(outcomes) != 3 || outcomes[2] != (registryclient.PullOutcome{Stage: "load", Code: "IMAGE_LOAD_FAILED"}) {
		t.Fatal("actual load failure observation", outcomes)
	}
	loadFailure.Store(false)
	brokenResponse.Store(true)
	auth, err = NewExternalRegistryAuth(authority, nil, nil, ca)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = engine.ImageWithAuth(ctx, ref, true, auth); err == nil || err.Error() != "IMAGE_LOAD_FAILED" || loaded.Load() {
		t.Fatal("broken load response accepted", err)
	}
	brokenResponse.Store(false)
	breakLayer.Store(true)
	auth, err = NewExternalRegistryAuth(authority, nil, nil, ca)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = engine.ImageWithAuth(ctx, ref, true, auth); err == nil || loaded.Load() || strings.Contains(err.Error(), "private-test-password") {
		t.Fatal("broken upstream layer accepted or exposed provider bytes", err)
	}
	breakLayer.Store(false)
	holdLayer.Store(true)
	request, stop := context.WithCancel(ctx)
	defer stop()
	stopped := make(chan struct{})
	go func() {
		select {
		case <-layerEntered:
			stop()
		case <-request.Done():
		}
		close(stopped)
	}()
	auth, err = NewExternalRegistryAuth(authority, nil, nil, ca)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = engine.ImageWithAuth(request, ref, true, auth); err == nil {
		t.Fatal("cancelled blob import accepted")
	}
	<-stopped
	select {
	case <-layerEnded:
	case <-ctx.Done():
		t.Fatal("original upstream reader did not join after cancel")
	}
}
