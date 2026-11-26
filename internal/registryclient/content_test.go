// SPDX-License-Identifier: Apache-2.0

package registryclient

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	oci "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

func TestContentSelectionRequiresImmutableDescriptorAndKeepsTenGiBBoundary(t *testing.T) {
	manifest := v1.Manifest{SchemaVersion: 2, MediaType: types.OCIManifestSchema1, Config: v1.Descriptor{Digest: v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("a", 64)}, MediaType: types.OCIConfigJSON}, Layers: []v1.Descriptor{{Digest: v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("b", 64)}, MediaType: types.OCILayer, Size: MaxImageBytes}}}
	raw, _ := json.Marshal(manifest)
	ref := fmt.Sprintf("registry.example/team/app@sha256:%x", sha256.Sum256(raw))
	q := ContentQuery{Ref: ref, Kind: "layer", Digest: manifest.Layers[0].Digest.String()}
	info, err := SelectContent(q, string(manifest.MediaType), raw)
	if err != nil || !info.Valid(q) || info.Bytes != 10<<30 {
		t.Fatal("10GiB descriptor boundary", info, err)
	}
	for _, edit := range []func(*ContentQuery){
		func(q *ContentQuery) { q.Ref = "registry.example/team/app:latest" },
		func(q *ContentQuery) { q.Digest = "sha256:" + strings.Repeat("c", 64) },
		func(q *ContentQuery) { q.Kind = "config" },
		func(q *ContentQuery) { q.Kind = "arbitrary-path" },
	} {
		bad := q
		edit(&bad)
		if _, err = SelectContent(bad, string(manifest.MediaType), raw); err == nil {
			t.Fatal("unwitnessed content accepted", bad)
		}
	}
	manifest.Layers[0].Size++
	raw, _ = json.Marshal(manifest)
	q.Ref = fmt.Sprintf("registry.example/team/app@sha256:%x", sha256.Sum256(raw))
	if _, err = SelectContent(q, string(manifest.MediaType), raw); err == nil {
		t.Fatal("image byte limit widened")
	}
	manifest.Layers[0].Size = 1
	manifest.Layers[0].URLs = []string{"https://foreign.example/private"}
	raw, _ = json.Marshal(manifest)
	q.Ref = fmt.Sprintf("registry.example/team/app@sha256:%x", sha256.Sum256(raw))
	if _, err = SelectContent(q, string(manifest.MediaType), raw); err == nil {
		t.Fatal("foreign descriptor URL accepted")
	}
}

func TestExternalContentUsesPrivateSDKAndRefusesUnrelatedBlobBeforeIO(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	backend := oci.New(oci.Logger(log.New(io.Discard, "", 0)))
	var blobs atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if !ok || user != "reader" || password != "private-content-test" {
			w.Header().Set("WWW-Authenticate", `Basic realm="private"`)
			w.WriteHeader(401)
			return
		}
		if r.Method == "GET" && strings.Contains(r.URL.Path, "/blobs/") {
			blobs.Add(1)
		}
		backend.ServeHTTP(w, r)
	}))
	defer server.Close()
	authority := strings.TrimPrefix(server.URL, "https://")
	image, err := random.Image(64<<10, 1)
	if err != nil {
		t.Fatal(err)
	}
	tag, err := name.NewTag(authority+"/team/app:stable", name.StrictValidation)
	if err != nil {
		t.Fatal(err)
	}
	if err = remote.Write(tag, image, remote.WithContext(ctx), remote.WithAuth(authn.FromConfig(authn.AuthConfig{Username: "reader", Password: "private-content-test"})), remote.WithTransport(server.Client().Transport), remote.WithJobs(1)); err != nil {
		t.Fatal(err)
	}
	digest, err := image.Digest()
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := image.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	client, err := New(authority, []byte("reader"), []byte("private-content-test"), ca)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ref := authority + "/team/app@" + digest.String()
	for _, q := range []ContentQuery{{Ref: ref, Kind: "manifest"}, {Ref: ref, Kind: "config", Digest: manifest.Config.Digest.String()}, {Ref: ref, Kind: "layer", Digest: manifest.Layers[0].Digest.String()}} {
		info, body, err := client.OpenContent(ctx, q)
		if err != nil {
			t.Fatal(q, err)
		}
		raw, err := io.ReadAll(io.LimitReader(body, MaxMetadataBytes+1))
		closeErr := body.Close()
		if err != nil || closeErr != nil || !info.Valid(q) || int64(len(raw)) != info.Bytes || fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) != info.Digest {
			t.Fatal("actual immutable content", q, info, err, closeErr)
		}
	}
	before := blobs.Load()
	if _, body, err := client.OpenContent(ctx, ContentQuery{Ref: ref, Kind: "layer", Digest: "sha256:" + strings.Repeat("f", 64)}); err == nil || body != nil || ResultCode(err) != "NOT_FOUND" || blobs.Load() != before {
		t.Fatal("arbitrary repository blob fetched", body, err, blobs.Load(), before)
	}
}
