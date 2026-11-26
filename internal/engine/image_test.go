// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/client"
)

func TestRealBoundaryRegistryDigestPull(t *testing.T) {
	owner := os.Getenv("MYDC_REGISTRY_TEST_OWNER")
	if owner == "" {
		t.Skip("requires explicit owner and docs/testing/r5-final.md registry rollback prestate")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := Open(ctx, "unix:///var/run/docker.sock", owner)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	digest := func(b []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(b)) }
	var layer bytes.Buffer
	tw := tar.NewWriter(&layer)
	if err = tw.WriteHeader(&tar.Header{Name: "registry-proof", Mode: 0644, Size: int64(len(owner))}); err != nil {
		t.Fatal(err)
	}
	if _, err = tw.Write([]byte(owner)); err != nil {
		t.Fatal(err)
	}
	if err = tw.Close(); err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err = zw.Write(layer.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	config, err := json.Marshal(map[string]any{
		"architecture": runtime.GOARCH, "os": "linux",
		"config": map[string]any{"Labels": map[string]string{"org.mydc.test.owner": owner}},
		"rootfs": map[string]any{"type": "layers", "diff_ids": []string{digest(layer.Bytes())}},
	})
	if err != nil {
		t.Fatal(err)
	}
	id := digest(config)
	descriptor := func(media string, b []byte) map[string]any {
		return map[string]any{"mediaType": media, "size": len(b), "digest": digest(b)}
	}
	const media = "application/vnd.docker.distribution.manifest.v2+json"
	manifest, err := json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": media,
		"config": descriptor("application/vnd.docker.container.image.v1+json", config),
		"layers": []any{descriptor("application/vnd.docker.image.rootfs.diff.tar.gzip", compressed.Bytes())},
	})
	if err != nil {
		t.Fatal(err)
	}
	var manifests, configs, layers atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
		var b []byte
		switch r.URL.Path {
		case "/v2/":
			w.WriteHeader(http.StatusOK)
			return
		case "/v2/proof/manifests/" + digest(manifest):
			manifests.Add(1)
			b = manifest
			w.Header().Set("Content-Type", media)
		case "/v2/proof/blobs/" + id:
			configs.Add(1)
			b = config
		case "/v2/proof/blobs/" + digest(compressed.Bytes()):
			layers.Add(1)
			b = compressed.Bytes()
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":[{"code":"MANIFEST_UNKNOWN","message":"absent"}]}`))
			return
		}
		w.Header().Set("Docker-Content-Digest", digest(b))
		w.Header().Set("Content-Length", fmt.Sprint(len(b)))
		if r.Method != http.MethodHead {
			_, _ = w.Write(b)
		}
	}))
	defer server.Close()
	ref := strings.TrimPrefix(server.URL, "http://") + "/proof@" + digest(manifest)
	for _, name := range []string{id, ref} {
		if _, err = c.API.ImageInspect(ctx, name); !cerrdefs.IsNotFound(err) {
			t.Fatal("fixture image must be initially absent", name, err)
		}
	}
	t.Logf("owner=%s config=%s ref=%s", owner, id, ref)
	defer func() {
		clean, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		im, e := c.API.ImageInspect(clean, ref)
		if !cerrdefs.IsNotFound(e) {
			if e != nil || im.Config == nil || im.Config.Labels["org.mydc.test.owner"] != owner {
				t.Error("rollback exact image owner", e)
				return
			}
			if _, e = c.API.ImageRemove(clean, im.ID, client.ImageRemoveOptions{}); e != nil {
				t.Error("rollback exact image", e)
			}
		}
		for _, name := range []string{id, ref} {
			if _, e = c.API.ImageInspect(clean, name); !cerrdefs.IsNotFound(e) {
				t.Error("registry image remains", name, e)
			}
		}
	}()
	if _, err = c.Image(ctx, ref, false); !cerrdefs.IsNotFound(err) || manifests.Load() != 0 {
		t.Fatal("pull=false contacted registry or hid absence", err)
	}
	if _, err = c.Image(ctx, strings.Split(ref, "@")[0]+":latest", true); err != ErrOwnership || manifests.Load() != 0 {
		t.Fatal("mutable tag accepted", err)
	}
	im, err := c.Image(ctx, ref, true)
	if err != nil || im.ID == "" || im.Config == nil || im.Config.Labels["org.mydc.test.owner"] != owner || !slices.Contains(im.RepoDigests, ref) || !slices.Equal(im.RootFS.Layers, []string{digest(layer.Bytes())}) {
		t.Fatal("actual digest pull/inspect", im.ID, err)
	}
	if manifests.Load() == 0 || configs.Load() == 0 || layers.Load() == 0 {
		t.Fatal("registry manifest/config/layer were not transferred")
	}
	before := manifests.Load()
	nativeID := im.ID
	if im, err = c.Image(ctx, ref, false); err != nil || im.ID != nativeID || manifests.Load() != before {
		t.Fatal("local content-addressed image was not reused", err)
	}
	missing := strings.TrimPrefix(server.URL, "http://") + "/missing@" + digest([]byte(owner))
	if _, err = c.Image(ctx, missing, true); err == nil {
		t.Fatal("registry absence reported success")
	}
	if _, err = c.API.ImageInspect(ctx, missing); !cerrdefs.IsNotFound(err) {
		t.Fatal("failed pull published an image", err)
	}
	t.Logf("nativeID=%s actualRegistryTransfers manifest=%d config=%d layer=%d; local reuse/tag rejection/pull=false/remote absence passed", nativeID, manifests.Load(), configs.Load(), layers.Load())
}
