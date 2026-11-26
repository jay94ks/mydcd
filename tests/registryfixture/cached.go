// SPDX-License-Identifier: Apache-2.0

package registryfixture

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Cached serves explicitly pre-provisioned, content-addressed real app images.
// It does no download/build/import. Both private Engines pull the same bytes
// through the real Registry V2 SDK path.
type Cached struct {
	Registry            string
	References, Configs map[string]string
	server              *httptest.Server
}

// Close stops only this owned input server, before host rollback comparison.
func (f *Cached) Close() { f.server.Close() }

func OpenCached(t *testing.T, listen, root string) *Cached {
	t.Helper()
	return openCached(t, listen, root, []string{"php", "mysql"})
}

// OpenCompilerCached serves an explicitly assembled local compiler image.
// Image import remains an explicit fixture preparation step, not a daemon job.
func OpenCompilerCached(t *testing.T, listen, root string) *Cached {
	t.Helper()
	return openCached(t, listen, root, []string{"lifecycle-compiler"})
}

func openCached(t *testing.T, listen, root string, repositories []string) *Cached {
	t.Helper()
	if !filepath.IsAbs(root) {
		t.Fatal("explicit absolute image cache required")
	}
	var metadata struct {
		Schema uint8
		Images []struct{ Repository, Digest, Config string }
	}
	raw, err := os.ReadFile(filepath.Join(root, "images.json"))
	if err != nil || json.Unmarshal(raw, &metadata) != nil || metadata.Schema != 1 || len(metadata.Images) != len(repositories) {
		t.Fatal("prepared real image metadata", err)
	}
	type descriptor struct {
		Digest, MediaType string
		Size              int64
	}
	type image struct {
		raw    []byte
		media  string
		blobs  map[string]descriptor
		digest string
	}
	images := map[string]image{}
	for _, row := range metadata.Images {
		allowed := false
		for _, repository := range repositories {
			allowed = allowed || row.Repository == repository
		}
		if _, duplicate := images[row.Repository]; !allowed || duplicate {
			t.Fatal("unexpected cached image")
		}
		b, err := os.ReadFile(filepath.Join(root, row.Repository+"-manifest.json"))
		if err != nil || fmt.Sprintf("sha256:%x", sha256.Sum256(b)) != row.Digest {
			t.Fatal("prepared image digest", err)
		}
		var m struct {
			SchemaVersion int
			MediaType     string
			Config        descriptor
			Layers        []descriptor
		}
		if json.Unmarshal(b, &m) != nil || m.SchemaVersion != 2 || m.Config.Digest != row.Config {
			t.Fatal("prepared manifest")
		}
		v := image{raw: b, media: m.MediaType, digest: row.Digest, blobs: map[string]descriptor{}}
		for _, d := range append(m.Layers, m.Config) {
			if len(d.Digest) != 71 || !strings.HasPrefix(d.Digest, "sha256:") || strings.ContainsAny(d.Digest[7:], "/\\") || d.Size < 1 || d.Size > 512<<20 {
				t.Fatal("prepared blob descriptor")
			}
			f, e := os.Open(filepath.Join(root, "blobs/sha256", d.Digest[7:]))
			if e != nil {
				t.Fatal(e)
			}
			h := sha256.New()
			n, e := io.Copy(h, f)
			_ = f.Close()
			if e != nil || n != d.Size || fmt.Sprintf("sha256:%x", h.Sum(nil)) != d.Digest {
				t.Fatal("prepared blob integrity", e)
			}
			v.blobs[d.Digest] = d
		}
		images[row.Repository] = v
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
		if r.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		p := strings.Split(r.URL.Path, "/")
		if len(p) != 5 || p[1] != "v2" {
			http.NotFound(w, r)
			return
		}
		v, ok := images[p[2]]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if p[3] == "manifests" && p[4] == v.digest {
			w.Header().Set("Content-Type", v.media)
			w.Header().Set("Docker-Content-Digest", v.digest)
			w.Header().Set("Content-Length", fmt.Sprint(len(v.raw)))
			if r.Method == http.MethodGet {
				_, _ = w.Write(v.raw)
			}
			return
		}
		if p[3] == "blobs" {
			if d, ok := v.blobs[p[4]]; ok {
				f, e := os.Open(filepath.Join(root, "blobs/sha256", d.Digest[7:]))
				if e != nil {
					http.NotFound(w, r)
					return
				}
				defer f.Close()
				w.Header().Set("Content-Type", "application/octet-stream")
				w.Header().Set("Docker-Content-Digest", d.Digest)
				w.Header().Set("Content-Length", fmt.Sprint(d.Size))
				if r.Method == http.MethodGet {
					_, _ = io.Copy(w, f)
				}
				return
			}
		}
		http.NotFound(w, r)
	}))
	server.Listener, err = net.Listen("tcp4", listen)
	if err != nil {
		t.Fatal(err)
	}
	server.Start()
	t.Cleanup(server.Close)
	f := &Cached{Registry: server.Listener.Addr().String(), References: map[string]string{}, Configs: map[string]string{}, server: server}
	for _, row := range metadata.Images {
		f.References[row.Repository] = f.Registry + "/" + row.Repository + "@" + row.Digest
		f.Configs[f.References[row.Repository]] = row.Config
	}
	return f
}
