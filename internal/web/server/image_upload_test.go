// SPDX-License-Identifier: Apache-2.0

package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ggcr "github.com/google/go-containerregistry/pkg/registry"

	"github.com/jay94ks/mydcd/internal/web/store"
)

// testRegistry is a distribution registry behind the bearer token flow the
// built-in registry uses (Basic username:credential at /token).
type testRegistry struct {
	srv    *httptest.Server
	tokens atomic.Int32
	seen   atomic.Value // last Basic password
}

func newTestRegistry(t *testing.T) *testRegistry {
	tr := &testRegistry{}
	inner := ggcr.New(ggcr.Logger(log.New(io.Discard, "", 0)))
	tr.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			u, p, ok := r.BasicAuth()
			if !ok || u == "" || !strings.HasPrefix(p, "mydc-fake-registry-login.") || !strings.HasPrefix(r.URL.Query().Get("scope"), "repository:shop/") {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			tr.seen.Store(p)
			tr.tokens.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"token": "bearer-" + u, "expires_in": 300})
			return
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer bearer-") {
			w.Header().Set("WWW-Authenticate", `Bearer realm="https://registry.mydc.local/token",service="registry.mydc.local"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(tr.srv.Close)
	return tr
}

type rewriteTransport struct{ host string }

func (rt rewriteTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.URL.Host, r.Host = rt.host, rt.host
	return http.DefaultTransport.RoundTrip(r)
}

func newRegistryFixture(t *testing.T) (*fixture, *testRegistry) {
	t.Helper()
	reg := newTestRegistry(t)
	st, err := store.Open(filepath.Join(t.TempDir(), "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	u, _ := url.Parse(reg.srv.URL)
	srv := New(Options{Client: strictFake(), Store: st, Logger: discardLogger(), DataDir: t.TempDir(),
		RegistryTransport: rewriteTransport{u.Host}, RegistryPlainHTTP: true})
	hs := httptest.NewServer(srv)
	t.Cleanup(hs.Close)
	jar, _ := cookiejar.New(nil)
	f := &fixture{t: t, store: st, srv: srv, http: hs}
	f.hc = hs.Client()
	f.hc.Jar = jar
	return f, reg
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

type tarFile struct {
	name string
	data []byte
}

func tarOf(files ...tarFile) []byte {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, f := range files {
		_ = tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.data)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(f.data)
	}
	tw.Close()
	return b.Bytes()
}

func gz(b []byte) []byte {
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	_, _ = zw.Write(b)
	zw.Close()
	return out.Bytes()
}

// ociArchive: one image (one gzip layer with two files and a whiteout)
// named shop/tool:1.0 in an OCI layout.
func ociArchive(t *testing.T) ([]byte, string, string) {
	layer := gz(tarOf(tarFile{"usr/bin/tool", []byte("#!/bin/sh\necho tool\n")}, tarFile{"etc/tool.conf", []byte("a=1\n")}, tarFile{"etc/.wh.old.conf", nil}))
	diff := tarOf(tarFile{"usr/bin/tool", []byte("#!/bin/sh\necho tool\n")}, tarFile{"etc/tool.conf", []byte("a=1\n")}, tarFile{"etc/.wh.old.conf", nil})
	cfg, _ := json.Marshal(map[string]any{"architecture": "amd64", "os": "linux",
		"rootfs":  map[string]any{"type": "layers", "diff_ids": []string{sha(diff)}},
		"history": []map[string]any{{"created_by": "COPY tool /usr/bin/tool"}, {"created_by": "CMD [\"tool\"]", "empty_layer": true}}})
	man, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": mediaOCIManifest,
		"config": map[string]any{"mediaType": mediaOCIConfig, "digest": sha(cfg), "size": len(cfg)},
		"layers": []any{map[string]any{"mediaType": mediaOCILayerGzip, "digest": sha(layer), "size": len(layer)}}})
	idx, _ := json.Marshal(map[string]any{"schemaVersion": 2, "manifests": []any{map[string]any{"mediaType": mediaOCIManifest, "digest": sha(man), "size": len(man),
		"annotations": map[string]string{"io.containerd.image.name": "docker.io/library/tool:1.0"}}}})
	blob := func(b []byte) tarFile { return tarFile{"blobs/sha256/" + strings.TrimPrefix(sha(b), "sha256:"), b} }
	return tarOf(tarFile{"oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}`)}, tarFile{"index.json", idx}, blob(cfg), blob(man), blob(layer)), sha(man), sha(layer)
}

func TestImageUploadPushTagLayers(t *testing.T) {
	f, reg := newRegistryFixture(t)
	fakeLogin(t, f, "alice")
	raw := func(method, path string, body []byte) (int, map[string]any) {
		t.Helper()
		req, _ := http.NewRequest(method, f.http.URL+path, bytes.NewReader(body))
		req.Header.Set("X-MyDC-Web", "1")
		res, err := f.hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(res.Body).Decode(&out)
		return res.StatusCode, out
	}
	base := "/api/v1/t/shop/registries/builtin"
	arch, manDigest, layerDigest := ociArchive(t)
	arch = gz(arch) // .tar.gz

	// Create, then send chunks out of order (resume = send what is missing).
	code, up := f.do("POST", base+"/uploads", map[string]any{"fileName": "tool.tar.gz", "bytes": len(arch)})
	if code != 201 || up["chunks"] != float64(1) {
		t.Fatalf("create: %d %v", code, up)
	}
	uid := up["id"].(string)
	if code, out := f.do("POST", base+"/uploads/"+uid+"/inspect", nil); code != 409 {
		t.Fatalf("inspect before chunks: %d %v", code, out)
	}
	if code, _ := raw("PUT", base+"/uploads/"+uid+"/chunks/0", arch[:10]); code != 400 {
		t.Fatalf("short chunk: %d", code)
	}
	if code, out := raw("PUT", base+"/uploads/"+uid+"/chunks/0", arch); code != 200 || out["received"] != float64(1) {
		t.Fatalf("chunk: %d %v", code, out)
	}
	if code, out := f.do("GET", base+"/uploads", nil); code != 200 || len(out["items"].([]any)) != 1 {
		t.Fatalf("list: %d %v", code, out)
	}
	wait := func(pred func(map[string]any) bool) map[string]any {
		t.Helper()
		for i := 0; i < 200; i++ {
			_, out := f.do("GET", base+"/uploads/"+uid, nil)
			if pred(out) {
				return out
			}
			time.Sleep(20 * time.Millisecond)
		}
		_, out := f.do("GET", base+"/uploads/"+uid, nil)
		t.Fatalf("timeout: %v", out)
		return nil
	}
	if code, out := f.do("POST", base+"/uploads/"+uid+"/inspect", nil); code != 202 {
		t.Fatalf("inspect: %d %v", code, out)
	}
	out := wait(func(o map[string]any) bool {
		s, _ := o["inspect"].(map[string]any)
		return s != nil && s["state"] != "running"
	})
	items := out["inspect"].(map[string]any)["items"].([]any)
	it := items[0].(map[string]any)
	if len(items) != 1 || it["kind"] != "image" || fmt.Sprint(it["platforms"]) != "[linux/amd64]" || fmt.Sprint(it["refs"]) != "[docker.io/library/tool:1.0]" {
		t.Fatalf("items: %v", out["inspect"])
	}

	// Push as shop/tool:1.0.
	code, out = f.do("POST", base+"/uploads/"+uid+"/push", map[string]any{"item": 0, "repository": "shop/tool", "tag": "1.0"})
	if code != 202 {
		t.Fatalf("push: %d %v", code, out)
	}
	out = wait(func(o map[string]any) bool {
		p, _ := o["push"].(map[string]any)
		return p != nil && (p["state"] == "done" || p["state"] == "failed")
	})
	p := out["push"].(map[string]any)
	if p["state"] != "done" || p["digest"] != manDigest || len(p["layers"].([]any)) != 2 {
		t.Fatalf("pushed: %v", p)
	}
	// The credential never reaches the browser or the web's records.
	if secret, _ := reg.seen.Load().(string); secret == "" || strings.Contains(fmt.Sprint(out), secret) {
		t.Fatalf("credential seen %q in %v", secret, out)
	} else {
		assertNowhere(t, f, secret)
	}

	// Pushing the same image again skips every blob.
	code, _ = f.do("POST", base+"/uploads/"+uid+"/push", map[string]any{"item": 0, "repository": "shop/tool", "tag": "1.0"})
	if code != 202 {
		t.Fatalf("again: %d", code)
	}
	out = wait(func(o map[string]any) bool {
		p, _ := o["push"].(map[string]any)
		return p != nil && p["state"] == "done"
	})
	for _, l := range out["push"].(map[string]any)["layers"].([]any) {
		if l.(map[string]any)["state"] != "skipped" {
			t.Fatalf("not skipped: %v", l)
		}
	}

	// Layer view.
	code, m := f.do("GET", base+"/images/manifest?repository=shop/tool&ref=1.0", nil)
	if code != 200 || m["digest"] != manDigest || len(m["layers"].([]any)) != 1 || m["layers"].([]any)[0].(map[string]any)["createdBy"] != "COPY tool /usr/bin/tool" || len(m["history"].([]any)) != 2 {
		t.Fatalf("manifest: %d %v", code, m)
	}
	code, lf := f.do("GET", base+"/images/layer?repository=shop/tool&digest="+layerDigest, nil)
	if code != 200 || len(lf["files"].([]any)) != 3 {
		t.Fatalf("layer: %d %v", code, lf)
	}
	wh := lf["files"].([]any)[2].(map[string]any)
	if wh["whiteout"] != true || wh["path"] != "/etc/old.conf" {
		t.Fatalf("whiteout: %v", wh)
	}
	// Cached list again; without a pull credential from mydcd the cache is
	// not served (alice only views payments).
	if code, _ := f.do("GET", base+"/images/layer?repository=shop/tool&digest="+layerDigest, nil); code != 200 {
		t.Fatalf("cached: %d", code)
	}
	if code, out := f.do("GET", "/api/v1/t/payments/registries/builtin/images/layer?repository=payments/tool&digest="+layerDigest, nil); code != 403 {
		t.Fatalf("no credential: %d %v", code, out)
	}
	if code, out := f.do("GET", base+"/images/layer?repository=shop/tool&digest=sha256:"+strings.Repeat("1", 64), nil); code != 404 {
		t.Fatalf("missing layer: %d %v", code, out)
	}

	// Tag add, and a tag that points at another image.
	if code, out := f.do("POST", base+"/images/tag", map[string]any{"repository": "shop/tool", "digest": manDigest, "tag": "stable"}); code != 200 {
		t.Fatalf("tag: %d %v", code, out)
	}
	if code, m := f.do("GET", base+"/images/manifest?repository=shop/tool&ref=stable", nil); code != 200 || m["digest"] != manDigest {
		t.Fatalf("tagged: %d %v", code, m)
	}
	code, out = f.do("POST", base+"/images/tag", map[string]any{"repository": "shop/tool", "digest": "sha256:" + strings.Repeat("0", 64), "tag": "stable"})
	if code != 409 || out["current"] != manDigest || out["usage"] == nil {
		t.Fatalf("conflict: %d %v", code, out)
	}

	// Bob (viewer) cannot start an upload; nobody else sees alice's.
	bobLogin(t, f)
	if code, _ := f.do("POST", base+"/uploads", map[string]any{"fileName": "x.tar", "bytes": 10}); code != 403 {
		t.Fatalf("viewer upload: %d", code)
	}
	if code, _ := f.do("GET", base+"/uploads/"+uid, nil); code != 404 {
		t.Fatalf("bob sees alice's upload: %d", code)
	}
	fakeLogin(t, f, "alice")
	if code, _ := f.do("DELETE", base+"/uploads/"+uid, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if code, _ := f.do("GET", base+"/uploads/"+uid, nil); code != 404 {
		t.Fatalf("deleted: %d", code)
	}
}

func TestLegacyDockerSave(t *testing.T) {
	f, _ := newRegistryFixture(t)
	fakeLogin(t, f, "alice")
	layer := tarOf(tarFile{"app/run", []byte("run\n")})
	cfg, _ := json.Marshal(map[string]any{"architecture": "arm64", "os": "linux", "rootfs": map[string]any{"type": "layers", "diff_ids": []string{sha(layer)}}})
	manifest, _ := json.Marshal([]any{map[string]any{"Config": "cfg.json", "RepoTags": []string{"legacy:2"}, "Layers": []string{"abc/layer.tar"}}})
	arch := tarOf(tarFile{"manifest.json", manifest}, tarFile{"cfg.json", cfg}, tarFile{"abc/layer.tar", layer})
	base := "/api/v1/t/shop/registries/builtin"
	_, up := f.do("POST", base+"/uploads", map[string]any{"fileName": "legacy.tar", "bytes": len(arch)})
	uid := up["id"].(string)
	req, _ := http.NewRequest("PUT", f.http.URL+base+"/uploads/"+uid+"/chunks/0", bytes.NewReader(arch))
	req.Header.Set("X-MyDC-Web", "1")
	if res, err := f.hc.Do(req); err != nil || res.StatusCode != 200 {
		t.Fatalf("chunk: %v %v", res, err)
	}
	f.do("POST", base+"/uploads/"+uid+"/inspect", nil)
	var out map[string]any
	for i := 0; i < 200; i++ {
		_, out = f.do("GET", base+"/uploads/"+uid, nil)
		if s, _ := out["inspect"].(map[string]any); s != nil && s["state"] != "running" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	it := out["inspect"].(map[string]any)["items"].([]any)[0].(map[string]any)
	if fmt.Sprint(it["refs"]) != "[legacy:2]" || fmt.Sprint(it["platforms"]) != "[linux/arm64]" {
		t.Fatalf("legacy item: %v", it)
	}
	f.do("POST", base+"/uploads/"+uid+"/push", map[string]any{"item": 0, "repository": "shop/legacy", "tag": "2"})
	for i := 0; i < 200; i++ {
		_, out = f.do("GET", base+"/uploads/"+uid, nil)
		if p, _ := out["push"].(map[string]any); p != nil && p["state"] != "preparing" && p["state"] != "pushing" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if p := out["push"].(map[string]any); p["state"] != "done" {
		t.Fatalf("legacy push: %v", p)
	}
	code, m := f.do("GET", base+"/images/manifest?repository=shop/legacy&ref=2", nil)
	if code != 200 || m["mediaType"] != mediaOCIManifest || m["layers"].([]any)[0].(map[string]any)["digest"] != sha(layer) {
		t.Fatalf("legacy manifest: %d %v", code, m)
	}
}
