// SPDX-License-Identifier: Apache-2.0

// Package registryfixture serves a bounded local test image over the real
// Registry V2 pull boundary. It is never linked into the MyDC products.
package registryfixture

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"debug/elf"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/moby/moby/api/types/container"
)

type Fixture struct {
	Reference, ConfigDigest, LayerDigest, Registry string
	Manifests, Blobs                               atomic.Int64
	Certificate                                    []byte
	private                                        map[string]*privateRepository
}

type BasicCredential struct {
	Username, Password string
	// DELETE is unsupported by default. Only the explicit maintenance fixture
	// opts an owned immutable manifest into 202, 403 or 405 responses.
	DeleteStatus int
}
type privateRepository struct {
	credential           BasicCredential
	image                *preparedImage
	deny, deleted        atomic.Bool
	authorized, rejected atomic.Int64
	deletes              atomic.Int64
}

// PrivateStats reports only the owned remote's counters, never MyDC facts or
// credentials. Repository-specific challenges catch same-host key confusion.
func (f *Fixture) PrivateStats(repository string) (authorized, rejected int64) {
	p := f.private[repository]
	if p == nil {
		return 0, 0
	}
	return p.authorized.Load(), p.rejected.Load()
}

// PrivateDeleteStats exposes only native HTTP attempt/effect facts for the
// owned repository, independently of MyDC's operation and result ledger.
func (f *Fixture) PrivateDeleteStats(repository string) (attempts int64, deleted bool) {
	p := f.private[repository]
	if p == nil {
		return 0, false
	}
	return p.deletes.Load(), p.deleted.Load()
}

func (f *Fixture) PrivateReference(repository string) string {
	p := f.private[repository]
	if p == nil {
		return ""
	}
	return f.Registry + "/" + repository + "@" + p.image.manifestDigest
}

func (f *Fixture) DenyPrivate(repository string, denied bool) {
	if p := f.private[repository]; p != nil {
		p.deny.Store(denied)
	}
}

func OpenPrivatePrepared(t *testing.T, binary string, config container.Config, credentials map[string]BasicCredential) *Fixture {
	t.Helper()
	if len(credentials) == 0 || credentials["fixture"].Username == "" {
		t.Fatal("explicit private fixture credentials including fixture repository required")
	}
	return openPrepared(t, binary, config, "127.0.0.1:0", credentials)
}

// OpenPrepared serves only a prebuilt static backend. The caller explicitly
// admits the registry to tenant trust, pulls with the real SDK, and rolls back
// its exact image after native consumers have been removed.
func OpenPrepared(t *testing.T, binary string, config container.Config) *Fixture {
	t.Helper()
	return OpenPreparedAt(t, binary, config, "127.0.0.1:0")
}

// OpenPreparedAt reuses the exact bounded image with an explicitly owned
// underlay listener so independent native namespaces can pull the same bytes.
func OpenPreparedAt(t *testing.T, binary string, config container.Config, listen string) *Fixture {
	return openPrepared(t, binary, config, listen, nil)
}

type preparedImage struct {
	manifest, config, layer                               []byte
	manifestDigest, configDigest, layerDigest, blobDigest string
}

// Each private repository has its own immutable layer/config/manifest graph;
// a solver cannot prove both FROM inputs with a shared image digest alone.
func prepareImage(t *testing.T, b []byte, config container.Config, repository string) *preparedImage {
	t.Helper()
	var err error
	var layer bytes.Buffer
	tw := tar.NewWriter(&layer)
	if err = tw.WriteHeader(&tar.Header{Name: "backend", Mode: 0755, Size: int64(len(b))}); err != nil {
		t.Fatal(err)
	}
	if _, err = tw.Write(b); err != nil {
		t.Fatal(err)
	}
	proof := []byte(config.Labels["org.mydc.test.owner"])
	if len(proof) == 0 {
		t.Fatal("explicit unique registry fixture ownership required")
	}
	if err = tw.WriteHeader(&tar.Header{Name: "registry-proof", Mode: 0444, Size: int64(len(proof))}); err != nil {
		t.Fatal(err)
	}
	if _, err = tw.Write(proof); err != nil {
		t.Fatal(err)
	}
	if repository != "" {
		if err = tw.WriteHeader(&tar.Header{Name: "registry-repository", Mode: 0444, Size: int64(len(repository))}); err != nil {
			t.Fatal(err)
		}
		if _, err = tw.Write([]byte(repository)); err != nil {
			t.Fatal(err)
		}
	}
	if err = tw.Close(); err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	zip, err := gzip.NewWriterLevel(&compressed, gzip.BestSpeed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = zip.Write(layer.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err = zip.Close(); err != nil {
		t.Fatal(err)
	}
	digest := func(v []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(v)) }
	image, err := json.Marshal(map[string]any{"architecture": runtime.GOARCH, "os": "linux", "config": config, "rootfs": map[string]any{"type": "layers", "diff_ids": []string{digest(layer.Bytes())}}})
	if err != nil {
		t.Fatal(err)
	}
	descriptor := func(media string, b []byte) map[string]any {
		return map[string]any{"mediaType": media, "digest": digest(b), "size": len(b)}
	}
	const media = "application/vnd.docker.distribution.manifest.v2+json"
	manifest, err := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": media, "config": descriptor("application/vnd.docker.container.image.v1+json", image), "layers": []any{descriptor("application/vnd.docker.image.rootfs.diff.tar.gzip", compressed.Bytes())}})
	if err != nil {
		t.Fatal(err)
	}
	return &preparedImage{manifest: manifest, config: image, layer: compressed.Bytes(), manifestDigest: digest(manifest), configDigest: digest(image), layerDigest: digest(layer.Bytes()), blobDigest: digest(compressed.Bytes())}
}

func openPrepared(t *testing.T, binary string, config container.Config, listen string, credentials map[string]BasicCredential) *Fixture {
	t.Helper()
	address, err := netip.ParseAddrPort(listen)
	if err != nil || address.Addr().IsUnspecified() || address.Addr().IsMulticast() {
		t.Fatal("explicit numeric owned registry listener required", err)
	}
	b, err := os.ReadFile(binary)
	if err != nil || len(b) == 0 || len(b) > 32<<20 {
		t.Fatal("bounded prebuilt registry backend", err)
	}
	executable, err := elf.NewFile(bytes.NewReader(b))
	if err != nil {
		t.Fatal("prebuilt registry backend must be a static Linux ELF", err)
	}
	defer executable.Close()
	for _, segment := range executable.Progs {
		if segment.Type == elf.PT_INTERP {
			t.Fatal("scratch registry backend needs CGO_ENABLED=0; dynamic ELF interpreter is unavailable")
		}
	}
	prepared := prepareImage(t, b, config, "")
	f := &Fixture{ConfigDigest: prepared.configDigest, LayerDigest: prepared.layerDigest}
	if len(credentials) != 0 {
		f.private = map[string]*privateRepository{}
		for repository, credential := range credentials {
			if repository == "" || strings.ContainsAny(repository, "/?#\\") || credential.Username == "" || credential.Password == "" || credential.DeleteStatus != 0 && credential.DeleteStatus != http.StatusAccepted && credential.DeleteStatus != http.StatusForbidden && credential.DeleteStatus != http.StatusMethodNotAllowed {
				t.Fatal("invalid owned private repository input")
			}
			f.private[repository] = &privateRepository{credential: credential, image: prepareImage(t, b, config, repository)}
		}
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
		requestPath := r.URL.Path
		selected := prepared
		var owned *privateRepository
		var catalogue any
		if f.private != nil {
			user, password, basic := r.BasicAuth()
			rest := strings.TrimPrefix(requestPath, "/v2/")
			repository, _, _ := strings.Cut(rest, "/")
			if p := f.private[repository]; p != nil && r.Method == http.MethodDelete {
				p.deletes.Add(1)
			}
			allowed := false
			if requestPath == "/v2/" {
				for _, p := range f.private {
					allowed = allowed || basic && user == p.credential.Username && password == p.credential.Password
				}
			} else if requestPath == "/v2/_catalog" {
				// A catalogue credential sees only repositories it actually owns;
				// sharing this HTTPS authority does not share another Basic secret.
				names := []string{}
				for name, p := range f.private {
					if basic && user == p.credential.Username && password == p.credential.Password {
						if p.deny.Load() {
							p.rejected.Add(1)
						} else {
							p.authorized.Add(1)
							names = append(names, name)
						}
					}
				}
				slices.Sort(names)
				allowed = len(names) != 0
				catalogue = struct {
					Repositories []string `json:"repositories"`
				}{names}
			} else if p := f.private[repository]; p != nil {
				allowed = basic && user == p.credential.Username && password == p.credential.Password && !p.deny.Load()
				if allowed {
					p.authorized.Add(1)
				} else {
					p.rejected.Add(1)
				}
			}
			if !allowed {
				w.Header().Set("WWW-Authenticate", `Basic realm="owned-private-registry"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			owned = f.private[repository]
			if r.Method == http.MethodDelete {
				// Never treat the GET body's old method-agnostic 200 as DELETE
				// success. Only this exact authenticated immutable path can mutate.
				if owned == nil || requestPath != "/v2/"+repository+"/manifests/"+owned.image.manifestDigest {
					w.WriteHeader(http.StatusMethodNotAllowed)
					return
				}
				status := owned.credential.DeleteStatus
				if status == 0 {
					status = http.StatusMethodNotAllowed
				}
				if status == http.StatusAccepted && owned.deleted.Swap(true) {
					status = http.StatusNotFound
				}
				w.WriteHeader(status)
				return
			}
			if requestPath == "/v2/"+repository+"/tags/list" {
				tags := []string{"owned"}
				if owned.deleted.Load() {
					tags = []string{}
				}
				catalogue = struct {
					Name string   `json:"name"`
					Tags []string `json:"tags"`
				}{repository, tags}
			}
			if catalogue != nil {
				if r.Method != http.MethodGet && r.Method != http.MethodHead {
					w.WriteHeader(http.StatusMethodNotAllowed)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if r.Method != http.MethodHead {
					_ = json.NewEncoder(w).Encode(catalogue)
				}
				return
			}
			if requestPath != "/v2/" {
				selected = f.private[repository].image
				requestPath = "/v2/fixture/" + strings.TrimPrefix(rest, repository+"/")
			}
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var value []byte
		switch requestPath {
		case "/v2/":
			w.WriteHeader(http.StatusOK)
			return
		case "/v2/fixture/manifests/" + selected.manifestDigest, "/v2/fixture/manifests/owned":
			if owned != nil && owned.deleted.Load() {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			value = selected.manifest
			f.Manifests.Add(1)
			w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
		case "/v2/fixture/blobs/" + selected.configDigest:
			value = selected.config
			f.Blobs.Add(1)
		case "/v2/fixture/blobs/" + selected.blobDigest:
			value = selected.layer
			f.Blobs.Add(1)
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Docker-Content-Digest", fmt.Sprintf("sha256:%x", sha256.Sum256(value)))
		w.Header().Set("Content-Length", fmt.Sprint(len(value)))
		if r.Method != http.MethodHead {
			_, _ = w.Write(value)
		}
	}))
	t.Cleanup(server.Close)
	if err := server.Listener.Close(); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		t.Fatal("owned prepared registry listener", err)
	}
	server.Listener = listener
	if f.private == nil {
		server.Start()
	} else {
		server.StartTLS()
		f.Certificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	}
	f.Registry = strings.TrimPrefix(strings.TrimPrefix(server.URL, "http://"), "https://")
	f.Reference = f.Registry + "/fixture@" + prepared.manifestDigest
	if f.private != nil {
		f.Reference = f.PrivateReference("fixture")
		f.ConfigDigest = f.private["fixture"].image.configDigest
		f.LayerDigest = f.private["fixture"].image.layerDigest
	}
	return f
}
