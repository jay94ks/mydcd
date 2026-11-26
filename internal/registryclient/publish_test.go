// SPDX-License-Identifier: Apache-2.0

package registryclient

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	oci "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// Actual private HTTPS + pinned SDK/OCI protocol, not MyDC's member/quorum or
// registry Volume/BuildKit integration. No real Docker or host trust changes.
func TestPublishImageAndIndexUseExplicitAuthAndBeforeRootGate(t *testing.T) {
	for _, multi := range []bool{false, true} {
		t.Run(map[bool]string{false: "image", true: "index"}[multi], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			backend := oci.New(oci.Logger(log.New(io.Discard, "", 0)))
			var writes, rootBefore, rootRequests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
				user, password, ok := q.BasicAuth()
				if !ok || user != "builder" || password != "private-publish-test-password" {
					w.Header().Set("WWW-Authenticate", `Basic realm="build"`)
					w.WriteHeader(401)
					return
				}
				if q.Method != http.MethodGet && q.Method != http.MethodHead {
					if writes.Load() == 0 {
						t.Error("write preceded durable callback")
					}
					if q.Method == http.MethodPut && q.URL.Path == "/v2/team/app/manifests/release" {
						rootRequests.Add(1)
						if rootBefore.Load() != 1 {
							t.Error("root preceded its original intent")
						}
					}
				}
				backend.ServeHTTP(w, q)
			}))
			defer server.Close()
			authority := strings.TrimPrefix(server.URL, "https://")
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			client, err := New(authority, []byte("builder"), []byte("private-publish-test-password"), ca)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			image, err := random.Image(128, 1)
			if err != nil {
				t.Fatal(err)
			}
			var index v1.ImageIndex
			if multi {
				index = mutate.IndexMediaType(mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: image}), types.OCIImageIndex)
				image = nil
			}
			out := client.PublishImage(ctx, authority+"/team/app:release", image, index, func(_ context.Context, root bool) error {
				writes.Add(1)
				if root {
					rootBefore.Add(1)
				}
				return nil
			})
			if !out.Valid() || out.Code != "OK" || !out.Started || !out.Attempted || rootRequests.Load() != 1 {
				t.Fatal("wrong original SDK result", out, rootRequests.Load())
			}
			got, err := client.Resolve(ctx, authority+"/team/app:release")
			if err != nil || got.Digest != out.Digest {
				t.Fatal("published content not readable", got, err)
			}
		})
	}
}

func TestPublishRootLossDenialAndRejectionDoNotRetry(t *testing.T) {
	for _, mode := range []string{"lost-response", "server-error", "accepted-pending", "wrong-digest-ack", "forbidden", "unsupported", "guard-storage", "guard-denied"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			backend := oci.New(oci.Logger(log.New(io.Discard, "", 0)))
			var roots, rootBefore atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
				if q.Method == http.MethodPut && q.URL.Path == "/v2/team/app/manifests/release" {
					roots.Add(1)
					switch mode {
					case "lost-response":
						conn, _, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Error(err)
							return
						}
						_ = conn.Close()
						return
					case "server-error":
						w.WriteHeader(500)
					case "accepted-pending":
						w.WriteHeader(202)
					case "wrong-digest-ack":
						w.Header().Set("Docker-Content-Digest", "sha256:"+strings.Repeat("a", 64))
						w.WriteHeader(201)
					case "forbidden":
						w.WriteHeader(403)
					case "unsupported":
						w.WriteHeader(405)
					default:
						t.Error("guard failure reached root write")
						w.WriteHeader(500)
					}
					_, _ = io.WriteString(w, `{"error":"private-publish-test-password"}`)
					return
				}
				backend.ServeHTTP(w, q)
			}))
			defer server.Close()
			authority := strings.TrimPrefix(server.URL, "https://")
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			client, err := New(authority, nil, nil, ca)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			image, err := random.Image(64, 1)
			if err != nil {
				t.Fatal(err)
			}
			out := client.PublishImage(ctx, authority+"/team/app:release", image, nil, func(_ context.Context, root bool) error {
				if root {
					rootBefore.Add(1)
					if mode == "guard-storage" {
						return io.ErrClosedPipe
					}
					if mode == "guard-denied" {
						return &Error{Code: "DENIED"}
					}
				}
				return nil
			})
			want := map[string]string{"lost-response": "UNKNOWN", "server-error": "UNKNOWN", "accepted-pending": "UNKNOWN", "wrong-digest-ack": "UNKNOWN", "forbidden": "DENIED", "unsupported": "UNSUPPORTED", "guard-storage": "UNAVAILABLE", "guard-denied": "DENIED"}[mode]
			attempted := !strings.HasPrefix(mode, "guard-")
			if !out.Valid() || out.Code != want || !out.Started || out.Attempted != attempted || rootBefore.Load() != 1 || roots.Load() != map[bool]int32{false: 0, true: 1}[attempted] {
				t.Fatal("lost/denied root retried or hidden", out, rootBefore.Load(), roots.Load())
			}
			raw, _ := json.Marshal(out)
			if strings.Contains(string(raw), "password") || strings.Contains(string(raw), authority) {
				t.Fatal("private HTTP details escaped", string(raw))
			}
		})
	}
}

func TestPublishRejectsClosedForeignAndNoncanonicalTargetsBeforeNetwork(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) { calls.Add(1); w.WriteHeader(500) }))
	defer server.Close()
	authority := strings.TrimPrefix(server.URL, "https://")
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	client, err := New(authority, nil, nil, ca)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for _, target := range []string{"foreign.example/team/app:release", "https://" + authority + "/team/app:release", authority + "/team/app", authority + "/team/app:release?extra=1"} {
		out := client.PublishImage(context.Background(), target, empty.Image, nil, func(context.Context, bool) error { t.Error("invalid request reached callback"); return nil })
		if !out.Valid() || out.Started || out.Attempted || calls.Load() != 0 {
			t.Fatal("invalid target reached I/O", out, calls.Load())
		}
	}
	client.Close()
	out := client.PublishImage(context.Background(), authority+"/team/app:release", empty.Image, nil, func(context.Context, bool) error { return nil })
	if !out.Valid() || out.Code != "DENIED" || calls.Load() != 0 {
		t.Fatal("closed credential performed I/O", out, calls.Load())
	}
}
