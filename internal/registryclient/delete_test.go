// SPDX-License-Identifier: Apache-2.0

package registryclient

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
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
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// Real HTTPS, authentication challenge and the pinned SDK's Delete transport.
// The remote fixture is not a MyDC Vault/Session/Raft authorization proof.
func TestExternalDeleteUsesOnlyOriginalResponseAndNeverRetriesMutation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		code   string
	}{
		{"acknowledged", 202, "OK"},
		{"original-absent-response", 404, "ALREADY_ABSENT"},
		{"denied", 403, "DENIED"},
		{"unsupported", 405, "UNSUPPORTED"},
		{"unimplemented", 501, "UNSUPPORTED"},
		{"server-error-may-follow-effect", 500, "UNKNOWN"},
		{"lost-original-response", 0, "UNKNOWN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			var attempts, before atomic.Int32
			digest := "sha256:" + strings.Repeat("a", 64)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
				if q.URL.Path == "/v2/" {
					w.Header().Set("WWW-Authenticate", `Basic realm="private"`)
					w.WriteHeader(401)
					return
				}
				if q.Method != http.MethodDelete || q.URL.Path != "/v2/team/app/manifests/"+digest {
					t.Error("mutation escaped the exact target", q.Method, q.URL.Path)
					w.WriteHeader(400)
					return
				}
				user, password, ok := q.BasicAuth()
				if !ok || user != "reader" || password != "private-delete-test-password" || before.Load() != 1 {
					t.Error("DELETE preceded its original intent or lacked exact source auth")
					w.WriteHeader(403)
					return
				}
				attempts.Add(1)
				if tc.status == 0 {
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					_ = conn.Close()
					return
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, `{"error":"private-delete-test-password must never leave this fixture"}`)
			}))
			defer server.Close()
			authority := strings.TrimPrefix(server.URL, "https://")
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			client, err := New(authority, []byte("reader"), []byte("private-delete-test-password"), ca)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			outcome := client.DeleteManifest(ctx, authority+"/team/app@"+digest, func(context.Context) error { before.Add(1); return nil })
			if !outcome.Valid() || !outcome.Attempted || outcome.Code != tc.code || attempts.Load() != 1 || before.Load() != 1 {
				t.Fatal("original response/retry boundary", outcome, attempts.Load(), before.Load())
			}
			raw, _ := json.Marshal(outcome)
			if strings.Contains(string(raw), "password") || strings.Contains(string(raw), authority) {
				t.Fatal("remote body/auth/address leaked through outcome", string(raw))
			}
		})
	}
}

func TestExternalDeleteGuardAndOneShotTransportRejectBeforeNetwork(t *testing.T) {
	var calls, before int
	path := "/v2/team/app/manifests/sha256:" + strings.Repeat("a", 64)
	guardErr := errors.New("authority withdrawn")
	gate := &deleteOnceTransport{host: "registry.example", path: path, before: func(context.Context) error { before++; return guardErr }, inner: roundTripFunc(func(q *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 202, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}, Request: q}, nil
	})}
	q, _ := http.NewRequest(http.MethodDelete, "https://registry.example"+path, nil)
	if _, err := gate.RoundTrip(q); !errors.Is(err, guardErr) || gate.attempted || calls != 0 || before != 1 {
		t.Fatal("last current guard ignored", err, calls, before)
	}
	gate.before = func(context.Context) error { before++; return nil }
	response, err := gate.RoundTrip(q)
	if err != nil || response.StatusCode != 202 {
		t.Fatal(err)
	}
	response.Body.Close()
	if _, err = gate.RoundTrip(q); err == nil || calls != 1 || before != 2 {
		t.Fatal("original DELETE replayed", err, calls, before)
	}
	for _, raw := range []string{"http://registry.example" + path, "https://foreign.example" + path, "https://registry.example/v2/team/app/manifests/stable", "https://registry.example" + path + "?retarget=1"} {
		q, _ := http.NewRequest(http.MethodDelete, raw, nil)
		gate.attempted = false
		if _, err = gate.RoundTrip(q); err == nil || calls != 1 || before != 2 {
			t.Fatal("scope/target changed before one-shot guard", raw, err)
		}
	}
}

func TestExternalDeleteRemovesActualPinnedRegistryManifestWithExplicitPrivateAuth(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	backend := oci.New(oci.Logger(log.New(io.Discard, "", 0)))
	var deletes atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		user, password, ok := q.BasicAuth()
		if !ok || user != "owner" || password != "private-delete-test-password" {
			w.Header().Set("WWW-Authenticate", `Basic realm="owned"`)
			w.WriteHeader(401)
			return
		}
		if q.Method == http.MethodDelete {
			deletes.Add(1)
		}
		backend.ServeHTTP(w, q)
	}))
	defer server.Close()
	authority := strings.TrimPrefix(server.URL, "https://")
	image, err := random.Image(1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	tag, err := name.NewTag(authority+"/team/app:stable", name.StrictValidation)
	if err != nil {
		t.Fatal(err)
	}
	push := func() {
		t.Helper()
		if err := remote.Write(tag, image, remote.WithContext(ctx), remote.WithAuth(authn.FromConfig(authn.AuthConfig{Username: "owner", Password: "private-delete-test-password"})), remote.WithTransport(server.Client().Transport), remote.WithJobs(1)); err != nil {
			t.Fatal(err)
		}
	}
	push()
	digest, err := image.Digest()
	if err != nil {
		t.Fatal(err)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	client, err := New(authority, []byte("owner"), []byte("private-delete-test-password"), ca)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ref := authority + "/team/app@" + digest.String()
	if _, err = client.Resolve(ctx, ref); err != nil {
		t.Fatal("fixture immutable manifest absent before deletion", err)
	}
	outcome := client.DeleteManifest(ctx, ref, func(context.Context) error { return nil })
	if !outcome.Valid() || outcome.Code != "OK" || !outcome.Attempted || deletes.Load() != 1 {
		t.Fatal(outcome, deletes.Load())
	}
	if _, err = client.Resolve(ctx, ref); ResultCode(err) != "NOT_FOUND" {
		t.Fatal("SDK DELETE acknowledged without removing actual manifest", ResultCode(err))
	}
	// The in-memory fixture retains tag aliases on digest deletion, so a
	// tag-based Write can skip publication after its successful HEAD. Publish
	// the absent immutable digest to perform a real new PUT of the same bytes.
	immutable, err := name.NewDigest(ref, name.StrictValidation)
	if err != nil {
		t.Fatal(err)
	}
	if err = remote.Write(immutable, image, remote.WithContext(ctx), remote.WithAuth(authn.FromConfig(authn.AuthConfig{Username: "owner", Password: "private-delete-test-password"})), remote.WithTransport(server.Client().Transport), remote.WithJobs(1)); err != nil {
		t.Fatal(err)
	}
	if _, err = client.Resolve(ctx, ref); err != nil || deletes.Load() != 1 {
		t.Fatal("later same-digest publication changed an original outcome", err, deletes.Load())
	}
}
