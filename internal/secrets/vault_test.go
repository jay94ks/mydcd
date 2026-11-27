// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/reconcile"
)

// This exercises the real SDK over TLS against a scripted KV HTTP boundary;
// it does not claim a real Vault server's storage/auth/unseal behavior.
func TestVaultLibraryOriginalCASUnknownReadbackAndFixedRevision(t *testing.T) {
	f := writable(t)
	q := valueRequest(f, "sdk-write", "runtime")
	f = prepare(t, f, q)
	f = dispatch(t, f, q.ID)
	record, _ := f.t.Write(q.ID)
	var mu sync.Mutex
	var stored map[string]any
	puts := 0
	failWrite := true
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path != "/v1/kv/data/tenant/runtime" || r.Header.Get("X-Vault-Token") != "installed-token" || r.Header.Get("X-Vault-Namespace") != "org/team" {
			w.WriteHeader(403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "PUT" {
			puts++
			var body struct {
				Data    map[string]any `json:"data"`
				Options struct {
					CAS int `json:"cas"`
				} `json:"options"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.Options.CAS != 1 {
				w.WriteHeader(400)
				return
			}
			stored = body.Data
			if failWrite {
				w.WriteHeader(503)
				fmt.Fprint(w, `{"errors":["private-provider-message"]}`)
				return
			}
			fmt.Fprint(w, `{"data":{"version":2}}`)
			return
		}
		if r.Method != "GET" || r.URL.Query().Get("version") != "2" || stored == nil {
			w.WriteHeader(404)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": stored, "metadata": map[string]any{"version": 2, "destroyed": false, "deletion_time": ""}}})
	}))
	defer s.Close()
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	v, err := NewVault(VaultProfile{ID: "vault", Address: s.URL, Mount: "kv", Prefix: "tenant", Namespace: "org/team", Token: "installed-token", Roots: roots, Timeout: time.Second, MaxBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if _, err = v.PutOnce(context.Background(), record, map[string][]byte{"DB_HOST": []byte("db"), "DB_PASSWORD": []byte{0, 1, 255}}); !errors.Is(err, ErrProvider) {
		t.Fatal("write ambiguity was exposed as success", err)
	}
	mu.Lock()
	count := puts
	mu.Unlock()
	if count != 1 {
		t.Fatal("SDK retried original write", count)
	}
	f = observe(t, f, observation(f, q.ID, reconcile.EffectUnknown))
	unknown, _ := f.t.Write(q.ID)
	if unknown.Status() != "Unknown" {
		t.Fatal("original uncertainty lost")
	}
	receipt, err := v.ReadOriginal(context.Background(), unknown)
	if err != nil || receipt.Revision != 2 {
		t.Fatal("original readback", err)
	}
	ref := Reference{Profile: "vault", Object: "tenant/runtime", Revision: 2, Keys: []string{"DB_HOST", "DB_PASSWORD"}}
	fetched, err := v.Fetch(context.Background(), "runtime", ref)
	if err != nil || string(fetched.Values["DB_HOST"]) != "db" || len(fetched.Values["DB_PASSWORD"]) != 3 {
		t.Fatal("fixed private revision", err)
	}
	if _, err = v.PutOnce(context.Background(), unknown, map[string][]byte{"DB_HOST": []byte("db"), "DB_PASSWORD": []byte("private")}); err == nil {
		t.Fatal("unknown write resubmitted")
	}
	ref.Revision = 1
	if _, err = v.Fetch(context.Background(), "runtime", ref); err == nil {
		t.Fatal("fell back from original revision")
	}
	if _, err = json.Marshal(v); err == nil {
		t.Fatal("provider material serialized")
	}
	if strings.Contains(fmt.Sprintf("%#v", v), "installed-token") {
		t.Fatal("token formatted")
	}
	mu.Lock()
	stored[vaultReceiptKey] = map[string]any{"schema": 1, "receipt": strings.Repeat("0", 64), "encoding": "base64"}
	mu.Unlock()
	if _, err = v.ReadOriginal(context.Background(), unknown); err == nil {
		t.Fatal("unrelated write proved original result")
	}
}

func TestVaultLibraryRejectsAmbientOverridesAndForeignProfileWithoutIO(t *testing.T) {
	p := VaultProfile{ID: "vault", Address: "https://vault.sfc.test", Mount: "kv", Prefix: "tenant", Token: "private", Timeout: time.Second, MaxBytes: 1024}
	t.Setenv("VAULT_ADDR", "https://unapproved.invalid")
	if _, err := NewVault(p); err == nil {
		t.Fatal("ambient SDK override accepted")
	}
	t.Setenv("VAULT_ADDR", "")
	v, err := NewVault(p)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	for _, ref := range []Reference{{Profile: "other", Object: "tenant/item", Revision: 1, Keys: []string{"KEY"}}, {Profile: "vault", Object: "elsewhere/item", Revision: 1, Keys: []string{"KEY"}}, {Profile: "vault", Object: "tenant/../foreign", Revision: 1, Keys: []string{"KEY"}}, {Profile: "vault", Object: "tenant/item", Revision: 0, Keys: []string{"KEY"}}} {
		if _, err = v.Fetch(context.Background(), "item", ref); err == nil {
			t.Fatal("unapproved provider scope accepted")
		}
	}
	p.Address = "http://vault.sfc.test"
	if _, err = NewVault(p); err == nil {
		t.Fatal("plaintext provider accepted")
	}
}

func TestVaultLibraryBoundsResponseAndDoesNotFollowRedirects(t *testing.T) {
	var requests atomic.Int32
	var large atomic.Bool
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if large.Load() {
			fmt.Fprint(w, strings.Repeat("x", 1025))
			return
		}
		w.Header().Set("Location", "https://unapproved.invalid/v1/kv/data/tenant/item")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer s.Close()
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	v, err := NewVault(VaultProfile{ID: "vault", Address: s.URL, Mount: "kv", Prefix: "tenant", Token: "installed-token", Roots: roots, Timeout: time.Second, MaxBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	ref := Reference{Profile: "vault", Object: "tenant/item", Revision: 1, Keys: []string{"KEY"}}
	if _, err = v.Fetch(context.Background(), "item", ref); !errors.Is(err, ErrProvider) {
		t.Fatal("redirect accepted", err)
	}
	if requests.Load() != 1 {
		t.Fatal("provider redirect/retry escaped profile")
	}
	large.Store(true)
	if _, err = v.Fetch(context.Background(), "item", ref); !errors.Is(err, ErrProvider) {
		t.Fatal("oversized provider response accepted")
	}
}

// An object outside the node's prefix is refused before any journal or HTTP
// step, and says so, so the caller can settle the write as not applied.
func TestWriterRefusesObjectOutsidePrefixAsNotCovered(t *testing.T) {
	f := writable(t)
	q := valueRequest(f, "outside-write", "runtime")
	f = prepare(t, f, q)
	f = dispatch(t, f, q.ID)
	record, _ := f.t.Write(q.ID)
	v, err := NewVault(VaultProfile{ID: record.Request.Profile, Address: "https://vault.sfc.test", Mount: "kv", Prefix: "elsewhere", Token: "private", Timeout: time.Second, MaxBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	w, err := OpenWriter(t.TempDir()+"/writer.db", v)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	_, err = w.Apply(context.Background(), f.t.cluster, "", record, map[string][]byte{"DB_HOST": []byte("db"), "DB_PASSWORD": []byte("value-7f3c")}, false)
	if !errors.Is(err, ErrNotCovered) || !errors.Is(err, ErrProvider) || strings.Contains(err.Error(), "value-7f3c") {
		t.Fatal("outside object not refused as not covered", err)
	}
}
