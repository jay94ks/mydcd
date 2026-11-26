// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/secrets"
)

func TestCredentialBackendPinnedTLSFixedRevisionSystemRealmAndPrivateFiles(t *testing.T) {
	cluster := [32]byte{61}
	ref := "vault/system/system/credentials/alice/password@1"
	password := []byte("backend-private-password")
	m, err := NewPassword(cluster, "alice", "password", ref, password, bytes.Repeat([]byte{5}, 16), identity.PasswordCost{Memory: 8 * 1024, Iterations: 1, Threads: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Destroy()
	raw, _ := m.ProtectedBytes()
	defer clear(raw)
	var requests atomic.Int64
	var unavailable atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if unavailable.Load() || r.Method != "GET" || r.URL.Path != "/v1/kv/data/system/credentials/alice/password" || r.URL.Query().Get("version") != "1" || r.Header.Get("X-Vault-Token") != "installed-private-token" {
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"errors":["private-provider-failure"]}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": map[string]any{"credential": string(raw)}, "metadata": map[string]any{"version": 1, "destroyed": false, "deletion_time": ""}}})
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	profile := secrets.VaultProfile{ID: "system", Address: server.URL, Mount: "kv", Prefix: "system/credentials", Token: "installed-private-token", Roots: roots, Timeout: time.Second, MaxBytes: 128 << 10}
	b, err := NewBackend(profile)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	c := access.Credential{ID: "password", Method: access.Password, VerifierRef: ref, Enabled: true}
	u := access.User{ID: "alice", Username: "alice.login", Enabled: true, Credentials: []access.Credential{c}}
	if grant, err := b.Verify(context.Background(), cluster, u, c, password, "127.0.0.1", time.Now()); err != nil || grant.Credential != "password" {
		t.Fatal(grant, err)
	}
	before := requests.Load()
	for _, foreign := range []string{"vault/tenant/system/credentials/alice/password@1", "vault/system/tenant/secrets/password@1"} {
		attempt := c
		attempt.VerifierRef = foreign
		if _, err := b.Verify(context.Background(), cluster, u, attempt, password, "127.0.0.1", time.Now()); err == nil {
			t.Fatal("foreign profile/realm used")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := b.Verify(ctx, cluster, u, c, password, "127.0.0.1", time.Now()); err == nil {
		t.Fatal("canceled fetch")
	}
	if requests.Load() != before {
		t.Fatal("foreign/canceled request reached private provider")
	}
	unavailable.Store(true)
	if _, err := b.Verify(context.Background(), cluster, u, c, password, "127.0.0.1", time.Now()); err != ErrDenied || strings.Contains(err.Error(), "private-provider") {
		t.Fatal("provider error/fallback leaked", err)
	}
	unavailable.Store(false)
	if requests.Load() != before+1 {
		t.Fatal("SDK retried authentication provider read")
	}
	copy := profile
	copy.Prefix = "tenant"
	if _, err := NewBackend(copy); err == nil {
		t.Fatal("tenant provider became system authentication")
	}
	copy = profile
	copy.Roots = x509.NewCertPool()
	badCA, err := NewBackend(copy)
	if err != nil {
		t.Fatal(err)
	}
	defer badCA.Close()
	if _, err = badCA.Verify(context.Background(), cluster, u, c, password, "127.0.0.1", time.Now()); err == nil {
		t.Fatal("untrusted TLS provider accepted")
	}
	root := t.TempDir()
	caFile, tokenFile := filepath.Join(root, "ca.pem"), filepath.Join(root, "token")
	if err = os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(tokenFile, []byte("installed-private-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	installed, err := OpenLocal("system", server.URL, "kv", "", caFile, tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	installed.Close()
	if err = os.Chmod(tokenFile, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenLocal("system", server.URL, "kv", "", caFile, tokenFile); err == nil {
		t.Fatal("public provider credential accepted")
	}
	if err = os.Chmod(tokenFile, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err = os.Symlink(tokenFile, link); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenLocal("system", server.URL, "kv", "", caFile, link); err == nil {
		t.Fatal("symlink provider credential accepted")
	}
	t.Log("actual SDK/HTTPS fixed version, no retries/fallback, bounded system realm and private installation files; scripted Vault HTTP, not a real Vault service")
}

func TestCredentialBackendOrdinaryEncodingIsRedacted(t *testing.T) {
	b, err := NewBackend(secrets.VaultProfile{ID: "system", Address: "https://vault.invalid", Mount: "kv", Prefix: "system/credentials", Token: "private-backend-token", Timeout: time.Second, MaxBytes: 128 << 10})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if _, err = json.Marshal(b); err == nil || fmt.Sprintf("%#v", b) != "[redacted credential backend]" {
		t.Fatal("credential provider appeared in ordinary structured output")
	}
}
