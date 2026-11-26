// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/secrets"
)

// Models the existing Vault KVv2 HTTP/CAS boundary. It is not evidence of an
// installed Vault service, MYDCP authentication, or Raft/user activation.
type initialProviderFixture struct {
	mu           sync.Mutex
	objects      map[string]map[string]any
	puts, claims int
	loseWrite    bool
}

func (f *initialProviderFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get("X-Vault-Token") != "system-only" || !strings.HasPrefix(r.URL.Path, "/v1/kv/data/system/credentials/") {
		w.WriteHeader(403)
		return
	}
	object := strings.TrimPrefix(r.URL.Path, "/v1/kv/data/")
	if r.Method == "GET" {
		data, ok := f.objects[object]
		if !ok {
			w.WriteHeader(404)
			return
		}
		if r.URL.Query().Get("version") != "1" {
			w.WriteHeader(400)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": data, "metadata": map[string]any{"version": 1, "destroyed": false, "deletion_time": ""}}})
		return
	}
	if r.Method != "PUT" {
		w.WriteHeader(405)
		return
	}
	f.puts++
	var body struct {
		Data    map[string]any
		Options struct {
			CAS *int `json:"cas"`
		}
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil || body.Options.CAS == nil || *body.Options.CAS != 0 || body.Data == nil {
		w.WriteHeader(400)
		return
	}
	if _, exists := f.objects[object]; exists {
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"errors":["CAS mismatch"]}`))
		return
	}
	f.objects[object] = body.Data
	if strings.HasSuffix(object, "/consumed") {
		f.claims++
	}
	if f.loseWrite && !strings.HasSuffix(object, "/consumed") {
		w.WriteHeader(500)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"version": 1}})
}

func initialBackend(t *testing.T) (*Backend, *initialProviderFixture, InitialRequest) {
	t.Helper()
	f := &initialProviderFixture{objects: map[string]map[string]any{}}
	server := httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	b, err := NewBackend(secrets.VaultProfile{ID: "system", Address: server.URL, Mount: "kv", Prefix: "system/credentials", Token: "system-only", Roots: roots, Timeout: time.Second, MaxBytes: 128 << 10})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	r := InitialRequest{Schema: 1, Cluster: [32]byte{31}, Owner: [32]byte{32}, Operation: [32]byte{33}, User: "new-user", Username: "new.user", Credential: "first", Profile: "system", Method: access.Token, ExpectedUserRevision: 4, At: time.Now().Unix()}
	return b, f, r
}

func TestInitialTokenProtectedCASOneUseAcrossIssuersAndRestart(t *testing.T) {
	b, f, r := initialBackend(t)
	issued, err := b.PrepareInitial(context.Background(), r, nil, "admin-source", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer issued.Destroy()
	if len(issued.Token) != 43 {
		t.Fatal("token length")
	}
	if err = b.ObserveInitial(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if _, err = json.Marshal(issued); err == nil || fmt.Sprintf("%#v", issued) != "[redacted initial credential]" {
		t.Fatal("private result exposed")
	}
	f.mu.Lock()
	provider, _ := json.Marshal(f.objects)
	f.mu.Unlock()
	if bytes.Contains(provider, issued.Token) || bytes.Contains(provider, []byte(base64.StdEncoding.EncodeToString(issued.Token))) {
		t.Fatal("raw token persisted")
	}
	credential := r.CredentialRecord()
	u := access.User{ID: r.User, Username: r.Username, Enabled: true, Credentials: []access.Credential{credential}}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for _, issuer := range []*Backend{b, {vault: b.vault, profile: b.profile, budget: NewBudget()}} {
		wg.Add(1)
		go func(issuer *Backend) {
			defer wg.Done()
			if _, err := issuer.Verify(context.Background(), r.Cluster, u, credential, issued.Token, "login-source", time.Now()); err == nil {
				successes.Add(1)
			}
		}(issuer)
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("one-use successes=%d", successes.Load())
	}
	// A separate backend (another issuer/restart) still sees the consumed marker.
	other := &Backend{vault: b.vault, profile: b.profile, budget: NewBudget()}
	if _, err := other.Verify(context.Background(), r.Cluster, u, credential, issued.Token, "new-source", time.Now()); err == nil {
		t.Fatal("consumed token accepted after restart")
	}
	f.mu.Lock()
	claims, puts := f.claims, f.puts
	f.mu.Unlock()
	if claims != 1 || puts != 4 {
		t.Fatalf("CAS calls claims=%d puts=%d", claims, puts)
	}
	copy := credential
	copy.OneTime = false
	if _, err := b.Verify(context.Background(), r.Cluster, u, copy, issued.Token, "downgrade", time.Now()); err == nil {
		t.Fatal("one-time downgrade")
	}
}

func TestInitialLostProviderReplyObservedWithoutRegenerationOrTokenReplay(t *testing.T) {
	b, f, r := initialBackend(t)
	f.loseWrite = true
	issued, err := b.PrepareInitial(context.Background(), r, nil, "admin-source", time.Now())
	if err == nil || len(issued.Token) != 0 {
		t.Fatal("lost response became issued")
	}
	if err = b.ObserveInitial(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	puts := f.puts
	f.mu.Unlock()
	if puts != 1 {
		t.Fatal("SDK retried unknown write", puts)
	}
	wrong := r
	wrong.User = "other"
	if b.ObserveInitial(context.Background(), wrong) == nil {
		t.Fatal("foreign intent observed")
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{51}, 32))
	r.Owner = [32]byte(key.Public().(ed25519.PublicKey))
	fact, err := SignInitialFact(r, key)
	if err != nil || !fact.Verify() {
		t.Fatal(err)
	}
	fact.Request.ExpectedUserRevision++
	if fact.Verify() {
		t.Fatal("fact target CAS changed")
	}
}

func TestInitialPasswordStoresOnlyExistingArgonVerifierAndExactBinding(t *testing.T) {
	b, f, r := initialBackend(t)
	r.Method = access.Password
	password := []byte("first-password-not-a-public-intent")
	issued, err := b.PrepareInitial(context.Background(), r, password, "admin-source", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer issued.Destroy()
	if len(issued.Token) != 0 {
		t.Fatal("password produced token")
	}
	if b.ObserveInitial(context.Background(), r) != nil {
		t.Fatal("original read")
	}
	f.mu.Lock()
	provider, _ := json.Marshal(f.objects)
	f.mu.Unlock()
	if bytes.Contains(provider, password) {
		t.Fatal("password persisted")
	}
	c := r.CredentialRecord()
	u := access.User{ID: r.User, Username: r.Username, Enabled: true, Credentials: []access.Credential{c}}
	if _, err = b.Verify(context.Background(), r.Cluster, u, c, password, "login-source", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err = b.Verify(context.Background(), r.Cluster, u, c, password, "second-login", time.Now()); err != nil {
		t.Fatal("password accidentally single-use", err)
	}
	if _, err = b.PrepareInitial(context.Background(), r, password, "new-admin-source", time.Now()); err == nil {
		t.Fatal("overwrote existing immutable verifier")
	}
}
