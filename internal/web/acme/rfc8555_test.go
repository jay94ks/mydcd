// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"

	"github.com/jay94ks/mydcd/internal/web/provlog"
)

// acmeServer is a small RFC 8555 server: enough for the Directory flow
// (account, order, dns-01, finalize, revoke). It does not verify JWS
// signatures; the client library is tested upstream.
type acmeServer struct {
	t        *testing.T
	srv      *httptest.Server
	mu       sync.Mutex
	nonce    int
	accounts int
	accepted map[string]bool // authz id → challenge accepted
	names    []string
	csr      *x509.CertificateRequest
	rateNext bool
	revoked  int
	caKey    *ecdsa.PrivateKey
	caCert   *x509.Certificate
}

func newACMEServer(t *testing.T) *acmeServer {
	a := &acmeServer{t: t, accepted: map[string]bool{}}
	a.caKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test ACME Root"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour * 24), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &a.caKey.PublicKey, a.caKey)
	a.caCert, _ = x509.ParseCertificate(der)
	a.srv = httptest.NewServer(a)
	t.Cleanup(a.srv.Close)
	return a
}

func (a *acmeServer) url(p string) string { return a.srv.URL + p }

func (a *acmeServer) payload(r *http.Request) map[string]any {
	var jws struct{ Payload string }
	b, _ := io.ReadAll(r.Body)
	json.Unmarshal(b, &jws)
	raw, _ := base64.RawURLEncoding.DecodeString(jws.Payload)
	var m map[string]any
	json.Unmarshal(raw, &m)
	return m
}

func (a *acmeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.nonce++
	w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", a.nonce))
	js := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(v)
	}
	switch {
	case r.URL.Path == "/dir":
		js(200, map[string]any{"newNonce": a.url("/nonce"), "newAccount": a.url("/acct"), "newOrder": a.url("/order"), "revokeCert": a.url("/revoke"),
			"meta": map[string]any{"termsOfService": a.url("/tos")}})
	case r.URL.Path == "/nonce":
		w.WriteHeader(200)
	case r.URL.Path == "/acct":
		w.Header().Set("Location", a.url("/acct/1"))
		code := 201
		if a.accounts > 0 {
			code = 200
		}
		a.accounts++
		js(code, map[string]any{"status": "valid"})
	case r.URL.Path == "/acct/1":
		js(200, map[string]any{"status": "valid"})
	case r.URL.Path == "/order":
		if a.rateNext {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(429)
			io.WriteString(w, `{"type":"urn:ietf:params:acme:error:rateLimited","detail":"too many certificates already issued"}`)
			return
		}
		p := a.payload(r)
		a.names = nil
		var authz []string
		for i, id := range p["identifiers"].([]any) {
			a.names = append(a.names, id.(map[string]any)["value"].(string))
			authz = append(authz, a.url(fmt.Sprintf("/authz/%d", i)))
		}
		w.Header().Set("Location", a.url("/order/1"))
		js(201, map[string]any{"status": "pending", "authorizations": authz, "finalize": a.url("/finalize/1")})
	case strings.HasPrefix(r.URL.Path, "/authz/"):
		i := strings.TrimPrefix(r.URL.Path, "/authz/")
		var n int
		fmt.Sscan(i, &n)
		name, wild := a.names[n], false
		if strings.HasPrefix(name, "*.") {
			name, wild = name[2:], true
		}
		st := "pending"
		if a.accepted[i] {
			st = "valid"
		}
		js(200, map[string]any{"status": st, "identifier": map[string]string{"type": "dns", "value": name}, "wildcard": wild,
			"challenges": []any{
				map[string]string{"type": "http-01", "url": a.url("/chall/http/" + i), "token": "h" + i, "status": "pending"},
				map[string]string{"type": "dns-01", "url": a.url("/chall/" + i), "token": "tok" + i, "status": st},
			}})
	case strings.HasPrefix(r.URL.Path, "/chall/"):
		i := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/chall/"), "http/")
		a.accepted[i] = true
		js(200, map[string]string{"type": "dns-01", "url": a.url(r.URL.Path), "token": "tok" + i, "status": "processing"})
	case r.URL.Path == "/order/1":
		st := "pending"
		if len(a.accepted) == len(a.names) {
			st = "ready"
		}
		if a.csr != nil {
			st = "valid"
		}
		js(200, map[string]any{"status": st, "finalize": a.url("/finalize/1"), "certificate": a.url("/cert/1")})
	case r.URL.Path == "/finalize/1":
		raw, _ := base64.RawURLEncoding.DecodeString(a.payload(r)["csr"].(string))
		csr, err := x509.ParseCertificateRequest(raw)
		if err != nil {
			js(400, map[string]string{"type": "urn:ietf:params:acme:error:badCSR"})
			return
		}
		a.csr = csr
		w.Header().Set("Location", a.url("/order/1"))
		js(200, map[string]any{"status": "valid", "finalize": a.url("/finalize/1"), "certificate": a.url("/cert/1")})
	case r.URL.Path == "/cert/1":
		tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: a.csr.DNSNames[0]}, DNSNames: a.csr.DNSNames,
			NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(90 * 24 * time.Hour)}
		der, _ := x509.CreateCertificate(rand.Reader, tpl, a.caCert, a.csr.PublicKey, a.caKey)
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: der})
		pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: a.caCert.Raw})
	case r.URL.Path == "/revoke":
		a.revoked++
		w.WriteHeader(200)
	default:
		js(404, map[string]string{"type": "urn:ietf:params:acme:error:malformed", "detail": "no " + r.URL.Path})
	}
}

func TestDirectoryIssueDNS01(t *testing.T) {
	a := newACMEServer(t)
	l, _ := provlog.Open("", provlog.Options{})
	l.Enable("test")
	ca := NewDirectory(CAInfo{ID: "test", Name: "Test", Directory: a.url("/dir"), KeyTypes: []KeyType{EC256}}, l, nil)
	if !ca.Info().Ready {
		t.Fatal("a directory CA is ready")
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ctx := t.Context()
	acct, err := ca.Register(ctx, key, "ops@example.com", nil)
	if err != nil || acct != a.url("/acct/1") {
		t.Fatalf("register: %q %v", acct, err)
	}
	if again, err := ca.Register(ctx, key, "ops@example.com", nil); err != nil || again != acct {
		t.Fatalf("an existing account is found again: %q %v", again, err)
	}
	names := []string{"shop.example.com", "*.shop.example.com"}
	o, err := ca.NewOrder(ctx, key, acct, names, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(o.Challenges) != 2 || o.Challenges[1].Name != "*.shop.example.com" || o.Challenges[1].TXTName != "_acme-challenge.shop.example.com" {
		t.Fatalf("challenges: %+v", o.Challenges)
	}
	th, _ := xacme.JWKThumbprint(key.Public())
	sum := sha256.Sum256([]byte("tok0." + th))
	if o.Challenges[0].TXTValue != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Fatal("TXT value must be the RFC 8555 key authorization digest")
	}
	if err := ca.Validate(ctx, key, acct, o); err != nil {
		t.Fatal(err)
	}
	certKey, _ := NewKey(EC256)
	csr, _ := CSR(certKey, names)
	chain, err := ca.Finalize(ctx, key, acct, o, csr)
	if err != nil {
		t.Fatal(err)
	}
	ci, err := Inspect(chain, EC256)
	if err != nil || len(chain) != 2 || len(ci.Names) != 2 || ci.Issuer != "Test ACME Root" {
		t.Fatalf("chain: %d %+v %v", len(chain), ci, err)
	}
	if err := ca.Revoke(ctx, key, acct, chain[0]); err != nil || a.revoked != 1 {
		t.Fatalf("revoke: %v", err)
	}

	// the log has the flow with ops, and no signature, nonce or CSR body
	p := l.List(provlog.Filter{Provider: "acme:test"}, 0, 0)
	ops := map[string]bool{}
	for _, e := range p.Entries {
		ops[e.Op] = true
		raw, _ := json.Marshal(e)
		if strings.Contains(string(raw), `"signature"`) || strings.Contains(string(raw), `nonce-`) && e.HTTP.Request != "" && strings.Contains(e.HTTP.Request, "nonce-") {
			t.Fatalf("JWS details leaked: %s", raw)
		}
		if e.HTTP != nil && strings.Contains(e.HTTP.Request, `"csr":"`) && !strings.Contains(e.HTTP.Request, "[CSR,") {
			t.Fatalf("CSR body kept: %s", e.HTTP.Request)
		}
	}
	for _, op := range []string{"Register", "NewOrder", "GetAuthorization", "Accept", "WaitAuthorization", "WaitOrder", "Finalize", "Revoke"} {
		if !ops[op] {
			t.Errorf("no log entry for %s (have %v)", op, ops)
		}
	}
}

func TestDirectoryHTTP01(t *testing.T) {
	a := newACMEServer(t)
	ca := NewDirectory(CAInfo{ID: "test", Directory: a.url("/dir")}, nil, nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	acct, _ := ca.Register(t.Context(), key, "", nil)
	o, err := ca.NewOrder(t.Context(), key, acct, []string{"www.example.com", "*.example.com"}, func(string) string { return HTTP01 })
	if err != nil {
		t.Fatal(err)
	}
	th, _ := xacme.JWKThumbprint(key.Public())
	if c := o.Challenges[0]; c.Type != HTTP01 || c.Token != "h0" || c.KeyAuth != "h0."+th || c.TXTName != "" {
		t.Fatalf("http-01 challenge: %+v", c)
	}
	if c := o.Challenges[1]; c.Type != DNS01 {
		t.Fatalf("a wildcard always gets dns-01: %+v", c)
	}
	if err := ca.Validate(t.Context(), key, acct, o); err != nil {
		t.Fatal(err)
	}
}

func TestDirectoryRateLimit(t *testing.T) {
	a := newACMEServer(t)
	ca := NewDirectory(CAInfo{ID: "test", Directory: a.url("/dir")}, nil, nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	acct, _ := ca.Register(t.Context(), key, "", nil)
	a.mu.Lock()
	a.rateNext = true
	a.mu.Unlock()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	_, err := ca.NewOrder(ctx, key, acct, []string{"a.example.com"}, nil)
	if !errors.Is(err, ErrRateLimited) || !strings.Contains(err.Error(), "too many certificates") {
		t.Fatalf("rate limit: %v", err)
	}
}

func TestRedactJWS(t *testing.T) {
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	body, _ := json.Marshal(map[string]string{
		"protected": enc(map[string]any{"alg": "ES256", "nonce": "n-secret", "url": "https://ca/x", "kid": "https://ca/acct/1"}),
		"payload":   enc(map[string]any{"csr": "AAAA", "externalAccountBinding": map[string]any{"protected": enc(map[string]any{"kid": "k1"}), "signature": "mac"}}),
		"signature": "sig-secret",
	})
	out := redactJWS(body, true)
	for _, bad := range []string{"n-secret", "sig-secret", "mac", `"AAAA"`} {
		if strings.Contains(out, bad) {
			t.Errorf("%q kept: %s", bad, out)
		}
	}
	if !strings.Contains(out, "https://ca/x") || !strings.Contains(out, `"kid":"k1"`) {
		t.Fatalf("useful parts must stay: %s", out)
	}
	if out := redactJWS([]byte("-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n"), false); out != "[certificate chain: 1 PEM blocks]" {
		t.Fatal(out)
	}
}
