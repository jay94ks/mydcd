// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDynamicStoreCertificateChoosesSupportedECDSAOrRSA(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	pairs := make([]CertificateVersion, 0, 2)
	for i, key := range []crypto.Signer{rsaKey, ecdsaKey} {
		leaf := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1)), DNSNames: []string{"shop.example"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, key.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		roots.AddCert(parsed)
		pairs = append(pairs, CertificateVersion{Fingerprint: sha256.Sum256(der), NotAfter: parsed.NotAfter.Unix(), Certificate: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: parsed}})
	}
	m := &Manager{ctx: context.Background()}
	m.SetCertificateSource(func(_ context.Context, host string, _ []CertificateVersion) ([]CertificateVersion, error) {
		if host != "shop.example" {
			t.Fatal(host)
		}
		return pairs, nil
	})
	dynamic := m.dynamicCertificateConfig(nil)
	for _, test := range []struct {
		name        string
		schemes     []tls.SignatureScheme
		fingerprint [32]byte
	}{
		{"ecdsa-preferred", []tls.SignatureScheme{tls.PSSWithSHA256, tls.ECDSAWithP256AndSHA256}, pairs[1].Fingerprint},
		{"rsa-only", []tls.SignatureScheme{tls.PSSWithSHA256}, pairs[0].Fingerprint},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
			server.TLS = dynamic.Clone()
			server.TLS.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				// Preserve the real handshake context and bound connection while
				// exercising the client's signature ceiling in the product selector.
				limited := *hello
				limited.SignatureSchemes = test.schemes
				return dynamic.GetCertificate(&limited)
			}
			server.StartTLS()
			defer server.Close()
			transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "shop.example", MinVersion: tls.VersionTLS13}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
			response, err := client.Get(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if got := sha256.Sum256(response.TLS.PeerCertificates[0].Raw); got != test.fingerprint {
				t.Fatal("unsupported or lower-preference key served")
			}
		})
	}
}

func TestDynamicCertificateKeepsOldValidPairOnReloadFailureAndRefusesExpired(t *testing.T) {
	local, _ := ingressCertificate(t)
	config, fingerprint, err := LoadCertificate(local)
	if err != nil {
		t.Fatal(err)
	}
	pair := CertificateVersion{Fingerprint: fingerprint, NotAfter: config.Certificates[0].Leaf.NotAfter.Unix(), Certificate: config.Certificates[0]}
	m := &Manager{ctx: context.Background()}
	current := []CertificateVersion{pair}
	var failure error
	m.SetCertificateSource(func(_ context.Context, host string, previous []CertificateVersion) ([]CertificateVersion, error) {
		if host != "example.test" {
			t.Fatal("source selection changed", host)
		}
		return current, failure
	})
	got, err := m.certificateVersions(context.Background(), "example.test")
	if err != nil || len(got) != 1 || got[0].Fingerprint != pair.Fingerprint {
		t.Fatal(got, err)
	}
	bad := pair
	bad.Fingerprint[0] ^= 1
	current = []CertificateVersion{bad}
	m.certMu.Lock()
	cached := m.certificateCache["example.test"]
	cached.checkedAt = 0
	m.certificateCache["example.test"] = cached
	m.certMu.Unlock()
	got, err = m.certificateVersions(context.Background(), "example.test")
	if err != nil || got[0].Fingerprint != pair.Fingerprint {
		t.Fatal("failed new version replaced original", got, err)
	}
	observed := m.certificateObservations(Spec{Listeners: []Listener{{TLS: true}}, Routes: []Route{{Host: "example.test"}}})
	if len(observed) != 1 || observed[0].Error != "certificate-load-failed" || observed[0].Fingerprint != pair.Fingerprint {
		t.Fatal(observed)
	}
	raw, _ := json.Marshal(observed)
	if strings.Contains(string(raw), "PRIVATE KEY") || strings.Contains(string(raw), "Certificate") || strings.Contains(string(raw), local.KeyFile) {
		t.Fatal("private material reached public observation")
	}
	m.certMu.Lock()
	state := m.certificateCache["example.test"]
	state.pairs[0].NotAfter = time.Now().Unix() - 1
	state.checkedAt = 0
	m.certificateCache["example.test"] = state
	m.certMu.Unlock()
	failure = errors.New("private adapter failure")
	if _, err = m.certificateVersions(context.Background(), "example.test"); err == nil {
		t.Fatal("expired last-good pair served")
	}
}

func TestHostOnlyTLSSelectionDoesNotDependOnRootRouteAndPrefersExactName(t *testing.T) {
	table, err := NewTable([]Route{{ID: "wild", Host: "*.test", Prefix: "/", Service: "wild"}, {ID: "exact", Host: "shop.test", Prefix: "/admin", Service: "exact"}})
	if err != nil {
		t.Fatal(err)
	}
	route, err := table.Host("shop.test")
	if err != nil || route.ID != "exact" {
		t.Fatal("TLS host selection used path or wildcard first", route, err)
	}
	route, err = table.Host("other.test")
	if err != nil || route.ID != "wild" {
		t.Fatal(route, err)
	}
}

func TestPlainSharedListenerDoesNotConsumeTLSAndNewHandshakesRecheckCertificates(t *testing.T) {
	m := &Manager{gateways: map[string]*sharedGateway{"http": {kind: "local", definition: Listener{ID: "http", Address: "10.0.0.11:80"}}, "https": {kind: "local", definition: Listener{ID: "https", Address: "10.0.0.11:443", TLS: true}}}}
	route := Route{ID: "web", Host: "shop.test", Prefix: "/", Service: "web"}
	s := Spec{Listeners: []Listener{{ID: "app-http", Shared: "http"}}}
	if m.routeServesTLS(s, route) {
		t.Fatal("plaintext emitted a TLS requirement")
	}
	s.Listeners = append(s.Listeners, Listener{ID: "app-https", Shared: "https"})
	if !m.routeServesTLS(s, route) {
		t.Fatal("shared TLS listener missing")
	}
	config := m.dynamicCertificateConfig(nil)
	if !config.SessionTicketsDisabled {
		t.Fatal("resumed new connection could bypass current certificate expiry")
	}
	if raw, err := json.Marshal(CertificateVersion{Digest: [32]byte{1}}); err == nil || len(raw) > 0 {
		t.Fatal("private TLS adapter result serialized")
	}
}

func TestAuthoritativeCertificateWithdrawalFencesLastGoodPairAndPassesExactPrevious(t *testing.T) {
	local, _ := ingressCertificate(t)
	config, fingerprint, err := LoadCertificate(local)
	if err != nil {
		t.Fatal(err)
	}
	pair := CertificateVersion{Digest: [32]byte{7}, Fingerprint: fingerprint, NotAfter: config.Certificates[0].Leaf.NotAfter.Unix(), Certificate: config.Certificates[0]}
	m := &Manager{}
	calls := 0
	withdraw := false
	m.SetCertificateSource(func(_ context.Context, host string, previous []CertificateVersion) ([]CertificateVersion, error) {
		calls++
		if calls > 1 {
			if len(previous) != 1 || previous[0].Digest != pair.Digest {
				t.Fatal("private reuse was not pinned to original exact digest")
			}
			original, originalOK := pair.Certificate.PrivateKey.(ed25519.PrivateKey)
			reused, reusedOK := previous[0].Certificate.PrivateKey.(ed25519.PrivateKey)
			if !originalOK || !reusedOK || len(original) != ed25519.PrivateKeySize || len(reused) != len(original) || &original[0] != &reused[0] {
				t.Fatal("private reuse did not retain the exact original key backing storage")
			}
		}
		if withdraw {
			return nil, ErrCertificateWithdrawn
		}
		return []CertificateVersion{pair}, nil
	})
	if _, err = m.certificateVersions(context.Background(), "example.test"); err != nil {
		t.Fatal(err)
	}
	// Recheck the source now without waiting or mutating wall-clock policy.
	m.certMu.Lock()
	state := m.certificateCache["example.test"]
	state.checkedAt = 0
	m.certificateCache["example.test"] = state
	m.certMu.Unlock()
	if _, err = m.certificateVersions(context.Background(), "example.test"); err != nil || calls != 2 {
		t.Fatal("unchanged source was not reauthorized", err, calls)
	}
	withdraw = true
	m.certMu.Lock()
	state = m.certificateCache["example.test"]
	state.checkedAt = 0
	m.certificateCache["example.test"] = state
	m.certMu.Unlock()
	if _, err = m.certificateVersions(context.Background(), "example.test"); err == nil {
		t.Fatal("authoritative delete/revocation served last good pair")
	}
	m.certMu.Lock()
	remaining := len(m.certificateCache["example.test"].pairs)
	m.certMu.Unlock()
	if remaining != 0 {
		t.Fatal("withdrawn private key retained")
	}
	if observations := m.certificateObservations(Spec{Listeners: []Listener{{TLS: true}}, Routes: []Route{{Host: "example.test"}}}); len(observations) != 1 || observations[0].Error != "certificate-withdrawn" {
		t.Fatal(observations)
	}
}
