// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/workload"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

func serverFixture(t *testing.T) (Specification, tls.Certificate, *http.Client) {
	t.Helper()
	cluster := [32]byte{1}
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := l.Addr().String()
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	spec := Specification{Schema: 1, Tenant: "tenant", ID: "private", Node: "node-a", Address: address, Authority: address, Volume: volumes.Scope{Cluster: cluster, Tenant: "tenant", Registry: "private", ID: "images", Generation: 1}, Enabled: true, Metadata: MetadataLimits{ManifestBytes: 4096, Records: 64, TotalBytes: 1 << 20}, Blobs: smallBlobLimits(), Budget: workload.Resources{CPU: 1, Memory: 16 << 20}, MaxRequests: 4, MaxHeaderBytes: 8192, RequestTimeoutMS: 3000, TokenSeconds: 60}
	pair, leaf := serverPair(t, net.ParseIP("127.0.0.1"))
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}, ForceAttemptHTTP2: true}
	t.Cleanup(transport.CloseIdleConnections)
	return spec, pair, &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

func serverPair(t *testing.T, ip net.IP) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "registry fixture"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true, IPAddresses: []net.IP{ip}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}, leaf
}

func serverAuthFixture() Authorization {
	return Authorization{
		Check: func(_ context.Context, token string, p Permission) error {
			if token != "fixture-access" {
				return ErrUnauthorized
			}
			if p.Action == "push" || p.Repository != "" && p.Repository != "team/app" {
				return ErrForbidden
			}
			return nil
		},
		Token: func(_ context.Context, q TokenRequest) (TokenResponse, error) {
			if q.Username != "alice" || !bytes.Equal(q.Secret, []byte("fixture-login")) || q.Scope != "repository:team/app:pull" {
				return TokenResponse{}, ErrUnauthorized
			}
			return TokenResponse{Token: "fixture-access", ExpiresIn: 30, IssuedAt: time.Now().UTC().Format(time.RFC3339)}, nil
		},
	}
}

// Actual TLS/HTTP and request I/O ownership with a fake account callback, not a
// proof of current Raft/catalog admission or Engine push/pull.
func TestRegistryDockerLoginOptionalOfflineHintKeepsBoundedAccess(t *testing.T) {
	spec, certificate, client := serverFixture(t)
	server, err := OpenServer(context.Background(), [32]byte{1}, spec, certificate, http.NotFoundHandler(), serverAuthFixture(), log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := server.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	for _, test := range []struct {
		name, query string
		want        int
	}{
		{"ordinary", "", 200}, {"docker-login", "&offline_token=true&client_id=docker&account=alice", 200},
		{"false", "&offline_token=false", 200}, {"invalid", "&offline_token=invalid", 403},
		{"empty", "&offline_token=", 403}, {"duplicate", "&offline_token=true&offline_token=false", 403},
		{"duplicate-service", "&service=other", 403}, {"refresh-grant", "&grant_type=refresh_token", 403},
		{"refresh-credential", "&refresh_token=not-supported", 403},
		{"redundant-pull", "&scope=repository:team/app:pull", 200},
		{"other-repository", "&scope=repository:other/app:pull", 403},
		{"additional-action-still-authorized", "&scope=repository:team/app:push", 401},
	} {
		t.Run(test.name, func(t *testing.T) {
			q, _ := http.NewRequest("GET", "https://"+spec.Authority+"/token?service="+url.QueryEscape(spec.Authority)+"&scope="+url.QueryEscape("repository:team/app:pull")+test.query, nil)
			q.SetBasicAuth("alice", "fixture-login")
			response, err := client.Do(q)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != test.want {
				t.Fatal(response.StatusCode, test.want)
			}
			if test.want == 200 {
				var token struct {
					Token   string `json:"token"`
					Expires int64  `json:"expires_in"`
					Refresh string `json:"refresh_token"`
				}
				if json.NewDecoder(response.Body).Decode(&token) != nil || token.Token != "fixture-access" || token.Expires != 30 || token.Refresh != "" {
					t.Fatal("optional hint changed access or issued refresh authority")
				}
			}
		})
	}
}

func TestRegistryTokenScopeNormalizesOnlySameRepository(t *testing.T) {
	for _, input := range [][]string{
		{"repository:team/app:push", "repository:team/app:pull"},
		{"repository:team/app:pull,push", "repository:team/app:pull,push"},
	} {
		scope, err := tokenScope(input)
		if err != nil || scope != "repository:team/app:pull,push" {
			t.Fatal(scope, err)
		}
	}
	for _, input := range [][]string{
		{"repository:team/app:pull", "registry:catalog:*"},
		{"repository:team/app:pull", ""},
		{"repository:team/app:pull", "repository:team/app:delete"},
		{"", "", "", "", ""},
	} {
		if _, err := tokenScope(input); !errors.Is(err, ErrForbidden) {
			t.Fatal("ambiguous/excess scope accepted", input, err)
		}
	}
}

func TestRegistryActualTLSServerRequiresAuthAndFixedAuthorityRepository(t *testing.T) {
	spec, certificate, client := serverFixture(t)
	var content atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { content.Add(1); _, _ = io.WriteString(w, "content") })
	server, err := OpenServer(context.Background(), [32]byte{1}, spec, certificate, handler, serverAuthFixture(), log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, public := server.Trust()
	if len(public) == 0 {
		t.Fatal("serving certificate chain unavailable")
	}
	leaf, err := x509.ParseCertificate(public[0])
	if err != nil || sha256.Sum256(leaf.Raw) != server.Certificate() || fingerprint != server.Certificate() {
		t.Fatal("public chain differs from serving certificate", err)
	}
	public[0][0] ^= 1
	if _, again := server.Trust(); func() error { _, err := x509.ParseCertificate(again[0]); return err }() != nil {
		t.Fatal("caller changed serving chain", err)
	}
	t.Cleanup(func() {
		if err := server.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	request := func(method, path, bearer, host string, want int) {
		t.Helper()
		q, _ := http.NewRequest(method, "https://"+spec.Authority+path, nil)
		if bearer != "" {
			q.Header.Set("Authorization", "Bearer "+bearer)
		}
		if host != "" {
			q.Host = host
		}
		resp, err := client.Do(q)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		if resp.StatusCode != want {
			t.Fatal(path, resp.StatusCode, want)
		}
		if want == 401 && !strings.Contains(resp.Header.Get("WWW-Authenticate"), "https://"+spec.Authority+"/token") {
			t.Fatal("wrong challenge")
		}
	}
	request("GET", "/v2/", "", "", 401)
	request("GET", "/v2/team/app/manifests/stable", "fixture-access", "other.example", 403)
	request("GET", "/v2/other/app/manifests/stable", "fixture-access", "", 403)
	request("PUT", "/v2/team/app/manifests/stable", "fixture-access", "", 403)
	if content.Load() != 0 {
		t.Fatal("denied request consumed content")
	}
	request("GET", "/v2/team/app/manifests/stable", "fixture-access", "", 200)
	q, _ := http.NewRequest("GET", "https://"+spec.Authority+"/token?service="+url.QueryEscape(spec.Authority)+"&scope="+url.QueryEscape("repository:team/app:pull"), nil)
	q.SetBasicAuth("alice", "fixture-login")
	resp, err := client.Do(q)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var token TokenResponse
	if resp.StatusCode != 200 || json.NewDecoder(resp.Body).Decode(&token) != nil || token.Token != "fixture-access" {
		t.Fatal("derived login exchange", resp.StatusCode)
	}
}

func TestRegistryCloseTimeoutRetainsOriginalHandlerUntilActualJoin(t *testing.T) {
	spec, certificate, client := serverFixture(t)
	spec.MaxRequests = 1
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	finish := func() { releaseOnce.Do(func() { close(release) }) }
	defer finish()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		_, _ = io.WriteString(w, "late")
	})
	server, err := OpenServer(context.Background(), [32]byte{1}, spec, certificate, handler, serverAuthFixture(), log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { finish(); _ = server.Close(context.Background()) })
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		q, _ := http.NewRequest("GET", "https://"+spec.Authority+"/v2/team/app/manifests/stable", nil)
		q.Header.Set("Authorization", "Bearer fixture-access")
		resp, err := client.Do(q)
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("handler not entered")
	}
	// A second admitted request cannot bypass the same request budget, even
	// when the transport could multiplex it over an already-open TLS connection.
	w := httptest.NewRecorder()
	q := httptest.NewRequest("GET", "https://"+spec.Authority+"/v2/", nil)
	server.handle(w, q)
	if w.Code != 429 {
		t.Fatal("request budget bypass", w.Code)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err = server.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("timeout became actual closure", err)
	}
	select {
	case <-server.done:
		t.Fatal("handler was still live")
	default:
	}
	finish()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	if err = server.Close(ctx2); err != nil {
		t.Fatal(err)
	}
	select {
	case <-clientDone:
	case <-ctx2.Done():
		t.Fatal("client not closed")
	}
}

func TestRegistryServerRefusesMissingAuthAndPublicCertificateKey(t *testing.T) {
	spec, certificate, _ := serverFixture(t)
	if _, err := OpenServer(context.Background(), [32]byte{1}, spec, certificate, http.NotFoundHandler(), Authorization{}, log.New(io.Discard, "", 0)); err == nil {
		t.Fatal("anonymous fallback")
	}
	public := certificate
	public.PrivateKey = nil
	if _, err := OpenServer(context.Background(), [32]byte{1}, spec, public, http.NotFoundHandler(), serverAuthFixture(), log.New(io.Discard, "", 0)); err == nil {
		t.Fatal("pair without key")
	}
	other, _ := serverPair(t, net.ParseIP("127.0.0.2"))
	if _, err := OpenServer(context.Background(), [32]byte{1}, spec, other, http.NotFoundHandler(), serverAuthFixture(), log.New(io.Discard, "", 0)); err == nil {
		t.Fatal("pair for another host")
	}
}

func TestRegistryServerReplacesCertificateForNewHandshakes(t *testing.T) {
	spec, certificate, _ := serverFixture(t)
	server, err := OpenServer(context.Background(), [32]byte{1}, spec, certificate, http.NotFoundHandler(), serverAuthFixture(), log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close(context.Background()) })
	first := server.Certificate()
	other, _ := serverPair(t, net.ParseIP("127.0.0.2"))
	if server.SetCertificate(other) == nil || server.Certificate() != first {
		t.Fatal("pair for another host replaced the served one")
	}
	next, leaf := serverPair(t, net.ParseIP("127.0.0.1"))
	if err := server.SetCertificate(next); err != nil || server.Certificate() != sha256.Sum256(leaf.Raw) {
		t.Fatal("renewed pair not served", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	conn, err := tls.Dial("tcp", spec.Address, &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal("new handshake does not use the renewed pair", err)
	}
	_ = conn.Close()
}
