// SPDX-License-Identifier: Apache-2.0

package servicecall

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/containerops"
)

func testTarget(address netip.Addr, port uint16) Target {
	return Target{Container: containerops.Target{Cluster: [32]byte{1}, Owner: [32]byte{2}, Binding: [32]byte{3}, Tenant: "tenant", App: "shop", Service: "api", Node: "node-a", Instance: "task/api", Generation: 1, Revision: 1, NativeID: strings.Repeat("a", 64)}, Address: address, Port: port}
}
func testIP(t *testing.T) netip.Addr {
	t.Helper()
	interfaces, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range interfaces {
		prefix, err := netip.ParsePrefix(raw.String())
		if err == nil && prefix.Addr().Is4() && !prefix.Addr().IsLoopback() && !prefix.Addr().IsLinkLocalUnicast() {
			return prefix.Addr()
		}
	}
	t.Skip("actual service-call socket fixture requires a local non-loopback IPv4")
	return netip.Addr{}
}
func testServer(t *testing.T, handler http.Handler, tlsConfig *tls.Config) (*httptest.Server, Target) {
	t.Helper()
	address := testIP(t)
	listener, err := net.Listen("tcp", net.JoinHostPort(address.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Listener.Close()
	server.Listener = listener
	if tlsConfig != nil {
		server.TLS = tlsConfig
		server.StartTLS()
	} else {
		server.Start()
	}
	t.Cleanup(server.Close)
	return server, testTarget(address, uint16(listener.Addr().(*net.TCPAddr).Port))
}

func TestActualServiceHTTPBoundsNoRedirectAndNoCredentialHeaders(t *testing.T) {
	var received atomic.Int64
	var redirected atomic.Int64
	server, target := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/target" {
			redirected.Add(1)
		}
		if r.URL.Path == "/redirect" {
			w.Header().Set("Location", "/target")
			w.WriteHeader(302)
			return
		}
		if r.URL.Path == "/large" {
			w.Header().Set("Content-Length", "65537")
			_, _ = w.Write(make([]byte, MaxResponse+1))
			return
		}
		body, _ := io.ReadAll(r.Body)
		received.Store(int64(len(body)))
		if r.Header.Get("X-MyDC-Test") != "fixed" || r.Header.Get("Authorization") != "" {
			t.Error("unexpected request headers")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "private-cookie")
		_, _ = w.Write([]byte("answer"))
	}), nil)
	_ = server
	q := Request{App: "shop", Service: "api", Port: int(target.Port), Path: "/decide", Method: "POST", Body: bytes.Repeat([]byte("b"), MaxBody), Headers: map[string]string{"Content-Type": "application/json", "X-MyDC-Test": "fixed"}}
	out, err := Execute(context.Background(), q, target, nil)
	if err != nil || !out.Valid() || out.Code != "" || out.Status != 200 || string(out.Body) != "answer" || len(out.Headers) != 1 || received.Load() != MaxBody {
		t.Fatal(out, err)
	}
	q.Path = "/redirect"
	q.Body = nil
	out, err = Execute(context.Background(), q, target, nil)
	if err != nil || out.Status != 302 || redirected.Load() != 0 {
		t.Fatal("followed redirect", out, err)
	}
	q.Path = "/large"
	out, err = Execute(context.Background(), q, target, nil)
	if err != nil || out.Code != TooLarge || out.Body != nil || out.Status != 0 {
		t.Fatal("response overflow", out, err)
	}
}

func TestActualServiceHTTPSCAExplicitSkipAndPlainPortClassification(t *testing.T) {
	address := testIP(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP(address.String())}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, public, private)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
	if err != nil {
		t.Fatal(err)
	}
	server, target := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("secure")) }), &tls.Config{Certificates: []tls.Certificate{certificate}})
	_ = server
	q := Request{App: "shop", Service: "api", Port: int(target.Port), Path: "/", Method: "POST", Scheme: "https"}
	out, err := Execute(context.Background(), q, target, nil)
	if err != nil || out.Code != TLS {
		t.Fatal("untrusted TLS", out, err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	out, err = Execute(context.Background(), q, target, roots)
	if err != nil || out.Code != "" || string(out.Body) != "secure" {
		t.Fatal("tenant CA TLS", out, err)
	}
	q.InsecureSkipVerify = true
	out, err = Execute(context.Background(), q, target, nil)
	if err != nil || out.Code != "" {
		t.Fatal("explicit TLS skip", out, err)
	}
	_, plain := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("plain")) }), nil)
	q.Port = int(plain.Port)
	out, err = Execute(context.Background(), q, plain, nil)
	if err != nil || out.Code != TLS {
		t.Fatal("plain port was not TLS error", out, err)
	}
}

func TestServiceRequestRejectsArbitraryHostHeaderAndMixedTLS(t *testing.T) {
	q := Request{App: "shop", Service: "api", Port: 8080, Path: "/decide?a=1", Method: "POST"}
	if !q.Valid() {
		t.Fatal("valid request")
	}
	for _, change := range []func(*Request){func(q *Request) { q.Path = "http://169.254.169.254/" }, func(q *Request) { q.Path = "//169.254.169.254/" }, func(q *Request) { q.Method = "GET" }, func(q *Request) { q.Headers = map[string]string{"Host": "private"} }, func(q *Request) { q.Headers = map[string]string{"Authorization": "private"} }, func(q *Request) { q.Headers = map[string]string{"X-MyDC-Test": "value\r\nHost: private"} }, func(q *Request) { q.Headers = map[string]string{"X-MyDC-A": "one", "x-mydc-a": "two"} }, func(q *Request) { q.Body = make([]byte, MaxBody+1) }, func(q *Request) { q.TimeoutMS = 30001 }, func(q *Request) { q.InsecureSkipVerify = true }} {
		bad := q
		change(&bad)
		if bad.Valid() {
			t.Fatal("unsafe service request accepted")
		}
	}
	for _, address := range []string{"127.0.0.1", "169.254.169.254", "::1", "0.0.0.0"} {
		target := testTarget(netip.MustParseAddr(address), 8080)
		if target.Valid() {
			t.Fatal("unsafe target", address)
		}
	}
}

func TestLimiterKeepsAccountQuotaAcrossSessionsAndPreservesLiveScopes(t *testing.T) {
	l := Limiter{Concurrent: 2, PerMinute: 4, ScopedPerMinute: 2}
	first, ok := l.Acquire("user", 1)
	if !ok {
		t.Fatal("first")
	}
	second, ok := l.Acquire("user", 2)
	if !ok {
		t.Fatal("second")
	}
	if _, ok := l.Acquire("other", 3); ok {
		t.Fatal("server concurrency exceeded")
	}
	first()
	first()
	second()
	if _, ok := l.Acquire("user", 5); ok {
		t.Fatal("renewed session reset stable user quota")
	}
	next, ok := l.Acquire("user", 61)
	if !ok {
		t.Fatal("new minute")
	}
	defer next()
	if _, ok := l.Acquire("", 61); ok {
		t.Fatal("empty scope")
	}
}
