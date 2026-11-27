// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/netip"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/schema"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

type boundaryDependencies map[string]BackendSpec

func (d boundaryDependencies) Acquire(_ context.Context, b BackendSpec, c string) error {
	if old, ok := d[c]; ok && marshal(old) != marshal(b) {
		return ErrRoute
	}
	d[c] = b
	return nil
}
func (d boundaryDependencies) Release(_ context.Context, b BackendSpec, c string) error {
	if old, ok := d[c]; ok && marshal(old) != marshal(b) {
		return ErrRoute
	}
	delete(d, c)
	return nil
}

func ingressPort(t *testing.T) string {
	t.Helper()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	a := l.Addr().String()
	if e = l.Close(); e != nil {
		t.Fatal(e)
	}
	return a
}
func ingressCertificate(t *testing.T) (Certificate, *tls.Config) {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.test"}, DNSNames: []string{"example.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	pk, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	d := t.TempDir()
	c := Certificate{filepath.Join(d, "cert.pem"), filepath.Join(d, "key.pem")}
	if e = os.WriteFile(c.CertFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(c.KeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), 0600); e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return c, &tls.Config{RootCAs: roots, ServerName: "example.test", MinVersion: tls.VersionTLS13}
}
func TestRealBoundaryHTTPProtocolsStreamingAndReferences(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	var healthy atomic.Bool
	healthy.Store(true)
	canceled := make(chan string, 8)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			if !healthy.Load() {
				w.WriteHeader(503)
			}
			return
		case "/events":
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "data: first\n\n")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			canceled <- r.URL.Path
		case "/slow":
			<-r.Context().Done()
			canceled <- r.URL.Path
		case "/early-hints":
			w.Header().Set("Link", "</early.css>; rel=preload; as=style")
			w.WriteHeader(http.StatusEarlyHints)
			w.Header().Del("Link")
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, "created after early hints")
		case "/upgrade":
			c, b, e := w.(http.Hijacker).Hijack()
			if e != nil {
				return
			}
			defer c.Close()
			fmt.Fprint(b, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
			b.Flush()
			line, e := b.ReadString('\n')
			if e == nil {
				fmt.Fprint(b, line)
				b.Flush()
			}
		default:
			fmt.Fprintf(w, "backend %s", r.URL.Path)
		}
	}))
	defer backend.Close()
	addr := netip.MustParseAddrPort(strings.TrimPrefix(backend.URL, "http://"))
	cert, tc := ingressCertificate(t)
	clear, secure := ingressPort(t), ingressPort(t)
	s := Spec{Schema: 1, Owner: "owner", Listeners: []Listener{{ID: "clear", Address: clear}, {ID: "tls", Address: secure, TLS: true, HTTP3: true}}, Routes: []Route{{ID: "root", Host: "example.test", Prefix: "/", Service: "api"}}, Services: []Service{{ID: "api", Backends: []BackendSpec{{ID: "original", Task: "workload/task/a", Network: "net", Generation: 1, Address: addr.Addr(), Port: addr.Port(), Weight: 1, Capacity: 2, HealthPath: "/health"}}}}, MaxRequests: 2, MaxConnections: 16, MaxHeaderBytes: 4096, BufferBytes: 2 * 64 << 10, MaxBodyBytes: 32, RequestTimeoutMS: 1500, DialTimeoutMS: 100, ResponseHeaderTimeoutMS: 200, HealthIntervalMS: 50}
	deps := boundaryDependencies{}
	db := filepath.Join(t.TempDir(), "ingress.db")
	m, e := openWithCertificates(ctx, db, deps, cert)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if m != nil {
			if e := m.Close(); e != nil {
				t.Error(e)
			}
		}
	}()
	key := "ingress/app/a"
	if e = m.Reconcile(ctx, key, 1, 1, &s); e != nil {
		t.Fatal(e)
	}
	wait := func(what string, p func() bool) {
		t.Helper()
		for !p() {
			select {
			case <-ctx.Done():
				t.Fatal(what, ctx.Err())
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	ready := func() bool { o, e := m.Observe(key); return e == nil && o.Ready }
	wait("fresh actual backend health", ready)
	h1t := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer h1t.CloseIdleConnections()
	h2t := &http2.Transport{TLSClientConfig: tc.Clone()}
	defer h2t.CloseIdleConnections()
	h3t := &http3.Transport{TLSClientConfig: tc.Clone()}
	defer h3t.Close()
	h1, h2, h3 := &http.Client{Transport: h1t}, &http.Client{Transport: h2t}, &http.Client{Transport: h3t}
	request := func(c *http.Client, endpoint, path string, requestCtx context.Context, body io.Reader) *http.Response {
		t.Helper()
		r, e := http.NewRequestWithContext(requestCtx, "GET", endpoint+path, body)
		if e != nil {
			t.Fatal(e)
		}
		r.Host = "example.test"
		res, e := c.Do(r)
		if e != nil {
			t.Fatal(path, e)
		}
		return res
	}
	for _, v := range []struct {
		c     *http.Client
		url   string
		major int
		alpn  string
	}{{h1, "http://" + clear, 1, ""}, {h2, "https://" + secure, 2, "h2"}, {h3, "https://" + secure, 3, "h3"}} {
		r := request(v.c, v.url, "/ping", ctx, nil)
		b, e := io.ReadAll(r.Body)
		r.Body.Close()
		if e != nil || r.StatusCode != 200 || r.ProtoMajor != v.major || string(b) != "backend /ping" || v.alpn != "" && (r.TLS == nil || r.TLS.NegotiatedProtocol != v.alpn) {
			t.Fatalf("protocol %d: %+v %q %v", v.major, r, b, e)
		}
	}
	// An upstream 103 must be forwarded while only the actual final 201 is
	// counted. This uses the same real upstream/proxy/listener as the protocol
	// requests above, including its original backend lease and response body.
	wait("protocol request metrics settled", func() bool { return m.management.Snapshot(key, uint64(time.Now().UnixMilli())).Instance.Requests == 3 })
	beforeHints := m.management.Snapshot(key, uint64(time.Now().UnixMilli()))
	hints := make(chan http.Header, 1)
	traceCtx := httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
		if code != http.StatusEarlyHints {
			return fmt.Errorf("unexpected informational response: %d", code)
		}
		hints <- http.Header(header).Clone()
		return nil
	}})
	hinted := request(h1, "http://"+clear, "/early-hints", traceCtx, nil)
	hintedBody, readErr := io.ReadAll(hinted.Body)
	hinted.Body.Close()
	if readErr != nil || hinted.StatusCode != http.StatusCreated || string(hintedBody) != "created after early hints" || hinted.Header.Get("Link") != "" {
		t.Fatal("informational response replaced final status/headers/body", hinted.StatusCode, hinted.Header, string(hintedBody), readErr)
	}
	select {
	case header := <-hints:
		if header.Get("Link") != "</early.css>; rel=preload; as=style" {
			t.Fatal("early hint headers not forwarded", header)
		}
	default:
		t.Fatal("upstream early hints not forwarded")
	}
	wait("final response metrics settled", func() bool {
		return m.management.Snapshot(key, uint64(time.Now().UnixMilli())).Instance.Requests == beforeHints.Instance.Requests+1
	})
	afterHints := m.management.Snapshot(key, uint64(time.Now().UnixMilli()))
	if afterHints.Instance.Responses[0] != beforeHints.Instance.Responses[0]+1 || afterHints.Instance.SentBytes != beforeHints.Instance.SentBytes+uint64(len(hintedBody)) || len(afterHints.Routes) != 1 || afterHints.Routes[0].Responses[0] != beforeHints.Routes[0].Responses[0]+1 || len(afterHints.Backends) != 1 || afterHints.Backends[0].Responses[0] != beforeHints.Backends[0].Responses[0]+1 {
		t.Fatal("early hints were counted instead of the final response", beforeHints, afterHints)
	}
	for _, p := range []struct {
		path string
		body io.Reader
		code int
	}{{"/x%2fy", nil, 400}, {"/ping", strings.NewReader(strings.Repeat("x", 33)), 413}, {"/slow", nil, 502}} {
		r := request(h1, "http://"+clear, p.path, ctx, p.body)
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
		if r.StatusCode != p.code {
			t.Fatalf("%s code %d want %d", p.path, r.StatusCode, p.code)
		}
	}
	select {
	case p := <-canceled:
		if p != "/slow" {
			t.Fatal(p)
		}
	case <-ctx.Done():
		t.Fatal("backend timeout not canceled")
	}
	// A real bidirectional HTTP/1.1 Upgrade must release its original lease.
	c, e := net.Dial("tcp4", clear)
	if e != nil {
		t.Fatal(e)
	}
	c.SetDeadline(time.Now().Add(time.Second))
	fmt.Fprint(c, "GET /upgrade HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
	rd := bufio.NewReader(c)
	up, e := http.ReadResponse(rd, &http.Request{Method: "GET"})
	if e != nil || up.StatusCode != 101 {
		c.Close()
		t.Fatal("upgrade", up, e)
	}
	fmt.Fprint(c, "echo\n")
	line, e := rd.ReadString('\n')
	c.Close()
	if e != nil || line != "echo\n" {
		t.Fatal("bidirectional upgrade", line, e)
	}
	wait("upgrade pin return", func() bool { o, _ := m.Observe(key); return o.Requests == 0 })
	// Close/reopen the actual module DB and every owned listener. The native
	// dependency survives and is reacquired by exactly the same consumer ID.
	if len(deps) != 1 {
		t.Fatal("dependency", deps)
	}
	var original string
	for k := range deps {
		original = k
	}
	if e = m.Close(); e != nil {
		t.Fatal(e)
	}
	m = nil
	m, e = openWithCertificates(ctx, db, deps, cert)
	if e != nil {
		t.Fatal(e)
	}
	if e = m.Reconcile(ctx, key, 1, 1, &s); e != nil {
		t.Fatal(e)
	}
	wait("restart health", ready)
	if len(deps) != 1 || deps[original].ID != "original" {
		t.Fatal("changed dependency on restart", deps)
	}
	healthy.Store(false)
	wait("actual unhealthy observation", func() bool { return !ready() })
	res := request(h1, "http://"+clear, "/ping", ctx, nil)
	res.Body.Close()
	if res.StatusCode != 503 {
		t.Fatal("unhealthy backend admitted", res.StatusCode)
	}
	healthy.Store(true)
	wait("actual health recovery", ready)
	streamCtx, stop := context.WithCancel(ctx)
	defer stop()
	res = request(h1, "http://"+clear, "/events", streamCtx, nil)
	reader := bufio.NewReader(res.Body)
	line, e = reader.ReadString('\n')
	if e != nil || line != "data: first\n" {
		t.Fatal("SSE flush", line, e)
	}
	s.Lifecycle = schema.Lifecycle{Drain: true, Nonce: [16]byte{1}}
	if e = m.Reconcile(ctx, key, 2, 1, &s); e != nil {
		t.Fatal(e)
	}
	o, e := m.Observe(key)
	if e != nil || o.Gone || o.Requests != 1 || len(deps) != 1 {
		t.Fatal("premature Drain return", o, deps, e)
	}
	denied := request(h1, "http://"+clear, "/ping", ctx, nil)
	denied.Body.Close()
	if denied.StatusCode != 503 {
		t.Fatal("Drain admitted request", denied.StatusCode)
	}
	stop()
	res.Body.Close()
	select {
	case p := <-canceled:
		if p != "/events" {
			t.Fatal(p)
		}
	case <-ctx.Done():
		t.Fatal("SSE backend did not observe cancel")
	}
	wait("SSE exact pin return", func() bool { o, _ := m.Observe(key); return o.Requests == 0 })
	if e = m.Reconcile(ctx, key, 2, 1, &s); e != nil {
		t.Fatal(e)
	}
	o, e = m.Observe(key)
	if e != nil || !o.Gone || len(deps) != 0 || len(o.Listeners) != 0 {
		t.Fatal("Gone without settled resources", o, deps, e)
	}
	t.Log("actual HTTP/1.1, TLS/ALPN h2 and h3; Upgrade/SSE; health failure/recovery; bounded body/path/header timeout; client cancel; same DB/stable dependency; live Drain then exact return and socket Wait")
}

// fileCertificateSource stands in for the cluster store: it serves each file
// certificate for the hosts its leaf covers.
func fileCertificateSource(certs ...Certificate) CertificateSource {
	return func(_ context.Context, host string, _ []CertificateVersion) ([]CertificateVersion, error) {
		out := []CertificateVersion{}
		for _, c := range certs {
			config, fingerprint, err := LoadCertificate(c)
			if err != nil {
				return nil, err
			}
			pair := config.Certificates[0]
			if pair.Leaf.VerifyHostname(strings.TrimPrefix(host, "*.")) == nil || strings.HasPrefix(host, "*.") {
				out = append(out, CertificateVersion{Fingerprint: fingerprint, NotAfter: pair.Leaf.NotAfter.Unix(), Certificate: pair})
			}
		}
		if len(out) == 0 {
			return nil, ErrCertificateWithdrawn
		}
		return out, nil
	}
}
func openWithCertificates(ctx context.Context, path string, deps Dependencies, certs ...Certificate) (*Manager, error) {
	m, err := Open(ctx, path, deps)
	if err == nil {
		m.SetCertificateSource(fileCertificateSource(certs...))
	}
	return m, err
}
