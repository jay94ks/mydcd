// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

// This fixture reuses Open/Reconcile, the actual DB, network dependency adapter,
// TCP/UDP listeners and SDK HTTP clients from the existing ingress boundary
// tests. Only the protected certificate catalog source is injected; it does
// not claim to exercise certificate-upload authentication or Raft delivery.
type tlsHandoffFixture struct {
	ctx                                 context.Context
	manager                             *Manager
	address, key                        string
	legacy                              Spec
	roots                               *x509.CertPool
	originalFingerprint, newFingerprint [32]byte
	originalTCP                         net.Listener
	originalUDP                         net.PacketConn
	originalServer                      *http.Server
	originalQUIC                        *http3.Server
	originalOwned                       *ownedHTTPListener
	entered                             chan struct{}
	release                             chan struct{}
	releaseOnce                         sync.Once
}

func handoffNewCertificate(t *testing.T, name string) (CertificateVersion, *x509.Certificate) {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, public, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(raw)
	return CertificateVersion{Digest: fingerprint, Fingerprint: fingerprint, NotAfter: leaf.NotAfter.Unix(), Certificate: tls.Certificate{Certificate: [][]byte{raw}, PrivateKey: key, Leaf: leaf}}, leaf
}

func newTLSHandoffFixture(t *testing.T, gatewayTLS bool) *tlsHandoffFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	f := &tlsHandoffFixture{ctx: ctx, key: "ingress/app/tenant-a/original/http", entered: make(chan struct{}, 1), release: make(chan struct{})}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path == "/hold" {
			io.WriteString(w, "original-start\n")
			w.(http.Flusher).Flush()
			select {
			case f.entered <- struct{}{}:
			default:
			}
			select {
			case <-f.release:
			case <-r.Context().Done():
				return
			}
			io.WriteString(w, "original-done\n")
			return
		}
		fmt.Fprintf(w, "backend %s", r.URL.Path)
	}))
	original, trust := ingressCertificate(t)
	originalConfig, fingerprint, err := LoadCertificate(original)
	if err != nil {
		backend.Close()
		cancel()
		t.Fatal(err)
	}
	newPair, newLeaf := handoffNewCertificate(t, "new.test")
	f.originalFingerprint, f.newFingerprint = fingerprint, newPair.Fingerprint
	f.roots = trust.RootCAs.Clone()
	f.roots.AddCert(newLeaf)
	m, err := Open(ctx, filepath.Join(t.TempDir(), "ingress.db"), boundaryDependencies{})
	if err != nil {
		backend.Close()
		cancel()
		t.Fatal(err)
	}
	f.manager = m
	// Register all cleanup before the first actual socket effect. Release the
	// original stream before waiting for server/handler termination on failures.
	t.Cleanup(func() {
		f.releaseOnce.Do(func() { close(f.release) })
		cancel()
		if err := m.Close(); err != nil {
			t.Error(err)
		}
		backend.Close()
	})
	address := netip.MustParseAddrPort(ingressPort(t))
	f.address = address.String()
	configuration := GatewayConfiguration{Local: Gateway{Enabled: true, Addresses: []netip.Addr{address.Addr()}, Ports: []uint16{address.Port()}, AllowedSources: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Listeners: []Listener{{ID: "web", Address: f.address, TLS: gatewayTLS, HTTP3: gatewayTLS}}}}
	if err = m.ConfigureGateways(configuration, nil); err != nil {
		t.Fatal(err)
	}
	if err = m.SetTenantPolicy("tenant-a", HostPolicy{LocalHosts: []string{"example.test"}}); err != nil {
		t.Fatal(err)
	}
	if err = m.SetTenantPolicy("tenant-b", HostPolicy{LocalHosts: []string{"new.test"}}); err != nil {
		t.Fatal(err)
	}
	originalPair := CertificateVersion{Fingerprint: fingerprint, NotAfter: originalConfig.Certificates[0].Leaf.NotAfter.Unix(), Certificate: originalConfig.Certificates[0]}
	m.SetCertificateSource(func(_ context.Context, host string, previous []CertificateVersion) ([]CertificateVersion, error) {
		switch host {
		case "example.test":
			return []CertificateVersion{originalPair}, nil
		case "new.test":
			return []CertificateVersion{newPair}, nil
		}
		return nil, ErrCertificateWithdrawn
	})
	s := sharedTestSpec("tenant-a", "original", "example.test", backend.URL)
	s.Listeners = []Listener{{ID: "original-tls", Address: f.address, TLS: true, HTTP3: true}}
	s.Services[0].Backends[0].HealthPath = "/health"
	s.RequestTimeoutMS = 15000
	f.legacy = s
	if err = m.Reconcile(ctx, f.key, 1, 1, &s); err != nil {
		t.Fatal(err)
	}
	if err = m.BindNative(f.key, 1, "original-native"); err != nil {
		t.Fatal(err)
	}
	f.wait(t, "original backend health", func() bool { o, err := m.Observe(f.key); return err == nil && o.Ready })
	m.mu.Lock()
	instance := m.instances[f.key]
	instance.mu.Lock()
	f.originalOwned = instance.direct["original-tls"]
	f.originalTCP, f.originalUDP = f.originalOwned.listener, f.originalOwned.packet
	f.originalServer, f.originalQUIC = instance.servers[0], instance.quicServers[0]
	instance.mu.Unlock()
	m.mu.Unlock()
	return f
}

func (f *tlsHandoffFixture) wait(t *testing.T, what string, condition func() bool) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for !condition() {
		select {
		case <-f.ctx.Done():
			t.Fatal(what, f.ctx.Err())
		case <-ticker.C:
		}
	}
}
func (f *tlsHandoffFixture) client(t *testing.T, major int, name string) *http.Client {
	t.Helper()
	config := &tls.Config{RootCAs: f.roots.Clone(), ServerName: name, MinVersion: tls.VersionTLS13}
	var transport http.RoundTripper
	switch major {
	case 1:
		config.NextProtos = []string{"http/1.1"}
		h := &http.Transport{Proxy: nil, TLSClientConfig: config, ForceAttemptHTTP2: false, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}
		t.Cleanup(h.CloseIdleConnections)
		transport = h
	case 2:
		h := &http2.Transport{TLSClientConfig: config}
		t.Cleanup(h.CloseIdleConnections)
		transport = h
	case 3:
		h := &http3.Transport{TLSClientConfig: config}
		t.Cleanup(func() {
			if err := h.Close(); err != nil {
				t.Error(err)
			}
		})
		transport = h
	default:
		t.Fatal("unknown fixture protocol", major)
	}
	return &http.Client{Transport: transport}
}
func (f *tlsHandoffFixture) request(client *http.Client, name, path string) (*http.Response, error) {
	request, err := http.NewRequestWithContext(f.ctx, http.MethodGet, "https://"+f.address+path, nil)
	if err != nil {
		return nil, err
	}
	request.Host = name
	return client.Do(request)
}
func (f *tlsHandoffFixture) response(t *testing.T, client *http.Client, major int, name, path string, status int, fingerprint [32]byte) {
	t.Helper()
	response, err := f.request(client, name, path)
	if err != nil {
		t.Fatal("TLS/HTTP request", major, name, path, err)
	}
	raw, readErr := io.ReadAll(response.Body)
	response.Body.Close()
	if readErr != nil || response.StatusCode != status || response.ProtoMajor != major {
		t.Fatal("actual protocol response", major, name, path, response.StatusCode, response.ProtoMajor, string(raw), readErr)
	}
	if response.TLS == nil || len(response.TLS.PeerCertificates) == 0 || sha256.Sum256(response.TLS.PeerCertificates[0].Raw) != fingerprint {
		t.Fatal("new handshake consumed an unexpected certificate", major, name)
	}
	alpn := map[int]string{1: "http/1.1", 2: "h2", 3: "h3"}[major]
	if response.TLS.NegotiatedProtocol != alpn {
		t.Fatal("actual negotiated protocol", major, response.TLS.NegotiatedProtocol)
	}
	if status == http.StatusOK && string(raw) != "backend "+path {
		t.Fatal("route did not reach selected backend", major, string(raw))
	}
}
func (f *tlsHandoffFixture) sharedSpec() Spec {
	next := f.legacy
	next.Listeners = []Listener{{ID: "shared", Shared: "web"}}
	next.Routes = append([]Route(nil), next.Routes...)
	next.Routes[0].Prefix = "/after"
	return next
}
func (f *tlsHandoffFixture) assertOriginalPhysical(t *testing.T, handed bool) {
	t.Helper()
	m := f.manager
	m.mu.Lock()
	i := m.instances[f.key]
	i.mu.Lock()
	revision, native := i.record.Revision, i.record.Native
	remaining := len(i.direct) + len(i.listeners) + len(i.servers) + len(i.quicServers)
	current := i.direct["original-tls"]
	i.mu.Unlock()
	m.mu.Unlock()
	if native != "original-native" {
		t.Fatal("original native identity changed", native)
	}
	m.gatewayMu.Lock()
	g := m.gateways["web"]
	g.mu.RLock()
	tcp, udp, server, quic, inherited := g.listener, g.packet, g.server, g.quic, g.inherited
	g.mu.RUnlock()
	m.gatewayMu.Unlock()
	if handed {
		if revision != 2 || remaining != 0 || tcp != f.originalTCP || udp != f.originalUDP || server != f.originalServer || quic != f.originalQUIC || inherited != f.originalOwned {
			t.Fatal("handoff rebound or retained app ownership of physical server", revision, remaining)
		}
		if f.originalOwned.gateway.Load() != g {
			t.Fatal("TLS/HTTP/QUIC delegate was not switched")
		}
	} else if revision != 1 || current != f.originalOwned || tcp != nil || udp != nil || server != nil || quic != nil || f.originalOwned.gateway.Load() != nil {
		t.Fatal("rejected handoff changed the original source/socket", revision)
	}
}

func TestActualTLSH1H2H3HandoffPreservesLeaseAndSwitchesNewSNI(t *testing.T) {
	for _, major := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("http%d", major), func(t *testing.T) {
			f := newTLSHandoffFixture(t, true)
			oldClient := f.client(t, major, "example.test")
			type heldResponse struct {
				body          string
				major, status int
				fingerprint   [32]byte
				err           error
			}
			held := make(chan heldResponse, 1)
			go func() {
				out := heldResponse{}
				response, err := f.request(oldClient, "example.test", "/hold")
				if err == nil {
					out.status, out.major = response.StatusCode, response.ProtoMajor
					if response.TLS != nil && len(response.TLS.PeerCertificates) > 0 {
						out.fingerprint = sha256.Sum256(response.TLS.PeerCertificates[0].Raw)
					}
					raw, e := io.ReadAll(response.Body)
					response.Body.Close()
					out.body, out.err = string(raw), e
				} else {
					out.err = err
				}
				held <- out
			}()
			select {
			case <-f.entered:
			case <-f.ctx.Done():
				t.Fatal("original request did not enter backend", f.ctx.Err())
			}
			f.wait(t, "original durable lease", func() bool { o, err := f.manager.Observe(f.key); return err == nil && o.Requests == 1 })
			next := f.sharedSpec()
			if err := f.manager.Reconcile(f.ctx, f.key, 2, 1, &next); err != nil {
				t.Fatal("exact TLS/QUIC socket handoff", err)
			}
			f.assertOriginalPhysical(t, true)
			if observation, err := f.manager.Observe(f.key); err != nil || observation.Requests != 1 {
				t.Fatal("handoff settled or canceled an active original lease", observation, err)
			}
			f.response(t, oldClient, major, "example.test", "/after", http.StatusOK, f.originalFingerprint)
			// A new tenant uses a different SNI and certificate through the same original
			// listener/server/QUIC objects. Capturing old static TLS config would fail.
			other := sharedTestSpec("tenant-b", "second", "new.test", backendURL(f.legacy.Services[0].Backends[0]).String())
			other.Listeners = []Listener{{ID: "second-shared", Shared: "web"}}
			other.Routes = []Route{{ID: "new-host", Host: "new.test", Prefix: "/", Service: "web"}}
			if err := f.manager.Reconcile(f.ctx, "ingress/app/tenant-b/second/http", 1, 1, &other); err != nil {
				t.Fatal("second tenant shared attachment", err)
			}
			f.wait(t, "second tenant backend health", func() bool {
				o, err := f.manager.Observe("ingress/app/tenant-b/second/http")
				return err == nil && o.Ready
			})
			newClient := f.client(t, major, "new.test")
			f.response(t, newClient, major, "new.test", "/new-route", http.StatusOK, f.newFingerprint)
			// A valid old SNI cannot address the new tenant using Host, even on H2/H3.
			f.response(t, oldClient, major, "new.test", "/after", http.StatusMisdirectedRequest, f.originalFingerprint)
			f.releaseOnce.Do(func() { close(f.release) })
			select {
			case result := <-held:
				if result.err != nil || result.status != 200 || result.major != major || result.fingerprint != f.originalFingerprint || result.body != "original-start\noriginal-done\n" {
					t.Fatal("old stream lost its original TLS/backend lease", result)
				}
			case <-f.ctx.Done():
				t.Fatal("original request never completed", f.ctx.Err())
			}
			f.wait(t, "original lease returned", func() bool { o, err := f.manager.Observe(f.key); return err == nil && o.Requests == 0 })
			draining := next
			draining.Lifecycle = schema.Lifecycle{Drain: true, Nonce: [16]byte{1}}
			if err := f.manager.Reconcile(f.ctx, f.key, 3, 1, &draining); err != nil {
				t.Fatal("original app retirement", err)
			}
			// Open another actual connection after the original app's ctx is canceled:
			// its stop must not close the transferred socket or pin new TLS to old ctx.
			f.response(t, f.client(t, major, "new.test"), major, "new.test", "/after-original-stop", http.StatusOK, f.newFingerprint)
		})
	}
}

func TestActualTLSHandoffRejectsForeignTenantSocketAndMismatchedIdentity(t *testing.T) {
	for _, scenario := range []string{"foreign-key", "same-key-tenant", "same-key-app", "tls-identity"} {
		t.Run(scenario, func(t *testing.T) {
			f := newTLSHandoffFixture(t, scenario != "tls-identity")
			next, key := f.sharedSpec(), f.key
			switch scenario {
			case "foreign-key":
				key = "ingress/app/tenant-b/second/http"
				next = sharedTestSpec("tenant-b", "second", "new.test", backendURL(f.legacy.Services[0].Backends[0]).String())
			case "same-key-tenant":
				next.Tenant = "tenant-b"
			case "same-key-app":
				next.App = "other"
			}
			if err := f.manager.Reconcile(f.ctx, key, 2, 1, &next); err == nil {
				t.Fatal("foreign source or TLS identity took the original socket", scenario)
			}
			f.assertOriginalPhysical(t, false)
			for _, major := range []int{1, 2, 3} {
				f.response(t, f.client(t, major, "example.test"), major, "example.test", "/still-original", http.StatusOK, f.originalFingerprint)
			}
		})
	}
}
