// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"context"
	"crypto/tls"
	"maps"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// A direct TLS listener refuses an SNI host outside its own route table
// before any certificate is read, so random names cannot fill the cache.
func TestDirectTLSListenerRefusesUnroutedHostBeforeCertificateRead(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	m, err := Open(ctx, filepath.Join(t.TempDir(), "ingress.db"), boundaryDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	routes := []Route{{ID: "root", Host: "example.test", Prefix: "/", Service: "api"}}
	reads, dial := admitFixture(t, ctx, m, routes)
	for _, name := range []string{"random-1.test", "random-2.test", "a.example.test"} {
		if dial(name) == nil {
			t.Fatalf("%s handshake accepted", name)
		}
	}
	for host, n := range reads() {
		if host != "example.test" {
			t.Fatalf("unrouted host %s read certificates %d times", host, n)
		}
	}
	if err = dial("example.test"); err != nil {
		t.Fatal("routed host refused", err)
	}
}

// The direct listener's own gateway kind picks the routes it admits, as
// ServeHTTP does: an external address serves `gateway: external` routes.
func TestDirectTLSListenerAdmitsRoutesOfItsGatewayKind(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	m, err := Open(ctx, filepath.Join(t.TempDir(), "ingress.db"), boundaryDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err = m.ConfigureGateways(GatewayConfiguration{External: Gateway{Addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}}, nil); err != nil {
		t.Fatal(err)
	}
	routes := []Route{{ID: "out", Host: "example.test", Prefix: "/", Service: "api", Gateway: "external"}, {ID: "in", Host: "inside.test", Prefix: "/", Service: "api", Gateway: "local"}}
	_, dial := admitFixture(t, ctx, m, routes)
	if err = dial("example.test"); err != nil {
		t.Fatal("external route refused on an external address", err)
	}
	if dial("inside.test") == nil {
		t.Fatal("local-only route admitted on an external address")
	}
}

func admitFixture(t *testing.T, ctx context.Context, m *Manager, routes []Route) (func() map[string]int, func(string) error) {
	t.Helper()
	cert, tc := ingressCertificate(t)
	var mu sync.Mutex
	reads := map[string]int{}
	source := fileCertificateSource(cert)
	m.SetCertificateSource(func(ctx context.Context, host string, previous []CertificateVersion) ([]CertificateVersion, error) {
		mu.Lock()
		reads[host]++
		mu.Unlock()
		// Any host gets the pair, so only admission can refuse a handshake.
		return source(ctx, "example.test", previous)
	})
	secure := ingressPort(t)
	backend := netip.MustParseAddrPort("127.0.0.1:9")
	s := Spec{Schema: 1, Owner: "owner", Listeners: []Listener{{ID: "tls", Address: secure, TLS: true}}, Routes: routes, Services: []Service{{ID: "api", Backends: []BackendSpec{{ID: "b", Task: "workload/task/a", Network: "net", Generation: 1, Address: backend.Addr(), Port: backend.Port(), Weight: 1, Capacity: 1, HealthPath: "/health"}}}}, MaxRequests: 2, MaxConnections: 16, MaxHeaderBytes: 4096, BufferBytes: 2 * 64 << 10, MaxBodyBytes: 32, RequestTimeoutMS: 1500, DialTimeoutMS: 100, ResponseHeaderTimeoutMS: 200, HealthIntervalMS: 50}
	if err := m.Reconcile(ctx, "ingress/app/a", 1, 1, &s); err != nil {
		t.Fatal(err)
	}
	dial := func(name string) error {
		config := tc.Clone()
		config.ServerName = name
		config.InsecureSkipVerify = name != "example.test"
		c, err := tls.Dial("tcp", secure, config)
		if err == nil {
			c.Close()
		}
		return err
	}
	return func() map[string]int {
		mu.Lock()
		defer mu.Unlock()
		return maps.Clone(reads)
	}, dial
}
