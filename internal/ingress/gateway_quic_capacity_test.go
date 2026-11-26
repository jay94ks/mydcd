// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// Both paths use actual UDP/QUIC/TLS, HTTP/3 multiplexing and the product
// Manager/dependency boundary. Handshake SNI stays on app A while authority
// selects app B in the same tenant; a new request is not a new connection.
func TestActualHTTP3SelectedAppConnectionCapacityAndCloseReturn(t *testing.T) {
	for _, handoff := range []bool{false, true} {
		name := "shared-listener"
		if handoff {
			name = "existing-direct-connection-handoff"
		}
		t.Run(name, func(t *testing.T) {
			var ctx context.Context
			var m *Manager
			var address, primaryKey, backend string
			var roots *x509.CertPool
			var becomeShared func()
			if handoff {
				f := newTLSHandoffFixture(t, true)
				ctx, m, address, primaryKey, roots = f.ctx, f.manager, f.address, f.key, f.roots
				backend = backendURL(f.legacy.Services[0].Backends[0]).String()
				becomeShared = func() {
					next := f.sharedSpec()
					if err := m.Reconcile(ctx, primaryKey, 2, 1, &next); err != nil {
						t.Fatal("exact direct-to-shared handoff", err)
					}
					f.assertOriginalPhysical(t, true)
				}
			} else {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(context.Background(), 20*time.Second)
				t.Cleanup(cancel)
				service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "backend "+r.URL.Path) }))
				t.Cleanup(service.Close)
				backend = service.URL
				certificate, trust := ingressCertificate(t)
				roots = trust.RootCAs
				var err error
				m, err = openWithCertificates(ctx, filepath.Join(t.TempDir(), "ingress.db"), boundaryDependencies{}, certificate)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := m.Close(); err != nil {
						t.Error(err)
					}
				})
				endpoint := netip.MustParseAddrPort(ingressPort(t))
				address = endpoint.String()
				if err := m.ConfigureGateways(GatewayConfiguration{Local: Gateway{Enabled: true, Addresses: []netip.Addr{endpoint.Addr()}, Ports: []uint16{endpoint.Port()}, AllowedSources: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Listeners: []Listener{{ID: "web", Address: address, TLS: true, HTTP3: true}}}}, nil); err != nil {
					t.Fatal(err)
				}
				primaryKey = "ingress/app/tenant-a/primary/http"
				becomeShared = func() {}
			}
			if err := m.SetTenantPolicy("tenant-a", HostPolicy{LocalHosts: []string{"example.test", "new.test"}}); err != nil {
				t.Fatal(err)
			}
			if !handoff {
				primary := sharedTestSpec("tenant-a", "primary", "example.test", backend)
				if err := m.Reconcile(ctx, primaryKey, 1, 1, &primary); err != nil {
					t.Fatal(err)
				}
			}
			wait := func(label string, condition func() bool) {
				t.Helper()
				ticker := time.NewTicker(10 * time.Millisecond)
				defer ticker.Stop()
				for !condition() {
					select {
					case <-ctx.Done():
						t.Fatal(label, ctx.Err())
					case <-ticker.C:
					}
				}
			}
			wait("primary backend ready", func() bool { row, err := m.Observe(primaryKey); return err == nil && row.Ready })
			newClient := func() (*http.Client, *http3.Transport, *atomic.Int64) {
				t.Helper()
				dials := &atomic.Int64{}
				transport := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: roots.Clone(), ServerName: "example.test", MinVersion: tls.VersionTLS13}, Dial: func(ctx context.Context, address string, config *tls.Config, options *quic.Config) (*quic.Conn, error) {
					dials.Add(1)
					return quic.DialAddr(ctx, address, config, options)
				}}
				t.Cleanup(func() {
					if err := transport.Close(); err != nil {
						t.Error(err)
					}
				})
				return &http.Client{Transport: transport}, transport, dials
			}
			request := func(client *http.Client, authority, path string, expected int) {
				t.Helper()
				r, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+address+path, nil)
				if err != nil {
					t.Fatal(err)
				}
				r.Host = authority
				response, err := client.Do(r)
				if err != nil {
					t.Fatal("actual HTTP/3 request", authority, err)
				}
				body, readErr := io.ReadAll(response.Body)
				closeErr := response.Body.Close()
				if readErr != nil || closeErr != nil || response.ProtoMajor != 3 || response.StatusCode != expected || response.TLS == nil || response.TLS.NegotiatedProtocol != "h3" {
					t.Fatal("actual HTTP/3 result", authority, response.StatusCode, response.Proto, string(body), readErr, closeErr)
				}
				if expected == http.StatusOK && string(body) != "backend "+path {
					t.Fatal("selected backend was not reached", string(body))
				}
			}
			first, firstTransport, firstDials := newClient()
			// In the handoff case this request fixes the original connection's
			// direct admission BEFORE its socket/handler becomes shared.
			request(first, "example.test", "/before", http.StatusOK)
			becomeShared()
			secondaryKey := "ingress/app/tenant-a/secondary/http"
			secondary := sharedTestSpec("tenant-a", "secondary", "new.test", backend)
			secondary.MaxConnections = 1
			if err := m.Reconcile(ctx, secondaryKey, 1, 1, &secondary); err != nil {
				t.Fatal(err)
			}
			wait("secondary backend ready", func() bool { row, err := m.Observe(secondaryKey); return err == nil && row.Ready })
			m.mu.Lock()
			primaryInstance, secondaryInstance := m.instances[primaryKey], m.instances[secondaryKey]
			m.mu.Unlock()
			connections := func(primary, secondary int64) bool {
				return primaryInstance.connections.Load() == primary && secondaryInstance.connections.Load() == secondary
			}
			request(first, "example.test", "/after", http.StatusOK)
			request(first, "new.test", "/after", http.StatusOK)
			request(first, "new.test", "/after-again", http.StatusOK)
			if firstDials.Load() != 1 || !connections(1, 1) {
				t.Fatal("one native connection was omitted or counted per request", firstDials.Load(), primaryInstance.connections.Load(), secondaryInstance.connections.Load())
			}
			second, secondTransport, secondDials := newClient()
			request(second, "example.test", "/after", http.StatusOK)
			request(second, "new.test", "/after-rejected", http.StatusServiceUnavailable)
			if secondDials.Load() != 1 || !connections(2, 1) {
				t.Fatal("same-tenant authority bypassed selected app capacity", secondDials.Load(), primaryInstance.connections.Load(), secondaryInstance.connections.Load())
			}
			// Closing/draining response streams above must keep both selected
			// owners charged until the actual first QUIC connection closes.
			if err := firstTransport.Close(); err != nil {
				t.Fatal(err)
			}
			wait("actual first QUIC close returns every selected app", func() bool { return connections(1, 0) })
			request(second, "new.test", "/after-return", http.StatusOK)
			request(second, "new.test", "/after-repeat", http.StatusOK)
			if secondDials.Load() != 1 || !connections(1, 1) {
				t.Fatal("released capacity was not reassigned once on the existing second connection", secondDials.Load(), primaryInstance.connections.Load(), secondaryInstance.connections.Load())
			}
			if err := secondTransport.Close(); err != nil {
				t.Fatal(err)
			}
			wait("actual final QUIC close returns both app owners", func() bool { return connections(0, 0) })
		})
	}
}
