// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestIngressRetryUsesAnotherBackendOnlyForSafeMethodDialFailure(t *testing.T) {
	for _, scenario := range []struct {
		name, method string
		closeFirst   bool
		status, good int
	}{{"get-dial", "GET", true, 200, 1}, {"head-dial", "HEAD", true, 200, 1}, {"post-dial", "POST", true, 502, 0}, {"response-502", "GET", false, 502, 0}} {
		t.Run(scenario.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var goodRequests atomic.Int32
			bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/ready" {
					w.WriteHeader(200)
					return
				}
				w.WriteHeader(502)
			}))
			defer bad.Close()
			good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/ready" {
					goodRequests.Add(1)
				}
				w.WriteHeader(200)
			}))
			defer good.Close()
			m, err := Open(ctx, filepath.Join(t.TempDir(), "ingress.db"), boundaryDependencies{})
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			address := netip.MustParseAddrPort(ingressPort(t))
			if err = m.ConfigureGateways(GatewayConfiguration{Local: Gateway{Enabled: true, Addresses: []netip.Addr{address.Addr()}, Ports: []uint16{address.Port()}, AllowedSources: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Listeners: []Listener{{ID: "web", Address: address.String()}}}}, nil); err != nil {
				t.Fatal(err)
			}
			if err = m.SetTenantPolicy("tenant", HostPolicy{LocalHosts: []string{"app.test"}}); err != nil {
				t.Fatal(err)
			}
			spec := sharedTestSpec("tenant", "app", "app.test", bad.URL)
			spec.HealthIntervalMS = 30000 // Observe real Ready once before closing the first socket.
			spec.Services[0].Backends[0].ID = "a"
			spec.Services[0].Backends[0].HealthPath = "/ready"
			second := spec.Services[0].Backends[0]
			endpoint := netip.MustParseAddrPort(strings.TrimPrefix(good.URL, "http://"))
			second.ID, second.Task, second.Address, second.Port = "b", "task/second", endpoint.Addr(), endpoint.Port()
			spec.Services[0].Backends = append(spec.Services[0].Backends, second)
			spec.Routes[0].Balance = &Balance{Retry: 1}
			if err = m.Reconcile(ctx, "app", 1, 1, &spec); err != nil {
				t.Fatal(err)
			}
			for {
				// Observe.Backends is the explicit dynamic-replica receipt;
				// Snapshot includes both static endpoints used by this fixture.
				observed, exists := m.Snapshot("app", uint64(time.Now().UnixMilli()))
				if exists && observed.Ready && len(observed.Backends) == 2 && observed.Backends[0].Healthy && observed.Backends[1].Healthy {
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal("real backend readiness", ctx.Err())
				case <-time.After(5 * time.Millisecond):
				}
			}
			if scenario.closeFirst {
				bad.Close()
			}
			req, _ := http.NewRequestWithContext(ctx, scenario.method, "http://"+address.String()+"/call", nil)
			req.Host = "app.test"
			client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
			defer client.CloseIdleConnections()
			response, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if err != nil || response.StatusCode != scenario.status || int(goodRequests.Load()) != scenario.good {
				t.Fatal("wrong retry/response", response.StatusCode, goodRequests.Load(), err)
			}
			for {
				observed, err := m.Observe("app")
				if err != nil {
					t.Fatal(err)
				}
				if observed.Requests == 0 {
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal("original retry leases not returned", observed.Requests)
				case <-time.After(5 * time.Millisecond):
				}
			}
		})
	}
}
