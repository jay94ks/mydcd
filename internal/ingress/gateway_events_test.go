// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestSharedGatewayListenerAndSourceEventsRetainNodeScope(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer backend.Close()
	m, err := Open(ctx, filepath.Join(t.TempDir(), "ingress.db"), boundaryDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err = m.SetBlocks(1, "node-a", nil, uint64(time.Now().Unix())); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var events []Event
	m.SetEventSink(func(e Event) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	})
	address := netip.MustParseAddrPort(ingressPort(t))
	configuration := GatewayConfiguration{Local: Gateway{Enabled: true, Addresses: []netip.Addr{address.Addr()}, Ports: []uint16{address.Port()}, AllowedSources: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Listeners: []Listener{{ID: "web", Address: address.String()}}}}
	if err = m.ConfigureGateways(configuration, nil); err != nil {
		t.Fatal(err)
	}
	if err = m.SetTenantPolicy("tenant", HostPolicy{LocalHosts: []string{"app.test"}}); err != nil {
		t.Fatal(err)
	}
	spec := sharedTestSpec("tenant", "app", "app.test", backend.URL)
	if err = m.Reconcile(ctx, "app", 1, 1, &spec); err != nil {
		t.Fatal(err)
	}
	m.gatewayMu.Lock()
	g := m.gateways["web"]
	m.gatewayMu.Unlock()
	if g == nil {
		t.Fatal("real shared listener missing")
	}
	// Exercise the real finite rejection counter, without a socket load test.
	// Each rejection is an injected input; opening/closing the listener is real.
	for range 100 {
		g.rejectSource()
	}
	if got := g.sourceRejected.Load(); got != 100 {
		t.Fatal("rejected sources were not counted", got)
	}
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	counts := map[string]int{}
	for _, e := range events {
		if e.Kind != "ingress-listener-up" && e.Kind != "ingress-listener-down" && e.Kind != "ingress-source-rejected-spike" {
			continue
		}
		if e.Node != "node-a" || e.Gateway != "local" || e.Tenant != "" || e.App != "" || e.RouteID != "" || e.Host != "" || e.ObservedAt == 0 {
			t.Fatal("node-wide gateway event gained tenant or lost source", e)
		}
		if e.Kind == "ingress-source-rejected-spike" && e.Value != 100 {
			t.Fatal("source spike lost its threshold", e)
		}
		counts[e.Kind]++
	}
	for _, kind := range []string{"ingress-listener-up", "ingress-listener-down", "ingress-source-rejected-spike"} {
		if counts[kind] != 1 {
			t.Fatal("missing or duplicated gateway transition", kind, counts)
		}
	}
}

func TestBothGatewaySourceBlockReportsApplicationAndCutsOriginalRequest(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	entered, exited := make(chan struct{}), make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			close(entered)
			<-r.Context().Done()
			close(exited)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()
	m, err := Open(ctx, filepath.Join(t.TempDir(), "ingress.db"), boundaryDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	address := netip.MustParseAddrPort(ingressPort(t))
	local := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.2"), address.Port())
	configuration := GatewayConfiguration{
		External: Gateway{Enabled: true, Addresses: []netip.Addr{address.Addr()}, Ports: []uint16{address.Port()}, Listeners: []Listener{{ID: "external", Address: address.String()}}},
		Local:    Gateway{Enabled: true, Addresses: []netip.Addr{local.Addr()}, Ports: []uint16{local.Port()}, AllowedSources: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Listeners: []Listener{{ID: "local", Address: local.String()}}},
	}
	if err = m.ConfigureGateways(configuration, nil); err != nil {
		t.Fatal(err)
	}
	if err = m.SetTenantPolicy("tenant", HostPolicy{ExternalAllowed: true, ExternalHosts: []string{"app.test"}, LocalHosts: []string{"app.test"}}); err != nil {
		t.Fatal(err)
	}
	if err = m.SetBlocks(1, "node-a", nil, uint64(time.Now().Unix())); err != nil {
		t.Fatal(err)
	}
	spec := sharedTestSpec("tenant", "app", "app.test", backend.URL)
	spec.Listeners = []Listener{{ID: "outside", Shared: "external"}, {ID: "inside", Shared: "local"}}
	spec.Routes[0].Gateway = "both"
	if err = m.Reconcile(ctx, "app", 1, 1, &spec); err != nil {
		t.Fatal(err)
	}
	for {
		actual, err := m.Observe("app")
		if err != nil {
			t.Fatal(err)
		}
		if actual.Ready {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("actual backend did not become healthy", ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	defer client.CloseIdleConnections()
	type result struct {
		status int
		err    error
	}
	request := func(endpoint, path string) result {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+endpoint+path, nil)
		if err != nil {
			return result{err: err}
		}
		req.Host = "app.test"
		response, err := client.Do(req)
		if err != nil {
			return result{err: err}
		}
		defer response.Body.Close()
		_, err = io.Copy(io.Discard, response.Body)
		return result{response.StatusCode, err}
	}
	done := make(chan result, 1)
	go func() { done <- request(address.String(), "/slow") }()
	select {
	case <-entered:
	case got := <-done:
		t.Fatal("original request ended before source cut", got)
	case <-ctx.Done():
		t.Fatal("original backend not entered", ctx.Err())
	}
	block := Block{ID: "source", Scope: "source", Tenant: "tenant", Apps: []string{"app"}, Node: "node-a", Source: "127.0.0.1/32", Gateway: "external", CutExisting: true, Response: "403", Actor: "admin", CreatedAt: uint64(time.Now().Unix())}
	if err = m.SetBlocks(2, "node-a", []Block{block}, uint64(time.Now().Unix())); err != nil {
		t.Fatal(err)
	}
	applications := m.BlockApplications()
	if len(applications) != 1 || applications[0].ID != block.ID || !applications[0].Applied || applications[0].Error != "" {
		t.Fatal("both route did not report its actual external policy", applications)
	}
	select {
	case got := <-done:
		if got.err == nil && got.status < 400 {
			t.Fatal("cut request became successful", got)
		}
	case <-ctx.Done():
		t.Fatal("original request did not end", ctx.Err())
	}
	select {
	case <-exited:
	case <-ctx.Done():
		t.Fatal("original backend I/O was not canceled", ctx.Err())
	}
	for {
		actual, ok := m.Snapshot("app", uint64(time.Now().UnixMilli()))
		if ok && actual.Requests == 0 && actual.Metrics.Instance.Failures["request-canceled"] == 1 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("cut did not return its original lease and cancellation metric", actual, ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
	for _, test := range []struct {
		endpoint string
		status   int
	}{{address.String(), 403}, {local.String(), 200}} {
		if got := request(test.endpoint, "/"); got.err != nil || got.status != test.status {
			t.Fatal("source block crossed gateway boundary", test, got)
		}
	}
	if err = m.SetBlocks(3, "node-a", nil, uint64(time.Now().Unix())); err != nil {
		t.Fatal(err)
	}
	if got := request(address.String(), "/"); got.err != nil || got.status != 200 {
		t.Fatal("original source unblock not restored", got)
	}
}
