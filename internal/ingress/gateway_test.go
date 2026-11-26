// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSharedGatewayRejectsCrossTenantSNIAndLocalSourceBeforeHTTP(t *testing.T) {
	g := &sharedGateway{manager: &Manager{hostPolicies: map[string]HostPolicy{"a": {LocalHosts: []string{"a.test"}}, "b": {LocalHosts: []string{"b.test"}}}}, kind: "local", allowed: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, bindings: map[string]gatewayBinding{}}
	for _, tenant := range []string{"a", "b"} {
		route := Route{ID: tenant, Host: tenant + ".test", Prefix: "/admin", Service: "web"}
		table, _ := NewTable([]Route{route})
		g.bindings[tenant] = gatewayBinding{spec: Spec{Tenant: tenant, App: "app"}, table: table}
	}
	g.rebuildLocked()
	request := httptest.NewRequest("GET", "https://a.test/admin", nil)
	request.TLS = &tls.ConnectionState{ServerName: "b.test"}
	request.RemoteAddr = "10.1.2.3:1234"
	response := httptest.NewRecorder()
	g.ServeHTTP(response, request)
	if response.Code != 421 {
		t.Fatal("cross-tenant TLS authority accepted", response.Code)
	}
	for _, row := range []struct {
		address string
		allowed bool
	}{{"10.1.2.3:1", true}, {"192.0.2.1:1", false}} {
		address := netip.MustParseAddrPort(row.address)
		if g.sourceAllowed(net.UDPAddrFromAddrPort(address)) != row.allowed {
			t.Fatal("source gate", row)
		}
	}
}

func TestSharedGatewayDrainKeepsNativeWhenDerivedWildcardAuthorityChanges(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer backend.Close()
	m, err := Open(ctx, filepath.Join(t.TempDir(), "ingress.db"), boundaryDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	address := netip.MustParseAddrPort(ingressPort(t))
	if err := m.ConfigureGateways(GatewayConfiguration{Local: Gateway{Enabled: true, Addresses: []netip.Addr{address.Addr()}, Ports: []uint16{address.Port()}, AllowedSources: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Listeners: []Listener{{ID: "web", Address: address.String()}}}}, nil); err != nil {
		t.Fatal(err)
	}
	m.SetTenantPolicy("tenant", HostPolicy{LocalHosts: []string{"*"}})
	if err := m.SetBlocks(1, "node-a", nil, uint64(time.Now().Unix())); err != nil {
		t.Fatal(err)
	}
	original := sharedTestSpec("tenant", "app", "*", backend.URL)
	original.SystemWildcard = true
	if err := m.Reconcile(ctx, "app", 1, 1, &original); err != nil {
		t.Fatal("original authorized listener", err)
	}
	native := ManagedNativeID("app", 1, original)
	if err := m.BindNative("app", 1, native); err != nil {
		t.Fatal(err)
	}
	drain := original
	drain.SystemWildcard = false
	drain.Lifecycle.Drain, drain.Lifecycle.Nonce = true, [16]byte{1}
	if err := m.Reconcile(ctx, "app", 2, 1, &drain); err != nil {
		t.Fatal("derived authority prevented original listener shutdown", err)
	}
	observed, err := m.Observe("app")
	if err != nil || !observed.Gone || observed.Requests != 0 || m.instances["app"].record.Native != native {
		t.Fatal("original native identity/closure lost", observed, err)
	}
	// Ignoring the flag for physical identity must never grant it on start.
	unauthorized := original
	unauthorized.SystemWildcard = false
	if err := m.Reconcile(ctx, "app", 3, 2, &unauthorized); err == nil {
		t.Fatal("fresh wildcard listener bypassed current authority")
	}
}

func sharedTestSpec(tenant, app, hostname, backend string) Spec {
	address := netip.MustParseAddrPort(strings.TrimPrefix(backend, "http://"))
	return Spec{Schema: 1, Owner: "owner", Tenant: tenant, App: app, Listeners: []Listener{{ID: "shared", Shared: "web"}}, Routes: []Route{{ID: "root", Host: hostname, Prefix: "/", Service: "web"}}, Services: []Service{{ID: "web", Backends: []BackendSpec{{ID: app, Task: "task/" + app, Node: "node-a", Network: "net", Generation: 1, Address: address.Addr(), Port: address.Port(), Weight: 1, Capacity: 2, HealthPath: "/"}}}}, MaxRequests: 2, MaxConnections: 8, MaxHeaderBytes: 4096, BufferBytes: 128 << 10, MaxBodyBytes: 1024, RequestTimeoutMS: 2000, DialTimeoutMS: 200, ResponseHeaderTimeoutMS: 500, HealthIntervalMS: 50}
}
func TestGatewayConfigurationRejectsUnspecifiedOverlappingAndForeignAddresses(t *testing.T) {
	for _, configuration := range []GatewayConfiguration{{Local: Gateway{Enabled: true, Addresses: []netip.Addr{netip.IPv4Unspecified()}, Ports: []uint16{443}, Listeners: []Listener{{ID: "web", Address: "0.0.0.0:443", TLS: true}}}}, {Local: Gateway{Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}, External: Gateway{Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}}, {Local: Gateway{Enabled: true, Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, Ports: []uint16{443}, Listeners: []Listener{{ID: "web", Address: "192.0.2.2:443", TLS: true}}}}} {
		if configuration.Validate() == nil {
			t.Fatal("unsafe gateway accepted", configuration)
		}
	}
}
func TestSharedGatewayTwoTenantsRetainSocketAndSelectedRouteBlock(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "tenant-a") }))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "tenant-b") }))
	defer second.Close()
	m, err := Open(ctx, filepath.Join(t.TempDir(), "ingress.db"), boundaryDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	address := netip.MustParseAddrPort(ingressPort(t))
	if err = m.ConfigureGateways(GatewayConfiguration{Local: Gateway{Enabled: true, Addresses: []netip.Addr{address.Addr()}, Ports: []uint16{address.Port()}, AllowedSources: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Listeners: []Listener{{ID: "web", Address: address.String()}}}}, nil); err != nil {
		t.Fatal(err)
	}
	m.SetTenantPolicy("tenant-a", HostPolicy{LocalHosts: []string{"a.test"}})
	m.SetTenantPolicy("tenant-b", HostPolicy{LocalHosts: []string{"b.test"}})
	if err = m.SetBlocks(1, "node-a", nil, uint64(time.Now().Unix())); err != nil {
		t.Fatal(err)
	}
	a := sharedTestSpec("tenant-a", "app-a", "a.test", first.URL)
	b := sharedTestSpec("tenant-b", "app-b", "b.test", second.URL)
	if err = m.Reconcile(ctx, "app-a", 1, 1, &a); err != nil {
		t.Fatal(err)
	}
	if err = m.Reconcile(ctx, "app-b", 1, 1, &b); err != nil {
		t.Fatal(err)
	}
	wait := time.Now().Add(3 * time.Second)
	for {
		oa, _ := m.Observe("app-a")
		ob, _ := m.Observe("app-b")
		if oa.Ready && ob.Ready {
			break
		}
		if time.Now().After(wait) {
			t.Fatal("shared instances did not become healthy", oa, ob)
		}
		time.Sleep(10 * time.Millisecond)
	}
	client := &http.Client{Timeout: time.Second}
	defer client.CloseIdleConnections()
	request := func(host string) (int, string) {
		t.Helper()
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+address.String()+"/", nil)
		req.Host = host
		response, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		raw, e := io.ReadAll(io.LimitReader(response.Body, 1024))
		if e != nil {
			t.Fatal(e)
		}
		return response.StatusCode, string(raw)
	}
	if code, body := request("a.test"); code != 200 || body != "tenant-a" {
		t.Fatal(code, body)
	}
	if code, body := request("b.test"); code != 200 || body != "tenant-b" {
		t.Fatal(code, body)
	}
	if code, _ := request("unknown.test"); code != 404 {
		t.Fatal("unknown host admitted", code)
	}
	bad := sharedTestSpec("tenant-b", "collision", "a.test", second.URL)
	if err = m.Reconcile(ctx, "collision", 1, 1, &bad); err == nil {
		t.Fatal("unassigned host accepted")
	}
	now := uint64(time.Now().Unix())
	block := Block{ID: "only-a", Scope: "route", Tenant: "tenant-a", App: "app-a", Key: "app-a", Route: "root", Host: "a.test", Prefix: "/", Gateway: "local", Response: "503", CreatedAt: now, Actor: "admin"}
	if err = m.SetBlocks(2, "node-a", []Block{block}, now); err != nil {
		t.Fatal(err)
	}
	if code, _ := request("a.test"); code != 503 {
		t.Fatal("route block ineffective", code)
	}
	if code, body := request("b.test"); code != 200 || body != "tenant-b" {
		t.Fatal("other tenant interrupted", code, body)
	}
	blocked, ok := m.Snapshot("app-a", uint64(time.Now().UnixMilli()))
	if !ok || blocked.BlockRevision != 2 || len(blocked.Blocks) != 1 || blocked.Blocks[0].ID != block.ID {
		t.Fatal("pending unblock lost the actual older policy receipt", blocked)
	}
	if err = m.SetBlocks(3, "node-a", nil, now); err != nil {
		t.Fatal(err)
	}
	if code, _ := request("a.test"); code != 200 {
		t.Fatal("unblock ineffective", code)
	}
	snapshot, ok := m.Snapshot("app-a", uint64(time.Now().UnixMilli()))
	if !ok || snapshot.BlockRevision != 3 || len(snapshot.Blocks) != 0 || snapshot.Metrics.Instance.Requests < 3 || snapshot.Metrics.Instance.Blocked != 1 {
		t.Fatal("actual request instrumentation missing", snapshot)
	}
}

func TestLegacyGatewayClassificationAndBlockedRetryAfter(t *testing.T) {
	m := &Manager{}
	c := GatewayConfiguration{External: Gateway{Addresses: []netip.Addr{netip.MustParseAddr("203.0.113.10")}}, Local: Gateway{Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.11")}}}
	if err := m.ConfigureGateways(c, nil); err != nil {
		t.Fatal(err)
	}
	for address, want := range map[string]string{"203.0.113.10:443": "external", "10.0.0.11:8443": "local", "127.0.0.1:8080": "unclassified"} {
		if got := m.listenerGateway(address); got != want {
			t.Fatal(address, got, want)
		}
	}
	response := httptest.NewRecorder()
	blockResponse(response, httptest.NewRequest("GET", "http://app.test/", nil), Block{Response: "503", ExpiresAt: uint64(time.Now().Unix()) + 60})
	if response.Code != 503 || response.Header().Get("Retry-After") == "" {
		t.Fatal("temporary denial lacks retry delay", response)
	}
}

func TestLegacySharedHandoffRetainsPhysicalSocketAndOriginalActiveLease(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, release := make(chan struct{}, 1), make(chan struct{})
	var releaseOnce sync.Once
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hold" {
			entered <- struct{}{}
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		io.WriteString(w, "original")
	}))
	defer backend.Close()
	defer releaseOnce.Do(func() { close(release) })
	m, err := Open(ctx, filepath.Join(t.TempDir(), "ingress.db"), boundaryDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	address := netip.MustParseAddrPort(ingressPort(t))
	if err = m.ConfigureGateways(GatewayConfiguration{Local: Gateway{Enabled: true, Addresses: []netip.Addr{address.Addr()}, Ports: []uint16{address.Port()}, AllowedSources: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Listeners: []Listener{{ID: "web", Address: address.String()}}}}, nil); err != nil {
		t.Fatal(err)
	}
	m.SetTenantPolicy("tenant", HostPolicy{LocalHosts: []string{"a.test", "new.test"}})
	legacy := sharedTestSpec("tenant", "app", "a.test", backend.URL)
	legacy.Listeners = []Listener{{ID: "legacy", Address: address.String()}}
	if err = m.Reconcile(ctx, "app", 1, 1, &legacy); err != nil {
		t.Fatal(err)
	}
	if err = m.BindNative("app", 1, "original-native"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		observation, _ := m.Observe("app")
		if observation.Ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("original not ready", observation)
		}
		time.Sleep(10 * time.Millisecond)
	}
	m.mu.Lock()
	original := m.instances["app"]
	original.mu.Lock()
	socket := original.direct["legacy"].listener
	original.mu.Unlock()
	m.mu.Unlock()
	client := &http.Client{Timeout: 3 * time.Second}
	defer client.CloseIdleConnections()
	done := make(chan error, 1)
	go func() {
		request, _ := http.NewRequest("GET", "http://"+address.String()+"/hold", nil)
		request.Host = "a.test"
		response, e := client.Do(request)
		if e == nil {
			raw, readErr := io.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode != 200 || string(raw) != "original" {
				e = fmt.Errorf("old response %d %q", response.StatusCode, raw)
			}
			if e == nil {
				e = readErr
			}
		}
		done <- e
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("original lease did not enter backend")
	}
	defer releaseOnce.Do(func() { close(release) })
	next := legacy
	next.Listeners = []Listener{{ID: "shared", Shared: "web"}}
	next.Routes = append([]Route(nil), legacy.Routes...)
	next.Routes[0].Host = "new.test"
	if err = m.Reconcile(ctx, "app", 2, 1, &next); err != nil {
		t.Fatal("exact original socket not handed off", err)
	}
	if _, native, ok := m.NativeSource("app", 1); !ok || native != "original-native" {
		t.Fatal("handoff reinterpreted native", native, ok)
	}
	m.gatewayMu.Lock()
	handed := m.gateways["web"].listener
	m.gatewayMu.Unlock()
	if handed != socket {
		t.Fatal("handoff rebound instead of reusing original socket")
	}
	if observation, _ := m.Observe("app"); observation.Requests != 1 {
		t.Fatal("original request lease was dropped", observation)
	}
	request, _ := http.NewRequest("GET", "http://"+address.String()+"/", nil)
	request.Host = "new.test"
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("new rule not applied", response.StatusCode)
	}
	releaseOnce.Do(func() { close(release) })
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	// Missing original socket proof and foreign endpoint identity cannot hand off.
	foreign := newInstance(m, "foreign", instanceRecord{Spec: legacy})
	foreign.started = true
	foreign.mu.Lock()
	if m.canHandoffLocked(foreign, next) {
		t.Fatal("another app's socket accepted")
	}
	foreign.mu.Unlock()
}
