// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Real listeners, HTTP streams, backend probes, policy selection and Manager
// lifecycle; only network dependency pins use the existing fake adapter.
func TestIngressRuntimeControlsKeepSharedListenerAndOtherTenant(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	entered, release := make(chan struct{}, 1), make(chan struct{})
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			entered <- struct{}{}
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		io.WriteString(w, "node-a")
	}))
	defer a.Close()
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "node-b") }))
	defer b.Close()
	m, err := Open(ctx, filepath.Join(t.TempDir(), "ingress.db"), boundaryDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	address := netip.MustParseAddrPort(ingressPort(t))
	configuration := GatewayConfiguration{Local: Gateway{Enabled: true, Addresses: []netip.Addr{address.Addr()}, Ports: []uint16{address.Port()}, AllowedSources: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Listeners: []Listener{{ID: "web", Address: address.String()}}}}
	if err = m.ConfigureGateways(configuration, nil); err != nil {
		t.Fatal(err)
	}
	if err = m.SetBlocks(0, "node-b", nil, uint64(time.Now().Unix())); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"tenant", "other"} {
		if err = m.SetTenantPolicy(tenant, HostPolicy{LocalHosts: []string{tenant + ".test"}}); err != nil {
			t.Fatal(err)
		}
	}
	spec := sharedTestSpec("tenant", "app", "tenant.test", a.URL)
	spec.MaxRequests = 4
	spec.BufferBytes = 256 << 10
	spec.RequestTimeoutMS = 10000
	second := spec.Services[0].Backends[0]
	second.ID, second.Task, second.Node = "second", "task/second", "node-b"
	target := netip.MustParseAddrPort(strings.TrimPrefix(b.URL, "http://"))
	second.Address, second.Port = target.Addr(), target.Port()
	spec.Services[0].Backends = append(spec.Services[0].Backends, second)
	other := sharedTestSpec("other", "other", "other.test", b.URL)
	if err = m.Reconcile(ctx, "app", 1, 1, &spec); err != nil {
		t.Fatal(err)
	}
	if err = m.Reconcile(ctx, "other", 1, 1, &other); err != nil {
		t.Fatal(err)
	}
	for {
		one, _ := m.Observe("app")
		two, _ := m.Observe("other")
		if one.Ready && two.Ready {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("actual backend readiness", ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	m.gatewayMu.Lock()
	listener := m.gateways["web"].listener
	m.gatewayMu.Unlock()
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	request := func(host, path string, cookie ...string) (int, string, error) {
		q, e := http.NewRequestWithContext(ctx, "GET", "http://"+address.String()+path, nil)
		if e != nil {
			return 0, "", e
		}
		q.Host = host
		if len(cookie) == 1 {
			q.Header.Set("Cookie", cookie[0])
		}
		reply, e := client.Do(q)
		if e != nil {
			return 0, "", e
		}
		defer reply.Body.Close()
		raw, e := io.ReadAll(reply.Body)
		return reply.StatusCode, string(raw), e
	}
	// The same cookie initially follows round-robin across both actual HTTP
	// backends. Four completed leases retain node-a as the next candidate.
	const sessionCookie = "session=original-session"
	counts := map[string]int{}
	for j := 0; j < 4; j++ {
		code, body, e := request("tenant.test", "/", sessionCookie)
		if e != nil || code != 200 || body != "node-a" && body != "node-b" {
			t.Fatal("round-robin actual backend request", code, body, e)
		}
		counts[body]++
	}
	if counts["node-a"] != 2 || counts["node-b"] != 2 {
		t.Fatal("round-robin did not distribute the same cookie across both backends", counts)
	}
	// The next round-robin lease is node-a. Keep that original HTTP request
	// alive while the next policy excludes only that node's backend.
	slow := make(chan error, 1)
	go func() {
		code, body, e := request("tenant.test", "/slow")
		if e == nil && (code != 200 || body != "node-a") {
			e = fmt.Errorf("old request changed backend/status")
		}
		slow <- e
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	now := uint64(time.Now().Unix())
	if err = m.SetRuntimeControls(1, []RuntimeControl{{Tenant: "tenant", App: "app", Node: "node-a", Drain: &ControlDrain{Revision: 1, Draining: true, StartedAt: now, Deadline: now + 10}}}); err != nil {
		t.Fatal(err)
	}
	for j := 0; j < 4; j++ {
		code, body, e := request("tenant.test", "/")
		if e != nil || code != 200 || body != "node-b" {
			t.Fatal("drained node remained a new backend candidate", code, body, e)
		}
	}
	close(release)
	if err = <-slow; err != nil {
		t.Fatal("in-flight request failed during graceful drain", err)
	}
	if err = m.SetRuntimeControls(2, []RuntimeControl{{Tenant: "tenant", App: "app", Route: "root", Balance: &Balance{Method: "hash", Key: "cookie:session"}, Revision: 1}, {Tenant: "tenant", App: "app", Drain: &ControlDrain{Revision: 2, Draining: true, StartedAt: now, Deadline: now + 10}}}); err != nil {
		t.Fatal(err)
	}
	if code, _, e := request("tenant.test", "/"); e != nil || code != 404 {
		t.Fatal("drained app remained in shared route table", code, e)
	}
	if code, body, e := request("other.test", "/"); e != nil || code != 200 || body != "node-b" {
		t.Fatal("one app drain affected the other tenant", code, body, e)
	}
	if err = m.SetRuntimeControls(3, []RuntimeControl{{Tenant: "tenant", App: "app", Route: "root", Balance: &Balance{Method: "hash", Key: "cookie:session"}, Revision: 1}, {Tenant: "tenant", App: "app", Drain: &ControlDrain{Revision: 3, Draining: false}}}); err != nil {
		t.Fatal(err)
	}
	if code, _, e := request("tenant.test", "/"); e != nil || code != 200 {
		t.Fatal("undrain did not restore existing route", code, e)
	}
	selected := ""
	for j := 0; j < 4; j++ {
		code, body, e := request("tenant.test", "/", sessionCookie)
		if e != nil || code != 200 || body != "node-a" && body != "node-b" {
			t.Fatal("cookie hash actual backend request", code, body, e)
		}
		if selected == "" {
			selected = body
		} else if body != selected {
			t.Fatal("cookie:session override did not retain the same actual backend", selected, body)
		}
	}
	if err = m.UpdateGateways(ctx, configuration, 1); err != nil {
		t.Fatal(err)
	}
	m.gatewayMu.Lock()
	same := m.gateways["web"].listener == listener
	m.gatewayMu.Unlock()
	if !same {
		t.Fatal("control-only changes replaced physical shared listener")
	}
	actual, _ := m.Observe("app")
	if actual.Generation != 1 || actual.Revision != 1 {
		t.Fatal("runtime policies minted a new native source", actual)
	}
}
func TestNodeGatewayAdapterRejectsUnownedAndWildcardAddresses(t *testing.T) {
	for _, address := range []string{"0.0.0.0", "::", "192.0.2.231"} {
		if ValidateLocalGateways(GatewayConfiguration{External: Gateway{Addresses: []netip.Addr{netip.MustParseAddr(address)}}}) == nil {
			t.Fatal("unowned or wildcard gateway address accepted", address)
		}
	}
	if ValidateLocalGateways(GatewayConfiguration{External: Gateway{AllowedSources: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}}) == nil {
		t.Fatal("external source list accepted")
	}
}

func TestIngressDrainDeadlineCancelsExistingRequestWithoutDeletingNative(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	entered := make(chan struct{}, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hang" {
			io.WriteString(w, "original\n")
			w.(http.Flusher).Flush()
			entered <- struct{}{}
			<-r.Context().Done()
			return
		}
		io.WriteString(w, "ready")
	}))
	defer backend.Close()
	m, err := Open(ctx, filepath.Join(t.TempDir(), "ingress.db"), boundaryDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	spec := sharedTestSpec("tenant", "app", "app.test", backend.URL)
	spec.Listeners = []Listener{{ID: "direct", Address: ingressPort(t)}}
	spec.RequestTimeoutMS = 7000
	if err = m.SetBlocks(0, "node-a", nil, uint64(time.Now().Unix())); err != nil {
		t.Fatal(err)
	}
	if err = m.Reconcile(ctx, "app", 1, 1, &spec); err != nil {
		t.Fatal(err)
	}
	for {
		o, _ := m.Observe("app")
		if o.Ready {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport}
	request, _ := http.NewRequestWithContext(ctx, "GET", "http://"+spec.Listeners[0].Address+"/hang", nil)
	request.Host = "app.test"
	done := make(chan error, 1)
	go func() {
		response, e := httpClient.Do(request)
		if e == nil {
			_, e = io.Copy(io.Discard, response.Body)
			response.Body.Close()
		}
		done <- e
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	before := time.Now()
	now := uint64(before.Unix())
	if err = m.SetRuntimeControls(1, []RuntimeControl{{Tenant: "tenant", App: "app", Drain: &ControlDrain{Revision: 1, Draining: true, StartedAt: now, Deadline: now + 1}}}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("drain deadline did not settle the original in-flight HTTP request")
	}
	if elapsed := time.Since(before); elapsed > 3*time.Second {
		t.Fatal("request ended only at original timeout", elapsed)
	}
	o, err := m.Observe("app")
	if err != nil || o.Gone || !o.Draining || o.Generation != 1 || o.Revision != 1 {
		t.Fatal("drain deleted/replaced native source", o, err)
	}
	if err = m.SetRuntimeControls(2, []RuntimeControl{{Tenant: "tenant", App: "app", Drain: &ControlDrain{Revision: 2}}}); err != nil {
		t.Fatal(err)
	}
	request, _ = http.NewRequestWithContext(ctx, "GET", "http://"+spec.Listeners[0].Address+"/", nil)
	request.Host = "app.test"
	response, err := httpClient.Do(request)
	if err != nil {
		t.Fatal("undrain did not reuse existing native listener", err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode)
	}
}
