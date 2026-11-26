// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestIngressProxyFailureObservationSettlesOriginalRequest(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var healthMode atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			if healthMode.Load() == 2 {
				<-r.Context().Done()
				return
			}
			if healthMode.Load() == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		<-r.Context().Done()
	}))
	defer backend.Close()
	addr := netip.MustParseAddrPort(strings.TrimPrefix(backend.URL, "http://"))
	s := Spec{Schema: 1, Owner: "owner", Listeners: []Listener{{ID: "http", Address: ingressPort(t)}}, Routes: []Route{{ID: "r", Host: "*", Prefix: "/", Service: "api"}}, Services: []Service{{ID: "api", Backends: []BackendSpec{{ID: "a", Task: "workload/task/a", Network: "net", Generation: 1, Address: addr.Addr(), Port: addr.Port(), Weight: 1, Capacity: 1, HealthPath: "/health"}}}}, MaxRequests: 1, MaxConnections: 4, MaxHeaderBytes: 1024, BufferBytes: 64 << 10, MaxBodyBytes: 1024, RequestTimeoutMS: 1000, DialTimeoutMS: 100, ResponseHeaderTimeoutMS: 20, HealthIntervalMS: 50}
	m, err := Open(ctx, filepath.Join(t.TempDir(), "ingress.db"), boundaryDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := m.Close(); err != nil {
			t.Error(err)
		}
	}()
	const key = "ingress/app/a"
	if err := m.Reconcile(ctx, key, 1, 1, &s); err != nil {
		t.Fatal(err)
	}
	for {
		o, err := m.Observe(key)
		if err != nil {
			t.Fatal(err)
		}
		if o.Ready {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	c := http.Client{Transport: transport}
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+s.Listeners[0].Address+"/stalled?private=not-for-diagnostics", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := c.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if readErr != nil || response.StatusCode != http.StatusBadGateway {
		t.Fatal(response.StatusCode, readErr)
	}
	for {
		o, err := m.Observe(key)
		if err != nil {
			t.Fatal(err)
		}
		if o.Requests == 0 {
			if !o.Ready || o.Error != "" || o.ProxyFailures != 1 || o.LastProxyFailure != "upstream-timeout" || o.LastProxyFailureMS < 1 {
				t.Fatal("proxy diagnostics changed owner health or lost original error", o)
			}
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("original request pin not returned", ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
	healthMode.Store(2)
	var firstFailure uint64
	var originalAt uint64
	for {
		o, err := m.Observe(key)
		if err != nil {
			t.Fatal(err)
		}
		if o.HealthFailures > 0 {
			firstFailure = o.HealthFailures
			m.mu.Lock()
			i := m.instances[key]
			i.mu.Lock()
			old := i.record.Balances["api"].Backends[0].Spec
			i.mu.Unlock()
			m.mu.Unlock()
			if !old.Healthy || o.LastHealthFailure != "upstream-timeout" {
				t.Fatal("timeout erased observed success", o)
			}
			originalAt = old.ObservedAt
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("unknown health not observed", ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
	for {
		o, err := m.Observe(key)
		if err != nil {
			t.Fatal(err)
		}
		if o.HealthFailures > firstFailure && !o.Ready {
			m.mu.Lock()
			i := m.instances[key]
			i.mu.Lock()
			now := i.record.Balances["api"].Backends[0].Spec
			i.mu.Unlock()
			m.mu.Unlock()
			if now.ObservedAt != originalAt || o.Error != "" {
				t.Fatal("unknown renewed timestamp or poisoned owner", o)
			}
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("unknown health never expired", ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
	healthMode.Store(0)
	for {
		o, err := m.Observe(key)
		if err != nil {
			t.Fatal(err)
		}
		if o.Ready {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("fresh known success not restored", ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
	healthMode.Store(1)
	for {
		o, err := m.Observe(key)
		if err != nil {
			t.Fatal(err)
		}
		if o.LastHealthFailure == "http-503" {
			if o.Ready || o.LastHealthFailure != "http-503" || o.Error != "" {
				t.Fatal("health rejection not distinguished", o)
			}
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("health observation missing", ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
}

func TestProxyDialTimeoutClassificationContainsNoTransportMessage(t *testing.T) {
	err := &url.Error{Op: "Post", URL: "http://private-placeholder.invalid/?private=not-for-diagnostics", Err: &net.OpError{Op: "dial", Net: "tcp", Err: context.DeadlineExceeded}}
	if got := proxyFailureKind(context.Background(), err); got != "upstream-dial-timeout" {
		t.Fatal("dial phase not distinguished", got)
	}
	if got := proxyFailureKind(context.Background(), context.DeadlineExceeded); got != "upstream-timeout" {
		t.Fatal("non-dial upstream timeout changed", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := proxyFailureKind(ctx, err); got != "request-canceled" {
		t.Fatal("original request cancellation hidden", got)
	}
}
