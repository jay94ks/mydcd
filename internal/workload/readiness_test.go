// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPReadinessBoundedOriginalEndpointAndNoRedirect(t *testing.T) {
	var redirected atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ready":
			fmt.Fprint(w, "ready")
		case "/redirect":
			http.Redirect(w, r, "/unexpected", http.StatusFound)
		case "/unexpected":
			redirected.Store(true)
		case "/stalled":
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer server.Close()
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	p, _ := strconv.Atoi(port)
	s := ContainerSpec{IPv4: netip.MustParseAddr("127.0.0.1"), Readiness: &HTTPReadiness{Path: "/ready", Port: uint16(p)}}
	if !httpReady(context.Background(), s) {
		t.Fatal("original healthy endpoint rejected")
	}
	for _, path := range []string{"/missing", "/redirect", "/stalled"} {
		s.Readiness.Path = path
		if httpReady(context.Background(), s) {
			t.Fatal("unhealthy/redirect accepted")
		}
	}
	if redirected.Load() {
		t.Fatal("probe followed a different endpoint")
	}
	for _, path := range []string{"http://example.test/", "//example.test/", "/ok\r\nheader", "/path#fragment"} {
		if (HTTPReadiness{Path: path, Port: 80}).Valid() {
			t.Fatal("arbitrary or invalid probe accepted", path)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.Readiness.Path = "/ready"
	if httpReady(ctx, s) {
		t.Fatal("cancelled probe reported ready")
	}
}

func TestHTTPReadinessExplicitDeadlineAndParentCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(1100 * time.Millisecond):
			fmt.Fprint(w, "ready")
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	p, _ := strconv.Atoi(port)
	s := ContainerSpec{IPv4: netip.MustParseAddr("127.0.0.1"), Readiness: &HTTPReadiness{Path: "/ready", Port: uint16(p)}}
	if httpReady(context.Background(), s) {
		t.Fatal("default one-second deadline changed")
	}
	s.Readiness.TimeoutMS = 2000
	if !httpReady(context.Background(), s) {
		t.Fatal("explicit valid response deadline ignored")
	}
	s.Readiness.TimeoutMS = 20
	if httpReady(context.Background(), s) {
		t.Fatal("explicit short deadline ignored")
	}
	s.Readiness.TimeoutMS = 2000
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
	defer cancel()
	if httpReady(ctx, s) {
		t.Fatal("parent deadline extended")
	}
	for _, bad := range []int{-1, 30001} {
		s.Readiness.TimeoutMS = bad
		if s.Readiness.Valid() || httpReady(context.Background(), s) {
			t.Fatal("invalid native deadline accepted", bad)
		}
	}
}
