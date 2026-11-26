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
)

func TestLifecycleHTTPUsesSharedTransportWithStatusBoundsAndNoRedirect(t *testing.T) {
	var escaped atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ready":
			w.WriteHeader(204)
		case "/large":
			fmt.Fprint(w, "a bounded prefix is sufficient for a status-only probe")
		case "/short":
			w.Header().Set("Content-Length", "100")
			fmt.Fprint(w, "short")
		case "/redirect":
			http.Redirect(w, r, "/escape", 302)
		case "/escape":
			escaped.Store(true)
		}
	}))
	defer server.Close()
	host, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	number, _ := strconv.Atoi(port)
	ip := netip.MustParseAddr(host)
	for _, q := range []struct {
		method, path string
		max, code    int
	}{{"GET", "/ready", 16, 204}, {"HEAD", "/ready", 16, 204}, {"GET", "/large", 8, 200}, {"GET", "/redirect", 16, 302}} {
		code, err := probeHTTP(context.Background(), ip, q.method, q.path, uint16(number), false, q.max)
		if err != nil || code != q.code {
			t.Fatal("shared HTTP transport", q.path, code, err)
		}
	}
	if escaped.Load() {
		t.Fatal("probe followed a different endpoint")
	}
	if _, err := probeHTTP(context.Background(), ip, "GET", "/short", uint16(number), false, 128); err == nil {
		t.Fatal("broken HTTP body became health success")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := probeHTTP(ctx, ip, "GET", "/ready", uint16(number), false, 16); err == nil {
		t.Fatal("canceled read became health success")
	}
}
