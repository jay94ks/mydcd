// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

// The direct listener (sfcd's node.yaml port) connects from the pool
// gateway the main listener trusts, so it must not believe a client's
// X-Forwarded-* headers: a plain request stays plain.
func TestDirectHandlerTrustsNoProxy(t *testing.T) {
	s := &Server{opt: Options{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.254.1.1/32")}}}
	var https bool
	var forwarded []string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		https = s.requestHTTPS(r)
		forwarded = []string{r.Header.Get("X-Forwarded-Proto"), r.Header.Get("X-Forwarded-For"), r.Header.Get("Forwarded")}
	})
	r := httptest.NewRequest("GET", "/api/v1/auth/session", nil)
	r.RemoteAddr = "10.254.1.1:41000"
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	r.Header.Set("Forwarded", "proto=https")
	if !s.requestHTTPS(r) {
		t.Fatal("main listener should trust the gateway")
	}
	direct(inner).ServeHTTP(httptest.NewRecorder(), r)
	if https {
		t.Fatal("direct listener believed X-Forwarded-Proto")
	}
	for _, v := range forwarded {
		if v != "" {
			t.Fatalf("forwarded header kept: %q", forwarded)
		}
	}
}
