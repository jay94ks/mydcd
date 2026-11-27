// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/tls"
	"net/http/httptest"
	"net/netip"
	"testing"
)

// The cookie is Secure only when the browser's request was HTTPS: this
// listener's TLS, or X-Forwarded-Proto from the trusted ingress.
func TestRequestHTTPS(t *testing.T) {
	s := &Server{opt: Options{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.88.0.1/32")}}}
	for _, c := range []struct {
		remote, proto string
		tls           bool
		want          bool
	}{
		{"10.88.0.1:41000", "https", false, true},
		{"10.88.0.1:41000", "http", false, false},
		{"10.88.0.1:41000", "", false, false},
		{"[::ffff:10.88.0.1]:41000", "HTTPS", false, true},
		{"10.88.0.7:41000", "https", false, false}, // another cluster app on sfc-system
		{"127.0.0.1:41000", "", true, true},
		{"127.0.0.1:41000", "", false, false},
	} {
		r := httptest.NewRequest("GET", "/api/v1/auth/session", nil)
		r.RemoteAddr = c.remote
		if c.proto != "" {
			r.Header.Set("X-Forwarded-Proto", c.proto)
		}
		if c.tls {
			r.TLS = &tls.ConnectionState{}
		}
		if got := s.requestHTTPS(r); got != c.want {
			t.Errorf("%+v: %v", c, got)
		}
	}
	// No ingress configured: HTTPS unless plain from loopback.
	none := &Server{}
	for remote, want := range map[string]bool{"10.88.0.7:41000": true, "127.0.0.1:41000": false, "[::1]:41000": false} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		if got := none.requestHTTPS(r); got != want {
			t.Errorf("no proxies, %s: %v", remote, got)
		}
	}
}
