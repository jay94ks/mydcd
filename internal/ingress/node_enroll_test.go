// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestNodeEnrollOnlyOnHTTPS(t *testing.T) {
	var m Manager
	r := httptest.NewRequest("POST", "https://shop.example"+NodeEnrollPath+"enroll", nil)
	if _, ok := m.nodeEnroll(httptest.NewRequest("GET", "https://shop.example/.well-known/other", nil)); ok {
		t.Fatal("other path taken")
	}
	h, ok := m.nodeEnroll(r)
	w := httptest.NewRecorder()
	if h(w, r, netip.Addr{}); !ok || w.Code != 404 {
		t.Fatal("no handler must answer 404", w.Code)
	}
	called := false
	m.SetNodeEnroll(func(w http.ResponseWriter, _ *http.Request, src netip.Addr) { called = src.IsValid() })
	r.TLS = &tls.ConnectionState{}
	h, _ = m.nodeEnroll(r)
	h(httptest.NewRecorder(), r, netip.MustParseAddr("203.0.113.9"))
	if !called {
		t.Fatal("handler not called on HTTPS")
	}
	r.TLS = nil
	h, _ = m.nodeEnroll(r)
	called = false
	if h(httptest.NewRecorder(), r, netip.MustParseAddr("203.0.113.9")); called {
		t.Fatal("handler ran on plain HTTP")
	}
}
