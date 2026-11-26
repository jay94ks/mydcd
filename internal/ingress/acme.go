// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"context"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// ACMEChallengePath is the certificate automation path (devel/design
// certificate-store §8). On a plain HTTP request for a host inside a
// registered domain it always goes to the cluster's ACME responder, ahead
// of every app route; an app route for it is ignored. With no responder set
// it answers 404.
const ACMEChallengePath = "/.well-known/acme-challenge/"

// acmeResponseBytes bounds a responder answer (a key authorization).
const acmeResponseBytes = 4 << 10

type acmeForward struct {
	responder netip.AddrPort
	covers    func(host string) bool
	proxy     *httputil.ReverseProxy
}

// SetACMEResponder sets the responder address ("" for none) and the check
// for hosts inside a registered domain. The app runtime calls it from its
// reconciliation with the current certificate store.
func (m *Manager) SetACMEResponder(address string, covers func(host string) bool) error {
	f := &acmeForward{covers: covers}
	if address != "" {
		ap, err := netip.ParseAddrPort(address)
		if err != nil || ap.Port() == 0 {
			return ErrRoute
		}
		f.responder = ap
		target := &url.URL{Scheme: "http", Host: ap.String()}
		dialer := &net.Dialer{Timeout: 2 * time.Second}
		f.proxy = &httputil.ReverseProxy{
			Rewrite: func(p *httputil.ProxyRequest) {
				// Host header and path pass through unchanged.
				p.Out.URL.Scheme, p.Out.URL.Host = target.Scheme, target.Host
				p.Out.Host = p.In.Host
				p.Out.Header.Del("Forwarded")
				p.SetXForwarded()
			},
			Transport: &http.Transport{Proxy: nil, DialContext: dialer.DialContext, ResponseHeaderTimeout: 5 * time.Second, MaxIdleConns: 4, IdleConnTimeout: 30 * time.Second, MaxResponseHeaderBytes: 4 << 10, DisableCompression: true},
			ModifyResponse: func(r *http.Response) error {
				r.Body = http.MaxBytesReader(nil, r.Body, acmeResponseBytes)
				return nil
			},
			ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
				http.Error(w, "acme responder unavailable", http.StatusBadGateway)
			},
		}
	}
	if covers == nil {
		f.covers = func(string) bool { return false }
	}
	m.acme.Store(f)
	return nil
}

// acmeChallenge reports whether a request belongs to certificate
// automation: plain HTTP, the challenge path, a host in a registered domain.
func (m *Manager) acmeChallenge(r *http.Request, host string) (*acmeForward, bool) {
	f := m.acme.Load()
	if f == nil || r.TLS != nil || !strings.HasPrefix(r.URL.Path, ACMEChallengePath) || !f.covers(host) {
		return nil, false
	}
	return f, true
}

func (f *acmeForward) serve(w http.ResponseWriter, r *http.Request) {
	if f.proxy == nil || r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	f.proxy.ServeHTTP(w, r.WithContext(ctx))
}
