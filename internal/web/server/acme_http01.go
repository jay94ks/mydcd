// SPDX-License-Identifier: Apache-2.0

package server

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jay94ks/seafield/internal/web/acme"
	"github.com/jay94ks/seafield/internal/web/provlog"
)

// ACME HTTP-01 responder (devel/design certificate-store §8). Ingress
// forwards only /.well-known/acme-challenge/ of registered domain hosts on
// :80 to this handler, with Host and path unchanged. It runs on its own
// listener (config acme-listen) so the forwarded traffic never reaches the
// UI or /api. Tokens live in memory for the life of one order.

// acmeHTTPTTL bounds a token that an order forgot to remove.
const acmeHTTPTTL = 30 * time.Minute

type acmeHTTPState struct {
	mu     sync.Mutex
	tokens map[string]acmeHTTPToken
}

type acmeHTTPToken struct {
	host, keyAuth string
	until         time.Time
}

func (a *acmeHTTPState) add(host, token, keyAuth string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.tokens == nil {
		a.tokens = map[string]acmeHTTPToken{}
	}
	now := time.Now()
	for k, t := range a.tokens {
		if now.After(t.until) {
			delete(a.tokens, k)
		}
	}
	a.tokens[token] = acmeHTTPToken{host: strings.ToLower(host), keyAuth: keyAuth, until: now.Add(acmeHTTPTTL)}
}

func (a *acmeHTTPState) remove(token string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.tokens, token)
}

func (a *acmeHTTPState) get(host, token string) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	t, ok := a.tokens[token]
	if !ok || time.Now().After(t.until) || t.host != host {
		return "", false
	}
	return t.keyAuth, true
}

// acmeMethod picks the challenge type of a certificate name: DNS-01 under
// a connected external domain, else HTTP-01 when the responder is on
// (never for a wildcard).
func (s *Server) acmeMethod(name string) (string, error) {
	_, _, _, err := s.dnsFor(acme.ChallengeName(name))
	if err == nil {
		return acme.DNS01, nil
	}
	if strings.HasPrefix(name, "*.") {
		return "", fmt.Errorf("%s: a wildcard needs DNS-01, and %w", name, err)
	}
	if s.opt.ACMEHTTP01 {
		return acme.HTTP01, nil
	}
	return "", errors.Join(err, errors.New("and the HTTP-01 responder is off (acme-listen)"))
}

// ACMEHandler serves GET /.well-known/acme-challenge/{token} and nothing
// else. Every request is logged to the provider log: it is how a missing
// ingress route shows up.
func (s *Server) ACMEHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.URL.Path, acme.HTTP01Path)
		if !ok || token == "" || strings.Contains(token, "/") || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
			http.NotFound(w, r)
			return
		}
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		ka, found := s.acmeHTTP.get(host, token)
		lvl := provlog.Info
		if !found {
			lvl = provlog.Warn
		}
		s.opt.ProviderLog.Add(provlog.Entry{Provider: "acme:http-01", Op: "Respond", Level: lvl, Msg: map[bool]string{true: "answered", false: "unknown token or host"}[found],
			Attrs: map[string]string{"host": host, "token": provlog.Truncate(token, 12), "remote": r.RemoteAddr, "forwardedFor": r.Header.Get("X-Forwarded-For"), "userAgent": provlog.Truncate(r.UserAgent(), 120)}})
		if !found {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method == http.MethodGet {
			w.Write([]byte(ka))
		}
	})
}
