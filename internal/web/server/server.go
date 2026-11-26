// SPDX-License-Identifier: Apache-2.0

// Package server is the mydc-web HTTP layer: browser login sessions, the
// /api/v1 JSON API, and static UI serving. It holds no management power of
// its own; every cluster call runs on the logged-in user's MYDCP session.
package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"github.com/jay94ks/mydcd/internal/web/ai"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jay94ks/mydcd/internal/web/acme"
	"github.com/jay94ks/mydcd/internal/web/dns"
	"github.com/jay94ks/mydcd/internal/web/mydc"
	"github.com/jay94ks/mydcd/internal/web/provlog"
	"github.com/jay94ks/mydcd/internal/web/seal"
	"github.com/jay94ks/mydcd/internal/web/store"
)

// Options configures a Server.
type Options struct {
	Client       mydc.Client
	Store        *store.Store
	Static       fs.FS // UI build (index.html at root); nil serves a notice
	CookieSecure bool
	LoginTTL     time.Duration
	OpRetention  time.Duration
	Logger       *slog.Logger
	Now          func() time.Time
	CallTimeout  time.Duration // per mydcd call
	Seal         *seal.Box     // sealed secrets; nil or not ready turns the features needing it off
	DataDir      string        // data folder (staged restores go here)
	Version      string        // shown in web app settings
	Socket       string        // mydcd socket path, shown in web app settings
	DBPath       string        // web.db path, shown in web app settings
	// SealKeySource: "env" or "file" (where MYDC_WEB_SEAL_KEY came from;
	// empty without a key), shown in web app settings.
	SealKeySource string
	DNS           *dns.Registry // external DNS vendor adapters
	// Resolver answers the DNS propagation check (default: the network).
	Resolver dns.Resolver
	ACME     *acme.Registry // certificate authorities
	// ProviderLog is the diagnostic log of DNS and ACME provider calls
	// (off until an administrator turns it on); nil hides the feature.
	ProviderLog *provlog.Log
	// ACMEHTTP01 says the HTTP-01 responder (ACMEHandler) is served, so
	// names outside connected external domains can be issued over HTTP-01.
	ACMEHTTP01 bool
	// ACMEAdvertise is the responder IP:port ingress dials (the cluster
	// set-acme-responder setting this daemon fills in); empty: not filled.
	ACMEAdvertise string
	// ACMEPropagation bounds the wait for challenge TXT records (default 10 min).
	ACMEPropagation time.Duration
	// RegistryTransport reaches built-in registries (default
	// http.DefaultTransport); RegistryPlainHTTP is for tests only.
	RegistryTransport http.RoundTripper
	RegistryPlainHTTP bool
	// AI reaches the AI vendors (empty: their public APIs); AIHideModels
	// replaces the OpenAI hide patterns (nil: ai.DefaultHidden).
	AI           ai.Endpoints
	AIHideModels []string
	// WebhookTLS and WebhookAllowAddr are for tests: the TLS settings of
	// external webhook sends and which addresses they may reach (nil:
	// public unicast only).
	WebhookTLS       *tls.Config
	WebhookAllowAddr func(netip.Addr) bool
}

// Server serves the web UI and API.
type Server struct {
	opt           Options
	sessions      *sessions
	mux           *http.ServeMux
	log           *slog.Logger
	now           func() time.Time
	cur           atomic.Pointer[store.Settings] // saved web settings (nil: defaults)
	acme          acmeRunner
	acmeAuto      acmeAutoState
	acmeResponder acmeResponderState
	acmeHTTP      acmeHTTPState
	mcpOAuth      mcpOAuthState
	images        imageCache // registry catalog pages (memory only)
	uploads       uploadSet  // image archive uploads (data folder)
	backup        autoBackupState
	aiLive        aiLive // coordinator transcripts (memory only)
	watch         incidentWatch
	hooks         webhookState
}

// New builds a Server. Call Run to start background sweeping.
func New(opt Options) *Server {
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}
	if opt.LoginTTL == 0 {
		opt.LoginTTL = 5 * time.Minute
	}
	if opt.OpRetention == 0 {
		opt.OpRetention = 30 * 24 * time.Hour
	}
	if opt.CallTimeout == 0 {
		opt.CallTimeout = 30 * time.Second
	}
	s := &Server{opt: opt, log: opt.Logger, now: opt.Now, mux: http.NewServeMux()}
	s.sessions = newSessions(opt.Store, opt.Now, opt.LoginTTL)
	s.loadSettings()
	s.sessions.limits = s.sessionLimits
	s.sessions.perUser = func() int { return s.settings().MaxSessionsPerUser }
	s.routes()
	return s
}

// Run expires sessions and prunes settled ops until ctx ends, then closes
// every session.
func (s *Server) Run(ctx context.Context) {
	if err := s.opt.Store.ExpireOpenSessions(s.now()); err != nil {
		s.log.Error("expire sessions from previous run", "err", err)
	}
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	lastPrune := time.Time{}
	for {
		select {
		case <-ctx.Done():
			s.sessions.closeAll()
			s.dropWatchSession()
			return
		case <-t.C:
			s.sessions.sweep()
			s.autoBackupTick()
			s.incidentTick(ctx)
			if s.now().Sub(lastPrune) > time.Hour {
				lastPrune = s.now()
				s.prune()
				s.acmeTick()
				s.aiCatalogTick(ctx)
				s.aiLive.sweep(s.now())
			}
		}
	}
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	if strings.HasPrefix(r.URL.Path, "/api/") {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if r.Header.Get("X-MyDC-Web") != "1" || !sameOrigin(r) {
				writeError(w, http.StatusForbidden, "csrf", "missing X-MyDC-Web header or cross-origin request")
				return
			}
		}
	}
	s.mux.ServeHTTP(w, r)
}

func setSecurityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
}

// sameOrigin rejects requests whose Origin header names another host.
// Requests without Origin (same-origin fetch from older browsers, curl) pass;
// SameSite=Strict on the cookie and the custom header cover them.
func sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return true
	}
	i := strings.Index(o, "://")
	if i < 0 {
		return false
	}
	return strings.EqualFold(o[i+3:], r.Host)
}

// apiError is the JSON error body.
type apiError struct {
	Code      string `json:"code"`
	Message   string `json:"message,omitempty"`
	InputCode string `json:"inputCode,omitempty"`
	Leader    string `json:"leader,omitempty"`
	// Diagnostics: compile-error problems ({line, column, message}).
	Diagnostics []map[string]any `json:"diagnostics,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]apiError{"error": {Code: code, Message: msg}})
}

// statusOf maps a mydcd reply code to an HTTP status.
func statusOf(code string) int {
	switch code {
	case "denied", "not-session-issuer", "forbidden":
		return http.StatusForbidden
	case "node-shell-disabled", "node-shell-not-ready", "limit":
		return http.StatusConflict
	case "node-unreachable":
		return http.StatusServiceUnavailable
	case "cursor-expired", "conflict":
		return http.StatusConflict
	case "invalid":
		return http.StatusUnprocessableEntity
	case "unsupported":
		return http.StatusNotImplemented
	case "missing":
		return http.StatusNotFound
	case "expired":
		return http.StatusGone
	case "ledger-full":
		return http.StatusInsufficientStorage
	case "unknown":
		return http.StatusAccepted
	case "not-leader", "unavailable", "closed", "disconnected":
		return http.StatusServiceUnavailable
	default:
		return http.StatusBadGateway
	}
}

// writeBackendError writes a mydcd error. When the connection or the login
// session behind ws is gone, the web session ends too and the browser gets
// 401 session-expired so it can log in again in place.
func (s *Server) writeBackendError(w http.ResponseWriter, ws *webSession, err error) {
	status, e := s.backendError(ws, err)
	writeJSON(w, status, map[string]apiError{"error": e})
}

// backendError is writeBackendError's status and body (it ends the web
// session the same way), for answers that are not plain HTTP.
func (s *Server) backendError(ws *webSession, err error) (int, apiError) {
	var he *httpErr
	if errors.As(err, &he) {
		return he.status, apiError{Code: he.code, Message: he.msg}
	}
	var me *mydc.Error
	if errors.As(err, &me) {
		code := string(me.Code)
		switch me.Code {
		case mydc.CodeClosed, mydc.CodeSessionExpired, mydc.CodeNotLoggedIn:
			if ws != nil {
				s.sessions.end(ws, code)
				return http.StatusUnauthorized, apiError{Code: "session-expired", Message: "the mydcd session ended (" + code + "); log in again"}
			}
			code = "disconnected"
		case mydc.CodeTransport:
			code = "disconnected"
		}
		return statusOf(code), apiError{Code: code, InputCode: me.InputCode, Leader: me.Leader, Message: me.Detail}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return http.StatusGatewayTimeout, apiError{Code: "timeout", Message: "mydcd did not answer in time"}
	}
	s.log.Error("backend call", "err", err)
	return http.StatusBadGateway, apiError{Code: "disconnected", Message: "mydcd connection failed"}
}

const maxBody = 8 << 20 // app.yaml documents are at most 4 MiB

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	body := http.MaxBytesReader(w, r.Body, maxBody)
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "bad-request", "invalid JSON body: "+err.Error())
		return false
	}
	if _, err := dec.Token(); err != io.EOF {
		writeError(w, http.StatusBadRequest, "bad-request", "trailing data after JSON body")
		return false
	}
	return true
}

func (s *Server) callCtx(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), s.opt.CallTimeout)
}
