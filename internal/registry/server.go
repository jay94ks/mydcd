// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Server owns TLS connections and request lifetime, while Store and its native
// Volume lease belong to the caller. Only a successful Close proves I/O joined.
type Server struct {
	spec               Specification
	serving            atomic.Pointer[tls.Certificate]
	auth               Authorization
	content            http.Handler
	server             *http.Server
	listener           net.Listener
	ctx                context.Context
	cancel             context.CancelFunc
	mu                 sync.Mutex
	stopping           bool
	connections        int
	active             chan struct{}
	requests           sync.WaitGroup
	serveDone, done    chan struct{}
	serveErr, closeErr error
	closeOnce          sync.Once
}

// OpenServer serves the authority with a pair taken from the cluster
// certificate store. SetCertificate replaces it for new handshakes.
func OpenServer(ctx context.Context, cluster [32]byte, spec Specification, certificate tls.Certificate, content http.Handler, auth Authorization, logger *log.Logger) (*Server, error) {
	if ctx == nil || ctx.Err() != nil || spec.Validate(cluster) != nil || content == nil || auth.Check == nil || auth.Token == nil || logger == nil {
		return nil, ErrUnavailable
	}
	base, cancel := context.WithCancel(ctx)
	s := &Server{spec: spec, auth: auth, content: content, ctx: base, cancel: cancel, active: make(chan struct{}, spec.MaxRequests), serveDone: make(chan struct{}), done: make(chan struct{})}
	if err := s.SetCertificate(certificate); err != nil {
		cancel()
		return nil, err
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return s.serving.Load(), nil }}
	duration := time.Duration(spec.RequestTimeoutMS) * time.Millisecond
	s.server = &http.Server{Handler: http.HandlerFunc(s.handle), TLSConfig: config, ReadHeaderTimeout: min(duration, 10*time.Second), ReadTimeout: duration, WriteTimeout: duration, IdleTimeout: min(duration, 30*time.Second), MaxHeaderBytes: spec.MaxHeaderBytes, BaseContext: func(net.Listener) context.Context { return base }, ErrorLog: logger}
	lc := net.ListenConfig{}
	l, err := lc.Listen(ctx, "tcp", spec.Address)
	if err != nil {
		cancel()
		return nil, err
	}
	s.listener = &registryListener{Listener: l, server: s}
	go func() {
		err := s.server.ServeTLS(s.listener, "", "")
		s.mu.Lock()
		if !errors.Is(err, http.ErrServerClosed) {
			s.serveErr = err
		}
		s.mu.Unlock()
		close(s.serveDone)
	}()
	go func() {
		select {
		case <-base.Done():
			_ = s.Close(context.Background())
		case <-s.done:
		}
	}()
	return s, nil
}

// SetCertificate checks that the pair covers the authority host and is valid
// now, then serves it to new handshakes. Open connections keep their pair.
func (s *Server) SetCertificate(pair tls.Certificate) error {
	if len(pair.Certificate) == 0 || pair.PrivateKey == nil {
		return ErrUnavailable
	}
	leaf := pair.Leaf
	if leaf == nil {
		parsed, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return ErrUnavailable
		}
		leaf = parsed
	}
	u, _ := url.Parse("https://" + s.spec.Authority)
	now := time.Now()
	if !bytes.Equal(leaf.Raw, pair.Certificate[0]) || leaf.VerifyHostname(u.Hostname()) != nil || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return ErrUnavailable
	}
	pair.Leaf = leaf
	s.serving.Store(&pair)
	return nil
}

// Certificate is the store ID (leaf DER SHA-256) of the pair now served.
func (s *Server) Certificate() [32]byte { return sha256.Sum256(s.serving.Load().Certificate[0]) }

// Trust exports the served chain and its fingerprint from one snapshot, never
// the signing key.
func (s *Server) Trust() ([32]byte, [][]byte) {
	pair := s.serving.Load()
	var out [][]byte
	for _, raw := range pair.Certificate {
		out = append(out, append([]byte(nil), raw...))
	}
	return sha256.Sum256(pair.Certificate[0]), out
}
func (s *Server) Error() error { s.mu.Lock(); defer s.mu.Unlock(); return s.serveErr }
func (s *Server) Close(ctx context.Context) error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.stopping = true
		s.mu.Unlock()
		s.cancel()
		s.closeErr = s.server.Close()
		go func() { <-s.serveDone; s.requests.Wait(); close(s.done) }()
	})
	select {
	case <-s.done:
		return s.closeErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func registryError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"errors": []map[string]string{{"code": code, "message": http.StatusText(status)}}})
}
func (s *Server) deny(w http.ResponseWriter, p Permission, err error) {
	if errors.Is(err, ErrUnauthorized) {
		challenge := "Bearer realm=" + strconv.Quote("https://"+s.spec.Authority+"/token") + ",service=" + strconv.Quote(s.spec.Authority)
		if scope := p.Scope(); scope != "" {
			challenge += ",scope=" + strconv.Quote(scope)
		}
		w.Header().Set("WWW-Authenticate", challenge)
		registryError(w, http.StatusUnauthorized, "UNAUTHORIZED")
		return
	}
	if errors.Is(err, ErrForbidden) {
		registryError(w, http.StatusForbidden, "DENIED")
		return
	}
	registryError(w, http.StatusServiceUnavailable, "UNAVAILABLE")
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		registryError(w, 503, "UNAVAILABLE")
		return
	}
	select {
	case s.active <- struct{}{}:
	default:
		s.mu.Unlock()
		registryError(w, 429, "TOOMANYREQUESTS")
		return
	}
	s.requests.Add(1)
	s.mu.Unlock()
	defer s.requests.Done()
	defer func() { <-s.active }()
	if r.Host != s.spec.Authority || r.URL.User != nil || r.URL.IsAbs() && (r.URL.Scheme != "https" || r.URL.Host != s.spec.Authority) || len(r.URL.RawQuery) > 4096 || r.URL.RawPath != "" {
		registryError(w, 403, "DENIED")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(s.spec.RequestTimeoutMS)*time.Millisecond)
	defer cancel()
	r = r.WithContext(ctx)
	deadline, _ := ctx.Deadline()
	controller := http.NewResponseController(w)
	_ = controller.SetReadDeadline(deadline)
	_ = controller.SetWriteDeadline(deadline)
	closeBody := context.AfterFunc(ctx, func() { _ = r.Body.Close() })
	defer closeBody()
	defer r.Body.Close()
	if r.URL.Path == "/token" {
		s.token(w, r)
		return
	}
	p, err := requestPermission(r)
	if err != nil {
		s.deny(w, p, err)
		return
	}
	raw := r.Header.Get("Authorization")
	if !strings.HasPrefix(raw, "Bearer ") || len(raw) > 16<<10 {
		s.deny(w, p, ErrUnauthorized)
		return
	}
	bearer := strings.TrimPrefix(raw, "Bearer ")
	if bearer == "" || strings.ContainsAny(bearer, " \t\r\n") {
		s.deny(w, p, ErrUnauthorized)
		return
	}
	if err = s.auth.Check(ctx, bearer, p); err != nil {
		s.server.ErrorLog.Printf("registry access rejected: action=%s error=%v", p.Action, err)
		s.deny(w, p, err)
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || query.Get("mount") != "" || query.Get("from") != "" {
		registryError(w, 400, "UNSUPPORTED")
		return
	}
	for key, values := range query {
		if len(values) != 1 || key != "digest" && key != "n" && key != "last" {
			registryError(w, 400, "UNSUPPORTED")
			return
		}
	}
	limit := s.spec.Blobs.BlobBytes
	if strings.Contains(r.URL.Path, "/manifests/") {
		limit = int64(s.spec.Metadata.ManifestBytes)
	}
	if r.ContentLength > limit {
		registryError(w, 413, "SIZE_INVALID")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	s.content.ServeHTTP(w, r)
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		registryError(w, 405, "UNSUPPORTED")
		return
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || q.Get("service") != s.spec.Authority || len(q["service"]) != 1 {
		s.server.ErrorLog.Printf("registry token query rejected: service_count=%d scope_count=%d", len(q["service"]), len(q["scope"]))
		s.deny(w, Permission{}, ErrForbidden)
		return
	}
	for key, values := range q {
		if key != "scope" && len(values) != 1 || key != "service" && key != "scope" && key != "account" && key != "client_id" && key != "offline_token" {
			s.deny(w, Permission{}, ErrForbidden)
			return
		}
	}
	scope, err := tokenScope(q["scope"])
	if err != nil {
		s.server.ErrorLog.Printf("registry token scope rejected: scope_count=%d", len(q["scope"]))
		s.deny(w, Permission{}, err)
		return
	}
	// Docker login requests an optional refresh token with offline_token=true.
	// Accept the boolean hint while returning only our existing short-lived
	// access token. No refresh credential, extra scope or longer TTL is issued.
	if values, supplied := q["offline_token"]; supplied && values[0] != "true" && values[0] != "false" {
		s.deny(w, Permission{}, ErrForbidden)
		return
	}
	username, password, ok := r.BasicAuth()
	if !ok || username == "" || len(username) > 63 || len(password) == 0 || len(password) > 12<<10 {
		s.deny(w, Permission{}, ErrUnauthorized)
		return
	}
	secret := []byte(password)
	defer clear(secret)
	source, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || source == "" {
		s.deny(w, Permission{}, ErrUnauthorized)
		return
	}
	response, err := s.auth.Token(r.Context(), TokenRequest{Username: username, Secret: secret, Service: s.spec.Authority, Scope: scope, Source: source})
	if err != nil {
		s.server.ErrorLog.Printf("registry token authorization rejected: error=%v", err)
		s.deny(w, Permission{}, err)
		return
	}
	if response.Token == "" || len(response.Token) > 12<<10 || response.ExpiresIn < 1 || response.ExpiresIn > int64(s.spec.TokenSeconds) {
		s.deny(w, Permission{}, ErrUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// Engine may request the same repository in multiple scope entries. Collapse
// only those entries; the current grant still authorizes every requested action.
// Multiple repositories and login/catalog mixed with repository scopes remain
// outside this server's single-repository credential contract.
func tokenScope(values []string) (string, error) {
	if len(values) == 0 {
		return "", nil
	}
	if len(values) > 4 {
		return "", ErrForbidden
	}
	var repository string
	var actions []string
	for i, value := range values {
		if len(value) > 1024 {
			return "", ErrForbidden
		}
		repo, requested, err := RequestedScope(value)
		if err != nil || i != 0 && repo != repository {
			return "", ErrForbidden
		}
		repository = repo
		actions = append(actions, requested...)
	}
	slices.Sort(actions)
	actions = slices.Compact(actions)
	if slices.Equal(actions, []string{"login"}) {
		return "", nil
	}
	if slices.Equal(actions, []string{"catalog"}) {
		return "registry:catalog:*", nil
	}
	canonical := "repository:" + repository + ":" + strings.Join(actions, ",")
	if _, _, err := RequestedScope(canonical); err != nil {
		return "", err
	}
	return canonical, nil
}

type registryListener struct {
	net.Listener
	server *Server
}
type registryConnection struct {
	net.Conn
	server *Server
	once   sync.Once
}

func (l *registryListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		l.server.mu.Lock()
		if l.server.stopping || l.server.connections >= l.server.spec.MaxRequests {
			l.server.mu.Unlock()
			_ = c.Close()
			continue
		}
		l.server.connections++
		l.server.mu.Unlock()
		return &registryConnection{Conn: c, server: l.server}, nil
	}
}
func (c *registryConnection) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.server.mu.Lock(); c.server.connections--; c.server.mu.Unlock() })
	return err
}

var _ net.Listener = (*registryListener)(nil)
var _ net.Conn = (*registryConnection)(nil)
