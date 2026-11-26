// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jay94ks/mydcd/internal/web/store"
)

// OAuth for MCP servers (UI-B9, mydc-web). The MCP authorization flow
// (2025-06-18): protected resource metadata → authorization server
// metadata → dynamic client registration → authorization code with PKCE
// (S256) and the resource indicator. The browser opens loginUrl; the
// authorization server sends it back to the callback here, which is bound to
// the login only by its one-use state (the session cookie is SameSite=Strict
// and does not come along). The tokens and the client registration sit in
// the seal box as mcp-oauth-{name}; nothing of them goes to the browser,
// bbolt or the log. The access token is refreshed with the refresh token a
// minute before it expires; when that fails the server shows needsLogin.

const (
	mcpOAuthLoginTTL = 10 * time.Minute
	mcpOAuthCallback = "/api/v1/system/mcp/oauth/callback"
)

func mcpOAuthKey(name string) string { return "mcp-oauth-" + name }

// mcpOAuthSecret is the sealed part.
type mcpOAuthSecret struct {
	TokenEndpoint string    `json:"tokenEndpoint"`
	ClientID      string    `json:"clientId"`
	ClientSecret  string    `json:"clientSecret,omitempty"`
	Resource      string    `json:"resource"`
	Redirect      string    `json:"redirect"`
	Access        string    `json:"access"`
	Refresh       string    `json:"refresh,omitempty"`
	Expiry        time.Time `json:"expiry,omitzero"`
}

type mcpOAuthLogin struct {
	name, url  string
	users      store.MCPUsers
	relogin    bool
	by, byName string
	ws         *webSession // who started it (audit)
	loginURL   string
	state      string
	verifier   string
	secret     mcpOAuthSecret // registration; tokens after the callback
	expiresAt  time.Time
	status     string // login, connected, failed, expired
	err        string
}

type mcpOAuthState struct {
	mu      sync.Mutex
	logins  map[string]*mcpOAuthLogin // by server name
	byState map[string]*mcpOAuthLogin
	refresh sync.Mutex // one refresh at a time
}

func randomURLToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// mcpRedirect is this web app's callback address as the browser sees it.
func (s *Server) mcpRedirect(r *http.Request) string {
	if o := r.Header.Get("Origin"); o != "" && sameOrigin(r) {
		return strings.TrimSuffix(o, "/") + mcpOAuthCallback
	}
	scheme := "https"
	if !s.requestHTTPS(r) {
		scheme = "http"
	}
	return scheme + "://" + r.Host + mcpOAuthCallback
}

// oauthGetJSON reads a public metadata document.
func (s *Server) oauthGetJSON(ctx context.Context, hc *http.Client, raw string, out any) error {
	if msg := s.checkWebhookURL(raw); msg != "" {
		return mcpErrorf("%s", msg)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return mcpErrorf("url: %v", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("MCP-Protocol-Version", mcpProtocol)
	res, err := hc.Do(req)
	if err != nil {
		return mcpErrorf("connect: %v", errors.Unwrap(err))
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return mcpErrorf("%s: %d %s", raw, res.StatusCode, http.StatusText(res.StatusCode))
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(out); err != nil {
		return mcpErrorf("%s: not JSON", raw)
	}
	return nil
}

// oauthPostForm calls a token endpoint (form body, JSON answer).
func (s *Server) oauthPostForm(ctx context.Context, hc *http.Client, endpoint string, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return mcpErrorf("url: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	res, err := hc.Do(req)
	if err != nil {
		return mcpErrorf("token: connect failed")
	}
	defer res.Body.Close()
	var body struct {
		Error string `json:"error"`
	}
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	if res.StatusCode != http.StatusOK {
		_ = json.Unmarshal(raw, &body)
		if body.Error != "" {
			return mcpErrorf("token: %d %s", res.StatusCode, oneLine(body.Error, 64))
		}
		return mcpErrorf("token: %d %s", res.StatusCode, http.StatusText(res.StatusCode))
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return mcpErrorf("token: not JSON")
	}
	return nil
}

type oauthASMeta struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	RegistrationEndpoint  string   `json:"registration_endpoint"`
	CodeChallengeMethods  []string `json:"code_challenge_methods_supported"`
	ScopesSupported       []string `json:"scopes_supported"`
}

// mcpOAuthDiscover finds the authorization server of an MCP address and
// registers this web app as a public client.
func (s *Server) mcpOAuthDiscover(ctx context.Context, mcpURL, redirect string) (*oauthASMeta, mcpOAuthSecret, []string, error) {
	hc := s.webhookClient(mcpTimeout)
	u, _ := url.Parse(mcpURL)
	origin := u.Scheme + "://" + u.Host
	path := strings.TrimSuffix(u.Path, "/")

	// RFC 9728: the protected resource names its authorization servers.
	var prm struct {
		AuthorizationServers []string `json:"authorization_servers"`
		ScopesSupported      []string `json:"scopes_supported"`
	}
	asURL := origin
	if err := s.oauthGetJSON(ctx, hc, origin+"/.well-known/oauth-protected-resource"+path, &prm); err != nil {
		_ = s.oauthGetJSON(ctx, hc, origin+"/.well-known/oauth-protected-resource", &prm)
	}
	if len(prm.AuthorizationServers) > 0 {
		asURL = strings.TrimSuffix(prm.AuthorizationServers[0], "/")
	}
	// RFC 8414 (path inserted after the well-known prefix), then OpenID.
	au, err := url.Parse(asURL)
	if err != nil || s.checkWebhookURL(asURL) != "" {
		return nil, mcpOAuthSecret{}, nil, mcpErrorf("authorization server: an https public address is needed")
	}
	asOrigin, asPath := au.Scheme+"://"+au.Host, strings.TrimSuffix(au.Path, "/")
	var meta oauthASMeta
	if err := s.oauthGetJSON(ctx, hc, asOrigin+"/.well-known/oauth-authorization-server"+asPath, &meta); err != nil {
		if err2 := s.oauthGetJSON(ctx, hc, asOrigin+"/.well-known/openid-configuration"+asPath, &meta); err2 != nil {
			return nil, mcpOAuthSecret{}, nil, mcpErrorf("authorization server metadata was not found")
		}
	}
	// RFC 8414 §3.3: the metadata must name the server it was asked from
	// (mix-up defence).
	if strings.TrimSuffix(meta.Issuer, "/") != asURL {
		return nil, mcpOAuthSecret{}, nil, mcpErrorf("authorization server metadata names another issuer")
	}
	for _, e := range []string{meta.AuthorizationEndpoint, meta.TokenEndpoint} {
		if e == "" || s.checkWebhookURL(e) != "" {
			return nil, mcpOAuthSecret{}, nil, mcpErrorf("authorization server: endpoints must be https public addresses")
		}
	}
	if len(meta.CodeChallengeMethods) > 0 && !contains(meta.CodeChallengeMethods, "S256") {
		return nil, mcpOAuthSecret{}, nil, mcpErrorf("authorization server does not support PKCE S256")
	}
	if meta.RegistrationEndpoint == "" || s.checkWebhookURL(meta.RegistrationEndpoint) != "" {
		return nil, mcpOAuthSecret{}, nil, mcpErrorf("authorization server does not offer dynamic client registration")
	}
	// RFC 7591 dynamic client registration (public client).
	body, _ := json.Marshal(map[string]any{"client_name": "MyDC", "redirect_uris": []string{redirect},
		"grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"}, "token_endpoint_auth_method": "none"})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, meta.RegistrationEndpoint, strings.NewReader(string(body)))
	if err != nil {
		return nil, mcpOAuthSecret{}, nil, mcpErrorf("registration: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	res, err := hc.Do(req)
	if err != nil {
		return nil, mcpOAuthSecret{}, nil, mcpErrorf("registration: connect failed")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated && res.StatusCode != http.StatusOK {
		return nil, mcpOAuthSecret{}, nil, mcpErrorf("registration: %d %s", res.StatusCode, http.StatusText(res.StatusCode))
	}
	var reg struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&reg); err != nil || reg.ClientID == "" {
		return nil, mcpOAuthSecret{}, nil, mcpErrorf("registration: no client_id")
	}
	scopes := prm.ScopesSupported
	return &meta, mcpOAuthSecret{TokenEndpoint: meta.TokenEndpoint, ClientID: reg.ClientID, ClientSecret: reg.ClientSecret, Resource: mcpURL, Redirect: redirect}, scopes, nil
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// mcpOAuthStart registers and returns the login (status login).
func (s *Server) mcpOAuthStart(ctx context.Context, r *http.Request, ws *webSession, name, mcpURL string, users store.MCPUsers, relogin bool) (*mcpOAuthLogin, error) {
	redirect := s.mcpRedirect(r)
	meta, sec, scopes, err := s.mcpOAuthDiscover(ctx, mcpURL, redirect)
	if err != nil {
		return nil, err
	}
	l := &mcpOAuthLogin{name: name, url: mcpURL, users: users, relogin: relogin, by: ws.user.ID, byName: ws.user.Username, ws: ws,
		state: randomURLToken(32), verifier: randomURLToken(48), secret: sec, expiresAt: s.now().Add(mcpOAuthLoginTTL), status: "login"}
	st := &s.mcpOAuth
	st.mu.Lock()
	if st.logins == nil {
		st.logins, st.byState = map[string]*mcpOAuthLogin{}, map[string]*mcpOAuthLogin{}
	}
	if old := st.logins[name]; old != nil {
		delete(st.byState, old.state)
	}
	// Ended logins are kept a while for their state answer, then dropped.
	for n, x := range st.logins {
		if s.now().After(x.expiresAt.Add(time.Hour)) {
			delete(st.byState, x.state)
			delete(st.logins, n)
		}
	}
	st.logins[name], st.byState[l.state] = l, l
	st.mu.Unlock()

	ch := sha256.Sum256([]byte(l.verifier))
	q := url.Values{"response_type": {"code"}, "client_id": {sec.ClientID}, "redirect_uri": {redirect}, "state": {l.state},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(ch[:])}, "code_challenge_method": {"S256"}, "resource": {mcpURL}}
	if len(scopes) > 0 {
		q.Set("scope", strings.Join(scopes, " "))
	}
	sep := "?"
	if strings.Contains(meta.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	l.loginURL = meta.AuthorizationEndpoint + sep + q.Encode()
	return l, nil
}

func (s *Server) writeOAuthLogin(w http.ResponseWriter, status int, l *mcpOAuthLogin) {
	writeJSON(w, status, map[string]any{"name": l.name, "loginUrl": l.loginURL, "expiresAt": rfc3339(l.expiresAt)})
}

// GET /system/mcp/oauth/callback?state&code|error (no session: bound by
// state).
func (s *Server) handleMCPOAuthCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	st := &s.mcpOAuth
	st.mu.Lock()
	l := st.byState[q.Get("state")]
	if l != nil {
		delete(st.byState, l.state) // one use
	}
	st.mu.Unlock()
	page := func(code int, msg string) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(code)
		_, _ = fmt.Fprintf(w, "<!doctype html><meta charset=utf-8><title>MyDC</title><p>%s</p>", msg)
	}
	if l == nil || q.Get("state") == "" {
		page(http.StatusBadRequest, "로그인 요청을 찾지 못했습니다. MyDC에서 다시 로그인해 주세요.")
		return
	}
	fail := func(status, msg string) {
		st.mu.Lock()
		l.status, l.err = status, msg
		st.mu.Unlock()
		page(http.StatusBadRequest, "로그인하지 못했습니다. MyDC 화면에서 이유를 볼 수 있습니다. 이 창은 닫아도 됩니다.")
	}
	if s.now().After(l.expiresAt) {
		fail("expired", "the login took too long; start it again")
		return
	}
	if e := q.Get("error"); e != "" {
		fail("failed", "authorization: "+oneLine(e, 64))
		return
	}
	code := q.Get("code")
	if code == "" || len(code) > 2048 {
		fail("failed", "authorization: no code")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*mcpTimeout)
	defer cancel()
	sec := l.secret
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {sec.Redirect}, "client_id": {sec.ClientID},
		"code_verifier": {l.verifier}, "resource": {sec.Resource}}
	if sec.ClientSecret != "" {
		form.Set("client_secret", sec.ClientSecret)
	}
	if err := s.oauthToken(ctx, &sec, form); err != nil {
		fail("failed", mcpErrMsg(err))
		return
	}
	if err := s.mcpOAuthFinish(ctx, l, sec); err != nil {
		fail("failed", mcpErrMsg(err))
		return
	}
	st.mu.Lock()
	l.status, l.err = "connected", ""
	st.mu.Unlock()
	page(http.StatusOK, "로그인을 마쳤습니다. 이 창을 닫고 MyDC로 돌아가 주세요.")
}

// validBearer: a token that fits an Authorization header (at most 8 KiB).
func validBearer(t string) bool {
	if t == "" || len(t) > 8192 {
		return false
	}
	for i := 0; i < len(t); i++ {
		if t[i] < 0x21 || t[i] > 0x7e {
			return false
		}
	}
	return true
}

func mcpErrMsg(err error) string {
	var me *mcpError
	if errors.As(err, &me) {
		return me.msg
	}
	return "failed"
}

// oauthToken runs a token request and puts the answer into sec.
func (s *Server) oauthToken(ctx context.Context, sec *mcpOAuthSecret, form url.Values) error {
	var tok struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := s.oauthPostForm(ctx, s.webhookClient(mcpTimeout), sec.TokenEndpoint, form, &tok); err != nil {
		return err
	}
	if !strings.EqualFold(tok.TokenType, "bearer") || !validBearer(tok.AccessToken) || tok.RefreshToken != "" && !validBearer(tok.RefreshToken) {
		return mcpErrorf("token: no bearer access token")
	}
	sec.Access = tok.AccessToken
	if tok.RefreshToken != "" {
		sec.Refresh = tok.RefreshToken
	}
	sec.Expiry = time.Time{}
	if tok.ExpiresIn > 0 {
		sec.Expiry = s.now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	}
	return nil
}

// mcpOAuthFinish reads the catalog with the new token, then seals the
// tokens and stores (or updates) the server.
func (s *Server) mcpOAuthFinish(ctx context.Context, l *mcpOAuthLogin, sec mcpOAuthSecret) error {
	info, listed, err := s.mcpCatalog(ctx, l.url, sec.Access)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(sec)
	if l.relogin {
		var added, removed []string
		_, err := s.opt.Store.UpdateMCPServer(l.name, 0, func(m *store.MCPServer) error {
			if m.Auth != "oauth" || m.URL != l.url {
				return errors.New("the server changed during the login")
			}
			var changed bool
			m.Tools, added, removed, changed = mergeTools(m.Tools, listed, false)
			if changed {
				m.CatalogRevision++
			}
			m.Info, m.State, m.Error, m.CheckedAt, m.TokenExpiresAt, m.NeedsLogin = info, "ok", "", s.now(), sec.Expiry, false
			return s.opt.Seal.Put(mcpOAuthKey(m.Name), raw)
		})
		if err != nil {
			return mcpErrorf("%s", oneLine(err.Error(), 100))
		}
		s.audit(l.ws, "", "mcp", "oauth-login", l.name, nil, map[string]any{"tools": map[string]any{"added": added, "removed": removed}})
		return nil
	}
	tools, _, _, _ := mergeTools(nil, listed, true)
	if tools == nil {
		tools = []*store.MCPTool{}
	}
	m := &store.MCPServer{Name: l.name, URL: l.url, Auth: "oauth", Enabled: true, State: "ok", CheckedAt: s.now(), Info: info, Users: l.users,
		Tools: tools, CatalogRevision: 1, CreatedBy: l.byName, CreatedAt: s.now(), TokenExpiresAt: sec.Expiry}
	if err := s.opt.Seal.Put(mcpOAuthKey(m.Name), raw); err != nil {
		return mcpErrorf("could not seal the token")
	}
	_ = s.opt.Seal.Delete(mcpTokenKey(m.Name))
	if err := s.opt.Store.CreateMCPServer(m); err != nil {
		_ = s.opt.Seal.Delete(mcpOAuthKey(m.Name))
		if errors.Is(err, store.ErrConflict) {
			return mcpErrorf("an MCP server with this name exists")
		}
		return mcpErrorf("could not store the server")
	}
	s.audit(l.ws, "", "mcp", "create", m.Name, nil, map[string]any{"url": m.URL, "auth": "oauth", "tools": len(m.Tools)})
	return nil
}

// mcpOAuthToken returns a usable access token, refreshing it when it ends
// within a minute.
func (s *Server) mcpOAuthToken(m *store.MCPServer) (string, error) {
	st := &s.mcpOAuth
	st.refresh.Lock()
	defer st.refresh.Unlock()
	raw, err := s.opt.Seal.Get(mcpOAuthKey(m.Name))
	var sec mcpOAuthSecret
	if err != nil || json.Unmarshal(raw, &sec) != nil || sec.Access == "" {
		return "", mcpErrorf("the sealed OAuth token could not be read; log in again")
	}
	if sec.Expiry.IsZero() || s.now().Before(sec.Expiry.Add(-time.Minute)) {
		return sec.Access, nil
	}
	if sec.Refresh == "" {
		s.mcpNeedsLogin(m.Name, sec.Expiry)
		return "", mcpErrorf("the OAuth token expired; log in again")
	}
	ctx, cancel := context.WithTimeout(context.Background(), mcpTimeout)
	defer cancel()
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {sec.Refresh}, "client_id": {sec.ClientID}, "resource": {sec.Resource}}
	if sec.ClientSecret != "" {
		form.Set("client_secret", sec.ClientSecret)
	}
	if err := s.oauthToken(ctx, &sec, form); err != nil {
		s.mcpNeedsLogin(m.Name, sec.Expiry)
		return "", mcpErrorf("the OAuth token could not be renewed (%s); log in again", mcpErrMsg(err))
	}
	raw, _ = json.Marshal(sec)
	if err := s.opt.Seal.Put(mcpOAuthKey(m.Name), raw); err != nil {
		return "", mcpErrorf("could not seal the token")
	}
	_, _ = s.opt.Store.UpdateMCPServer(m.Name, 0, func(x *store.MCPServer) error {
		x.TokenExpiresAt, x.NeedsLogin = sec.Expiry, false
		return nil
	})
	return sec.Access, nil
}

func (s *Server) mcpNeedsLogin(name string, expiry time.Time) {
	_, _ = s.opt.Store.UpdateMCPServer(name, 0, func(x *store.MCPServer) error {
		x.NeedsLogin, x.TokenExpiresAt = true, expiry
		return nil
	})
}

// GET /system/mcp/{name}/oauth → {state, error?, server?}
func (s *Server) handleMCPOAuthState(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if !s.requireAdmin(w, r, ws) {
		return
	}
	name := r.PathValue("name")
	st := &s.mcpOAuth
	st.mu.Lock()
	l := st.logins[name]
	var state, msg string
	if l != nil {
		if l.status == "login" && s.now().After(l.expiresAt) {
			l.status = "expired"
			delete(st.byState, l.state)
		}
		state = l.status
		if state != "login" {
			msg = l.err
		}
	}
	st.mu.Unlock()
	m, err := s.opt.Store.GetMCPServer(name)
	if l == nil {
		if err != nil || m.Auth != "oauth" {
			writeError(w, http.StatusNotFound, "not-found", "no OAuth login for this name")
			return
		}
		state = "connected"
	}
	out := map[string]any{"state": state}
	if msg != "" && state != "connected" {
		out["error"] = msg
	}
	if state == "connected" && err == nil {
		out["server"] = s.mcpView(m)
	}
	writeJSON(w, http.StatusOK, out)
}

// POST /system/mcp/{name}/oauth/login: log in again (the old token keeps
// working until the new one comes).
func (s *Server) handleMCPOAuthLogin(w http.ResponseWriter, r *http.Request, ws *webSession) {
	m, ok := s.loadMCP(w, r, ws)
	if !ok {
		return
	}
	if m.Auth != "oauth" {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "this server does not use OAuth")
		return
	}
	l, err := s.mcpOAuthStart(r.Context(), r, ws, m.Name, m.URL, m.Users, true)
	if err != nil {
		writeMCPConnect(w, err)
		return
	}
	s.audit(ws, "", "mcp", "oauth-login-start", m.Name, nil, nil)
	s.writeOAuthLogin(w, http.StatusOK, l)
}
