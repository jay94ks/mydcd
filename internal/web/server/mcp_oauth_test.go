// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// oauthFake is an MCP server behind an OAuth 2.1 authorization server
// (protected resource metadata, RFC 8414 metadata, dynamic registration).
type oauthFake struct {
	*httptest.Server
	mu         sync.Mutex
	challenge  string
	access     string
	refreshOK  bool
	issuer     string
	expiresIn  int
	issued     int
	registered int
}

func newOAuthFake(t *testing.T, f *fixture) *oauthFake {
	o := &oauthFake{refreshOK: true, expiresIn: 3600}
	mux := http.NewServeMux()
	o.Server = httptest.NewTLSServer(mux)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"resource": o.URL + "/mcp", "authorization_servers": []string{o.URL}})
	})
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		o.mu.Lock()
		iss := o.issuer
		o.mu.Unlock()
		if iss == "" {
			iss = o.URL
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": iss, "authorization_endpoint": o.URL + "/authorize", "token_endpoint": o.URL + "/token",
			"registration_endpoint": o.URL + "/register", "code_challenge_methods_supported": []string{"S256"}})
	})
	mux.HandleFunc("POST /register", func(w http.ResponseWriter, r *http.Request) {
		o.mu.Lock()
		o.registered++
		o.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"client_id": "client-1"})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		o.mu.Lock()
		defer o.mu.Unlock()
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if r.Form.Get("code") != "code-1" || base64.RawURLEncoding.EncodeToString(sum[:]) != o.challenge || r.Form.Get("client_id") != "client-1" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
				return
			}
		case "refresh_token":
			if !o.refreshOK || !strings.HasPrefix(r.Form.Get("refresh_token"), "refresh-") {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
				return
			}
		}
		o.issued++
		o.access = "access-" + string(rune('0'+o.issued))
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": o.access, "token_type": "Bearer", "refresh_token": "refresh-" + string(rune('0'+o.issued)), "expires_in": o.expiresIn})
	})
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		o.mu.Lock()
		ok := o.access != "" && r.Header.Get("Authorization") == "Bearer "+o.access
		o.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodDelete {
			return
		}
		var q struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&q)
		w.Header().Set("Content-Type", "application/json")
		switch q.Method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "s1")
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`+string(q.ID)+`,"result":{"protocolVersion":"`+mcpProtocol+`","serverInfo":{"name":"wiki"}}}`)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`+string(q.ID)+`,"result":{"tools":[{"name":"search","description":"찾기","inputSchema":{"type":"object"}}]}}`)
		}
	})
	t.Cleanup(o.Close)
	pool := x509.NewCertPool()
	pool.AddCert(o.Certificate())
	f.srv.opt.WebhookTLS = &tls.Config{RootCAs: pool}
	f.srv.opt.WebhookAllowAddr = func(a netip.Addr) bool { return a.IsLoopback() }
	return o
}

func TestMCPOAuth(t *testing.T) {
	f, _, _ := incidentFixture(t)
	o := newOAuthFake(t, f)
	fakeLogin(t, f, "admin")
	callback := func(q url.Values) int {
		res, err := f.hc.Get(f.http.URL + mcpOAuthCallback + "?" + q.Encode())
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	login := func(out map[string]any) url.Values {
		u, err := url.Parse(out["loginUrl"].(string))
		if err != nil || !strings.HasPrefix(out["loginUrl"].(string), o.URL+"/authorize?") {
			t.Fatalf("loginUrl: %v", out)
		}
		q := u.Query()
		if q.Get("code_challenge_method") != "S256" || q.Get("resource") != o.URL+"/mcp" || q.Get("client_id") != "client-1" ||
			!strings.HasSuffix(q.Get("redirect_uri"), mcpOAuthCallback) {
			t.Fatalf("login query: %v", q)
		}
		o.mu.Lock()
		o.challenge = q.Get("code_challenge")
		o.mu.Unlock()
		return q
	}

	if code, _ := f.do("POST", "/api/v1/system/mcp", map[string]any{"name": "wiki", "url": o.URL + "/mcp", "auth": map[string]any{"kind": "oauth", "token": "x"}}); code != 422 {
		t.Fatalf("oauth with token: %d", code)
	}
	o.issuer = "https://evil.example"
	if code, out := f.do("POST", "/api/v1/system/mcp", map[string]any{"name": "wiki", "url": o.URL + "/mcp", "auth": map[string]any{"kind": "oauth"}}); code != 422 || !strings.Contains(mustString(out), "another issuer") {
		t.Fatalf("issuer mix-up: %d %v", code, out)
	}
	o.issuer = ""
	code, out := f.do("POST", "/api/v1/system/mcp", map[string]any{"name": "wiki", "url": o.URL + "/mcp", "auth": map[string]any{"kind": "oauth"}})
	if code != 202 || out["name"] != "wiki" || out["expiresAt"] == nil {
		t.Fatalf("start: %d %v", code, out)
	}
	q := login(out)
	if _, out := f.do("GET", "/api/v1/system/mcp/wiki/oauth", nil); out["state"] != "login" {
		t.Fatalf("state: %v", out)
	}
	if _, err := f.store.GetMCPServer("wiki"); err == nil {
		t.Fatal("stored before the login")
	}
	if c := callback(url.Values{"state": {"other"}, "code": {"code-1"}}); c != 400 {
		t.Fatalf("wrong state: %d", c)
	}
	if c := callback(url.Values{"state": {q.Get("state")}, "code": {"code-1"}}); c != 200 {
		t.Fatalf("callback: %d", c)
	}
	if c := callback(url.Values{"state": {q.Get("state")}, "code": {"code-1"}}); c != 400 {
		t.Fatalf("replayed state: %d", c)
	}
	_, out = f.do("GET", "/api/v1/system/mcp/wiki/oauth", nil)
	srv, _ := out["server"].(map[string]any)
	if out["state"] != "connected" || srv == nil || srv["auth"].(map[string]any)["kind"] != "oauth" || srv["auth"].(map[string]any)["expiresAt"] == nil ||
		len(srv["tools"].([]any)) != 1 {
		t.Fatalf("connected: %v", out)
	}

	// tokens are sealed only
	var db bytes.Buffer
	if _, err := f.store.Backup(func(int64) io.Writer { return &db }); err != nil {
		t.Fatal(err)
	}
	_, list := f.do("GET", "/api/v1/system/mcp", nil)
	if bytes.Contains(db.Bytes(), []byte("access-1")) || bytes.Contains(db.Bytes(), []byte("refresh-1")) || strings.Contains(mustString(list), "access-1") {
		t.Fatal("token outside the seal box")
	}

	// a token that ends within a minute is renewed on use
	o.mu.Lock()
	o.expiresIn = 30
	o.mu.Unlock()
	_, out = f.do("POST", "/api/v1/system/mcp/wiki/oauth/login", nil)
	q = login(out)
	callback(url.Values{"state": {q.Get("state")}, "code": {"code-1"}})
	if code, out := f.do("POST", "/api/v1/system/mcp/wiki/refresh", nil); code != 200 || o.access != "access-3" {
		t.Fatalf("renew: %d %v %s", code, out, o.access)
	}
	// renewal refused: needsLogin
	o.mu.Lock()
	o.refreshOK = false
	o.mu.Unlock()
	if code, _ := f.do("POST", "/api/v1/system/mcp/wiki/refresh", nil); code != 422 {
		t.Fatalf("renew refused: %d", code)
	}
	_, list = f.do("GET", "/api/v1/system/mcp", nil)
	if !strings.Contains(mustString(list), `"needsLogin":true`) {
		t.Fatalf("needsLogin: %v", list)
	}
	// log in again clears it
	o.mu.Lock()
	o.expiresIn = 3600
	o.mu.Unlock()
	_, out = f.do("POST", "/api/v1/system/mcp/wiki/oauth/login", nil)
	q = login(out)
	callback(url.Values{"state": {q.Get("state")}, "code": {"code-1"}})
	if _, list = f.do("GET", "/api/v1/system/mcp", nil); strings.Contains(mustString(list), "needsLogin") {
		t.Fatalf("after login: %v", list)
	}

	// moving an OAuth server needs a new login; deleting drops the tokens
	m, _ := f.store.GetMCPServer("wiki")
	if code, out := f.do("PUT", "/api/v1/system/mcp/wiki", map[string]any{"revision": m.Revision, "url": o.URL + "/mcp2"}); code != 422 || errCode(out) != "login-required" {
		t.Fatalf("move: %d %v", code, out)
	}
	if code, _ := f.do("POST", "/api/v1/system/mcp/grafana/oauth/login", nil); code != 404 {
		t.Fatalf("unknown server: %d", code)
	}
	if code, _ := f.do("DELETE", "/api/v1/system/mcp/wiki", map[string]any{"confirmName": "wiki"}); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if _, err := f.srv.opt.Seal.Get(mcpOAuthKey("wiki")); err == nil {
		t.Fatal("sealed tokens kept")
	}
	if code, _ := f.do("GET", "/api/v1/system/mcp/wiki/oauth", nil); code != 404 {
		t.Fatalf("state after delete: %d", code)
	}
}
