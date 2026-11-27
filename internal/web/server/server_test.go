// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jay94ks/seafield/internal/web/sfc"
	"github.com/jay94ks/seafield/internal/web/store"
)

// testClient is a minimal in-test adapter. Methods the tests do not use
// panic through the embedded nil interface.
type testClient struct {
	mu      sync.Mutex
	conns   []*testConn
	submit  func(op sfc.SignedOp) (sfc.Result, error)
	result  func(op sfc.SignedOp) (sfc.Result, bool, error)
	source  func() (sfc.AppSource, error)
	whoErr  error
	nextReq int
	sent    []string
}

type testConn struct {
	sfc.Conn
	c        *testClient
	closed   bool
	loggedIn bool
	user     string
}

func (c *testClient) Dial(ctx context.Context) (sfc.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	tc := &testConn{c: c}
	c.conns = append(c.conns, tc)
	return tc, nil
}

func (t *testConn) Close() error { t.closed = true; return nil }

func (t *testConn) CredentialChallenge(ctx context.Context, username string, m sfc.AuthMethod, cred string) (sfc.Ticket, error) {
	if username == "nobody" {
		return sfc.Ticket{}, &sfc.Error{Code: sfc.CodeDenied, Method: "credential-challenge"}
	}
	t.user = username
	return sfc.Ticket{Username: username, Deadline: time.Now().Add(time.Minute).Unix()}, nil
}

func (t *testConn) CredentialLogin(ctx context.Context, tk sfc.Ticket, secret []byte) (sfc.Session, error) {
	if string(secret) != "pw" {
		return sfc.Session{}, &sfc.Error{Code: sfc.CodeDenied, Method: "credential-login"}
	}
	t.loggedIn = true
	return sfc.Session{User: "u-" + t.user, ExpiresAt: time.Now().Add(time.Hour).Unix()}, nil
}

func (t *testConn) Challenge(ctx context.Context, username string, key [32]byte) (sfc.Ticket, error) {
	t.user = username
	return sfc.Ticket{Username: username, UserKey: key, Deadline: time.Now().Add(time.Minute).Unix()}, nil
}

func (t *testConn) Login(ctx context.Context, tk sfc.Ticket, p sfc.KeyProof) (sfc.Session, error) {
	if len(p.Signature) != 64 || p.Signature[0] != 7 || p.Username != tk.Username {
		return sfc.Session{}, &sfc.Error{Code: sfc.CodeDenied, Method: "login"}
	}
	t.loggedIn = true
	return sfc.Session{User: "u-" + t.user, ExpiresAt: time.Now().Add(time.Hour).Unix()}, nil
}

func (t *testConn) ApproveSession(ctx context.Context, a sfc.SessionApproval) (sfc.Session, error) {
	if !t.loggedIn || len(a.Signature) != 64 || a.Signature[0] != 8 {
		return sfc.Session{}, &sfc.Error{Code: sfc.CodeDenied, Method: "approve-session"}
	}
	return sfc.Session{User: "u-" + t.user, ExpiresAt: time.Now().Add(time.Hour).Unix(), Approval: &a}, nil
}

func (t *testConn) check() error {
	if t.closed {
		return &sfc.Error{Code: sfc.CodeClosed}
	}
	if !t.loggedIn {
		return &sfc.Error{Code: sfc.CodeNotLoggedIn}
	}
	return nil
}

func (t *testConn) Whoami(ctx context.Context) (sfc.Whoami, error) {
	if err := t.check(); err != nil {
		return sfc.Whoami{}, err
	}
	if t.c.whoErr != nil {
		return sfc.Whoami{}, t.c.whoErr
	}
	return sfc.Whoami{User: sfc.UserView{ID: "u-" + t.user, Username: t.user, Revision: 3}}, nil
}

func (t *testConn) Tenants(ctx context.Context) ([]sfc.TenantView, error) {
	if err := t.check(); err != nil {
		return nil, err
	}
	return []sfc.TenantView{{ID: "shop", Revision: 1, Role: sfc.RoleManager}, {ID: "pay", Revision: 2, Role: sfc.RoleViewer}}, nil
}

func (t *testConn) Apps(ctx context.Context, tenant, after string) (sfc.Page[sfc.AppView], error) {
	if err := t.check(); err != nil {
		return sfc.Page[sfc.AppView]{}, err
	}
	if tenant != "shop" {
		return sfc.Page[sfc.AppView]{}, &sfc.Error{Code: sfc.CodeDenied}
	}
	return sfc.Page[sfc.AppView]{Items: []sfc.AppView{{Tenant: "shop", App: "web", Health: "healthy", Operation: sfc.OperationSummary{Plan: [32]byte{0xab}}}}, Next: "c1", Revision: 9}, nil
}

func (t *testConn) AppSource(ctx context.Context, tenant, app string, v uint64) (sfc.AppSource, error) {
	if err := t.check(); err != nil {
		return sfc.AppSource{}, err
	}
	return t.c.source()
}

func (t *testConn) Prepare(ctx context.Context, ch sfc.Change, root uint64) (sfc.SignedOp, error) {
	if err := t.check(); err != nil {
		return nil, err
	}
	t.c.mu.Lock()
	t.c.nextReq++
	id := t.c.nextReq
	t.c.mu.Unlock()
	return json.Marshal(map[string]any{"RequestID": "req-" + string(rune('0'+id)), "Change": ch, "RootRevision": root})
}

func (t *testConn) Submit(ctx context.Context, op sfc.SignedOp) (sfc.Result, error) {
	if err := t.check(); err != nil {
		return sfc.Result{}, err
	}
	t.c.mu.Lock()
	t.c.sent = append(t.c.sent, string(op))
	t.c.mu.Unlock()
	return t.c.submit(op)
}

func (t *testConn) Result(ctx context.Context, op sfc.SignedOp) (sfc.Result, bool, error) {
	if err := t.check(); err != nil {
		return sfc.Result{}, false, err
	}
	return t.c.result(op)
}

type fixture struct {
	t      *testing.T
	client *testClient
	store  *store.Store
	srv    *Server
	http   *httptest.Server
	hc     *http.Client
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	tc := &testClient{
		submit: func(sfc.SignedOp) (sfc.Result, error) {
			return sfc.Result{Code: sfc.ResultApplied, Index: 5, Revision: 6}, nil
		},
		result: func(sfc.SignedOp) (sfc.Result, bool, error) { return sfc.Result{}, false, nil },
		source: func() (sfc.AppSource, error) {
			return sfc.AppSource{Tenant: "shop", App: "web", Version: 4, Document: []byte("services: {}\n"), Digest: [32]byte{1}}, nil
		},
	}
	static := fstest.MapFS{
		"index.html":       {Data: []byte("<html>app</html>")},
		"assets/app-1a.js": {Data: []byte("console.log(1)")},
	}
	srv := New(Options{Client: tc, Store: st, Static: static, Logger: discardLogger()})
	hs := httptest.NewServer(srv)
	t.Cleanup(hs.Close)
	jar, _ := cookiejar.New(nil)
	return &fixture{t: t, client: tc, store: st, srv: srv, http: hs, hc: &http.Client{Jar: jar}}
}

func (f *fixture) do(method, path string, body any) (int, map[string]any) {
	f.t.Helper()
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = strings.NewReader(string(raw))
	}
	req, _ := http.NewRequest(method, f.http.URL+path, rd)
	if method != http.MethodGet {
		req.Header.Set("X-SFC-Web", "1")
	}
	resp, err := f.hc.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func (f *fixture) login() {
	f.t.Helper()
	code, out := f.do("POST", "/api/v1/auth/credential/challenge", map[string]any{"username": "alice", "method": "password"})
	if code != 200 {
		f.t.Fatalf("challenge: %d %v", code, out)
	}
	code, out = f.do("POST", "/api/v1/auth/credential/login", map[string]any{"ticketId": out["ticketId"], "secret": "pw"})
	if code != 200 {
		f.t.Fatalf("login: %d %v", code, out)
	}
}

func errCode(out map[string]any) string {
	e, _ := out["error"].(map[string]any)
	s, _ := e["code"].(string)
	return s
}

func TestCredentialLoginAndSession(t *testing.T) {
	f := newFixture(t)
	if code, out := f.do("GET", "/api/v1/auth/session", nil); code != 401 || errCode(out) != "session-expired" {
		t.Fatalf("unauthenticated session: %d %v", code, out)
	}
	// wrong password closes the login connection and does not set a cookie
	_, out := f.do("POST", "/api/v1/auth/credential/challenge", map[string]any{"username": "alice", "method": "password"})
	if code, out := f.do("POST", "/api/v1/auth/credential/login", map[string]any{"ticketId": out["ticketId"], "secret": "bad"}); code != 403 || errCode(out) != "denied" {
		t.Fatalf("bad password: %d %v", code, out)
	}
	if !f.client.conns[0].closed {
		t.Fatal("failed login must close its connection")
	}
	f.login()
	code, out := f.do("GET", "/api/v1/auth/session", nil)
	if code != 200 {
		t.Fatalf("session: %d %v", code, out)
	}
	u := out["user"].(map[string]any)
	if u["username"] != "alice" || u["id"] != "u-alice" {
		t.Fatalf("user view: %v", u)
	}
	ten := out["tenants"].([]any)
	if len(ten) != 2 || ten[0].(map[string]any)["role"] != "manager" {
		t.Fatalf("tenants view: %v", ten)
	}
	rows, _ := f.store.ListSessions("u-alice")
	if len(rows) != 1 || rows[0].Hash == "" {
		t.Fatalf("session rows: %+v", rows)
	}
	// the cookie value itself is never stored
	for _, c := range f.hc.Jar.Cookies(mustURL(f.http.URL)) {
		if c.Name == cookieName && c.Value == rows[0].Hash {
			t.Fatal("cookie value stored in clear")
		}
	}
	if code, _ := f.do("POST", "/api/v1/auth/logout", nil); code != 204 {
		t.Fatalf("logout: %d", code)
	}
	if code, _ := f.do("GET", "/api/v1/auth/session", nil); code != 401 {
		t.Fatalf("after logout: %d", code)
	}
	if !f.client.conns[1].closed {
		t.Fatal("logout must close the SFCP connection")
	}
}

func TestTicketIsSingleUse(t *testing.T) {
	f := newFixture(t)
	_, out := f.do("POST", "/api/v1/auth/credential/challenge", map[string]any{"username": "alice", "method": "password"})
	id := out["ticketId"]
	f.do("POST", "/api/v1/auth/credential/login", map[string]any{"ticketId": id, "secret": "bad"})
	if code, out := f.do("POST", "/api/v1/auth/credential/login", map[string]any{"ticketId": id, "secret": "pw"}); code != 401 || errCode(out) != "ticket-expired" {
		t.Fatalf("reused ticket: %d %v", code, out)
	}
}

func TestKeyLogin(t *testing.T) {
	f := newFixture(t)
	pub := strings.Repeat("11", 32)
	code, out := f.do("POST", "/api/v1/auth/key/challenge", map[string]any{"username": "bob", "publicKey": pub})
	if code != 200 {
		t.Fatalf("key challenge: %d %v", code, out)
	}
	proof, err := base64.StdEncoding.DecodeString(out["proof"].(string))
	if err != nil || !strings.HasPrefix(string(proof), "sfc-user-key-proof-1\x00") {
		t.Fatalf("proof bytes: %q %v", proof, err)
	}
	ticket := out["ticket"].(map[string]any)
	if ticket["userKey"] != pub || ticket["username"] != "bob" {
		t.Fatalf("ticket view: %v", ticket)
	}
	sig := make([]byte, 64)
	sig[0] = 7
	code, out = f.do("POST", "/api/v1/auth/key/login", map[string]any{"ticketId": out["ticketId"], "signature": hex.EncodeToString(sig)})
	if code != 200 || out["approve"] != true || out["method"] != nil {
		t.Fatalf("key login: %d %v", code, out)
	}
	approval, err := base64.StdEncoding.DecodeString(out["approval"].(string))
	if err != nil || !strings.HasPrefix(string(approval), "sfc-user-session-approval-1\x00") || len(out["sessionDigest"].(string)) != 64 {
		t.Fatalf("approval bytes: %q %v", approval, err)
	}
	// no web session before the approval
	if code, _ := f.do("GET", "/api/v1/auth/session", nil); code != 401 {
		t.Fatalf("session before approval: %d", code)
	}
	// the login ticket is not an approval ticket
	if code, _ := f.do("POST", "/api/v1/auth/key/approve", map[string]any{"ticketId": "nope", "signature": hex.EncodeToString(sig)}); code != 401 {
		t.Fatalf("unknown approval ticket: %d", code)
	}
	sig[0] = 8
	code, out = f.do("POST", "/api/v1/auth/key/approve", map[string]any{"ticketId": out["ticketId"], "signature": hex.EncodeToString(sig)})
	if code != 200 || out["method"] != "key" {
		t.Fatalf("key approve: %d %v", code, out)
	}
}

func TestCSRFAndOrigin(t *testing.T) {
	f := newFixture(t)
	req, _ := http.NewRequest("POST", f.http.URL+"/api/v1/auth/logout", nil)
	resp, _ := f.hc.Do(req)
	if resp.StatusCode != 403 {
		t.Fatalf("missing header: %d", resp.StatusCode)
	}
	req, _ = http.NewRequest("POST", f.http.URL+"/api/v1/auth/logout", nil)
	req.Header.Set("X-SFC-Web", "1")
	req.Header.Set("Origin", "https://evil.example")
	resp, _ = f.hc.Do(req)
	if resp.StatusCode != 403 {
		t.Fatalf("cross origin: %d", resp.StatusCode)
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") {
		t.Fatalf("csp: %q", csp)
	}
}

func TestListCamelCase(t *testing.T) {
	f := newFixture(t)
	f.login()
	code, out := f.do("GET", "/api/v1/t/shop/apps", nil)
	if code != 200 || out["next"] != "c1" || out["revision"].(float64) != 9 || out["asOf"] == "" {
		t.Fatalf("apps page: %d %v", code, out)
	}
	app := out["items"].([]any)[0].(map[string]any)
	if app["app"] != "web" || app["health"] != "healthy" {
		t.Fatalf("app item: %v", app)
	}
	plan := app["operation"].(map[string]any)["plan"].(string)
	if !strings.HasPrefix(plan, "ab00") || len(plan) != 64 {
		t.Fatalf("digest as hex: %q", plan)
	}
	if code, out := f.do("GET", "/api/v1/t/pay2/apps", nil); code != 403 || errCode(out) != "denied" {
		t.Fatalf("denied tenant: %d %v", code, out)
	}
}

const opA = "6f1c2d3e-4b5a-4c6d-8e7f-0a1b2c3d4e5f"
const opB = "7f1c2d3e-4b5a-4c6d-9e7f-0a1b2c3d4e5f"

func TestSubmitAppliedAndIdempotent(t *testing.T) {
	f := newFixture(t)
	f.login()
	body := map[string]any{"opId": opA, "action": "create-tenant", "principal": "u-alice", "expected": 1, "payload": map[string]any{"ID": "x"}, "rootRevision": 3}
	code, out := f.do("POST", "/api/v1/ops", body)
	op := out["op"].(map[string]any)
	if code != 200 || op["state"] != "applied" || op["requestId"] != "req-1" || op["index"].(float64) != 5 {
		t.Fatalf("submit: %d %v", code, out)
	}
	// same opId and content: stored op, no second send
	code, out = f.do("POST", "/api/v1/ops", body)
	if code != 200 || out["op"].(map[string]any)["state"] != "applied" || len(f.client.sent) != 1 {
		t.Fatalf("idempotent resend: %d %v sent=%d", code, out, len(f.client.sent))
	}
	body["expected"] = 2
	if code, out := f.do("POST", "/api/v1/ops", body); code != 409 || errCode(out) != "op-conflict" {
		t.Fatalf("conflicting reuse: %d %v", code, out)
	}
	if code, _ := f.do("POST", "/api/v1/ops", map[string]any{"opId": "nope", "action": "x"}); code != 400 {
		t.Fatalf("bad opId: %d", code)
	}
}

func TestSubmitUnknownIsSettledByResult(t *testing.T) {
	f := newFixture(t)
	f.login()
	f.client.submit = func(sfc.SignedOp) (sfc.Result, error) { return sfc.Result{}, &sfc.Error{Code: sfc.CodeUnknown} }
	code, out := f.do("POST", "/api/v1/ops", map[string]any{"opId": opA, "action": "set-trust", "rootRevision": 1, "payload": map[string]any{"Tenant": "shop", "Remove": []any{map[string]any{"Registry": "docker.io", "Repository": "**"}}}})
	if code != 202 || out["op"].(map[string]any)["state"] != "unknown" {
		t.Fatalf("unknown submit: %d %v", code, out)
	}
	stored, _ := f.store.GetOp("u-alice", opA)
	if len(stored.Signed) == 0 || f.client.sent[0] != string(stored.Signed) {
		t.Fatal("the stored original must be the bytes that were sent")
	}
	// not found is not proof of non-execution: stays unknown
	code, out = f.do("POST", "/api/v1/ops/"+opA+"/result", nil)
	if code != 202 || out["op"].(map[string]any)["state"] != "unknown" {
		t.Fatalf("result not found: %d %v", code, out)
	}
	var got string
	f.client.result = func(op sfc.SignedOp) (sfc.Result, bool, error) {
		got = string(op)
		return sfc.Result{Code: sfc.ResultConditionFailed, Index: 8}, true, nil
	}
	code, out = f.do("POST", "/api/v1/ops/"+opA+"/result", nil)
	if code != 200 || out["op"].(map[string]any)["state"] != "failed" || got != string(stored.Signed) {
		t.Fatalf("result found: %d %v", code, out)
	}
	// a settled op cannot be resumed
	if code, _ := f.do("POST", "/api/v1/ops/"+opA+"/resume", nil); code != 409 {
		t.Fatalf("resume settled: %d", code)
	}
	code, out = f.do("GET", "/api/v1/ops?state=failed", nil)
	if code != 200 || len(out["items"].([]any)) != 1 {
		t.Fatalf("list failed ops: %d %v", code, out)
	}
	// another user's session cannot see it
	if o, err := f.store.GetOp("u-bob", opA); err == nil || o != nil {
		t.Fatal("ops are per user")
	}
}

func TestSubmitRejected(t *testing.T) {
	f := newFixture(t)
	f.login()
	f.client.submit = func(sfc.SignedOp) (sfc.Result, error) { return sfc.Result{}, &sfc.Error{Code: sfc.CodeDenied} }
	code, out := f.do("POST", "/api/v1/ops", map[string]any{"opId": opA, "action": "set-trust", "payload": map[string]any{"Tenant": "shop", "Remove": []any{map[string]any{"Registry": "docker.io", "Repository": "**"}}}})
	op := out["op"].(map[string]any)
	if code != 200 || op["state"] != "rejected" || op["errorCode"] != "denied" {
		t.Fatalf("rejected: %d %v", code, out)
	}
}

func TestClosedConnectionEndsSession(t *testing.T) {
	f := newFixture(t)
	f.login()
	f.client.conns[0].closed = true
	if code, out := f.do("GET", "/api/v1/t/shop/apps", nil); code != 401 || errCode(out) != "session-expired" {
		t.Fatalf("closed conn: %d %v", code, out)
	}
	if code, _ := f.do("GET", "/api/v1/auth/session", nil); code != 401 {
		t.Fatalf("session must be gone: %d", code)
	}
}

func TestDownArchivesFirst(t *testing.T) {
	f := newFixture(t)
	f.login()
	f.client.source = func() (sfc.AppSource, error) { return sfc.AppSource{}, &sfc.Error{Code: sfc.CodeUnavailable} }
	pl := map[string]any{"Tenant": "shop", "App": "web", "Operation": "op-1"}
	code, _ := f.do("POST", "/api/v1/t/shop/apps/web/down", map[string]any{"opId": opA, "expected": 4, "rootRevision": 2, "payload": pl})
	if code != 503 || len(f.client.sent) != 0 {
		t.Fatalf("down without source must not be sent: %d sent=%d", code, len(f.client.sent))
	}
	f.client.source = func() (sfc.AppSource, error) {
		return sfc.AppSource{Tenant: "shop", App: "web", Version: 4, Document: []byte("services: {}\n")}, nil
	}
	code, out := f.do("POST", "/api/v1/t/shop/apps/web/down", map[string]any{"opId": opB, "expected": 4, "rootRevision": 2, "volumes": []string{"db"}, "payload": pl})
	if code != 200 || out["op"].(map[string]any)["action"] != "down-app" {
		t.Fatalf("down: %d %v", code, out)
	}
	code, out = f.do("GET", "/api/v1/t/shop/archived", nil)
	items := out["items"].([]any)
	if code != 200 || len(items) != 1 {
		t.Fatalf("archived list: %d %v", code, out)
	}
	key := items[0].(map[string]any)["key"].(string)
	code, out = f.do("GET", "/api/v1/t/shop/archived/"+key, nil)
	if code != 200 || out["yaml"] != "services: {}\n" {
		t.Fatalf("archived get: %d %v", code, out)
	}
	if code, _ := f.do("GET", "/api/v1/t/other/archived", nil); code != 403 {
		t.Fatalf("archived of a tenant without access: %d", code)
	}
	if code, _ := f.do("POST", "/api/v1/t/shop/archived/"+key+"/purge", map[string]any{"confirm": "wrong"}); code != 400 {
		t.Fatalf("purge confirm: %d", code)
	}
	if code, _ := f.do("POST", "/api/v1/t/shop/archived/"+key+"/purge", map[string]any{"confirm": "web"}); code != 204 {
		t.Fatalf("purge: %d", code)
	}
}

func TestPurgeNeedsManager(t *testing.T) {
	f := newFixture(t)
	f.login()
	key, _ := f.store.PutArchived(&store.ArchivedApp{Tenant: "pay", App: "api", DownAt: time.Now()})
	if code, _ := f.do("GET", "/api/v1/t/pay/archived/"+archiveKeyOut(key), nil); code != 200 {
		t.Fatalf("viewer can read: %d", code)
	}
	if code, _ := f.do("POST", "/api/v1/t/pay/archived/"+archiveKeyOut(key)+"/purge", map[string]any{"confirm": "api"}); code != 403 {
		t.Fatalf("viewer cannot purge: %d", code)
	}
}

func TestStaticFallback(t *testing.T) {
	f := newFixture(t)
	get := func(p string) (int, string, http.Header) {
		resp, err := http.Get(f.http.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b), resp.Header
	}
	if code, body, h := get("/apps/shop/web"); code != 200 || body != "<html>app</html>" || h.Get("Cache-Control") != "no-cache" {
		t.Fatalf("spa fallback: %d %q %v", code, body, h)
	}
	if code, _, h := get("/assets/app-1a.js"); code != 200 || !strings.Contains(h.Get("Cache-Control"), "immutable") {
		t.Fatalf("asset: %d %v", code, h)
	}
	// a client route with a dot in it is not a file
	if code, body, _ := get("/system/domains/example.com"); code != 200 || body != "<html>app</html>" {
		t.Fatalf("dotted route: %d %q", code, body)
	}
	if code, _, _ := get("/assets/missing.js"); code != 404 {
		t.Fatalf("missing asset: %d", code)
	}
	if code, _, _ := get("/api/v1/nope"); code != 404 {
		t.Fatalf("unknown api: %d", code)
	}
}

func TestPrefs(t *testing.T) {
	f := newFixture(t)
	f.login()
	if code, _ := f.do("PUT", "/api/v1/prefs", map[string]any{"prefs": map[string]any{"tenant": "shop"}}); code != 204 {
		t.Fatalf("put prefs: %d", code)
	}
	code, out := f.do("GET", "/api/v1/prefs", nil)
	if code != 200 || out["prefs"].(map[string]any)["tenant"] != "shop" {
		t.Fatalf("get prefs: %d %v", code, out)
	}
}

var _ = errors.New

const opC = "8f1c2d3e-4b5a-4c6d-ae7f-0a1b2c3d4e5f"

func TestDownPayloadMustMatchURL(t *testing.T) {
	f := newFixture(t)
	f.login()
	for _, pl := range []any{
		nil,
		map[string]any{"Tenant": "shop", "App": "db", "Operation": "x"},
		map[string]any{"Tenant": "pay", "App": "web", "Operation": "x"},
		map[string]any{"Tenant": "shop", "App": "web", "Operation": "x", "Extra": 1},
	} {
		code, out := f.do("POST", "/api/v1/t/shop/apps/web/down", map[string]any{"opId": opA, "expected": 4, "payload": pl})
		if code != 400 || errCode(out) != "target-mismatch" {
			t.Fatalf("payload %v: %d %v", pl, code, out)
		}
	}
	if len(f.client.sent) != 0 {
		t.Fatal("a mismatched down must not be sent")
	}
	if rows, _ := f.store.ListArchived("shop"); len(rows) != 0 {
		t.Fatal("a mismatched down must not archive")
	}
}

func TestDownNotAppliedDropsArchive(t *testing.T) {
	f := newFixture(t)
	f.login()
	pl := map[string]any{"Tenant": "shop", "App": "web", "Operation": "x"}
	for i, res := range []func(sfc.SignedOp) (sfc.Result, error){
		func(sfc.SignedOp) (sfc.Result, error) { return sfc.Result{}, &sfc.Error{Code: sfc.CodeDenied} },
		func(sfc.SignedOp) (sfc.Result, error) { return sfc.Result{Code: sfc.ResultConditionFailed}, nil },
	} {
		f.client.submit = res
		id := []string{opA, opB}[i]
		code, out := f.do("POST", "/api/v1/t/shop/apps/web/down", map[string]any{"opId": id, "expected": 4, "payload": pl})
		if code != 200 {
			t.Fatalf("down %d: %d %v", i, code, out)
		}
		if rows, _ := f.store.ListArchived("shop"); len(rows) != 0 {
			t.Fatalf("down %d (%v): archive row left", i, out["op"])
		}
	}
	// unknown keeps the row until the result says it did not apply
	f.client.submit = func(sfc.SignedOp) (sfc.Result, error) { return sfc.Result{}, &sfc.Error{Code: sfc.CodeUnknown} }
	if code, _ := f.do("POST", "/api/v1/t/shop/apps/web/down", map[string]any{"opId": opC, "expected": 4, "payload": pl}); code != 202 {
		t.Fatalf("unknown down: %d", code)
	}
	if rows, _ := f.store.ListArchived("shop"); len(rows) != 1 {
		t.Fatal("unknown down must keep its archive row")
	}
	f.client.result = func(sfc.SignedOp) (sfc.Result, bool, error) {
		return sfc.Result{Code: sfc.ResultConditionFailed}, true, nil
	}
	if code, out := f.do("POST", "/api/v1/ops/"+opC+"/result", nil); code != 200 || out["op"].(map[string]any)["state"] != "failed" {
		t.Fatalf("settle: %d %v", code, out)
	}
	if rows, _ := f.store.ListArchived("shop"); len(rows) != 0 {
		t.Fatal("archive row of a down that failed on settle must be removed")
	}
}

// ops sent together as one change set share a batch the list filters by
func TestSubmitBatch(t *testing.T) {
	f := newFixture(t)
	f.login()
	const batch = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
	trust := map[string]any{"Tenant": "shop", "Remove": []any{map[string]any{"Registry": "docker.io", "Repository": "**"}}}
	for _, id := range []string{opA, opB} {
		if code, out := f.do("POST", "/api/v1/ops", map[string]any{"opId": id, "action": "set-trust", "payload": trust, "batch": batch}); code != 200 || out["op"].(map[string]any)["batch"] != batch {
			t.Fatalf("submit %s: %d %v", id, code, out)
		}
	}
	if code, _ := f.do("POST", "/api/v1/ops", map[string]any{"opId": opC, "action": "set-trust", "payload": trust}); code != 200 {
		t.Fatalf("unbatched: %d", code)
	}
	if code, out := f.do("GET", "/api/v1/ops?batch="+batch, nil); code != 200 || len(out["items"].([]any)) != 2 {
		t.Fatalf("batch list: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/ops", map[string]any{"opId": opA, "action": "set-trust", "payload": trust, "batch": "B"}); code != 400 {
		t.Fatalf("bad batch: %d %v", code, out)
	}
}
