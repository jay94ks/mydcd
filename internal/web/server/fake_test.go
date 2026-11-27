// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/web/sfc"
	"github.com/jay94ks/seafield/internal/web/store"
)

// Runs the HTTP layer against the fake adapter from internal/web/sfc. This
// is mock evidence only, not a real sfcd result.
// strictFake: the default fixture checking each command key's own root,
// as sfcd does.
func strictFake() *sfc.Fake {
	f := sfc.NewFake(sfc.DefaultFixture())
	f.StrictRoots(true)
	return f
}

func newFakeFixture(t *testing.T) (*fixture, *sfc.Fake) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	fake := strictFake()
	srv := New(Options{Client: fake, Store: st, Logger: discardLogger()})
	hs := httptest.NewServer(srv)
	t.Cleanup(hs.Close)
	jar, _ := cookiejar.New(nil)
	f := &fixture{t: t, store: st, srv: srv, http: hs}
	f.hc = hs.Client()
	f.hc.Jar = jar
	return f, fake
}

func TestFakePasswordLoginAndReads(t *testing.T) {
	f, _ := newFakeFixture(t)
	_, out := f.do("POST", "/api/v1/auth/credential/challenge", map[string]any{"username": "alice", "method": "password"})
	code, out := f.do("POST", "/api/v1/auth/credential/login", map[string]any{"ticketId": out["ticketId"], "secret": "alice"})
	if code != 200 {
		t.Fatalf("login: %d %v", code, out)
	}
	if out["user"].(map[string]any)["username"] != "alice" {
		t.Fatalf("session view: %v", out)
	}
	code, out = f.do("GET", "/api/v1/t/shop/apps", nil)
	if code != 200 || len(out["items"].([]any)) == 0 {
		t.Fatalf("apps: %d %v", code, out)
	}
	app := out["items"].([]any)[0].(map[string]any)["app"].(string)
	if code, out := f.do("GET", "/api/v1/t/shop/apps/"+app+"/source", nil); code != 200 || out["yaml"] == "" {
		t.Fatalf("source: %d %v", code, out)
	}
	// alice is not a system admin
	if code, out := f.do("GET", "/api/v1/nodes", nil); code != 403 {
		t.Fatalf("members as tenant user: %d %v", code, out)
	}
	if code, _ := f.do("GET", "/api/v1/dashboard?tenant=shop", nil); code != 200 {
		t.Fatalf("dashboard: %d", code)
	}
	code, out = f.do("GET", "/api/v1/me/credentials", nil)
	if code != 200 || out["username"] != "alice" || len(out["credentials"].([]any)) == 0 || out["accountRevision"] != out["revision"] || len(out["clusterId"].(string)) != 64 {
		t.Fatalf("own credentials: %d %v", code, out)
	}
	// credential rows are camelCase like every other view (access.Credential
	// has a MarshalJSON only for sfcd's stored bytes); keys are hex
	cred := out["credentials"].([]any)[0].(map[string]any)
	if cred["id"] != "password" || cred["method"] != "password" || cred["enabled"] != true || cred["ID"] != nil || cred["verifierRef"] != nil {
		t.Fatalf("own credential row: %v", cred)
	}
	fakeLogin(t, f, "admin")
	code, out = f.do("GET", "/api/v1/users/bob", nil)
	if code != 200 || out["accountRevision"] != out["revision"] {
		t.Fatalf("user record: %d %v", code, out)
	}
	for _, x := range out["credentials"].([]any) {
		c := x.(map[string]any)
		if c["method"] == "private-key" && (len(c["publicKey"].(string)) != 64 || c["id"] == nil) {
			t.Fatalf("key credential: %v", c)
		}
	}
	code, out = f.do("GET", "/api/v1/users", nil)
	if items, _ := out["items"].([]any); code != 200 || len(items) == 0 || items[0].(map[string]any)["accountRevision"] == nil {
		t.Fatalf("users: %d %v", code, out)
	}
}

func TestFakeKeyLogin(t *testing.T) {
	f, _ := newFakeFixture(t)
	priv := sfc.FixtureKey("bob")
	pub := priv.Public().(ed25519.PublicKey)
	code, out := f.do("POST", "/api/v1/auth/key/challenge", map[string]any{"username": "bob", "publicKey": hex.EncodeToString(pub)})
	if code != 200 {
		t.Fatalf("challenge: %d %v", code, out)
	}
	proof, _ := base64.StdEncoding.DecodeString(out["proof"].(string))
	// what the browser does with WebCrypto
	sig := ed25519.Sign(priv, proof)
	code, out = f.do("POST", "/api/v1/auth/key/login", map[string]any{"ticketId": out["ticketId"], "signature": hex.EncodeToString(sig)})
	if code != 200 || out["approve"] != true {
		t.Fatalf("key login: %d %v", code, out)
	}
	approval, _ := base64.StdEncoding.DecodeString(out["approval"].(string))
	// an approval signed by another key is denied and the login ends
	other := ed25519.NewKeyFromSeed(make([]byte, 32))
	if code, _ := f.do("POST", "/api/v1/auth/key/approve", map[string]any{"ticketId": out["ticketId"], "signature": hex.EncodeToString(ed25519.Sign(other, approval))}); code != 403 {
		t.Fatalf("approval by another key: %d", code)
	}
	if code, out := keyLogin(f, "bob", priv); code != 200 || out["user"].(map[string]any)["username"] != "bob" || out["method"] != "key" {
		t.Fatalf("key login: %d %v", code, out)
	}
	// a wrong key is denied
	_, out = f.do("POST", "/api/v1/auth/key/challenge", map[string]any{"username": "bob", "publicKey": hex.EncodeToString(pub)})
	proof, _ = base64.StdEncoding.DecodeString(out["proof"].(string))
	if code, _ := f.do("POST", "/api/v1/auth/key/login", map[string]any{"ticketId": out["ticketId"], "signature": hex.EncodeToString(ed25519.Sign(other, proof))}); code != 403 {
		t.Fatalf("wrong key: %d", code)
	}
}

func TestFakeLostReplySettledByResult(t *testing.T) {
	f, fake := newFakeFixture(t)
	_, out := f.do("POST", "/api/v1/auth/credential/challenge", map[string]any{"username": "admin", "method": "password"})
	f.do("POST", "/api/v1/auth/credential/login", map[string]any{"ticketId": out["ticketId"], "secret": "admin"})
	_, out = f.do("GET", "/api/v1/auth/session", nil)
	uid := out["user"].(map[string]any)["id"].(string)
	fake.LoseNextReply("submit", true)
	body := map[string]any{"opId": opA, "action": sfc.ActionCreateTenant, "principal": uid, "expected": 0,
		"payload": map[string]any{"ID": "lab"}, "rootRevision": fake.RootRevision()}
	code, out := f.do("POST", "/api/v1/ops", body)
	if code != 202 || out["op"].(map[string]any)["state"] != "unknown" {
		t.Fatalf("lost reply: %d %v", code, out)
	}
	code, out = f.do("POST", "/api/v1/ops/"+opA+"/result", nil)
	st := out["op"].(map[string]any)["state"]
	if code != 200 || (st != "applied" && st != "failed") {
		t.Fatalf("result after lost reply: %d %v", code, out)
	}
	// the journal holds one create-tenant only: no new ID was used
	n := 0
	for _, j := range fake.Journal() {
		if j.Action == sfc.ActionCreateTenant {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("create-tenant entries in journal: %d", n)
	}
}

func TestFakeDeployJob(t *testing.T) {
	f, fake := newFakeFixture(t)
	_, out := f.do("POST", "/api/v1/auth/credential/challenge", map[string]any{"username": "alice", "method": "password"})
	f.do("POST", "/api/v1/auth/credential/login", map[string]any{"ticketId": out["ticketId"], "secret": "alice"})
	_, out = f.do("GET", "/api/v1/t/shop/apps", nil)
	app := out["items"].([]any)[0].(map[string]any)["app"].(string)
	_, out = f.do("GET", "/api/v1/t/shop/apps/"+app+"/source", nil)
	doc := out["yaml"].(string)
	// a big document needs several parts
	big := doc + "\n# " + strings.Repeat("x", 2*sfc.AppPartBytes) + "\n"

	fake.LoseNextReply("submit", true) // first step's reply is lost
	code, out := f.do("POST", "/api/v1/t/shop/apps/deploy", map[string]any{"opId": opA, "yaml": big})
	op := out["op"].(map[string]any)
	if code != 202 || op["state"] != "unknown" || op["action"] != "deploy" {
		t.Fatalf("deploy with lost reply: %d %v", code, out)
	}
	// the step is settled by result of the same original
	step := opA + ".0"
	if code, out := f.do("POST", "/api/v1/ops/"+step+"/result", nil); code != 200 || out["op"].(map[string]any)["state"] != "applied" {
		t.Fatalf("settle step: %d %v", code, out)
	}
	// sending the same opId continues the job
	code, out = f.do("POST", "/api/v1/t/shop/apps/deploy", map[string]any{"opId": opA, "yaml": big})
	op = out["op"].(map[string]any)
	if code != 200 || op["state"] != "applied" || op["step"].(float64) != op["steps"].(float64) {
		t.Fatalf("deploy continue: %d %v", code, out)
	}
	_, out = f.do("GET", "/api/v1/t/shop/apps/"+app+"/source", nil)
	if out["yaml"] != big {
		t.Fatal("deployed document differs")
	}
	// the job list hides step rows unless asked
	_, out = f.do("GET", "/api/v1/ops", nil)
	if n := len(out["items"].([]any)); n != 1 {
		t.Fatalf("ops list: %d items", n)
	}
	_, out = f.do("GET", "/api/v1/ops?children=1", nil)
	if n := len(out["items"].([]any)); n < 4 {
		t.Fatalf("ops list with steps: %d items", n)
	}
	// different yaml under the same opId
	if code, _ := f.do("POST", "/api/v1/t/shop/apps/deploy", map[string]any{"opId": opA, "yaml": doc}); code != 409 {
		t.Fatalf("conflict: %d", code)
	}
}

// R03: sfcd closing an idle connection is not a logout. The next request
// redials and uses the same session; no keepalive is sent meanwhile.
func TestFakeIdleDisconnectKeepsSession(t *testing.T) {
	f, fake := newFakeFixture(t)
	var mu sync.Mutex
	now := time.Now()
	fake.SetClock(func() time.Time { mu.Lock(); defer mu.Unlock(); return now })
	fakeLogin(t, f, "alice")
	if code, _ := f.do("GET", "/api/v1/auth/session", nil); code != 200 {
		t.Fatalf("session: %d", code)
	}
	mu.Lock()
	now = now.Add(45 * time.Second)
	mu.Unlock()
	code, out := f.do("GET", "/api/v1/auth/session", nil)
	if code != 200 || out["user"].(map[string]any)["username"] != "alice" {
		t.Fatalf("after idle disconnect: %d %v", code, out)
	}
	var ws *webSession
	f.srv.sessions.mu.Lock()
	for _, x := range f.srv.sessions.live {
		ws = x
	}
	f.srv.sessions.mu.Unlock()
	if ws == nil || sfc.Reconnects(ws.conn) != 1 {
		t.Fatalf("reconnects: %v", ws)
	}

	// a pending ticket is bound to the old connection: login after an idle
	// disconnection is refused and starts over
	code, ch := f.do("POST", "/api/v1/auth/credential/challenge", map[string]any{"username": "alice", "method": "password"})
	if code != 200 {
		t.Fatalf("challenge: %d %v", code, ch)
	}
	mu.Lock()
	now = now.Add(45 * time.Second)
	mu.Unlock()
	if code, out := f.do("POST", "/api/v1/auth/credential/login", map[string]any{"ticketId": ch["ticketId"], "secret": "alice"}); code != 403 {
		t.Fatalf("stale ticket login: %d %v", code, out)
	}
}
