// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
)

// These tests are written against the Client/Conn contract. They run on the
// Fake now; the real adapter should pass the same scenarios (with a matching
// seeded cluster) before a method is marked real-integrated.

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *testClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newTestFake(t *testing.T) (*Fake, *testClock) {
	t.Helper()
	f := NewFake(DefaultFixture())
	clk := &testClock{t: time.Unix(fixtureNow, 0)}
	f.SetClock(clk.now)
	return f, clk
}

var ctx = context.Background()

func passwordLogin(t *testing.T, c Client, user, pass string) Conn {
	t.Helper()
	conn, err := c.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tk, err := conn.CredentialChallenge(ctx, user, MethodPassword, "")
	if err != nil {
		t.Fatalf("challenge %s: %v", user, err)
	}
	if _, err := conn.CredentialLogin(ctx, tk, []byte(pass)); err != nil {
		t.Fatalf("login %s: %v", user, err)
	}
	return conn
}

func keyLogin(t *testing.T, c Client, user string, key ed25519.PrivateKey) (Conn, error) {
	t.Helper()
	conn, err := c.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tk, err := conn.Challenge(ctx, user, pub32(key))
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(tk.Issuer[:], TicketSigningBytes(tk), tk.Signature) {
		t.Fatal("ticket issuer signature does not verify")
	}
	p := NewKeyProof(tk)
	p.Signature = ed25519.Sign(key, KeyProofSigningBytes(p))
	if _, err := conn.Login(ctx, tk, p); err != nil {
		return nil, err
	}
	return conn, nil
}

func wantCode(t *testing.T, err error, code Code) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || e.Code != code {
		t.Fatalf("want %s, got %v", code, err)
	}
	if !errors.Is(err, &Error{Code: code}) {
		t.Fatalf("errors.Is(%v, %s) is false", err, code)
	}
}

func mustPayload(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// submit signs with root; a root equal to the current catalog root
// (root(t, c)) means "current" and is replaced by Whoami.RootFor(action).
func submit(t *testing.T, c Conn, action string, expected uint64, payload any, root uint64) (SignedOp, Result) {
	t.Helper()
	if w, err := c.Whoami(ctx); err == nil && root == w.RootRevision {
		root = w.RootFor(action)
	}
	op, err := c.Prepare(ctx, Change{Action: action, Expected: expected, Payload: mustPayload(t, payload)}, root)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Submit(ctx, op)
	if err != nil {
		t.Fatalf("submit %s: %v", action, err)
	}
	return op, res
}

// rootFor: the root to sign action with now.
func rootFor(t *testing.T, c Conn, action string) uint64 {
	t.Helper()
	w, err := c.Whoami(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return w.RootFor(action)
}

func root(t *testing.T, c Conn) uint64 {
	t.Helper()
	w, err := c.Whoami(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return w.RootRevision
}

func TestPasswordLoginAndScopes(t *testing.T) {
	f, _ := newTestFake(t)
	alice := passwordLogin(t, f, "alice", "alice")
	w, err := alice.Whoami(ctx)
	if err != nil || w.User.Username != "alice" || w.User.SystemAdmin {
		t.Fatalf("whoami %+v %v", w, err)
	}
	tenants, err := alice.Tenants(ctx)
	if err != nil || len(tenants) != 2 || tenants[0].ID != "payments" || tenants[0].Role != RoleViewer || tenants[1].Role != RoleManager {
		t.Fatalf("tenants %+v %v", tenants, err)
	}
	s, ok := alice.Session()
	if !ok || s.ExpiresAt-s.IssuedAt != 3600 {
		t.Fatalf("session %+v", s)
	}

	// A wrong password of another user does not affect alice.
	other, _ := f.Dial(ctx)
	tk, err := other.CredentialChallenge(ctx, "admin", MethodPassword, "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = other.CredentialLogin(ctx, tk, []byte("wrong"))
	wantCode(t, err, CodeDenied)
	if _, err := alice.Apps(ctx, "shop", ""); err != nil {
		t.Fatal(err)
	}
	// The ticket is single-use on its connection.
	_, err = other.CredentialLogin(ctx, tk, []byte("admin"))
	wantCode(t, err, CodeDenied)
	// bob has no password credential.
	_, err = other.CredentialChallenge(ctx, "bob", MethodPassword, "")
	wantCode(t, err, CodeDenied)
}

func TestPrivateKeyLogin(t *testing.T) {
	f, _ := newTestFake(t)
	bob, err := keyLogin(t, f, "bob", FixtureKey("bob"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.Apps(ctx, "shop", ""); err != nil {
		t.Fatal(err)
	}
	_, err = keyLogin(t, f, "bob", FixtureKey("mallory"))
	wantCode(t, err, CodeDenied)

	// A proof signed by the wrong key is denied.
	conn, _ := f.Dial(ctx)
	tk, err := conn.Challenge(ctx, "bob", pub32(FixtureKey("bob")))
	if err != nil {
		t.Fatal(err)
	}
	p := NewKeyProof(tk)
	p.Signature = ed25519.Sign(FixtureKey("mallory"), KeyProofSigningBytes(p))
	_, err = conn.Login(ctx, tk, p)
	wantCode(t, err, CodeDenied)
}

func TestTenantIsolationAndAdminMethods(t *testing.T) {
	f, _ := newTestFake(t)
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))
	alice := passwordLogin(t, f, "alice", "alice")
	admin := passwordLogin(t, f, "admin", "admin")

	_, err := bob.Apps(ctx, "payments", "")
	wantCode(t, err, CodeDenied)
	_, err = bob.Tasks(ctx, TaskFilter{Tenant: "payments"}, "")
	wantCode(t, err, CodeDenied)
	_, err = bob.Vault(ctx, "shop", "") // viewer: no ManageSecrets
	wantCode(t, err, CodeDenied)
	if _, err := alice.Vault(ctx, "shop", ""); err != nil {
		t.Fatal(err)
	}
	_, err = alice.Members(ctx, "")
	wantCode(t, err, CodeDenied)
	_, err = alice.RaftStatus(ctx)
	wantCode(t, err, CodeDenied)
	_, err = alice.Users(ctx, "")
	wantCode(t, err, CodeDenied)

	mp, err := admin.Members(ctx, "")
	if err != nil || len(mp.Entries) != 4 || len(mp.Nodes) != 3 || mp.NodeVoters != 3 || mp.NodeQuorum != 2 {
		t.Fatalf("members %+v %v", mp, err)
	}
	users, err := admin.Users(ctx, "")
	if err != nil || len(users.Items) != 3 {
		t.Fatalf("users %+v %v", users, err)
	}
	members, err := alice.TenantMembers(ctx, "shop", "")
	if err != nil || len(members.Items) != 2 {
		t.Fatalf("tenant members %+v %v", members, err)
	}
	_, err = alice.TenantMembers(ctx, "payments", "")
	wantCode(t, err, CodeDenied)
}

func TestNodeSummaryScope(t *testing.T) {
	f, _ := newTestFake(t)
	alice := passwordLogin(t, f, "alice", "alice")
	admin := passwordLogin(t, f, "admin", "admin")

	got, err := alice.NodeSummary(ctx, "payments", "", "")
	if err != nil || len(got.Nodes) != 2 {
		t.Fatalf("summary %+v %v", got, err)
	}
	for _, s := range got.Nodes {
		if s.Node != "node-a" && s.Node != "node-c" {
			t.Fatalf("payments sees %s", s.Node)
		}
		want := map[string]uint64{"node-a": 0, "node-c": 2}[s.Node]
		if s.Admin != nil || s.Usage == nil || s.Usage.Tenant != "payments" || *s.Usage.Containers != want {
			t.Fatalf("%s usage %+v want %d containers (only payments tasks)", s.Node, s.Usage, want)
		}
	}
	_, err = alice.NodeSummary(ctx, "", "", "")
	wantCode(t, err, CodeDenied)
	all, err := admin.NodeSummary(ctx, "", "", "")
	if err != nil || len(all.Nodes) != 4 || all.Nodes[0].Admin == nil || all.Nodes[0].Admin.Host == nil || all.Nodes[0].Admin.Role != "leader" {
		t.Fatalf("admin summary %+v %v", all, err)
	}
}

func TestPagination(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetPageSize(1)
	alice := passwordLogin(t, f, "alice", "alice")
	p1, err := alice.Apps(ctx, "shop", "")
	if err != nil || len(p1.Items) != 1 || p1.Next == "" {
		t.Fatalf("page1 %+v %v", p1, err)
	}
	p2, err := alice.Apps(ctx, "shop", p1.Next)
	if err != nil || len(p2.Items) != 1 || p2.Next != "" || p2.Items[0].App == p1.Items[0].App {
		t.Fatalf("page2 %+v %v", p2, err)
	}
}

func uploadApp(t *testing.T, c Conn, tenant, app, id string, doc []byte) {
	t.Helper()
	_, res := submit(t, c, ActionBeginAppUpload, 0, control.AppUploadBegin{Tenant: tenant, App: app, Deployment: "dep-" + app, ID: id, Length: len(doc), Digest: sha256.Sum256(doc)}, 0)
	if res.Code != ResultApplied {
		t.Fatalf("begin upload %+v", res)
	}
	rev := uint64(1)
	for i := 0; i*AppPartBytes < len(doc); i++ {
		part := doc[i*AppPartBytes : min(len(doc), (i+1)*AppPartBytes)]
		_, res := submit(t, c, ActionPutAppPart, rev, control.AppUploadPart{Tenant: tenant, ID: id, Index: i, Data: part}, 0)
		if res.Code != ResultApplied {
			t.Fatalf("part %d %+v", i, res)
		}
		rev++
	}
}

func TestDeployNewVersion(t *testing.T) {
	f, _ := newTestFake(t)
	alice := passwordLogin(t, f, "alice", "alice")
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))

	doc := []byte(strings.Replace(phpShopYAML, "php-shop:1.4.2", "php-shop:1.5.0", 1))
	plan, err := alice.AppPlan(ctx, AppPlanRequest{Tenant: "shop", Document: doc, Diff: true})
	if err != nil {
		t.Fatal(err)
	}
	changes := map[string]string{}
	for _, s := range plan.Services {
		changes[s.Name] = s.Change
	}
	if changes["web"] != "update" || changes["db"] != "keep" || !strings.Contains(plan.Diff, "+    image: registry.mydc.local/shop/php-shop:1.5.0") {
		t.Fatalf("plan %+v", plan)
	}
	_, err = bob.AppPlan(ctx, AppPlanRequest{Tenant: "shop", Document: doc})
	wantCode(t, err, CodeDenied)
	_, err = alice.AppPlan(ctx, AppPlanRequest{Tenant: "shop", Document: []byte(strings.Replace(phpShopYAML, "node-b", "node-c", 1))})
	var pe *Error
	if !errors.As(err, &pe) || pe.Code != CodeInvalid || pe.InputCode != "NODE_NOT_ALLOWED" {
		t.Fatalf("plan error %v", err)
	}

	uploadApp(t, alice, "shop", "php-shop", "up-1", doc)
	apps, _ := alice.Apps(ctx, "shop", "")
	var cur AppView
	for _, a := range apps.Items {
		if a.App == "php-shop" {
			cur = a
		}
	}
	_, res := submit(t, alice, ActionBeginApp, cur.Revision, control.AppBegin{Tenant: "shop", App: "php-shop", Deployment: cur.Deployment, Upload: "up-1", Operation: "deploy-1"}, rootFor(t, alice, ActionBeginApp))
	if res.Code != ResultApplied {
		t.Fatalf("begin-app %+v", res)
	}
	src, err := bob.AppSource(ctx, "shop", "php-shop", 0)
	if err != nil || src.Version != 2 || string(src.Document) != string(doc) {
		t.Fatalf("source %+v %v", src, err)
	}
	old, err := bob.AppSource(ctx, "shop", "php-shop", 1)
	if err != nil || string(old.Document) != phpShopYAML {
		t.Fatalf("old source %v", err)
	}
	revs, _ := bob.AppRevisions(ctx, "shop", "php-shop", "")
	if len(revs.Items) != 2 || revs.Items[1].Operation != "deploy-1" {
		t.Fatalf("revisions %+v", revs)
	}
	tasks, _ := bob.Tasks(ctx, TaskFilter{Tenant: "shop", App: "php-shop"}, "")
	for _, task := range tasks.Items {
		if task.Service == "web" && (task.Image != "registry.mydc.local/shop/php-shop:1.5.0" || task.Generation != 2) {
			t.Fatalf("task %+v", task)
		}
	}
	op, err := bob.AppOperation(ctx, "shop", "php-shop", "deploy-1")
	if err != nil || op.Status != "succeeded" || op.Submitter != "alice" {
		t.Fatalf("app op %+v %v", op, err)
	}
	if _, err := bob.ContainerObserve(ctx, "shop", ContainerQuery{Selection: ContainerSelection{App: "php-shop", Service: "web"}, Kind: "logs", Tail: 5}); err != nil {
		t.Fatal(err)
	}

	// Viewer cannot deploy.
	_, res = submit(t, bob, ActionDownApp, cur.Revision, control.AppDown{Tenant: "shop", App: "php-shop", Operation: "down-1"}, rootFor(t, bob, ActionDownApp))
	if res.Code != ResultForbidden {
		t.Fatalf("viewer down %+v", res)
	}
}

func TestDownApp(t *testing.T) {
	f, _ := newTestFake(t)
	alice := passwordLogin(t, f, "alice", "alice")
	apps, _ := alice.Apps(ctx, "shop", "")
	cur := apps.Items[0]
	_, res := submit(t, alice, ActionDownApp, cur.Revision, control.AppDown{Tenant: "shop", App: cur.App, Operation: "down-1"}, rootFor(t, alice, ActionDownApp))
	if res.Code != ResultApplied {
		t.Fatalf("down %+v", res)
	}
	tasks, _ := alice.Tasks(ctx, TaskFilter{Tenant: "shop", App: cur.App}, "")
	if len(tasks.Items) != 0 {
		t.Fatalf("tasks after down %+v", tasks)
	}
	_, err := alice.AppSource(ctx, "shop", cur.App, 0)
	wantCode(t, err, CodeMissing)
	if _, err := alice.AppSource(ctx, "shop", cur.App, 1); err != nil {
		t.Fatal("down app keeps its history", err)
	}
}

func TestCASAndOriginalResults(t *testing.T) {
	f, _ := newTestFake(t)
	admin := passwordLogin(t, f, "admin", "admin")
	r := root(t, admin)

	op, res := submit(t, admin, ActionCreateTenant, 0, control.TenantID{ID: "analytics"}, r)
	if res.Code != ResultApplied || res.Revision != r+1 {
		t.Fatalf("create %+v", res)
	}
	// Same original again → same durable result.
	again, err := admin.Submit(ctx, op)
	if err != nil || again != res {
		t.Fatalf("resubmit %+v %v", again, err)
	}
	got, found, err := admin.Result(ctx, op)
	if err != nil || !found || got != res {
		t.Fatalf("result %+v %v %v", got, found, err)
	}
	// Stale root → condition failed.
	_, res = submit(t, admin, ActionCreateTenant, 0, control.TenantID{ID: "other"}, r)
	if res.Code != ResultConditionFailed {
		t.Fatalf("stale root %+v", res)
	}
	// Tampered original is rejected.
	bad := []byte(strings.Replace(string(op), "analytics", "analytica", 1))
	_, err = admin.Submit(ctx, bad)
	wantCode(t, err, CodeInvalid)
	if id, err := OperationID(op); err != nil || !strings.HasPrefix(id, "web-") {
		t.Fatalf("operation id %q %v", id, err)
	}
	// Old originals expire for submit but stay readable.
	f.SetIdleTimeout(0)
	clkOp, _ := admin.Prepare(ctx, Change{Action: ActionCreateTenant, Payload: mustPayload(t, control.TenantID{ID: "late"})}, rootFor(t, admin, ActionCreateTenant))
	f.SetClock(func() time.Time { return time.Unix(fixtureNow+301, 0) })
	_, err = admin.Submit(ctx, clkOp)
	wantCode(t, err, CodeExpired)
}

func TestUnknownReplyThenResume(t *testing.T) {
	f, _ := newTestFake(t)
	admin := passwordLogin(t, f, "admin", "admin")

	// Lost after commit: result is found and applied.
	f.LoseNextReply("submit", true)
	op, err := admin.Prepare(ctx, Change{Action: ActionCreateTenant, Payload: mustPayload(t, control.TenantID{ID: "t1"})}, rootFor(t, admin, ActionCreateTenant))
	if err != nil {
		t.Fatal(err)
	}
	_, err = admin.Submit(ctx, op)
	if !errors.Is(err, ErrUnknown) {
		t.Fatalf("want unknown, got %v", err)
	}
	res, found, err := admin.Result(ctx, op)
	if err != nil || !found || res.Code != ResultApplied {
		t.Fatalf("result after lost reply %+v %v %v", res, found, err)
	}

	// Lost before commit: not found, resume applies the same original.
	f.LoseNextReply("submit", false)
	op2, _ := admin.Prepare(ctx, Change{Action: ActionCreateTenant, Payload: mustPayload(t, control.TenantID{ID: "t2"})}, rootFor(t, admin, ActionCreateTenant))
	_, err = admin.Submit(ctx, op2)
	wantCode(t, err, CodeUnknown)
	if _, found, _ := admin.Result(ctx, op2); found {
		t.Fatal("not committed yet")
	}
	res, found, err = admin.Resume(ctx, op2)
	if err != nil || !found || res.Code != ResultApplied {
		t.Fatalf("resume %+v %v %v", res, found, err)
	}
	tenants, _ := admin.Tenants(ctx)
	if len(tenants) != 4 {
		t.Fatalf("tenants %+v", tenants)
	}
}

func TestConnectionFailures(t *testing.T) {
	f, clk := newTestFake(t)
	alice := passwordLogin(t, f, "alice", "alice")

	f.FailNext("apps", CodeNotLeader)
	_, err := alice.Apps(ctx, "shop", "")
	if !errors.Is(err, ErrNotLeader) {
		t.Fatalf("injected %v", err)
	}
	f.SetQuorum(false)
	_, err = alice.Apps(ctx, "shop", "")
	wantCode(t, err, CodeUnavailable)
	f.SetQuorum(true)

	// R03: an idle disconnection redials and keeps the session
	clk.add(31 * time.Second)
	if _, err = alice.Apps(ctx, "shop", ""); err != nil || Reconnects(alice) != 1 {
		t.Fatalf("after idle disconnect: %v %d", err, Reconnects(alice))
	}
	if _, ok := alice.Session(); !ok {
		t.Fatal("idle disconnection keeps the session")
	}
	// a closed Conn is gone
	closed := passwordLogin(t, f, "alice", "alice")
	closed.Close()
	_, err = closed.Apps(ctx, "shop", "")
	wantCode(t, err, CodeClosed)
	if _, ok := closed.Session(); ok {
		t.Fatal("closed connection keeps no session")
	}

	f.SetSessionIssuer(false)
	conn, _ := f.Dial(ctx)
	_, err = conn.CredentialChallenge(ctx, "alice", MethodPassword, "")
	wantCode(t, err, CodeNotSessionIssuer)
	f.SetSessionIssuer(true)

	f.SetIdleTimeout(0)
	alice = passwordLogin(t, f, "alice", "alice")
	clk.add(3601 * time.Second)
	_, err = alice.Apps(ctx, "shop", "")
	wantCode(t, err, CodeSessionExpired)
}

func TestRevokeSession(t *testing.T) {
	f, _ := newTestFake(t)
	alice := passwordLogin(t, f, "alice", "alice")
	s, _ := alice.Session()
	_, res := submit(t, alice, ActionRevokeSession, 0, control.SessionRevocation{User: s.User, Session: s.ID}, rootFor(t, alice, ActionRevokeSession))
	if res.Code != ResultApplied {
		t.Fatalf("revoke %+v", res)
	}
	_, err := alice.Apps(ctx, "shop", "")
	wantCode(t, err, CodeDenied)
}

func TestOwnBrowserKey(t *testing.T) {
	f, _ := newTestFake(t)
	alice := passwordLogin(t, f, "alice", "alice")
	w, _ := alice.Whoami(ctx)
	key := FixtureKey("alice-browser")
	_, res := submit(t, alice, ActionAddCredential, w.User.Revision,
		CredentialAdd{User: w.User.ID, Credential: Credential{ID: "browser-1", Method: MethodPrivateKey, PublicKey: pub32(key)}}, w.RootRevision)
	if res.Code != ResultApplied {
		t.Fatalf("add key %+v", res)
	}
	byKey, err := keyLogin(t, f, "alice", key)
	if err != nil {
		t.Fatal(err)
	}
	w, _ = byKey.Whoami(ctx)
	own, err := byKey.OwnCredentials(ctx)
	if err != nil || len(own.Credentials) != 2 || own.Revision != w.User.Revision {
		t.Fatalf("own credentials %+v %v", own, err)
	}
	// Another user's credential cannot be changed with the own action.
	_, res = submit(t, byKey, ActionDisableCredential, w.User.Revision, CredentialDisable{User: "u-bob", ID: "key-1"}, w.RootRevision)
	if res.Code != ResultInvalid {
		t.Fatalf("other user %+v", res)
	}
	_, res = submit(t, byKey, ActionDisableCredential, w.User.Revision, CredentialDisable{User: w.User.ID, ID: "browser-1"}, w.RootRevision)
	if res.Code != ResultApplied {
		t.Fatalf("disable key %+v", res)
	}
	_, err = keyLogin(t, f, "alice", key)
	wantCode(t, err, CodeDenied)

	// The last enabled credential cannot be disabled.
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))
	w, _ = bob.Whoami(ctx)
	_, res = submit(t, bob, ActionDisableCredential, w.User.Revision, CredentialDisable{User: w.User.ID, ID: "key-1"}, w.RootRevision)
	if res.Code != ResultInvalid {
		t.Fatalf("last credential %+v", res)
	}
}

func TestEvents(t *testing.T) {
	f, _ := newTestFake(t)
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))
	admin := passwordLogin(t, f, "admin", "admin")

	all, err := seedEvents(admin, "", "")
	if err != nil || len(all.Items) != 5 {
		t.Fatalf("events %+v %v", all, err)
	}
	shop, err := seedEvents(bob, "shop", "")
	if err != nil || len(shop.Items) != 3 {
		t.Fatalf("shop events %+v %v", shop, err)
	}
	_, err = seedEvents(bob, "", "")
	wantCode(t, err, CodeDenied)
	// The real page: Limit, More and a resume Cursor; rows are eventlog
	// items (Unix ms).
	p1, err := admin.Events(ctx, EventQuery{Limit: 2})
	if err != nil || len(p1.Items) != 2 || !p1.More || p1.Cursor != p1.Items[1].Cursor || p1.Items[0].At == 0 || p1.Items[0].At%1000 != 0 || p1.Schema != 1 {
		t.Fatalf("page %+v %v", p1, err)
	}
	if p2, err := admin.Events(ctx, EventQuery{After: p1.Cursor, Limit: 100}); err != nil || len(p2.Items) != 3 || p2.More {
		t.Fatalf("rest %+v %v", p2, err)
	}

	last := all.Items[len(all.Items)-1].Cursor
	c := f.AddEvent(FixtureEvent{Scope: "app", Tenant: "shop", App: "php-shop", Kind: "probe-failed", Target: "shop/php-shop/web/1"})
	next, _ := seedEvents(bob, "shop", last)
	if len(next.Items) != 1 || next.Items[0].Cursor != c {
		t.Fatalf("since %+v", next)
	}
	f.TrimEvents(c)
	_, err = seedEvents(bob, "shop", shop.Items[0].Cursor)
	wantCode(t, err, CodeCursorExpired)
}

func TestSignedOpIsRealUserOperation(t *testing.T) {
	f, _ := newTestFake(t)
	alice := passwordLogin(t, f, "alice", "alice")
	op, err := alice.Prepare(ctx, Change{Action: ActionDownApp, Expected: 7, Payload: mustPayload(t, control.AppDown{Tenant: "shop", App: "php-shop", Operation: "x"})}, 9)
	if err != nil {
		t.Fatal(err)
	}
	u, err := DecodeOperation(op)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := alice.Session()
	if u.Session.ID != s.ID || u.RootRevision != 9 || u.Change.Principal != s.User ||
		!ed25519.Verify(s.Key[:], control.OperationBytes(u), u.Signature) {
		t.Fatalf("operation %+v", u)
	}
}

// Each command key has its own root (fake_roots.go): an apps change moves
// control/apps only, so a vault action still signs with the vault root, and
// signing an apps action with the catalog root is refused once strict.
func TestCommandKeyRoots(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	before, _ := alice.Whoami(ctx)
	if len(before.Roots) == 0 || before.RootFor(ActionRestartTask) != before.Roots[control.AppsKey] || before.RootFor(ActionCreateTenant) != before.Roots[control.CatalogKey] {
		t.Fatalf("roots %+v", before.Roots)
	}
	restart := func(root uint64, op string) ResultCode {
		t.Helper()
		rs, rev := restartChange(t, alice, "shop", ContainerSelection{App: "shop-worker", Service: "worker", Instance: "1"}, op)
		ch := Change{Action: ActionRestartTask, Expected: rev, Payload: mustPayload(t, rs)}
		signed, err := alice.Prepare(ctx, ch, root)
		if err != nil {
			t.Fatal(err)
		}
		res, err := alice.Submit(ctx, signed)
		if err != nil {
			t.Fatal(err)
		}
		return res.Code
	}
	if code := restart(before.Roots[control.AppsKey], "r-1"); code != ResultApplied {
		t.Fatalf("restart with the apps root: %v", code)
	}
	after, _ := alice.Whoami(ctx)
	if after.Roots[control.AppsKey] == before.Roots[control.AppsKey] || after.Roots[control.VaultKey] != before.Roots[control.VaultKey] || after.RootRevision != before.RootRevision {
		t.Fatalf("roots after an apps change %+v → %+v", before.Roots, after.Roots)
	}
	if code := restart(after.RootRevision, "r-2"); code != ResultConditionFailed {
		t.Fatalf("apps action with the catalog root: %v", code)
	}
	f.StrictRoots(false) // lenient: the global root is accepted too
	lenient, _ := alice.Whoami(ctx)
	if code := restart(lenient.RootRevision, "r-3"); code != ResultApplied {
		t.Fatalf("lenient global root: %v", code)
	}
}

// fc: the fake behind a Conn, for the fake-only readers PublicRead builds on.
func fc(c Conn) *fakeConn { return c.(*fakeConn) }
