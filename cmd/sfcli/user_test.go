// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
)

func TestRealUserPrivateKeyCLIProfileSessionAndCurrentAuthority(t *testing.T) {
	// This scenario performs repeated real encrypted-wallet logins, a snapshot
	// and same-DB restart, lost-reply recovery and credential rotation. Keep a
	// finite scenario budget separate from unchanged CLI/RPC request deadlines.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	root, home := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	invoke, loadCredentials := fixtureWallet(t, home)
	makeKey := func(name string) *identity.Identity {
		t.Helper()
		id, err := identity.Create(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	admin, alice := makeKey("admin"), makeKey("alice")
	otherKey := makeKey("other")
	fixture := newManagedNode(t, ctx, root, "node", admin)
	runtime, address, clusterID, node := fixture.Runtime, fixture.Address, fixture.Cluster, fixture.Node()
	wait := func() {
		t.Helper()
		for {
			if runtime.Engine().IsLeader() {
				if _, err := runtime.Engine().Read(ctx, true); err == nil {
					return
				}
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	wait()
	readView := func() cluster.View {
		t.Helper()
		view, err := runtime.Engine().Read(ctx, true)
		if err != nil {
			t.Fatal("read original committed state", err)
		}
		return view
	}
	catalog := fixture.Catalog
	sequence := 0
	change := func(action, principal string, expected uint64, payload any) {
		t.Helper()
		sequence++
		if result := fixture.Change(fmt.Sprintf("setup-%d", sequence), action, expected, payload); result.Code != state.Applied {
			t.Fatal(action, result)
		}
	}
	makeUser := func(id, username string, key [32]byte, system bool) access.User {
		return access.User{ID: id, Username: username, Enabled: true, SystemAdmin: system, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: key, Enabled: true}}}
	}
	fixture.EnrollAdmin(makeUser("admin", "operator", admin.Public, true))
	change("put-user", "admin", 0, makeUser("alice", "alice.login", alice.Public, false))
	change("create-tenant", "admin", 0, control.TenantID{ID: "one"})
	change("create-tenant", "admin", 0, control.TenantID{ID: "two"})
	change("set-membership", "admin", 0, access.Membership{Tenant: "one", User: "alice", Role: access.Manager, Enabled: true})
	profilePath := filepath.Join(root, "user.yaml")
	text := fmt.Sprintf("version: 1\nauth: user\ncluster: '%x'\npeers:\n  - {id: node, key: '%s', endpoint: '%s', voter: true}\n", clusterID, node.Actor(), address)
	if err := os.WriteFile(profilePath, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	call := func(expected int, args ...string) string {
		t.Helper()
		var out, diagnostic bytes.Buffer
		if len(args) > 0 && args[0] != "login" {
			args = append([]string{"--user", "alice.login"}, args...)
		}
		code := invoke(append([]string{"--config", profilePath}, args...), &out, &diagnostic)
		if code != expected {
			t.Fatal("CLI result", args, code, expected, out.String(), diagnostic.String())
		}
		if strings.Contains(out.String(), "Signature") || strings.Contains(out.String(), "PRIVATE KEY") || strings.Contains(out.String(), "Seed") {
			t.Fatal("private session material printed")
		}
		return out.String()
	}
	call(3, "login", "--username", "alice.login", "--method", "private-key", "--key-file", filepath.Join(root, "other", "key.pem"))
	call(0, "login", "--username", "alice.login", "--method", "private-key", "--key-file", filepath.Join(root, "alice", "key.pem"))
	if got := call(0, "whoami"); !strings.Contains(got, "alice.login") {
		t.Fatal("username is not the stable user ID", got)
	}
	peer := sfcp.Peer{ID: "node", Endpoint: address, Policy: sfcp.Policy{Key: sfcp.Identity(node.Public), Respond: true}}
	client := userauth.Client{Cluster: clusterID, Peers: []sfcp.Peer{peer}}
	saved, err := loadCredentials(client, "alice.login")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(saved.Self.Private)
	// A new TLS connection restores the same proof key; a signature for an
	// unrelated challenge cannot authenticate a request on that connection.
	client.Self = saved.Self
	client.Mesh, err = sfcp.NewTransport(saved.Self, clusterID, func(k sfcp.Identity) (sfcp.Peer, bool) { return peer, k == peer.Key })
	if err != nil {
		t.Fatal(err)
	}
	defer client.Mesh.Close()
	tenantList := func() []userauth.TenantView {
		t.Helper()
		reply, err := client.Tenants(ctx, peer, saved.Session)
		if err != nil {
			t.Fatal(err)
		}
		return reply.Tenants
	}
	if got := tenantList(); len(got) != 1 || got[0].ID != "one" {
		t.Fatal("tenant filter", got)
	}
	conn, err := client.Mesh.Dial(ctx, peer)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(userauth.Request{Schema: 1, Method: "whoami", Nonce: [32]byte{1}, Params: json.RawMessage(`{}`)})
	envelope, _ := json.Marshal(userauth.Envelope{Body: body, Session: &saved.Session, Signature: ed25519.Sign(saved.Self.Private, access.RequestBytes(saved.Session, [32]byte{99}, body))})
	digest := sha256.Sum256(envelope)
	stream, err := conn.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	id := client.Mesh.NextRequest()
	if err = sfcp.WriteFrame(stream, sfcp.Frame{Purpose: sfcp.User, Kind: 1, Request: id, Fields: []sfcp.Field{{Tag: 1, Required: true, Value: envelope}, {Tag: 2, Required: true, Value: digest[:]}}}); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal("request EOF", err)
	}
	response, err := sfcp.ReadFrame(stream, 128<<10)
	stream.CancelRead(0)
	_ = stream.Close()
	if err != nil {
		t.Fatal(err)
	}
	var rejected userauth.Reply
	if json.Unmarshal(response.Fields[0].Value, &rejected) != nil || rejected.Code != "denied" {
		t.Fatal("connection proof replay accepted", rejected.Code)
	}
	prepare := func(c userauth.Client, session access.Session, id, action string, expected uint64, payload any) control.UserOperation {
		t.Helper()
		raw, err := control.ChangeBytes(action, session.User, expected, payload)
		if err != nil {
			t.Fatal(err)
		}
		var change control.Change
		if err = json.Unmarshal(raw, &change); err != nil {
			t.Fatal(err)
		}
		op, err := c.Prepare(ctx, peer, session, id, change)
		if err != nil {
			t.Fatal("prepare signed user operation", err)
		}
		return op
	}
	one, _ := catalog().Tenant("one")
	trust := prepare(client, saved.Session, "alice-trust", "set-trust", one.Revision, control.TrustChange{Tenant: "one", Add: []access.TrustRule{{Registry: "docker.io", Repository: "library/php"}}})
	applied, err := client.Operation(ctx, peer, trust, false)
	if err != nil || applied.Result == nil || applied.Result.Code != state.Applied {
		t.Fatal("actual user mutation", applied.Code, applied.Result, err)
	}
	duplicate, err := client.Operation(ctx, peer, trust, false)
	if err != nil || duplicate.Result == nil || *duplicate.Result != *applied.Result {
		t.Fatal("original signed operation re-executed", err)
	}
	// These signatures and current root CAS are valid; only the edge's real
	// admission clock distinguishes them from accepted committed operations.
	clockView, err := runtime.Engine().Read(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	clockTenant, _ := catalog().Tenant("one")
	var staleClock control.UserOperation
	for _, future := range []bool{true, false} {
		clock := trust
		clock.RootRevision = clockView.State.Object(control.CatalogKey).Revision
		clock.Change.Expected = clockTenant.Revision
		// A fresh delta against the current rules: the first one already applied.
		clock.Change.Payload, _ = json.Marshal(control.TrustChange{Tenant: "one", Remove: []access.TrustRule{{Registry: "docker.io", Repository: "library/php"}}})
		clock.RequestID = "future-admission"
		now := time.Now().Unix()
		clock.At = now + 60
		if !future {
			clock.RequestID, clock.At = "stale-admission", now-301
			clock.Session.IssuedAt, clock.Session.ExpiresAt = now-600, now+3000
			clock.Session.Signature = ed25519.Sign(node.Private, access.SessionBytes(clock.Session))
			clock.Session, err = access.ApproveSession(clock.Session, alice.Private)
			if err != nil {
				t.Fatal("approve original backdated fixture grant", err)
			}
		}
		clock.Signature = ed25519.Sign(saved.Self.Private, control.OperationBytes(clock))
		if !future {
			staleClock = clock
		}
		if _, err = client.Operation(ctx, peer, clock, false); err == nil {
			t.Fatal("invalid admission clock accepted", future)
		}
	}
	clockAfter, err := runtime.Engine().Read(ctx, true)
	if err != nil || clockAfter.State.Index() != clockView.State.Index() {
		t.Fatal("clock rejection appended a command", err)
	}
	explicit, err := client.Resume(ctx, peer, saved.Session, staleClock)
	if err != nil || explicit.Result == nil || explicit.Result.Code != state.Applied {
		t.Fatal("explicit unchanged stale intent resume", explicit.Code, explicit.Result, err)
	}
	beforeResumeDuplicate := readView()
	explicitAgain, err := client.Resume(ctx, peer, saved.Session, staleClock)
	afterResumeDuplicate := readView()
	if err != nil || explicitAgain.Result == nil || *explicitAgain.Result != *explicit.Result || beforeResumeDuplicate.State.Index() != afterResumeDuplicate.State.Index() {
		t.Fatal("explicit resume duplicated an effect", err)
	}
	_, _, _, legacy := func() (state.Rights, uint64, uint64, bool) {
		v, err := runtime.Engine().Read(ctx, true)
		if err != nil {
			t.Fatal(err)
		}
		return v.State.Principal(saved.Self.Actor())
	}()
	if legacy {
		t.Fatal("user proof key gained a legacy principal")
	}
	forged := trust
	forged.RequestID = "forged-proof"
	currentRoot, err := runtime.Engine().Read(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	forged.RootRevision = currentRoot.State.Object(control.CatalogKey).Revision
	forgedCommand, _ := forged.Command()
	deniedCommit, err := runtime.Engine().Submit(ctx, forgedCommand)
	if err != nil || deniedCommit.Result.Code != state.Forbidden {
		t.Fatal("FSM trusted forged client operation", deniedCommit.Result.Code, err)
	}
	otherTenant, _ := catalog().Tenant("two")
	foreign := prepare(client, saved.Session, "foreign-trust", "set-trust", otherTenant.Revision, control.TrustChange{Tenant: "two", Add: []access.TrustRule{{Registry: "docker.io", Repository: "library/redis"}}})
	denied, err := client.Operation(ctx, peer, foreign, false)
	if err != nil || denied.Result == nil || denied.Result.Code != state.Forbidden {
		t.Fatal("cross-tenant user mutation", denied.Code, err)
	}
	scoped := saved.Session
	scoped.Scopes = []access.Scope{{Tenant: "one", Actions: []access.Action{access.Read}}}
	scoped.Signature = ed25519.Sign(node.Private, access.SessionBytes(scoped))
	scoped, err = access.ApproveSession(scoped, alice.Private)
	if err != nil {
		t.Fatal("approve narrowed fixture grant", err)
	}
	one, _ = catalog().Tenant("one")
	limited := prepare(client, scoped, "scope-cannot-widen", "set-trust", one.Revision, control.TrustChange{Tenant: "one", Add: []access.TrustRule{{Registry: "docker.io", Repository: "library/redis"}}})
	denied, err = client.Operation(ctx, peer, limited, false)
	if err != nil || denied.Result == nil || denied.Result.Code != state.Forbidden {
		t.Fatal("account manager widened read-only credential scope", denied.Code, err)
	}
	resumeCeiling := staleClock
	resumeCeiling.RequestID = "resume-scope-ceiling"
	ceilingRoot := readView()
	ceilingTenant, _ := catalog().Tenant("one")
	resumeCeiling.RootRevision, resumeCeiling.Change.Expected = ceilingRoot.State.Object(control.CatalogKey).Revision, ceilingTenant.Revision
	resumeCeiling.Signature = ed25519.Sign(saved.Self.Private, control.OperationBytes(resumeCeiling))
	if _, err = client.Resume(ctx, peer, scoped, resumeCeiling); err == nil {
		t.Fatal("resume widened current read-only session")
	}
	// Revoking membership affects the existing session without reissuing it.
	m, _ := catalog().Membership("one", "alice")
	m.Revision, m.Enabled = 0, false
	old, _ := catalog().Membership("one", "alice")
	change("set-membership", "admin", old.Revision, m)
	if got := tenantList(); len(got) != 0 {
		t.Fatal("stale membership cached", got)
	}
	one, _ = catalog().Tenant("one")
	staleRole := prepare(client, saved.Session, "revoked-membership-trust", "set-trust", one.Revision, control.TrustChange{Tenant: "one", Add: []access.TrustRule{{Registry: "docker.io", Repository: "library/redis"}}})
	denied, err = client.Operation(ctx, peer, staleRole, false)
	if err != nil || denied.Result == nil || denied.Result.Code != state.Forbidden {
		t.Fatal("current role not checked in committed apply", denied.Code, err)
	}
	// Same DB/key, fresh transport and unchanged session proof survive restart.
	if err = runtime.Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	fixture.Close()
	fixture.Open()
	runtime = fixture.Runtime
	wait()
	call(0, "whoami")
	receipt, err := client.Operation(ctx, peer, trust, true)
	if err != nil || !receipt.Found || receipt.Result == nil || *receipt.Result != *applied.Result {
		t.Fatal("signed operation receipt lost after Snapshot/restart", err)
	}
	current, _ := catalog().User("alice")
	change("revoke-session", "admin", current.Revision, control.SessionRevocation{User: "alice", Session: saved.Session.ID})
	call(3, "whoami")
	call(0, "login", "--username", "alice.login", "--method", "private-key", "--key-file", filepath.Join(root, "alice", "key.pem"))
	newSaved, err := loadCredentials(userauth.Client{Cluster: clusterID, Peers: []sfcp.Peer{peer}}, "alice.login")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(newSaved.Self.Private)
	newClient := userauth.Client{Self: newSaved.Self, Cluster: clusterID, Peers: []sfcp.Peer{peer}}
	newClient.Mesh, err = sfcp.NewTransport(newClient.Self, clusterID, func(k sfcp.Identity) (sfcp.Peer, bool) { return peer, k == peer.Key })
	if err != nil {
		t.Fatal(err)
	}
	defer newClient.Mesh.Close()
	logout := prepare(newClient, newSaved.Session, "lost-logout-reply", "revoke-session", newSaved.Session.AccountRevision, control.SessionRevocation{User: newSaved.Session.User, Session: newSaved.Session.ID})
	if err = fixtureStageLogout(t, home, "alice.login", newClient, logout); err != nil {
		t.Fatal(err)
	}
	if err = fixtureSaveSession(t, home, "alice.login", newClient, newSaved.Session); err == nil {
		t.Fatal("unsettled logout overwritten")
	}
	logoutBody, _ := json.Marshal(userauth.Request{Schema: 1, Method: "submit", Operation: &logout, Nonce: [32]byte{22}})
	logoutConn, err := newClient.Mesh.Dial(ctx, peer)
	if err != nil {
		t.Fatal(err)
	}
	logoutEnvelope, _ := json.Marshal(userauth.Envelope{Body: logoutBody, Session: &logout.Session, Signature: ed25519.Sign(newClient.Self.Private, access.RequestBytes(logout.Session, logoutConn.PeerChallenge(), logoutBody))})
	logoutDigest := sha256.Sum256(logoutEnvelope)
	lost, err := logoutConn.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = sfcp.WriteFrame(lost, sfcp.Frame{Purpose: sfcp.User, Kind: 1, Request: newClient.Mesh.NextRequest(), Fields: []sfcp.Field{{Tag: 1, Required: true, Value: logoutEnvelope}, {Tag: 2, Required: true, Value: logoutDigest[:]}}}); err != nil {
		t.Fatal(err)
	}
	lost.CancelRead(1)
	_ = lost.Close()
	logoutCommand, _ := logout.Command()
	for {
		v, err := runtime.Engine().Read(ctx, true)
		if err != nil {
			t.Fatal(err)
		}
		if result, found := v.State.LookupResult(logoutCommand); found {
			if result.Code != state.Applied {
				t.Fatal("logout not committed", result.Code)
			}
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	call(3, "whoami")
	before := readView()
	call(0, "logout")
	after := readView()
	if before.State.Index() != after.State.Index() {
		t.Fatal("logout recovery resubmitted instead of querying")
	}
	if _, err := loadCredentials(newClient, "alice.login"); err == nil {
		t.Fatal("confirmed logout retained proof seed")
	}
	call(2, "whoami")
	call(0, "login", "--username", "alice.login", "--method", "private-key", "--key-file", filepath.Join(root, "alice", "key.pem"))
	call(0, "logout")
	call(2, "whoami")
	// A retained intent with NO matching server receipt is not evidence of
	// non-execution. Re-running logout must not submit it or generate a new ID.
	call(0, "login", "--username", "alice.login", "--method", "private-key", "--key-file", filepath.Join(root, "alice", "key.pem"))
	unknown, err := loadCredentials(userauth.Client{Cluster: clusterID, Peers: []sfcp.Peer{peer}}, "alice.login")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(unknown.Self.Private)
	unknownClient := userauth.Client{Self: unknown.Self, Cluster: clusterID, Peers: []sfcp.Peer{peer}}
	unknownClient.Mesh, err = sfcp.NewTransport(unknownClient.Self, clusterID, func(k sfcp.Identity) (sfcp.Peer, bool) { return peer, k == peer.Key })
	if err != nil {
		t.Fatal(err)
	}
	defer unknownClient.Mesh.Close()
	unsubmitted := prepare(unknownClient, unknown.Session, "not-yet-observed", "revoke-session", unknown.Session.AccountRevision, control.SessionRevocation{User: unknown.Session.User, Session: unknown.Session.ID})
	if err = fixtureStageLogout(t, home, "alice.login", unknownClient, unsubmitted); err != nil {
		t.Fatal(err)
	}
	before = readView()
	got := call(4, "logout")
	after = readView()
	if !strings.Contains(got, `"status":"unknown"`) || before.State.Index() != after.State.Index() {
		t.Fatal("absent result became non-execution/resubmission")
	}
	retained, err := loadCredentials(unknownClient, "alice.login")
	if err != nil || retained.Pending == nil || retained.Pending.RequestID != unsubmitted.RequestID {
		t.Fatal("unknown original intent/key lost", err)
	}
	clear(retained.Self.Private)
	call(0, "whoami")
	// Explicit submission of that exact original intent; then rotate the
	// account credential before the client has received/settled its receipt.
	committedLogout, err := unknownClient.Operation(ctx, peer, unsubmitted, false)
	if err != nil || committedLogout.Result == nil || committedLogout.Result.Code != state.Applied {
		t.Fatal("explicit original logout submission", err)
	}
	account, _ := catalog().User("alice")
	change("add-credential", "admin", account.Revision, access.CredentialAddition{User: "alice", Credential: access.CredentialKey{ID: "rotated", Method: access.PrivateKey, PublicKey: otherKey.Public}})
	account, _ = catalog().User("alice")
	change("disable-credential", "admin", account.Revision, access.CredentialDisable{User: "alice", Credential: "key"})
	call(3, "whoami")
	call(0, "login", "--username", "operator", "--method", "private-key", "--key-file", filepath.Join(root, "admin", "key.pem"))
	call(3, "login", "--username", "alice.login", "--method", "private-key", "--key-file", filepath.Join(root, "alice", "key.pem"))
	call(0, "login", "--username", "alice.login", "--method", "private-key", "--key-file", filepath.Join(root, "other", "key.pem"))
	resumed, err := loadCredentials(userauth.Client{Cluster: clusterID, Peers: []sfcp.Peer{peer}}, "alice.login")
	if err != nil || resumed.Pending == nil || resumed.Session.AccountRevision == unsubmitted.Session.AccountRevision || resumed.Session.Key == unsubmitted.Session.Key || resumed.Pending.RequestID != unsubmitted.RequestID {
		t.Fatal("same-user credential re-login lost/rewrote original intent", err)
	}
	clear(resumed.Self.Private)
	settled := call(0, "logout")
	if !strings.Contains(settled, `"status":"original-logout-settled"`) || !strings.Contains(settled, `"current_session_retained":true`) {
		t.Fatal("old logout deleted new active session", settled)
	}
	call(0, "whoami")
	active, err := loadCredentials(userauth.Client{Cluster: clusterID, Peers: []sfcp.Peer{peer}}, "alice.login")
	if err != nil || active.Pending != nil {
		t.Fatal("old original intent not settled", err)
	}
	clear(active.Self.Private)
	call(0, "logout")
	call(2, "whoami")
	call(0, "login", "--username", "alice.login", "--method", "private-key", "--key-file", filepath.Join(root, "other", "key.pem"))
	finalStored, err := loadCredentials(userauth.Client{Cluster: clusterID, Peers: []sfcp.Peer{peer}}, "alice.login")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(finalStored.Self.Private)
	finalClient := userauth.Client{Self: finalStored.Self, Cluster: clusterID, Peers: []sfcp.Peer{peer}}
	finalClient.Mesh, err = sfcp.NewTransport(finalClient.Self, clusterID, func(k sfcp.Identity) (sfcp.Peer, bool) { return peer, k == peer.Key })
	if err != nil {
		t.Fatal(err)
	}
	defer finalClient.Mesh.Close()
	finalIntent := prepare(finalClient, finalStored.Session, "cli-explicit-original-resume", "revoke-session", finalStored.Session.AccountRevision, control.SessionRevocation{User: finalStored.Session.User, Session: finalStored.Session.ID})
	if err = fixtureStageLogout(t, home, "alice.login", finalClient, finalIntent); err != nil {
		t.Fatal(err)
	}
	before = readView()
	call(4, "logout")
	call(0, "logout", "--resume-original")
	after = readView()
	if after.State.Index() != before.State.Index()+1 {
		t.Fatal("explicit original resume did not commit exactly once")
	}
	call(2, "whoami")
	// A logout CASes only its own account record (R17 B2a): a commit to
	// another record of the catalog no longer rejects it.
	call(0, "login", "--username", "alice.login", "--method", "private-key", "--key-file", filepath.Join(root, "other", "key.pem"))
	raced, err := loadCredentials(userauth.Client{Cluster: clusterID, Peers: []sfcp.Peer{peer}}, "alice.login")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raced.Self.Private)
	raceClient := userauth.Client{Self: raced.Self, Cluster: clusterID, Peers: []sfcp.Peer{peer}}
	raceClient.Mesh, err = sfcp.NewTransport(raceClient.Self, clusterID, func(k sfcp.Identity) (sfcp.Peer, bool) { return peer, k == peer.Key })
	if err != nil {
		t.Fatal(err)
	}
	defer raceClient.Mesh.Close()
	raceIntent := prepare(raceClient, raced.Session, "logout-cas-race", "revoke-session", raced.Session.AccountRevision, control.SessionRevocation{User: raced.Session.User, Session: raced.Session.ID})
	if err = fixtureStageLogout(t, home, "alice.login", raceClient, raceIntent); err != nil {
		t.Fatal(err)
	}
	change("create-tenant", "admin", 0, control.TenantID{ID: "cas-race"})
	unrelated := call(0, "logout", "--resume-original")
	if !strings.Contains(unrelated, `"status":"logged-out"`) {
		t.Fatal("unrelated catalog commit rejected logout", unrelated)
	}
}

func TestUserCLIHelpAndProfileDoNotRequireNodeIdentity(t *testing.T) {
	var out, diagnostic bytes.Buffer
	if code := run([]string{"--config", filepath.Join(t.TempDir(), "absent.yaml"), "login", "--help"}, &out, &diagnostic); code != 0 {
		t.Fatal(code, diagnostic.String())
	}
	diagnostic.Reset()
	if code := run([]string{"--config", filepath.Join(t.TempDir(), "absent.yaml"), "logout", "--help"}, &out, &diagnostic); code != 0 || !strings.Contains(diagnostic.String(), "--resume-original") {
		t.Fatal("logout help requires configuration or omits actual resume option", code, diagnostic.String())
	}
	path := filepath.Join(t.TempDir(), "client.yaml")
	text := "version: 1\nauth: user\ncluster: '" + strings.Repeat("01", 32) + "'\npeers:\n  - {id: node, key: '" + strings.Repeat("02", 32) + "', endpoint: '127.0.0.1:7443', voter: true}\n"
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := config.LoadClient(path)
	if err != nil || c.Auth != "user" {
		t.Fatal(c, err)
	}
	if err = os.WriteFile(path, []byte(text+"identity_dir: missing\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = config.LoadClient(path); err == nil {
		t.Fatal("user profile allowed identity fallback")
	}
}
