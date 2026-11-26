// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/credentials"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/secrets"

	"github.com/hashicorp/raft"
)

// Real protected credential material/KDF, pinned TLS provider SDK, Raft/bbolt
// and User handler. The provider's HTTP service is a finite test fixture; it
// is not a claim of deploying Vault, UI, Docker or a managed member cluster.
func TestMultiUserPasswordIdleRebindAndSelfCredentialActualRuntime(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	root, err := os.MkdirTemp("", "mydc-rq2-auth-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	newKey := func() *identity.Identity {
		t.Helper()
		key, err := identity.Ephemeral()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { clear(key.Private) })
		return key
	}
	node, admin, web, browser := newKey(), newKey(), newKey(), newKey()
	clusterID := [32]byte{202}
	peer := mydcp.Peer{ID: "node", Policy: mydcp.Policy{Key: mydcp.Identity(node.Public), Member: true, Read: true, Respond: true}}
	lookup := func(k mydcp.Identity) (mydcp.Peer, bool) {
		if k == mydcp.Identity(web.Public) {
			return mydcp.Peer{ID: "web", Policy: mydcp.Policy{Key: k, UserAuth: true}}, true
		}
		return peer, k == peer.Key
	}
	server, err := mydcp.NewTransport(node, clusterID, lookup)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err = server.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	peer.Endpoint = server.Addr().String()
	policy := control.Policy{Cluster: clusterID, BootstrapKey: admin.Public, Issuers: [][32]byte{node.Public}, TrustRoot: node.Public, Genesis: config.Peer{ID: "node", Key: node.Actor(), Endpoint: peer.Endpoint, Voter: true}}
	e, err := cluster.Open(cluster.Options{ID: "node", Root: filepath.Join(root, "db"), Admin: admin.Actor(), Cluster: clusterID, Mesh: server, Bootstrap: true,
		Servers: []raft.Server{{ID: "node", Address: raft.ServerAddress(peer.Endpoint), Suffrage: raft.Voter}}, Resolve: func(id raft.ServerID, _ raft.ServerAddress) (mydcp.Peer, bool) { return peer, id == "node" }, ModuleID: policy.ID(), Validate: policy.Validate, Reduce: policy.Reduce, AdmitModule: policy.AdmitModule, TrackConfiguration: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	for {
		if _, err := e.Read(ctx, true); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	sequence := 0
	install := func(action string, expected uint64, payload any) {
		t.Helper()
		principal := "operator"
		if action == "enroll" {
			principal = ""
		}
		raw, err := control.ChangeBytes(action, principal, expected, payload)
		if err != nil {
			t.Fatal(err)
		}
		view, err := e.Read(ctx, true)
		if err != nil {
			t.Fatal(err)
		}
		sequence++
		result, err := e.Submit(ctx, state.Command{Kind: state.Module, Actor: admin.Actor(), Epoch: 1, RequestID: fmt.Sprintf("rq2-install-%d", sequence), Key: control.CatalogKey, Expected: view.State.Object(control.CatalogKey).Revision, Value: string(raw)})
		if err != nil || result.Result.Code != state.Applied {
			t.Fatal("installation", action, result.Result, err)
		}
	}
	install("enroll", 0, access.User{ID: "operator", Username: "operator", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: admin.Public, Enabled: true}}})
	password := []byte("rq2-test-password-never-logged")
	defer clear(password)
	readToken := []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{83}, 32)))
	defer clear(readToken)
	materials := map[string]string{}
	for _, name := range []string{"alice", "bob", "carol", "failed"} {
		ref := "vault/system/system/credentials/" + name + "/password@1"
		material, err := credentials.NewPassword(clusterID, name, "password", ref, password, bytes.Repeat([]byte{31}, 16), identity.PasswordCost{Memory: 8 * 1024, Iterations: 1, Threads: 1})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := material.ProtectedBytes()
		if err != nil {
			t.Fatal(err)
		}
		materials["/v1/kv/data/system/credentials/"+name+"/password"] = string(raw)
		clear(raw)
		material.Destroy()
		account := access.User{ID: name, Username: name, Enabled: true, Credentials: []access.Credential{{ID: "password", Method: access.Password, VerifierRef: ref, Enabled: true}}}
		if name == "bob" || name == "carol" {
			tokenRef := "vault/system/system/credentials/" + name + "/token@1"
			tokenID, tokenAction := "readonly", access.Read
			if name == "carol" {
				tokenID, tokenAction = "own-key", access.ManageCredentials
			}
			material, err := credentials.NewToken(clusterID, name, tokenID, tokenRef, readToken, time.Now().Unix()+3600, []access.Scope{{Tenant: "*", Actions: []access.Action{tokenAction}}})
			if err != nil {
				t.Fatal(err)
			}
			raw, err := material.ProtectedBytes()
			if err != nil {
				t.Fatal(err)
			}
			materials["/v1/kv/data/system/credentials/"+name+"/token"] = string(raw)
			clear(raw)
			material.Destroy()
			account.Credentials = append(account.Credentials, access.Credential{ID: tokenID, Method: access.Token, VerifierRef: tokenRef, Enabled: true})
		}
		install("put-user", 0, account)
		if name != "failed" {
			install("create-tenant", 0, control.TenantID{ID: name})
			install("set-membership", 0, access.Membership{Tenant: name, User: name, Role: access.Manager, Enabled: true})
		}
	}
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		raw, ok := materials[r.URL.Path]
		if !ok || r.Method != "GET" || r.URL.Query().Get("version") != "1" || r.Header.Get("X-Vault-Token") != "installed-test-only-token" {
			w.WriteHeader(403)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": map[string]any{"credential": raw}, "metadata": map[string]any{"version": 1, "destroyed": false, "deletion_time": ""}}})
	}))
	defer provider.Close()
	roots := x509.NewCertPool()
	roots.AddCert(provider.Certificate())
	backend, err := credentials.NewBackend(secrets.VaultProfile{ID: "system", Address: provider.URL, Mount: "kv", Prefix: "system/credentials", Token: "installed-test-only-token", Roots: roots, Timeout: time.Second, MaxBytes: 128 << 10})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	svc := Service{Engine: e, Mesh: server, Self: node, Policy: policy, Credentials: backend}
	if err = svc.Serve(); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(root, "mydc.sock")
	if err = server.ListenUnix(socket); err != nil {
		t.Fatal(err)
	}
	target := peer
	target.Endpoint = "unix://" + socket
	newMesh := func(target mydcp.Peer) *mydcp.Transport {
		t.Helper()
		m, err := mydcp.NewTransport(web, clusterID, func(k mydcp.Identity) (mydcp.Peer, bool) { return target, k == target.Key })
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = m.Close() })
		return m
	}
	c := Client{Self: web, Cluster: clusterID, Peers: []mydcp.Peer{target}, Mesh: newMesh(target)}
	// Username rejection must not drain the shared UID/global source bucket.
	for range 5 {
		if _, err = c.LoginCredential(ctx, target, "failed", access.Password, "password", []byte("wrong")); err == nil {
			t.Fatal("wrong password accepted")
		}
	}
	for range 25 {
		if _, err = c.LoginCredential(ctx, target, "failed", access.Password, "password", []byte("wrong")); err == nil {
			t.Fatal("failed user's rate cap bypassed")
		}
	}
	sessions := map[string]access.Session{}
	clients := map[string]Client{}
	for _, name := range []string{"alice", "bob", "carol"} {
		caller := c
		caller.Mesh = newMesh(target)
		s, err := caller.LoginCredential(ctx, target, name, access.Password, "password", password)
		if err != nil {
			t.Fatal("other user's password login blocked", name, err)
		}
		sessions[name] = s
		clients[name] = caller
	}
	var writes sync.Mutex
	var workers sync.WaitGroup
	errs := make(chan error, 3)
	for _, name := range []string{"alice", "bob", "carol"} {
		workers.Add(1)
		go func() {
			defer workers.Done()
			s := sessions[name]
			caller := clients[name]
			r, err := caller.Query(ctx, target, s, "tenants", "")
			if err != nil || len(r.Tenants) != 1 || r.Tenants[0].ID != name {
				errs <- fmt.Errorf("multi-user query %s: %w", name, err)
				return
			}
			// Root CAS serializes independent signed changes; identity/session are
			// simultaneously live on the same client, never selected from a cache.
			writes.Lock()
			defer writes.Unlock()
			raw, _ := json.Marshal(control.TrustAssignment{Tenant: name, Rules: []access.TrustRule{{Registry: "docker.io", Repository: "**"}}})
			op, err := caller.Prepare(ctx, target, s, "trust-"+name, control.Change{Schema: 1, Action: "set-trust", Principal: name, Expected: r.Tenants[0].Revision, Payload: raw})
			if err == nil {
				r, err = caller.Operation(ctx, target, op, false)
			}
			if err != nil || r.Result == nil || r.Result.Code != state.Applied {
				errs <- fmt.Errorf("multi-user submit %s: code=%s error=%v", name, r.Code, err)
				return
			}
		}()
	}
	workers.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if t.Failed() {
		return
	}
	c = clients["alice"]
	session := sessions["alice"]
	original, _ := json.Marshal(session)
	conn, err := c.Mesh.Dial(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	oldChallenge := conn.PeerChallenge()
	// This is an actual 61-second idle interval, longer than Unix cache/server
	// 30s reclamation, with no ping/password/credential replay.
	t.Log("three users logged in, queried and submitted; beginning 61s credential-free idle")
	timer := time.NewTimer(61 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-timer.C:
	}
	self, err := c.Query(ctx, target, session, "my-credentials", "")
	if err != nil || self.SelfCredentials == nil || self.SelfCredentials.ID != "alice" {
		t.Fatal("original password session after idle", self.Code, err)
	}
	conn, err = c.Mesh.Dial(ctx, target)
	if err != nil || conn.PeerChallenge() == oldChallenge {
		t.Fatal("idle did not change connection challenge", err)
	}
	after, _ := json.Marshal(session)
	if !bytes.Equal(original, after) {
		t.Fatal("idle changed session/scope/expiry")
	}
	// The exact same proof key also works on a new QUIC transport, without
	// browser account signing or password. Expiry/issuer are not extended.
	remote := c
	remote.Mesh = newMesh(peer)
	remote.Peers = []mydcp.Peer{peer}
	if _, err = remote.Query(ctx, peer, session, "my-credentials", ""); err != nil {
		t.Fatal("original session on fresh network connection", err)
	}
	mutate := func(s access.Session, id, action string, expected uint64, payload any) Reply {
		t.Helper()
		raw, _ := json.Marshal(payload)
		op, err := c.Prepare(ctx, target, s, id, control.Change{Schema: 1, Action: action, Principal: s.User, Expected: expected, Payload: raw})
		if err != nil {
			t.Fatal("prepare", action, err)
		}
		r, err := c.Operation(ctx, target, op, false)
		if err != nil {
			t.Fatal("submit", action, err)
		}
		return r
	}
	if r := mutate(session, "revoke-idle-original", "revoke-session", session.AccountRevision, control.SessionRevocation{User: session.User, Session: session.ID}); r.Result == nil || r.Result.Code != state.Applied {
		t.Fatal("revoke exact idle session", r.Code)
	}
	if _, err = c.Query(ctx, target, session, "my-credentials", ""); err == nil {
		t.Fatal("revoked idle session survived Unix request")
	}
	if _, err = remote.Query(ctx, peer, session, "my-credentials", ""); err == nil {
		t.Fatal("revoked idle session rebound on QUIC")
	}
	session, err = c.LoginCredential(ctx, target, "alice", access.Password, "password", password)
	if err != nil {
		t.Fatal("fresh login after original session revoke", err)
	}
	// Cross-user mutation fails even though the client TLS key is shared.
	addition, err := c.NewCredentialAddition(session, "browser", "local browser", browser.Private)
	if err != nil {
		t.Fatal(err)
	}
	wrong := addition
	wrong.User = "bob"
	wrong.Proof = ed25519.Sign(browser.Private, access.CredentialAdditionBytes(clusterID, session.AccountRevision, wrong))

	if r := mutate(session, "wrong-user", "add-credential", session.AccountRevision, wrong); r.Result == nil || r.Result.Code != state.Forbidden {
		t.Fatal("cross-user credential change", r.Code)
	}
	// A valid signed but read-only token ceiling cannot mint a login key.
	narrow, err := c.LoginCredential(ctx, target, "bob", access.Token, "readonly", readToken)
	if err != nil {
		t.Fatal("actual restricted token login", err)
	}
	limited, err := c.NewCredentialAddition(narrow, "forbidden-browser", "", browser.Private)
	if err != nil {
		t.Fatal(err)
	}
	if r := mutate(narrow, "read-only", "add-credential", narrow.AccountRevision, limited); r.Result == nil || r.Result.Code != state.Forbidden {
		t.Fatal("read-only grant minted a login key", r.Code)
	}
	if r := mutate(session, "own-browser", "add-credential", session.AccountRevision, addition); r.Result == nil || r.Result.Code != state.Applied {
		t.Fatal("own browser key", r.Code)
	}
	if _, err = c.Query(ctx, target, session, "my-credentials", ""); err == nil {
		t.Fatal("old account session survived credential change")
	}
	keyToken, err := c.LoginCredential(ctx, target, "carol", access.Token, "own-key", readToken)
	if err != nil {
		t.Fatal("credential-scoped token login", err)
	}
	tokenAddition, err := c.NewCredentialAddition(keyToken, "token-browser", "token login", browser.Private)
	if err != nil {
		t.Fatal(err)
	}
	if r := mutate(keyToken, "token-own-browser", "add-credential", keyToken.AccountRevision, tokenAddition); r.Result == nil || r.Result.Code != state.Applied {
		t.Fatal("token first browser key", r.Code)
	}

	keySession, err := c.Login(ctx, target, "alice", browser.Private)
	if err != nil {
		t.Fatal("new browser credential login", err)
	}
	owned, err := c.Query(ctx, target, keySession, "my-credentials", "")
	if err != nil || owned.SelfCredentials == nil || owned.SelfCredentials.ID != "alice" || owned.SelfCredentials.Revision != keySession.AccountRevision || owned.SelfCredentials.Revision <= session.AccountRevision {
		t.Fatal("REQ-26 own account revision after key addition", err)
	}
	foundBrowser := false
	for _, credential := range owned.SelfCredentials.Credentials {
		foundBrowser = foundBrowser || credential.ID == "browser" && credential.Enabled && credential.PublicKey == browser.Public
	}
	if !foundBrowser {
		t.Fatal("REQ-26 own public list omitted the newly registered key")
	}
	if r := mutate(keySession, "disable-browser", "disable-credential", keySession.AccountRevision, access.CredentialDisable{User: "alice", Credential: "browser"}); r.Result == nil || r.Result.Code != state.Applied {
		t.Fatal("self disable", r.Code)
	}
	if _, err = c.Query(ctx, target, keySession, "my-credentials", ""); err == nil {
		t.Fatal("self-disabled credential retained a session")
	}
	if _, err = c.Login(ctx, target, "alice", browser.Private); err == nil {
		t.Fatal("disabled browser key logged in")
	}
	fresh, err := c.LoginCredential(ctx, target, "alice", access.Password, "password", password)
	if err != nil {
		t.Fatal("remaining password credential lost", err)
	}
	info, err := c.Query(ctx, target, fresh, "my-credentials", "")
	if err != nil || info.SelfCredentials == nil || info.SelfCredentials.Credentials[0].ID == "" {
		t.Fatal("own public credentials", err)
	}
	encoded, _ := json.Marshal(info)
	if strings.Contains(string(encoded), "VerifierRef") || strings.Contains(string(encoded), string(password)) {
		t.Fatal("credential metadata leaked")
	}
	// Self logout uses the existing accepted operation contract; the next
	// query with the same key and new or old connection is immediately denied.
	if r := mutate(fresh, "revoke-original", "revoke-session", fresh.AccountRevision, control.SessionRevocation{User: fresh.User, Session: fresh.ID}); r.Result == nil || r.Result.Code != state.Applied {
		t.Fatal("self revoke", r.Code)
	}
	if _, err = remote.Query(ctx, peer, fresh, "my-credentials", ""); err == nil {
		t.Fatal("revoked session rebound on another connection")
	}
}
