// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/app"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/membership"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/credentials"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/secrets"
	"github.com/jay94ks/mydcd/internal/userauth"
	"github.com/jay94ks/mydcd/tests/vaultfixture"
)

// The CLI tests retain their private names while sharing the same actual
// Vault process/TLS/file-storage fixture with Runtime/native integration tests.
type ownedVault struct {
	*vaultfixture.Vault
	t                            *testing.T
	address, root, admin, unseal string
	client                       *http.Client
	roots                        *x509.CertPool
}

func newOwnedVault(t *testing.T) *ownedVault {
	v := vaultfixture.Open(t)
	return &ownedVault{Vault: v, t: t, address: v.Address, root: v.Root, admin: v.Admin, unseal: v.Unseal, client: v.Client, roots: v.Roots}
}
func (v *ownedVault) start() { v.Start() }
func (v *ownedVault) stop()  { v.Stop() }
func (v *ownedVault) api(method, path string, input, output any, token string) {
	v.API(method, path, input, output, token)
}
func (v *ownedVault) unsealOriginal()     { v.UnsealOriginal() }
func (v *ownedVault) readerToken() string { return v.ReaderToken() }

func (v *ownedVault) backend(token string) *credentials.Backend {
	v.t.Helper()
	b, err := credentials.NewBackend(secrets.VaultProfile{ID: "system", Address: v.address, Mount: "kv", Prefix: "system/credentials", Roots: v.roots, Token: token, Timeout: time.Second, MaxBytes: 128 << 10})
	if err != nil {
		v.t.Fatal(err)
	}
	v.t.Cleanup(b.Close)
	return b
}

func TestRealVaultServiceProtectedCredentialsSealRestartAndVersion(t *testing.T) {
	v := newOwnedVault(t)
	cluster := [32]byte{82}
	password := []byte("actual-vault-password")
	defer clear(password)
	ref := "vault/system/system/credentials/alice/password@1"
	m, err := credentials.NewPassword(cluster, "alice", "password", ref, password, bytes.Repeat([]byte{31}, 16), identity.DefaultPasswordCost())
	if err != nil {
		t.Fatal(err)
	}
	defer m.Destroy()
	raw, err := m.ProtectedBytes()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	put := func(object string, value []byte, cas int) {
		t.Helper()
		var result struct {
			Data struct {
				Version int `json:"version"`
			} `json:"data"`
		}
		v.api("POST", "kv/data/"+object, map[string]any{"data": map[string]any{"credential": string(value)}, "options": map[string]any{"cas": cas}}, &result, v.admin)
		if result.Data.Version != cas+1 {
			t.Fatal("real provider revision mismatch")
		}
	}
	put("system/credentials/alice/password", raw, 0)
	opaque := make([]byte, 32)
	if _, err = rand.Read(opaque); err != nil {
		t.Fatal(err)
	}
	defer clear(opaque)
	token := []byte(base64.RawURLEncoding.EncodeToString(opaque))
	defer clear(token)
	robot, err := credentials.NewToken(cluster, "alice", "robot", "vault/system/system/credentials/alice/robot@1", token, time.Now().Unix()+300, []access.Scope{{Tenant: "first", Actions: []access.Action{access.Read}}})
	if err != nil {
		t.Fatal(err)
	}
	defer robot.Destroy()
	robotBytes, err := robot.ProtectedBytes()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(robotBytes)
	put("system/credentials/alice/robot", robotBytes, 0)
	passwordCredential := access.Credential{ID: "password", Method: access.Password, VerifierRef: ref, Enabled: true}
	tokenCredential := access.Credential{ID: "robot", Method: access.Token, VerifierRef: "vault/system/system/credentials/alice/robot@1", Enabled: true}
	u := access.User{ID: "alice", Username: "alice", Enabled: true, Credentials: []access.Credential{passwordCredential, tokenCredential}}
	reader := v.readerToken()
	backend := v.backend(reader)
	verify := func(b *credentials.Backend, c access.Credential, value []byte, success bool) {
		t.Helper()
		grant, err := b.Verify(context.Background(), cluster, u, c, value, "127.0.0.1", time.Now())
		if (err == nil) != success {
			t.Fatal("real provider authentication outcome", c.Method, success, err)
		}
		if success && grant.Credential != c.ID {
			t.Fatal("foreign credential grant")
		}
	}
	verify(backend, passwordCredential, password, true)
	verify(backend, tokenCredential, token, true)
	v.api("POST", "sys/seal", nil, nil, v.admin)
	verify(backend, passwordCredential, password, false)
	v.unsealOriginal()
	verify(backend, passwordCredential, password, true)
	backend.Close()
	v.stop()
	v.start()
	v.unsealOriginal()
	backend = v.backend(reader)
	verify(backend, passwordCredential, password, true)
	// A new latest revision cannot replace the public record's exact version.
	put("system/credentials/alice/password", []byte("unrelated-new-material"), 1)
	verify(backend, passwordCredential, password, true)
	v.api("POST", "kv/delete/system/credentials/alice/password", map[string]any{"versions": []int{1}}, nil, v.admin)
	verify(backend, passwordCredential, password, false)
	v.api("POST", "auth/token/revoke", map[string]any{"token": reader}, nil, v.admin)
	verify(backend, tokenCredential, token, false)
	other := v.backend(v.readerToken())
	verify(other, tokenCredential, token, true)
	t.Log("real pinned Vault1.21.0/TLS/file storage: init/unseal, system ACL token, password+opaque token, sealed fail-closed, same DB/TLS/unseal restart, exact old version, deletion and reader revocation; owned child/ports/private root removed")
}

func TestRealVaultPasswordTokenDynamicControlHandoffAndSameDB(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	vault := newOwnedVault(t)
	root := t.TempDir()
	adminKey, err := identity.Create(filepath.Join(root, "admin"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(adminKey.Private)
	type controlNode struct {
		cfg     config.Node
		runtime *app.Runtime
		peer    mydcp.Peer
		reader  string
	}
	var nodes []*controlNode
	defer func() {
		for _, n := range nodes {
			if n.runtime != nil {
				_ = n.runtime.Close()
			}
		}
	}()
	makeNode := func(id string) *controlNode {
		t.Helper()
		probe, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address := probe.LocalAddr().String()
		_ = probe.Close()
		c := config.Node{Version: 1, Common: config.Common{}, Modules: map[string]config.Module{"network": {}, "workload": {}, "ingress": {}}}
		c.Node.ID, c.Node.Listen = id, address
		c.Node.StateDir, c.Node.IdentityDir = filepath.Join(root, id, "state"), filepath.Join(root, id, "identity")
		reader := vault.readerToken()
		tokenFile := filepath.Join(root, id+".token")
		if err = os.WriteFile(tokenFile, []byte(reader), 0600); err != nil {
			t.Fatal(err)
		}
		c.Credentials = &config.CredentialBackend{Profile: "system", Address: vault.address, Mount: "kv", CAFile: filepath.Join(vault.root, "tls.pem"), TokenFile: tokenFile}
		n := &controlNode{cfg: c, reader: reader}
		nodes = append(nodes, n)
		return n
	}
	a := makeNode("node-a")
	initialized, err := app.Initialize(ctx, a.cfg, adminKey.Public, "init-vault-ha")
	if err != nil {
		t.Fatal(err)
	}
	a.runtime, err = app.Open(a.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.runtime.InstallConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	clusterID := initialized.Installation.Root.Cluster
	sourceKey := a.runtime.Identity.Public
	policy := control.Policy{Cluster: clusterID, BootstrapKey: adminKey.Public, TrustRoot: sourceKey, Genesis: initialized.Installation.Genesis}
	self, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(self.Private)
	var peerMu sync.RWMutex
	peers := map[mydcp.Identity]mydcp.Peer{}
	client := userauth.Client{Self: self, Cluster: clusterID}
	addPeer := func(id, address string, key [32]byte) mydcp.Peer {
		p := mydcp.Peer{ID: id, Endpoint: address, Policy: mydcp.Policy{Key: mydcp.Identity(key), Respond: true}}
		peerMu.Lock()
		peers[p.Key] = p
		peerMu.Unlock()
		client.Peers = append(client.Peers, p)
		return p
	}
	a.peer = addPeer(a.cfg.Node.ID, a.cfg.Node.Listen, sourceKey)
	client.Mesh, err = mydcp.NewTransport(self, clusterID, func(k mydcp.Identity) (mydcp.Peer, bool) {
		peerMu.RLock()
		defer peerMu.RUnlock()
		p, ok := peers[k]
		return p, ok
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Mesh.Close()
	enrolled, err := client.Enroll(ctx, a.peer, control.Enrollment{Schema: 1, RequestID: "enroll-ha", User: access.User{ID: "admin", Username: "operator", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: adminKey.Public, Enabled: true}}}}, adminKey.Private)
	if err != nil || enrolled.Result == nil || enrolled.Result.Code != state.Applied {
		t.Fatal("enroll", err)
	}
	session, err := client.Login(ctx, a.peer, "operator", adminKey.Private)
	if err != nil {
		t.Fatal(err)
	}
	target := a.peer
	propose := func(id, action string, expected uint64, payload any) {
		t.Helper()
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		op, err := client.Prepare(ctx, target, session, id, control.Change{Schema: 1, Principal: "admin", Action: action, Expected: expected, Payload: raw})
		if err != nil {
			t.Fatal("prepare", action, err)
		}
		reply, err := client.Operation(ctx, target, op, false)
		if err != nil || reply.Result == nil || reply.Result.Code != state.Applied {
			t.Fatal("submit", action, reply.Result, err)
		}
	}
	password := []byte("actual-vault-ha-password")
	defer clear(password)
	pwRef, tokenRef := "vault/system/system/credentials/admin/password@1", "vault/system/system/credentials/admin/robot@1"
	material, err := credentials.NewPassword(clusterID, "admin", "password", pwRef, password, bytes.Repeat([]byte{41}, 16), identity.DefaultPasswordCost())
	if err != nil {
		t.Fatal(err)
	}
	defer material.Destroy()
	pwBytes, _ := material.ProtectedBytes()
	defer clear(pwBytes)
	vault.api("POST", "kv/data/system/credentials/admin/password", map[string]any{"data": map[string]any{"credential": string(pwBytes)}, "options": map[string]int{"cas": 0}}, nil, vault.admin)
	random := make([]byte, 32)
	if _, err = rand.Read(random); err != nil {
		t.Fatal(err)
	}
	defer clear(random)
	token := []byte(base64.RawURLEncoding.EncodeToString(random))
	defer clear(token)
	robot, err := credentials.NewToken(clusterID, "admin", "robot", tokenRef, token, time.Now().Unix()+300, []access.Scope{{Tenant: "first", Actions: []access.Action{access.Read}}})
	if err != nil {
		t.Fatal(err)
	}
	defer robot.Destroy()
	tokenBytes, _ := robot.ProtectedBytes()
	defer clear(tokenBytes)
	vault.api("POST", "kv/data/system/credentials/admin/robot", map[string]any{"data": map[string]any{"credential": string(tokenBytes)}, "options": map[string]int{"cas": 0}}, nil, vault.admin)
	view, err := a.runtime.Engine().Read(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := policy.Catalog(view.State)
	if err != nil {
		t.Fatal(err)
	}
	account, _ := catalog.User("admin")
	expected := account.Revision
	account.Revision = 0
	account.Credentials = append(account.Credentials, access.Credential{ID: "password", Method: access.Password, VerifierRef: pwRef, Enabled: true}, access.Credential{ID: "robot", Method: access.Token, VerifierRef: tokenRef, Enabled: true})
	propose("enable-protected", "put-user", expected, account)
	session, err = client.LoginCredential(ctx, a.peer, "operator", access.Password, "password", password)
	if err != nil {
		t.Fatal("first actual Vault password login", err)
	}
	// The real catalog boundary rejects authentication-means=0, while a single
	// protected password is sufficient without retaining a hidden key fallback.
	view, err = a.runtime.Engine().Read(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err = policy.Catalog(view.State)
	if err != nil {
		t.Fatal(err)
	}
	account, _ = catalog.User("admin")
	expected = account.Revision
	account.Revision = 0
	allCredentials := account.Credentials
	account.Credentials = nil
	badPayload, _ := json.Marshal(account)
	badOperation, err := client.Prepare(ctx, target, session, "zero-auth-means", control.Change{Schema: 1, Principal: "admin", Action: "put-user", Expected: expected, Payload: badPayload})
	if err != nil {
		t.Fatal(err)
	}
	rejected, err := client.Operation(ctx, target, badOperation, false)
	if err != nil || rejected.Result == nil || rejected.Result.Code != state.Invalid {
		t.Fatal("catalog accepted authentication-means=0", err)
	}
	account.Credentials = []access.Credential{allCredentials[1]}
	propose("password-only", "put-user", expected, account)
	if _, err = client.Login(ctx, target, "operator", adminKey.Private); err == nil {
		t.Fatal("removed user key remained a hidden login fallback")
	}
	session, err = client.LoginCredential(ctx, target, "operator", access.Password, "password", password)
	if err != nil {
		t.Fatal("single password credential login", err)
	}
	view, err = a.runtime.Engine().Read(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err = policy.Catalog(view.State)
	if err != nil {
		t.Fatal(err)
	}
	account, _ = catalog.User("admin")
	expected = account.Revision
	account.Revision = 0
	account.Credentials = []access.Credential{allCredentials[1], allCredentials[2]}
	propose("password-and-token", "put-user", expected, account)
	session, err = client.LoginCredential(ctx, target, "operator", access.Password, "password", password)
	if err != nil {
		t.Fatal("updated protected credential catalog", err)
	}
	propose("tenant-first", "create-tenant", 0, control.TenantID{ID: "first"})
	directory := func(r *app.Runtime) membership.Directory {
		t.Helper()
		view, err := r.Engine().Read(ctx, false)
		if err != nil {
			t.Fatal(err)
		}
		d, err := policy.Members(view.State)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	wait := func(label string, check func() bool) {
		t.Helper()
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for !check() {
			select {
			case <-ctx.Done():
				t.Fatal(label, ctx.Err())
			case <-tick.C:
			}
		}
	}
	for _, id := range []string{"node-b", "node-c"} {
		n := makeNode(id)
		key, err := identity.Create(n.cfg.Node.IdentityDir)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(key.Private)
		peer := config.Peer{ID: id, Key: key.Actor(), Endpoint: n.cfg.Node.Listen}
		propose("invite-"+id, "invite-node", 0, control.NodeInvitation{Peer: peer, JoinID: "join-" + id})
		inv, err := client.NodeInvitation(ctx, target, session, id)
		if err != nil {
			t.Fatal(err)
		}
		n.runtime, _, err = app.Join(ctx, n.cfg, inv, clusterID, sourceKey)
		if err != nil {
			t.Fatal("actual protected control join", err)
		}
		n.peer = addPeer(id, n.cfg.Node.Listen, n.runtime.Identity.Public)
		wait("installed joining directory", func() bool { e, ok := directory(a.runtime).Entry(id); return ok && e.Phase == membership.Ready })
		e, _ := directory(a.runtime).Entry(id)
		propose("promote-"+id, "promote-node", e.Revision, control.NodeSelection{ID: id})
		wait("promoted control and installed session authority", func() bool {
			e, ok := directory(a.runtime).Entry(id)
			if !ok || e.Phase != membership.Active || !e.Peer.Voter {
				return false
			}
			// Observe commits the voter role before the configuration report
			// installs that role as login authority on the joining control.
			for _, issuer := range directory(n.runtime).SessionIssuers() {
				if issuer == n.runtime.Identity.Public {
					return true
				}
			}
			return false
		})
	}
	if err = a.runtime.Close(); err != nil {
		t.Fatal(err)
	}
	a.runtime = nil
	var leader, other *controlNode
	wait("new majority leader", func() bool {
		for _, n := range nodes[1:] {
			if n.runtime.Engine().IsLeader() {
				if _, err := n.runtime.Engine().Read(ctx, true); err == nil {
					leader = n
					return true
				}
			}
		}
		return false
	})
	for _, n := range nodes[1:] {
		if n != leader {
			other = n
		}
	}
	target = leader.peer
	session, err = client.LoginCredential(ctx, target, "operator", access.Password, "password", password)
	if err != nil || session.Issuer == sourceKey || session.Issuer != leader.runtime.Identity.Public {
		t.Fatal("new issuer did not read real protected backend", err)
	}
	propose("after-handoff", "create-tenant", 0, control.TenantID{ID: "after"})
	limited, err := client.LoginCredential(ctx, target, "operator", access.Token, "robot", token)
	if err != nil {
		t.Fatal("new leader token login", err)
	}
	if len(limited.Scopes) != 1 || limited.Scopes[0].Tenant != "first" {
		t.Fatal("token ceiling widened during handoff")
	}
	if _, err = client.Query(ctx, other.peer, limited, "select-tenant", "first"); err != nil {
		t.Fatal("new protected session follower relay", err)
	}
	// Each control uses its own installed reader token. Losing one reader must
	// not fall back to root/another control's installation credential.
	vault.api("POST", "auth/token/revoke", map[string]any{"token": leader.reader}, nil, vault.admin)
	if _, err = client.LoginCredential(ctx, target, "operator", access.Password, "password", password); err == nil {
		t.Fatal("revoked local reader fell back")
	}
	if _, err = client.Query(ctx, other.peer, session, "whoami", ""); err != nil {
		t.Fatal("backend credential revocation falsely revoked an issued session", err)
	}
	// Temporarily lose quorum, then reopen the same voter root with a newly
	// installed reader token. Neither node identity nor catalog is recreated.
	if _, err = leader.runtime.InstallConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	originalView, err := leader.runtime.Engine().Read(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	oldKey := leader.runtime.Identity.Public
	if err = leader.runtime.Close(); err != nil {
		t.Fatal(err)
	}
	leader.runtime = nil
	short, stop := context.WithTimeout(ctx, 500*time.Millisecond)
	_, minorityErr := client.LoginCredential(short, other.peer, "operator", access.Password, "password", password)
	stop()
	if minorityErr == nil {
		t.Fatal("minority issued protected login")
	}
	leader.reader = vault.readerToken()
	if err = os.WriteFile(leader.cfg.Credentials.TokenFile, []byte(leader.reader), 0600); err != nil {
		t.Fatal(err)
	}
	leader.runtime, err = app.Open(leader.cfg)
	if err != nil {
		t.Fatal("same voter DB reopen", err)
	}
	if _, err = leader.runtime.ResumeInstallation(ctx); err != nil {
		t.Fatal("same voter installation", err)
	}
	if leader.runtime.Identity.Public != oldKey {
		t.Fatal("same DB changed identity")
	}
	var current *controlNode
	wait("restored two-voter quorum", func() bool {
		for _, n := range nodes[1:] {
			if n.runtime.Engine().IsLeader() {
				if _, err := n.runtime.Engine().Read(ctx, true); err == nil {
					current = n
					return true
				}
			}
		}
		return false
	})
	fresh, err := client.LoginCredential(ctx, current.peer, "operator", access.Password, "password", password)
	if err != nil {
		t.Fatal("recovered real protected login", err)
	}
	if _, err = client.Query(ctx, current.peer, fresh, "whoami", ""); err != nil {
		t.Fatal(err)
	}
	view, err = current.runtime.Engine().Read(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if view.State.Index() != originalView.State.Index() {
		t.Fatal("completed join recovery submitted new management commands")
	}
	catalog, err = policy.Catalog(view.State)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := catalog.Tenant("after"); !ok {
		t.Fatal("same root lost post-handoff management commit")
	}
	shared, _ := state.Encode(view.State)
	for _, private := range [][]byte{password, token, []byte(`"Verifier":`)} {
		if bytes.Contains(shared, private) {
			t.Fatal("private authentication material entered shared DB")
		}
	}
	t.Log("actual Vault/TLS/ACL + dynamically joined N3/Q2: password-authorized admin changes, source loss/new issuer, token scope/follower relay, per-node reader revocation/no fallback, minority login rejection and original voter DB/key/recovered reader")
}
