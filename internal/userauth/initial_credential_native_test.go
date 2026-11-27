// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/credentials"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/secrets"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/tests/vaultfixture"
)

// Owns only a loopback Vault/TLS/file-store fixture, one Raft/bbolt root and
// User transport sockets. No Docker/host routing effects. Execute once at the
// final RQ4 gate with the explicitly pinned Vault binary already prepared.
func TestInitialCredentialActualVaultManagedRaftAndUserLogin(t *testing.T) {
	if os.Getenv("SFC_TEST_RQ4_INITIAL_CREDENTIAL") != "1" {
		t.Skip("requires explicit RQ4 owned Vault/system rollback gate")
	}
	if !filepath.IsAbs(os.Getenv("SFC_TEST_CLI")) {
		t.Fatal("explicit prebuilt CLI is required for initial-credential acceptance")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	v := vaultfixture.Open(t)
	v.API("PUT", "sys/policies/acl/sfc-initial-writer", map[string]any{"policy": `path "kv/data/system/credentials/*" { capabilities = ["create", "read"] }`}, nil, v.Admin)
	var token struct {
		Auth struct {
			Token string `json:"client_token"`
		} `json:"auth"`
	}
	v.API("POST", "auth/token/create", map[string]any{"policies": []string{"sfc-initial-writer"}, "no_default_policy": true, "ttl": "5m"}, &token, v.Admin)
	if token.Auth.Token == "" {
		t.Fatal("owned system provider credential absent")
	}
	backend, err := credentials.NewBackend(secrets.VaultProfile{ID: "system", Address: v.Address, Mount: "kv", Prefix: "system/credentials", Token: token.Auth.Token, Roots: v.Roots, Timeout: 3 * time.Second, MaxBytes: 128 << 10})
	token.Auth.Token = ""
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	key := func() *identity.Identity {
		t.Helper()
		k, err := identity.Ephemeral()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { clear(k.Private) })
		return k
	}
	node, admin, proof, browser := key(), key(), key(), key()
	clusterID := [32]byte{215}
	peer := sfcp.Peer{ID: "node-a", Policy: sfcp.Policy{Key: sfcp.Identity(node.Public), Member: true, Read: true, Respond: true}}
	server, err := sfcp.NewTransportWithPurposeLookup(node, clusterID, func(k sfcp.Identity, purpose sfcp.Purpose) (sfcp.Peer, bool) {
		if k == peer.Key {
			return peer, true
		}
		if purpose == sfcp.Handshake || purpose == sfcp.User || purpose == sfcp.ContainerSession || purpose == 0 {
			return sfcp.Peer{ID: "user-client", Policy: sfcp.Policy{Key: k, UserAuth: true}}, true
		}
		return peer, k == peer.Key
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err = server.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	peer.Endpoint = server.Addr().String()
	policy := control.Policy{Cluster: clusterID, BootstrapKey: admin.Public, TrustRoot: node.Public, Genesis: config.Peer{ID: peer.ID, Key: hex.EncodeToString(node.Public[:]), Endpoint: peer.Endpoint, Voter: true}}
	root := t.TempDir()
	e, err := cluster.Open(cluster.Options{ID: peer.ID, Root: filepath.Join(root, "node-db"), Admin: admin.Actor(), Cluster: clusterID, Mesh: server, Bootstrap: true,
		Servers: []raft.Server{{ID: raft.ServerID(peer.ID), Address: raft.ServerAddress(peer.Endpoint), Suffrage: raft.Voter}}, Resolve: func(id raft.ServerID, _ raft.ServerAddress) (sfcp.Peer, bool) { return peer, string(id) == peer.ID },
		ModuleID: policy.ID(), Validate: policy.ValidateManaged, Reduce: policy.Reduce, AdmitModule: policy.AdmitModule, AdmitMutation: policy.AdmitAppMutation, AdmitModulePatch: policy.AdmitAppPatch})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err = e.ServeManagement(); err != nil {
		t.Fatal(err)
	}
	for {
		if _, err = e.Read(ctx, true); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	if err = (Service{Engine: e, Mesh: server, Self: node, Policy: policy, Credentials: backend}).Serve(); err != nil {
		t.Fatal(err)
	}
	mesh, err := sfcp.NewTransport(proof, clusterID, func(k sfcp.Identity) (sfcp.Peer, bool) { return peer, k == peer.Key })
	if err != nil {
		t.Fatal(err)
	}
	defer mesh.Close()
	c := Client{Mesh: mesh, Self: proof, Cluster: clusterID, Peers: []sfcp.Peer{peer}}
	if _, err = c.Enroll(ctx, peer, control.Enrollment{Schema: 1, RequestID: "rq4-initial-enroll", User: access.User{ID: "admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: admin.Public, Enabled: true}}}}, admin.Private); err != nil {
		t.Fatal(err)
	}
	adminSession, err := c.Login(ctx, peer, "admin", admin.Private)
	if err != nil {
		t.Fatal(err)
	}
	sequence := 0
	apply := func(session access.Session, action string, expected uint64, payload any) control.UserOperation {
		t.Helper()
		sequence++
		raw, err := control.ChangeBytes(action, session.User, expected, payload)
		if err != nil {
			t.Fatal(err)
		}
		var change control.Change
		if json.Unmarshal(raw, &change) != nil {
			t.Fatal("change encoding")
		}
		op, err := c.Prepare(ctx, peer, session, fmt.Sprintf("rq4-initial-%d", sequence), change)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = StageOperation(root, c, op); err != nil {
			t.Fatal(err)
		}
		reply, err := c.Operation(ctx, peer, op, false)
		if err != nil || reply.Result == nil || reply.Result.Code != state.Applied {
			t.Fatal("actual initial user mutation", action, err)
		}
		if err = RecordOperationResult(root, c, session, op, *reply.Result); err != nil {
			t.Fatal(err)
		}
		return op
	}
	apply(adminSession, "put-user", 0, access.User{ID: "new-user", Username: "new.user", Enabled: true})
	account, err := c.UserCredentials(ctx, peer, adminSession, "new.user")
	if err != nil || account.CredentialUser == nil {
		t.Fatal(err)
	}
	r := credentials.InitialRequest{Schema: 1, Cluster: clusterID, Owner: node.Public, Operation: [32]byte{1}, User: "new-user", Username: "new.user", Credential: "first-password", Profile: "system", Method: access.Password, ExpectedUserRevision: account.CredentialUser.Revision, At: time.Now().Unix()}
	if _, err = StageInitialIntent(root, c, adminSession, "password-stage", r); err != nil {
		t.Fatal(err)
	}
	if err = MarkInitialDispatch(root, c, adminSession, "password-stage"); err != nil {
		t.Fatal(err)
	}
	password := []byte("rq4-initial-password-never-recorded")
	defer clear(password)
	prepared, err := c.StageInitialCredential(ctx, peer, adminSession, r, password)
	if err != nil || prepared.InitialCredentialFact == nil || len(prepared.InitialCredentialToken) != 0 {
		t.Fatal("actual private stage", err)
	}
	if err = RecordInitialFact(root, c, adminSession, "password-stage", *prepared.InitialCredentialFact); err != nil {
		t.Fatal(err)
	}
	passwordOperation := apply(adminSession, "issue-initial-credential", r.ExpectedUserRevision, *prepared.InitialCredentialFact)
	if bytes.Contains(control.OperationBytes(passwordOperation), password) {
		t.Fatal("password entered Raft intent")
	}
	userSession, err := c.LoginCredential(ctx, peer, "new.user", access.Password, "first-password", password)
	if err != nil {
		t.Fatal("actual first password login", err)
	}
	addition, err := c.NewCredentialAddition(userSession, "browser", "new browser", browser.Private)
	if err != nil {
		t.Fatal(err)
	}
	apply(userSession, "add-credential", userSession.AccountRevision, addition)
	if _, err = c.Login(ctx, peer, "new.user", browser.Private); err != nil {
		t.Fatal("actual registered browser key login", err)
	}
	// A separate ordinary user gets a token whose raw bytes never enter Raft.
	apply(adminSession, "put-user", 0, access.User{ID: "token-user", Username: "token.user", Enabled: true})
	account, err = c.UserCredentials(ctx, peer, adminSession, "token.user")
	if err != nil || account.CredentialUser == nil {
		t.Fatal(err)
	}
	r.User, r.Username, r.Credential, r.Method, r.ExpectedUserRevision, r.Operation = "token-user", "token.user", "first-token", access.Token, account.CredentialUser.Revision, [32]byte{2}
	r.At = time.Now().Unix()
	if _, err = StageInitialIntent(root, c, adminSession, "token-stage", r); err != nil {
		t.Fatal(err)
	}
	if err = MarkInitialDispatch(root, c, adminSession, "token-stage"); err != nil {
		t.Fatal(err)
	}
	prepared, err = c.StageInitialCredential(ctx, peer, adminSession, r, nil)
	if err != nil || prepared.InitialCredentialFact == nil || len(prepared.InitialCredentialToken) != 43 {
		t.Fatal("actual token stage", err)
	}
	defer clear(prepared.InitialCredentialToken)
	tokenOperation := apply(adminSession, "issue-initial-credential", r.ExpectedUserRevision, *prepared.InitialCredentialFact)
	if bytes.Contains(control.OperationBytes(tokenOperation), prepared.InitialCredentialToken) {
		t.Fatal("token entered Raft intent")
	}
	tokenSession, err := c.LoginCredential(ctx, peer, "token.user", access.Token, "first-token", prepared.InitialCredentialToken)
	if err != nil {
		t.Fatal("actual first token login", err)
	}
	if _, err = c.LoginCredential(ctx, peer, "token.user", access.Token, "first-token", prepared.InitialCredentialToken); err == nil {
		t.Fatal("actual token reused")
	}
	if _, err = c.Whoami(ctx, peer, tokenSession); err != nil {
		t.Fatal("consuming token invalidated issued session", err)
	}
	v.Stop()
	v.Start()
	v.UnsealOriginal()
	if _, err = c.LoginCredential(ctx, peer, "token.user", access.Token, "first-token", prepared.InitialCredentialToken); err == nil {
		t.Fatal("token reused after actual Vault restart")
	}
	// The ledger's exact original is still a result, with no regenerated secret.
	reply, err := c.Operation(ctx, peer, tokenOperation, true)
	if err != nil || reply.Result == nil || reply.Result.Code != state.Applied || len(reply.InitialCredentialToken) != 0 {
		t.Fatal("original public result replay", err)
	}
	verifyInitialCredentialCLI(t, ctx, root, c, peer, adminSession, admin)
}
