// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/app"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/secrets"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/workload"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

func TestRealVaultManagedMetadataAndOriginalProviderJournal(t *testing.T) {
	testRealVaultManagedRuntime(t, false)
}
func TestRealVaultReplacementWriterRecoversOriginalWithoutPut(t *testing.T) {
	testRealVaultManagedRuntime(t, true)
}
func testRealVaultManagedRuntime(t *testing.T, replacementWriter bool) {
	vault := newOwnedVault(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	root := t.TempDir()
	admin, err := identity.Create(filepath.Join(root, "admin"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(admin.Private)
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := socket.LocalAddr().String()
	_ = socket.Close()
	cfg := config.Node{Version: 1, Common: config.Common{}, Modules: map[string]config.Module{"network": {}, "workload": {}, "ingress": {}}}
	cfg.Node.ID, cfg.Node.Listen = "node-a", address
	cfg.Node.StateDir, cfg.Node.IdentityDir = filepath.Join(root, "state"), filepath.Join(root, "node")
	// sfcd leaves the app secret tmpfs mounted when it stops (running
	// containers bind from it); the test unmounts it before TempDir cleanup.
	t.Cleanup(func() { unmountInputMemory(cfg.Node.StateDir) })
	initialized, err := app.Initialize(ctx, cfg, admin.Public, "init-vault")
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := app.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if runtime != nil {
			_ = runtime.Close()
		}
	}()
	if _, err = runtime.InstallConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	clusterID := initialized.Installation.Root.Cluster
	policy := control.Policy{Cluster: clusterID, BootstrapKey: admin.Public, TrustRoot: runtime.Identity.Public, Genesis: initialized.Installation.Genesis}
	peer := sfcp.Peer{ID: cfg.Node.ID, Endpoint: address, Policy: sfcp.Policy{Key: sfcp.Identity(runtime.Identity.Public), Respond: true}}
	proof, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(proof.Private)
	mesh, err := sfcp.NewTransport(proof, clusterID, func(k sfcp.Identity) (sfcp.Peer, bool) { return peer, k == peer.Key })
	if err != nil {
		t.Fatal(err)
	}
	defer mesh.Close()
	user := userauth.Client{Mesh: mesh, Self: proof, Cluster: clusterID, Peers: []sfcp.Peer{peer}}
	enrolled, err := user.Enroll(ctx, peer, control.Enrollment{Schema: 1, RequestID: "enroll-vault", User: access.User{ID: "admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: admin.Public, Enabled: true}}}}, admin.Private)
	if err != nil || enrolled.Result == nil || enrolled.Result.Code != state.Applied {
		t.Fatal("enroll", err)
	}
	session, err := user.Login(ctx, peer, "admin", admin.Private)
	if err != nil {
		t.Fatal(err)
	}
	read := func() state.State {
		t.Helper()
		for {
			view, e := runtime.Engine().Read(ctx, true)
			if e == nil {
				return view.State
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	current := func() control.Vault {
		t.Helper()
		v, e := policy.Vault(read())
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	apply := func(id, action string, expected uint64, payload any, want state.Code) control.UserOperation {
		t.Helper()
		raw, e := control.ChangeBytes(action, "admin", expected, payload)
		if e != nil {
			t.Fatal(e)
		}
		var ch control.Change
		_ = json.Unmarshal(raw, &ch)
		op, e := user.Prepare(ctx, peer, session, id, ch)
		if e != nil {
			t.Fatal(id, e)
		}
		reply, e := user.Operation(ctx, peer, op, false)
		if e != nil || reply.Result == nil || reply.Result.Code != want {
			t.Fatal(id, reply.Code, reply.Result, want, e)
		}
		return op
	}
	apply("tenant", "create-tenant", 0, control.TenantID{ID: "tenant"}, state.Applied)
	catalog, _ := policy.Catalog(read())
	tenant, _ := catalog.Tenant("tenant")
	apply("nodes", "set-nodes", tenant.Revision, control.NodeChangeTo("tenant", tenant.AllowedNodes, []string{"node-a"}), state.Applied)
	if len(current().Trees) != 0 {
		t.Fatal("implicit Vault realm in blank cluster")
	}
	apply("init", "vault-init", 0, control.VaultRealm{Realm: "tenant", Root: "root"}, state.Applied)
	apply("group", "vault-create", current().Trees["tenant"].Revision(), control.VaultObject{Realm: "tenant", Object: secrets.Object{ID: "group", Parent: "root", Kind: secrets.Group}}, state.Applied)
	apply("secret", "vault-create", current().Trees["tenant"].Revision(), control.VaultObject{Realm: "tenant", Object: secrets.Object{ID: "runtime", Parent: "group", Kind: secrets.Secret, Reference: secrets.Reference{Profile: "values", Object: "tenant/runtime", Keys: []string{"key"}}}}, state.Applied)
	apply("writer", "vault-set-profile", current().Trees["tenant"].Revision(), control.VaultProfile{Realm: "tenant", Profile: secrets.WriteProfile{ID: "values", Node: "node-a", Key: runtime.Identity.Public, Enabled: true, Values: true}}, state.Applied)
	request := secrets.WriteRequest{ID: "first-write", Object: "runtime", Profile: "values", ProviderObject: "tenant/runtime", Epoch: 1, Kind: secrets.ValueWrite, Keys: []string{"key"}}
	apply("prepare", "vault-prepare-write", current().Trees["tenant"].Revision(), control.VaultWrite{Realm: "tenant", Request: request}, state.Applied)
	apply("rotate-blocked", "rotate-ledger", 1, control.LedgerWindow{NextEpoch: 2}, state.ConditionFailed)
	apply("dispatch", "vault-dispatch-write", current().Trees["tenant"].Revision(), control.VaultWriteAction{Realm: "tenant", ID: request.ID, Epoch: 1}, state.Applied)
	record, _ := current().Trees["tenant"].Write(request.ID)
	// Actual Vault auth/DB remains authoritative. The TLS proxy injects one
	// lost successful PUT response; it does not implement or replace the provider.
	destination, _ := url.Parse(vault.address)
	proxy := httputil.NewSingleHostReverseProxy(destination)
	proxy.Transport = vault.client.Transport
	var puts atomic.Int32
	var loseAt atomic.Int32
	var pauseVerifier atomic.Bool
	var pauseValue atomic.Bool
	var valueReads atomic.Int32
	verifierEntered, verifierContinue := make(chan struct{}, 1), make(chan struct{})
	valueEntered, valueContinue := make(chan struct{}, 1), make(chan struct{})
	loseAt.Store(1)
	proxy.ModifyResponse = func(response *http.Response) error {
		if response.Request.Method == "GET" && response.Request.URL.Path == "/v1/kv/data/other/data" {
			valueReads.Add(1)
			if pauseValue.CompareAndSwap(true, false) {
				valueEntered <- struct{}{}
				select {
				case <-valueContinue:
				case <-response.Request.Context().Done():
				}
			}
		}
		if response.Request.Method == "GET" && strings.HasPrefix(response.Request.URL.Path, "/v1/kv/data/groups/other/") && pauseVerifier.CompareAndSwap(true, false) {
			verifierEntered <- struct{}{}
			select {
			case <-verifierContinue:
			case <-response.Request.Context().Done():
			}
		}
		if response.Request.Method == "PUT" && puts.Add(1) == loseAt.Load() {
			response.Body.Close()
			response.StatusCode = 503
			response.Status = "503 injected response loss"
			response.Body = io.NopCloser(strings.NewReader(`{"errors":["injected response loss"]}`))
			response.ContentLength = -1
			response.Header.Del("Content-Length")
		}
		return nil
	}
	server := httptest.NewTLSServer(proxy)
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	vault.api("PUT", "sys/policies/acl/sfc-app-writer", map[string]any{"policy": `path "kv/data/tenant/*" { capabilities = ["create","update","read"] } path "kv/data/groups/tenant/*" { capabilities = ["create","update","read"] } path "kv/data/other/*" { capabilities = ["create","update","read"] } path "kv/data/groups/other/*" { capabilities = ["create","update","read"] }`}, nil, vault.admin)
	var issued struct {
		Auth struct {
			Token string `json:"client_token"`
		} `json:"auth"`
	}
	vault.api("POST", "auth/token/create", map[string]any{"policies": []string{"sfc-app-writer"}, "no_default_policy": true, "ttl": "5m"}, &issued, vault.admin)
	profile := secrets.VaultProfile{ID: "values", Address: server.URL, Mount: "kv", Prefix: "tenant", Token: issued.Auth.Token, Roots: roots, Timeout: 2 * time.Second, MaxBytes: 64 << 10}
	provider, err := secrets.NewVault(profile)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	journalPath := filepath.Join(root, "writer.db")
	writer, err := secrets.OpenWriter(journalPath, provider)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if writer != nil {
			_ = writer.Close()
		}
	}()
	private := []byte("private-first-provider-value")
	defer clear(private)
	if _, err = writer.Apply(ctx, clusterID, "tenant", record, map[string][]byte{"key": private}, false); err == nil {
		t.Fatal("lost response did not remain Unknown")
	}
	local, err := writer.Record(clusterID, "tenant", record)
	if err != nil || local.State.Pending == nil || local.State.Pending.Phase != reconcile.RecoveryRequired || puts.Load() != 1 {
		t.Fatal("original local provider dispatch", err)
	}
	rawLocal, _ := json.Marshal(local)
	if bytes.Contains(rawLocal, private) {
		t.Fatal("private material in A2")
	}
	observe := func(w secrets.WriteRecord, outcome reconcile.Outcome, revision uint64, ref string) {
		t.Helper()
		fact := secrets.WriteObservation{Cluster: clusterID, Tenant: "tenant", Request: w.Request, Generation: w.Generation, ExpectedObjectRevision: w.ExpectedObjectRevision, Writer: w.Writer, Operation: w.Journal.LastID, Outcome: outcome, ProviderRevision: revision, VerifierRef: ref}
		fact.Signature = ed25519.Sign(runtime.Identity.Private, secrets.WriteObservationBytes(fact))
		apply("observe-"+w.Request.ID+fmt.Sprint(outcome), "vault-observe-write", current().Trees["tenant"].Revision(), control.VaultObserve{Observation: fact}, state.Applied)
	}
	observe(record, reconcile.EffectUnknown, 0, "")
	saved := current()
	commandState, _ := state.Encode(read())
	if bytes.Contains(commandState, private) {
		t.Fatal("secret in shared state")
	}
	if err = runtime.Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if err = runtime.Close(); err != nil {
		t.Fatal(err)
	}
	runtime = nil
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	writer = nil
	caPath, tokenPath := filepath.Join(root, "app-ca.pem"), filepath.Join(root, "app-token")
	if err = os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(tokenPath, []byte(issued.Auth.Token), 0600); err != nil {
		t.Fatal(err)
	}
	cfg.Vaults = []config.VaultBackend{{Realm: "tenant", Profile: "values", Address: server.URL, Mount: "kv", Prefix: "tenant", CAFile: caPath, TokenFile: tokenPath, Values: true}, {Realm: "other", Profile: "values-other", Address: server.URL, Mount: "kv", Prefix: "other", CAFile: caPath, TokenFile: tokenPath, Values: true}, {Realm: "other", Profile: "auth-other", Address: server.URL, Mount: "kv", Prefix: "groups/other", CAFile: caPath, TokenFile: tokenPath, Verifiers: true}}
	runtime, err = app.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runtime.InstallConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(saved, current()) {
		t.Fatal("shared Unknown/tree lost across Snapshot/same DB")
	}
	if replacementWriter {
		verifyRealVaultReplacementWriter(t, ctx, root, cfg, runtime, user, peer, session, current, read, apply, vault, issued.Auth.Token, &puts, request.ID, private)
		return
	}
	writer, err = secrets.OpenWriter(journalPath, provider)
	if err != nil {
		t.Fatal(err)
	}
	record, _ = current().Trees["tenant"].Write(request.ID)
	receipt, err := writer.Apply(ctx, clusterID, "tenant", record, map[string][]byte{"key": []byte("different-never-dispatched")}, false)
	if err != nil || receipt.Revision != 1 || puts.Load() != 1 {
		t.Fatal("original read-back issued another write", puts.Load(), err)
	}
	observe(record, reconcile.EffectApplied, receipt.Revision, "")
	tree := current().Trees["tenant"]
	apply("publish", "vault-publish-write", tree.Revision(), control.VaultWriteAction{Realm: "tenant", ID: request.ID, Epoch: 1, ObjectRevision: record.ExpectedObjectRevision}, state.Applied)
	object, _ := current().Trees["tenant"].Object("runtime")
	got, err := provider.Fetch(ctx, "runtime", object.Reference)
	if err != nil || !bytes.Equal(got.Values["key"], private) {
		t.Fatal("published fixed original value", err)
	}
	for _, b := range got.Values {
		clear(b)
	}
	// A nonexistent original version on a fresh observer is still Unknown. Even
	// supplied private input cannot turn explicit recovery into a provider PUT.
	fresh, err := secrets.OpenWriter(filepath.Join(root, "observer.db"), provider)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	missing := request
	missing.ID = "missing"
	missing.ProviderObject = "tenant/missing"
	apply("missing-secret", "vault-create", current().Trees["tenant"].Revision(), control.VaultObject{Realm: "tenant", Object: secrets.Object{ID: "missing", Parent: "group", Kind: secrets.Secret, Reference: secrets.Reference{Profile: "values", Object: missing.ProviderObject, Keys: []string{"key"}}}}, state.Applied)
	missing.Object = "missing"
	apply("missing-prepare", "vault-prepare-write", current().Trees["tenant"].Revision(), control.VaultWrite{Realm: "tenant", Request: missing}, state.Applied)
	apply("missing-dispatch", "vault-dispatch-write", current().Trees["tenant"].Revision(), control.VaultWriteAction{Realm: "tenant", ID: missing.ID, Epoch: 1}, state.Applied)
	absent, _ := current().Trees["tenant"].Write(missing.ID)
	if _, err = fresh.Apply(ctx, clusterID, "tenant", absent, map[string][]byte{"key": private}, true); err == nil || puts.Load() != 1 {
		t.Fatal("absence became nonexecution/rewrite")
	}
	// Real protected verifier bytes use a separate installed profile/prefix; its
	// public WriteRequest has no Secret keys and publishes only an opaque ref.
	apply("auth-profile", "vault-set-profile", current().Trees["tenant"].Revision(), control.VaultProfile{Realm: "tenant", Profile: secrets.WriteProfile{ID: "auth", Node: "node-a", Key: runtime.Identity.Public, Enabled: true, Verifiers: true}}, state.Applied)
	group, _ := current().Trees["tenant"].Object("group")
	verifierRequest := secrets.WriteRequest{ID: "group-password", Object: "group", Profile: "auth", ProviderObject: fmt.Sprintf("groups/tenant/group/%d", group.Generation), Epoch: 1, Kind: secrets.VerifierWrite, Protected: true}
	apply("auth-prepare", "vault-prepare-write", current().Trees["tenant"].Revision(), control.VaultWrite{Realm: "tenant", Request: verifierRequest}, state.Applied)
	apply("auth-dispatch", "vault-dispatch-write", current().Trees["tenant"].Revision(), control.VaultWriteAction{Realm: "tenant", ID: verifierRequest.ID, Epoch: 1}, state.Applied)
	verifierRecord, _ := current().Trees["tenant"].Write(verifierRequest.ID)
	password := []byte("private-group-password")
	defer clear(password)
	hash, err := identity.PasswordHash(password, bytes.Repeat([]byte{81}, 16), identity.DefaultPasswordCost())
	if err != nil {
		t.Fatal(err)
	}
	protected, err := hash.ProtectedBytes()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(protected)
	authProfile := profile
	authProfile.ID, authProfile.Prefix = "auth", "groups/tenant"
	auth, err := secrets.NewVault(authProfile)
	if err != nil {
		t.Fatal(err)
	}
	defer auth.Close()
	authWriter, err := secrets.OpenWriter(filepath.Join(root, "auth-writer.db"), auth)
	if err != nil {
		t.Fatal(err)
	}
	defer authWriter.Close()
	verifierReceipt, err := authWriter.Apply(ctx, clusterID, "tenant", verifierRecord, map[string][]byte{"verifier": protected}, false)
	if err != nil || verifierReceipt.Revision != 1 || puts.Load() != 2 {
		t.Fatal("real verifier provider write", err)
	}
	observe(verifierRecord, reconcile.EffectApplied, verifierReceipt.Revision, "group-password-record")
	apply("auth-publish", "vault-publish-write", current().Trees["tenant"].Revision(), control.VaultWriteAction{Realm: "tenant", ID: verifierRequest.ID, Epoch: 1, ObjectRevision: verifierRecord.ExpectedObjectRevision}, state.Applied)
	group, _ = current().Trees["tenant"].Object("group")
	if !group.Protected || group.VerifierRef != "group-password-record" {
		t.Fatal("verifier policy not published")
	}
	fetched, err := auth.Fetch(ctx, "group", secrets.Reference{Profile: "auth", Object: verifierRequest.ProviderObject, Revision: 1, Keys: []string{"verifier"}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, b := range fetched.Values {
			clear(b)
		}
	}()
	restored, err := identity.RestorePasswordVerifier(fetched.Values["verifier"])
	if err != nil || !restored.Verify(password) || restored.Verify([]byte("wrong")) {
		t.Fatal("real stored Argon2 verifier", err)
	}
	if _, err = provider.Fetch(ctx, "group", secrets.Reference{Profile: "auth", Object: verifierRequest.ProviderObject, Revision: 1, Keys: []string{"verifier"}}); err == nil {
		t.Fatal("value profile read protected verifier")
	}
	page, err := user.QueryVault(ctx, peer, session, "tenant", "")
	if err != nil || len(page.Items) == 0 || page.RootRevision == 0 || page.TreeRevision != current().Trees["tenant"].Revision() {
		t.Fatal("actual public Vault view", err)
	}
	// Unknown/private fields cannot enter replicated management intents.
	rawInput := []byte(`{"schema":1,"action":"vault-create","expected":1,"payload":{"Realm":"tenant","Object":{"ID":"bad","Password":"never-share"}}}`)
	if _, err = control.InputChange(rawInput, "admin"); err == nil {
		t.Fatal("private metadata field accepted")
	}
	final, _ := state.Encode(read())
	if bytes.Contains(final, password) || bytes.Contains(final, protected) || bytes.Contains(final, private) {
		t.Fatal("private provider material in shared DB/ledger")
	}
	if _, err = os.Stat(journalPath); err != nil {
		t.Fatal(err)
	}
	// Now consume the same provider through the actual Runtime's dedicated
	// authenticated sensitive stream and installed realm/profile. No plaintext
	// request is forwarded to a leader or entered in a shared command.
	rpcValue := []byte("private-runtime-stream-value")
	defer clear(rpcValue)
	apply("rpc-secret", "vault-create", current().Trees["tenant"].Revision(), control.VaultObject{Realm: "tenant", Object: secrets.Object{ID: "rpc", Parent: "group", Kind: secrets.Secret, Reference: secrets.Reference{Profile: "values", Object: "tenant/rpc", Keys: []string{"key"}}}}, state.Applied)
	rpcRequest := secrets.WriteRequest{ID: "rpc-write", Object: "rpc", Profile: "values", ProviderObject: "tenant/rpc", Epoch: 1, Kind: secrets.ValueWrite, Keys: []string{"key"}}
	apply("rpc-prepare", "vault-prepare-write", current().Trees["tenant"].Revision(), control.VaultWrite{Realm: "tenant", Request: rpcRequest}, state.Applied)
	apply("rpc-dispatch", "vault-dispatch-write", current().Trees["tenant"].Revision(), control.VaultWriteAction{Realm: "tenant", ID: rpcRequest.ID, Epoch: 1}, state.Applied)
	loseAt.Store(3)
	unknown, unknownErr := user.WriteVault(ctx, peer, session, userauth.SecretRequest{Realm: "tenant", ID: rpcRequest.ID, Mode: "execute", Values: map[string][]byte{"key": rpcValue}})
	if unknownErr == nil || unknown.Code != "unknown" || unknown.VaultObservation == nil || unknown.VaultObservation.Outcome != reconcile.EffectUnknown || puts.Load() != 3 {
		t.Fatal("real private stream Unknown", unknown.Code, puts.Load(), unknownErr)
	}
	apply("rpc-observe-unknown", "vault-observe-write", current().Trees["tenant"].Revision(), control.VaultObserve{Observation: *unknown.VaultObservation}, state.Applied)
	if err = runtime.Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if err = runtime.Close(); err != nil {
		t.Fatal(err)
	}
	runtime = nil
	runtime, err = app.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runtime.InstallConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	_ = read()
	recovered, recoverErr := user.WriteVault(ctx, peer, session, userauth.SecretRequest{Realm: "tenant", ID: rpcRequest.ID, Mode: "recover"})
	if recoverErr != nil || recovered.VaultObservation == nil || recovered.VaultObservation.Outcome != reconcile.EffectApplied || recovered.VaultObservation.ProviderRevision != 1 || puts.Load() != 3 {
		t.Fatal("real private stream original recovery", recovered.Code, puts.Load(), recoverErr)
	}
	apply("rpc-observe-applied", "vault-observe-write", current().Trees["tenant"].Revision(), control.VaultObserve{Observation: *recovered.VaultObservation}, state.Applied)
	rpcRecord, _ := current().Trees["tenant"].Write(rpcRequest.ID)
	apply("rpc-publish", "vault-publish-write", current().Trees["tenant"].Revision(), control.VaultWriteAction{Realm: "tenant", ID: rpcRequest.ID, Epoch: 1, ObjectRevision: rpcRecord.ExpectedObjectRevision}, state.Applied)
	rpcObject, _ := current().Trees["tenant"].Object("rpc")
	rpcFetched, e := provider.Fetch(ctx, "rpc", rpcObject.Reference)
	if e != nil || !bytes.Equal(rpcFetched.Values["key"], rpcValue) {
		t.Fatal("Runtime original private value", e)
	}
	for _, b := range rpcFetched.Values {
		clear(b)
	}
	// Execute cannot use an already settled or wrong realm provider operation.
	if _, e = user.WriteVault(ctx, peer, session, userauth.SecretRequest{Realm: "tenant", ID: rpcRequest.ID, Mode: "execute", Values: map[string][]byte{"key": []byte("replacement")}}); e == nil || puts.Load() != 3 {
		t.Fatal("settled provider executed again")
	}
	if _, e = user.WriteVault(ctx, peer, session, userauth.SecretRequest{Realm: "other", ID: rpcRequest.ID, Mode: "recover"}); e == nil || puts.Load() != 3 {
		t.Fatal("foreign realm provider recovery")
	}
	// Exercise the new adapter's realm/session ceiling with a real second
	// user, rather than infer tenant isolation from system-admin success.
	bobKey, e := identity.Ephemeral()
	if e != nil {
		t.Fatal(e)
	}
	defer clear(bobKey.Private)
	apply("other-tenant", "create-tenant", 0, control.TenantID{ID: "other"}, state.Applied)
	apply("bob-user", "put-user", 0, access.User{ID: "bob", Username: "bob", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: bobKey.Public, Enabled: true}}}, state.Applied)
	apply("bob-membership", "set-membership", 0, access.Membership{Tenant: "other", User: "bob", Role: access.Manager, Enabled: true}, state.Applied)
	bobProof, e := identity.Ephemeral()
	if e != nil {
		t.Fatal(e)
	}
	defer clear(bobProof.Private)
	bobMesh, e := sfcp.NewTransport(bobProof, clusterID, func(k sfcp.Identity) (sfcp.Peer, bool) { return peer, k == peer.Key })
	if e != nil {
		t.Fatal(e)
	}
	defer bobMesh.Close()
	bob := userauth.Client{Mesh: bobMesh, Self: bobProof, Cluster: clusterID, Peers: []sfcp.Peer{peer}}
	bobSession, e := bob.Login(ctx, peer, "bob", bobKey.Private)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = bob.Query(ctx, peer, bobSession, "vault", "tenant"); e == nil {
		t.Fatal("cross-tenant metadata disclosed")
	}
	if _, e = bob.Query(ctx, peer, bobSession, "vault", ""); e == nil {
		t.Fatal("tenant manager read cluster realm")
	}
	if _, e = bob.WriteVault(ctx, peer, bobSession, userauth.SecretRequest{Realm: "tenant", ID: rpcRequest.ID, Mode: "recover"}); e == nil || puts.Load() != 3 {
		t.Fatal("cross-tenant private provider admission")
	}
	bobPrepare := func(id, action string, expected uint64, payload any) control.UserOperation {
		t.Helper()
		raw, e := control.ChangeBytes(action, "bob", expected, payload)
		if e != nil {
			t.Fatal(e)
		}
		var ch control.Change
		_ = json.Unmarshal(raw, &ch)
		op, e := bob.Prepare(ctx, peer, bobSession, id, ch)
		if e != nil {
			t.Fatal(e)
		}
		return op
	}
	bobApply := func(op control.UserOperation, want state.Code) {
		t.Helper()
		reply, e := bob.Operation(ctx, peer, op, false)
		if e != nil || reply.Result == nil || reply.Result.Code != want {
			t.Fatal("bob intent", op.Change.Action, reply.Result, e)
		}
	}
	bobApply(bobPrepare("bob-init", "vault-init", 0, control.VaultRealm{Realm: "other", Root: "root"}), state.Applied)
	bobApply(bobPrepare("bob-foreign", "vault-create", current().Trees["tenant"].Revision(), control.VaultObject{Realm: "tenant", Object: secrets.Object{ID: "foreign", Parent: "root", Kind: secrets.Group}}), state.Forbidden)
	bobApply(bobPrepare("bob-profile", "vault-set-profile", current().Trees["other"].Revision(), control.VaultProfile{Realm: "other", Profile: secrets.WriteProfile{ID: "values", Node: "node-a", Key: runtime.Identity.Public, Enabled: true, Values: true}}), state.Forbidden)
	stale := bobPrepare("bob-stale", "vault-create", current().Trees["other"].Revision(), control.VaultObject{Realm: "other", Object: secrets.Object{ID: "nested", Parent: "root", Kind: secrets.Group}})
	rootObject, _ := current().Trees["tenant"].Object("root")
	apply("advance-other-root", "vault-approval-age", rootObject.Revision, control.VaultAge{Realm: "tenant", ID: "root", Seconds: 300}, state.Applied)
	bobApply(stale, state.ConditionFailed)
	if _, exists := current().Trees["other"].Object("nested"); exists {
		t.Fatal("stale root CAS partially wrote a realm")
	}
	bobApply(bobPrepare("bob-own-group", "vault-create", current().Trees["other"].Revision(), control.VaultObject{Realm: "other", Object: secrets.Object{ID: "nested", Parent: "root", Kind: secrets.Group}}), state.Applied)

	// Real Group approval uses a clean realm; unresolved original writes in the
	// first realm are preserved rather than force-settled to enable collection.
	catalog, _ = policy.Catalog(read())
	other, _ := catalog.Tenant("other")
	apply("other-node", "set-nodes", other.Revision, control.NodeChangeTo("other", other.AllowedNodes, []string{"node-a"}), state.Applied)
	for i, realm := range []string{"", "other"} {
		apply(fmt.Sprintf("approval-limit-%d", i), "set-node-quota", 0, tenancy.NodeLimit{Tenant: realm, Node: "node-a", Capacity: workload.Resources{CPU: 1e9, Memory: 256 << 20}, Networks: 2, MaxConsumers: 8}, state.Applied)
	}
	for _, profile := range []secrets.WriteProfile{{ID: "values-other", Node: "node-a", Key: runtime.Identity.Public, Enabled: true, Values: true}, {ID: "auth-other", Node: "node-a", Key: runtime.Identity.Public, Enabled: true, Verifiers: true}} {
		apply("other-profile-"+profile.ID, "vault-set-profile", current().Trees["other"].Revision(), control.VaultProfile{Realm: "other", Profile: profile}, state.Applied)
	}
	apply("other-data", "vault-create", current().Trees["other"].Revision(), control.VaultObject{Realm: "other", Object: secrets.Object{ID: "data", Parent: "nested", Kind: secrets.Secret, Reference: secrets.Reference{Profile: "values-other", Object: "other/data", Keys: []string{"key"}}}}, state.Applied)
	providerWrite := func(id, object, profile, path string, kind secrets.WriteKind, values map[string][]byte) {
		t.Helper()
		q := secrets.WriteRequest{ID: id, Object: object, Profile: profile, ProviderObject: path, Epoch: current().Trees["other"].WriteEpoch(), Kind: kind}
		if kind == secrets.ValueWrite {
			q.Keys = []string{"key"}
		} else {
			q.Protected = true
			if binding, e := current().Trees["other"].Verifier(object); e == nil {
				q.ExpectedProviderRevision = binding.Reference.Revision
			}
		}
		intentID := fmt.Sprintf("%s-epoch%d", id, q.Epoch)
		apply(intentID+"-prepare", "vault-prepare-write", current().Trees["other"].Revision(), control.VaultWrite{Realm: "other", Request: q}, state.Applied)
		apply(intentID+"-dispatch", "vault-dispatch-write", current().Trees["other"].Revision(), control.VaultWriteAction{Realm: "other", ID: id, Epoch: q.Epoch}, state.Applied)
		reply, e := user.WriteVault(ctx, peer, session, userauth.SecretRequest{Realm: "other", ID: id, Mode: "execute", Values: values})
		if e != nil || reply.VaultObservation == nil || reply.VaultObservation.Outcome != reconcile.EffectApplied {
			t.Fatal("actual Group provider", id, e)
		}
		w, _ := current().Trees["other"].Write(id)
		apply(intentID+"-observe", "vault-observe-write", current().Trees["other"].Revision(), control.VaultObserve{Observation: *reply.VaultObservation}, state.Applied)
		apply(intentID+"-publish", "vault-publish-write", current().Trees["other"].Revision(), control.VaultWriteAction{Realm: "other", ID: id, Epoch: q.Epoch, ObjectRevision: w.ExpectedObjectRevision}, state.Applied)
	}
	providerWrite("other-value", "data", "values-other", "other/data", secrets.ValueWrite, map[string][]byte{"key": []byte("other-private-value")})
	otherGroup, _ := current().Trees["other"].Object("nested")
	providerWrite("other-password", "nested", "auth-other", fmt.Sprintf("groups/other/nested/%d", otherGroup.Generation), secrets.VerifierWrite, map[string][]byte{"verifier": protected})
	apply("approval-issuer", "vault-set-issuer", current().Approvals.Revision(), control.VaultIssuer{Key: runtime.Identity.Public, Enabled: true}, state.Applied)
	uses := []secrets.Use{{Tenant: "other", User: "admin", App: "app", Deployment: "app", Service: "web", Node: "node-a", NodeKey: runtime.Identity.Public, RequesterKey: session.Key, Sources: []string{"data"}}}
	dbUse := uses[0]
	dbUse.Service = "db"
	uses = append(uses, dbUse)
	planApproval := func(id string, batch []secrets.Use) control.VaultApprovalPlan {
		t.Helper()
		p, e := user.PlanVaultApprovals(ctx, peer, session, "other", control.VaultApprovalPlanRequest{Realm: "other", ID: id, Issuer: runtime.Identity.Public, Uses: batch})
		if e != nil || len(p.Targets) != 1 {
			t.Fatal("actual approval plan", e)
		}
		return p
	}
	approvalPlan := planApproval("compose-first", uses)
	target := approvalPlan.Targets[0].Target
	if approvalPlan.Targets[0].Existing != nil || len(target.Services) != 2 {
		t.Fatal("initial batch Group plan")
	}
	if _, e = user.ApproveVault(ctx, peer, session, target, []byte("wrong-password")); e == nil {
		t.Fatal("wrong Group password approved")
	}
	// Send a valid private request and abandon its response. The server must
	// publish the approval first so a retry needs no password or provider read.
	conn, e := mesh.Dial(ctx, peer)
	if e != nil {
		t.Fatal(e)
	}
	stream, e := conn.Open(ctx)
	if e != nil {
		t.Fatal(e)
	}
	privateRequest := userauth.SecretRequest{Schema: 1, Realm: "other", ID: target.ApprovalID, Mode: "approve", Target: &target, Password: password}
	if _, e = rand.Read(privateRequest.Nonce[:]); e != nil {
		t.Fatal(e)
	}
	privateBody, _ := json.Marshal(privateRequest)
	envelope := userauth.Envelope{Body: privateBody, Session: &session, Signature: ed25519.Sign(proof.Private, access.RequestBytes(session, conn.PeerChallenge(), privateBody))}
	privateFrame, _ := json.Marshal(envelope)
	privateDigest := sha256.Sum256(privateFrame)
	e = sfcp.WriteFrame(stream, sfcp.Frame{Purpose: sfcp.SecretInput, Kind: 1, Request: mesh.NextRequest(), Fields: []sfcp.Field{{Tag: 1, Required: true, Value: privateFrame}, {Tag: 2, Required: true, Value: privateDigest[:]}}})
	clear(privateBody)
	clear(privateFrame)
	if e != nil {
		t.Fatal(e)
	}
	_ = stream.Close()
	stream.CancelRead(9)
	var committed *secrets.Approval
	for committed == nil {
		p := planApproval("compose-retry", uses)
		committed = p.Targets[0].Existing
		if committed != nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("approval after lost client response", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	if !ed25519.Verify(runtime.Identity.Public[:], secrets.ApprovalBytes(*committed), committed.Signature) || committed.Payload.Fact != "secret-group-use-approved" {
		t.Fatal("actual owner approval fact")
	}
	payload, _ := json.Marshal(committed.Payload)
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(payload, &fields)
	if len(fields) != 3 {
		t.Fatal("approval signature payload includes more than time/fact/target")
	}
	originalApproval := *committed
	// The currently approved Group keeps its pinned verifier after writes GC.
	oldBinding, e := current().Trees["other"].Verifier("nested")
	if e != nil {
		t.Fatal(e)
	}
	apply("other-write-gc", "vault-rotate-writes", current().Trees["other"].Revision(), control.VaultWriteAction{Realm: "other", Epoch: current().Trees["other"].WriteEpoch()}, state.Applied)
	if len(current().Trees["other"].Writes()) != 0 {
		t.Fatal("old provider metadata not collected")
	}
	if err = runtime.Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if err = runtime.Close(); err != nil {
		t.Fatal(err)
	}
	runtime = nil
	runtime, err = app.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runtime.InstallConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	_ = read()
	restoredBinding, e := current().Trees["other"].Verifier("nested")
	if e != nil || !oldBinding.Equal(restoredBinding) {
		t.Fatal("active verifier lost after GC/Snapshot/restart", e)
	}
	vault.api("POST", "sys/seal", nil, nil, vault.admin)
	reused, e := user.ApproveVault(ctx, peer, session, planApproval("compose-subset", uses[:1]).Targets[0].Target, nil)
	if e != nil || reused.VaultApproval == nil || !reflect.DeepEqual(originalApproval, *reused.VaultApproval) {
		t.Fatal("first-once approval was not reused without provider/password", e)
	}
	vault.unsealOriginal()
	// A policy change while the original fixed-version read is in flight must
	// fail the post-KDF current policy check and publish no new approval.
	groupNow, _ := current().Trees["other"].Object("nested")
	apply("other-policy-before", "vault-acl", groupNow.Revision, control.VaultACL{Realm: "other", ID: "nested", Add: secrets.ACL{Users: []string{"admin"}}}, state.Applied)
	newPlan := planApproval("compose-policy-change", uses)
	if newPlan.Targets[0].Existing != nil {
		t.Fatal("old Group policy approval reused")
	}
	pauseVerifier.Store(true)
	done := make(chan error, 1)
	go func() { _, e := user.ApproveVault(ctx, peer, session, newPlan.Targets[0].Target, password); done <- e }()
	select {
	case <-verifierEntered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	groupNow, _ = current().Trees["other"].Object("nested")
	apply("other-policy-during", "vault-acl", groupNow.Revision, control.VaultACL{Realm: "other", ID: "nested", Add: secrets.ACL{Services: []string{"web"}}, Remove: secrets.ACL{Users: []string{"admin"}}}, state.Applied)
	close(verifierContinue)
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("stale policy approved after provider read")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	// Approval creation never writes provider data; the only additional PUTs
	// so far were the selected Secret and protected Group verifier.
	if puts.Load() != 5 {
		t.Fatal("approval/reuse/restart issued another provider write", puts.Load())
	}
	// The same write ID in a new explicit write epoch is a new provider CAS,
	// not the old verifier identity. It must replace only the active reference.
	oldGroup, _ := current().Trees["other"].Object("nested")
	providerWrite("other-password", "nested", "auth-other", fmt.Sprintf("groups/other/nested/%d", oldGroup.Generation), secrets.VerifierWrite, map[string][]byte{"verifier": protected})
	newGroup, _ := current().Trees["other"].Object("nested")
	newBinding, e := current().Trees["other"].Verifier("nested")
	if e != nil || newGroup.VerifierRef == oldGroup.VerifierRef || newBinding.Reference.Revision != 2 || newBinding.Equal(oldBinding) {
		t.Fatal("same ID/new epoch password did not preserve a distinct fixed provider reference", e)
	}
	if _, e = user.ApproveVault(ctx, peer, session, target, nil); e == nil {
		t.Fatal("old policy approval survived password rotation")
	}
	renewal := planApproval("compose-new-password", uses[:1])
	if renewal.Targets[0].Existing != nil {
		t.Fatal("old password policy reused")
	}
	renewed, e := user.ApproveVault(ctx, peer, session, renewal.Targets[0].Target, password)
	if e != nil || renewed.VaultApproval == nil || puts.Load() != 6 {
		t.Fatal("new fixed verifier could not authorize a fresh approval", e, puts.Load())
	}
	// Connect that REAL provider/Group approval to the actual app FSM. Native
	// ready/termination facts here are signed fixtures; no Docker is claimed.
	volumeScope := volumes.Scope{Cluster: clusterID, Tenant: "other", App: "app", ID: "data", Generation: 1}
	nativeSpec := volumes.NativeSpec{Schema: 1, Scope: volumeScope, Node: "node-a", NodeKey: runtime.Identity.Public, Materialization: "initial", UID: 10001, GID: 10001, Mode: 0750, Retain: true}
	nativeRaw, _ := json.Marshal(nativeSpec)
	engineIdentity := engine.Client{Owner: engine.Owner(clusterID, runtime.Identity.Public)}
	volumeID, e := engineIdentity.Identity("volume", volumes.NativeKey(nativeSpec), reconcile.Resource{Present: true, Generation: 1, Spec: string(nativeRaw)})
	if e != nil {
		t.Fatal(e)
	}
	ready := volumes.NativeReady{Schema: 1, Spec: nativeSpec, Generation: 1, Owner: volumes.Owner{Node: "node-a", Key: runtime.Identity.Public, Native: volumeID.Name}}
	ready.Signature = ed25519.Sign(runtime.Identity.Private, volumes.NativeReadyBytes(ready))
	apply("app-volume", "create-volume", 0, ready, state.Applied)
	resources, e := policy.Resources(read())
	if e != nil {
		t.Fatal(e)
	}
	apply("app-network", "create-tun-network", resources.Networks.Revision(), tenancy.TUNDefinition{Tenant: "other", Name: "existing", Members: []tenancy.TUNNode{{Node: "node-a", Pools: []tenancy.Subnet{{ID: "pool", Prefix: netip.MustParsePrefix("10.88.0.0/24"), Gateway: netip.MustParseAddr("10.88.0.1"), MTU: 1280}}}}}, state.Applied)
	document := []byte("name: app\nservices:\n web:\n  image: docker.io/library/php@sha256:" + strings.Repeat("a", 64) + "\n  cpus: 0.1\n  mem_limit: 16m\n  volumes: [data:/data]\n  secrets: [password]\n  networks: {app: {ipv4_address: 10.88.0.10}}\n  x-sfc: {node: node-a, secrets: {from: [data]}}\nnetworks:\n app: {external: true, name: existing}\nvolumes:\n data:\n  external: true\n  x-sfc: {node: node-a}\nsecrets:\n password:\n  x-sfc: {key: key}\n")
	document = bytes.Replace(document, []byte("secrets: [password]"), []byte(fmt.Sprintf("secrets: [{source: password, target: /run/secrets/password, uid: '%d', gid: '%d', mode: '0400'}]", os.Geteuid(), os.Getegid())), 1)
	planned, e := user.PlanApp(ctx, peer, session, "other", control.AppPlanRequest{Document: document})
	if e != nil || planned.AppPlan == nil {
		t.Fatal("app binding plan", e)
	}
	blueprint, e := deployment.DecodeBlueprint(planned.AppPlan.Data)
	if e != nil {
		t.Fatal(e)
	}
	apply("bind-upload", "begin-app-upload", 0, control.AppUploadBegin{Tenant: "other", App: "app", Deployment: "app", ID: "artifact", Length: planned.AppPlan.Length, Digest: planned.AppPlan.Digest}, state.Applied)
	apply("bind-part", "put-app-part", 1, control.AppUploadPart{Tenant: "other", ID: "artifact", Data: planned.AppPlan.Data}, state.Applied)
	apply("bind-begin", "begin-app", 0, control.AppBegin{Tenant: "other", App: "app", Deployment: "app", Upload: "artifact", Operation: "rollout"}, state.Applied)
	appState := func() (control.Apps, deployment.Execution, control.AppView) {
		t.Helper()
		a, e := policy.Apps(read())
		if e != nil {
			t.Fatal(e)
		}
		x, ok := a.Execution("other", "app")
		if !ok {
			t.Fatal("missing binding app")
		}
		for _, v := range a.Records() {
			if v.Tenant == "other" && v.App == "app" {
				return a, x, v
			}
		}
		t.Fatal("missing binding app row")
		return a, x, control.AppView{}
	}
	memberPeer := peer
	memberPeer.Member = true
	memberPeer.Read = true
	memberMesh, e := sfcp.NewTransport(runtime.Identity, clusterID, func(k sfcp.Identity) (sfcp.Peer, bool) { return memberPeer, k == memberPeer.Key })
	if e != nil {
		t.Fatal(e)
	}
	defer memberMesh.Close()
	memberCall := func(method string, input []byte) cluster.ManagementReply {
		t.Helper()
		reply, e := cluster.CallManagement(ctx, memberMesh, runtime.Identity, clusterID, memberPeer, cluster.ManagementRequest{Method: method, Latest: true, Input: input})
		if e != nil {
			t.Fatal(method, reply.Code, e)
		}
		return reply
	}
	var progressID int
	progress := func(action, key string, o *deployment.Observation, release *control.AppBindingRelease, want state.Code) {
		t.Helper()
		progressID++
		s := read()
		_, _, v := appState()
		r := control.AppProgress{Schema: 1, Cluster: clusterID, Reporter: runtime.Identity.Public, Tenant: "other", App: "app", Operation: "rollout", Key: key, Action: action, Expected: v.Revision, At: uint64(time.Now().Unix()), Observation: o, Release: release, Epoch: s.ModuleEpoch(), RootRevision: s.Object(control.AppsKey).Revision, RequestID: fmt.Sprintf("binding-progress-%d", progressID)}
		if control.StageReport(r.Action) {
			r.Stage = policy.StageDigest(s, r.Tenant, r.App, r.Key)
		}
		r.Signature = ed25519.Sign(runtime.Identity.Private, control.AppProgressBytes(r))
		raw, _ := json.Marshal(r)
		reply := memberCall("app-progress", raw)
		if reply.Committed == nil || reply.Committed.Result.Code != want {
			t.Fatal("binding progress", action, key, reply.Committed, want)
		}
	}
	commitStage := func(key string) {
		t.Helper()
		progress("prepare", key, nil, nil, state.Applied)
		progress("send", key, nil, nil, state.Applied)
		_, x, _ := appState()
		stage, _ := x.Stage(key)
		raw, _ := state.EncodeCommand(*stage.Command)
		reply := memberCall("app-command", raw)
		if reply.Committed == nil || reply.Committed.Result.Code != state.Applied {
			t.Fatal("binding goal", key, reply.Committed)
		}
		progress("collect", key, nil, nil, state.Applied)
	}
	fact := func(key, native string, applied bool) deployment.Observation {
		_, x, _ := appState()
		stage, _ := x.Stage(key)
		o := deployment.Observation{Cluster: clusterID, Plan: blueprint.Digest(), Operation: "rollout", Key: key, Native: native, Owner: runtime.Identity.Public, Command: state.Digest(*stage.Command), Generation: stage.Result.Generation, Revision: stage.Result.Revision, Sequence: 1, At: uint64(time.Now().Unix()), Applied: applied}
		o.Signature = ed25519.Sign(runtime.Identity.Private, deployment.ObservationBytes(o))
		return o
	}
	bridgeKey := ""
	for _, step := range blueprint.Steps() {
		if step.Kind == "network-ref" {
			bridgeKey = step.Key
		}
	}
	if bridgeKey == "" {
		t.Fatal("missing named network reference")
	}
	volumeKey := deployment.ResourceKey("volume", "other", "app", "data")
	taskKey := deployment.ResourceKey("task", "other", "app", "web")
	inputKey := deployment.ResourceKey("inputs", "other", "app", "web")
	progress("bind-inputs", taskKey, nil, nil, state.ConditionFailed)
	for _, pair := range [][2]string{{bridgeKey, "fixture-bridge"}, {volumeKey, ready.Owner.Native}} {
		commitStage(pair[0])
		o := fact(pair[0], pair[1], true)
		progress("observe", pair[0], &o, nil, state.Applied)
	}
	commitStage(taskKey)
	progress("bind-inputs", taskKey, nil, nil, state.ConditionFailed)
	commitStage(inputKey)
	registry, e := policy.Volumes(read())
	if e != nil {
		t.Fatal(e)
	}
	core, _ := registry.Volume(volumeScope)
	apply("block-binding-writer", "acquire-volume", core.Revision(), control.VolumeAcquire{Scope: volumeScope, Consumer: "manual", Generation: 123, Writable: true}, state.Applied)
	registry, _ = policy.Volumes(read())
	core, _ = registry.Volume(volumeScope)
	beforeBinding := read()
	progress("bind-inputs", taskKey, nil, nil, state.ConditionFailed)
	for _, key := range []string{control.AppsKey, control.VaultKey, control.VolumesKey} {
		if read().Object(key) != beforeBinding.Object(key) {
			t.Fatal("failed binding leaked candidate", key)
		}
	}
	manualGone := volumes.Gone{Scope: volumeScope, Consumer: core.Consumers()[0], Stopped: true, MountsGone: true}
	manualGone.Signature = ed25519.Sign(runtime.Identity.Private, volumes.GoneBytes(manualGone))
	apply("unblock-binding-writer", "release-volume", core.Revision(), manualGone, state.Applied)
	progress("bind-inputs", taskKey, nil, nil, state.Applied)
	a, x, _ := appState()
	stage, _ := x.Stage(taskKey)
	taskSource := deployment.ObjectRef{Key: taskKey, Revision: stage.Result.Revision, Generation: stage.Result.Generation}
	bound, ok := a.Binding(taskSource)
	if !ok || bound.Needs().Generation == 1 || bound.Needs().Generation != taskSource.Generation || len(bound.Grants()) != 1 || len(bound.Grants()[0].Pins) != 1 || len(bound.Pins()) != 1 {
		t.Fatal("original shared binding/generation/pins")
	}
	grant := bound.Grants()[0]
	usage, ok := current().Approvals.Usage(grant)
	if !ok {
		t.Fatal("missing original usage")
	}
	usage.Grant.Use.Sources[0] = "foreign"
	if _, ok := current().Approvals.Usage(grant); !ok {
		t.Fatal("usage view mutated original")
	}
	firstBinding := a.Bindings().Revision()
	firstApproval := current().Approvals.Revision()
	progress("bind-inputs", taskKey, nil, nil, state.Applied)
	a, _, _ = appState()
	if a.Bindings().Revision() != firstBinding || current().Approvals.Revision() != firstApproval {
		t.Fatal("duplicate binding borrowed again")
	}
	permitRequest := control.AppBindingRequest{Task: taskSource, Digest: bound.Digest(), At: time.Now().Unix()}
	permitRaw, _ := json.Marshal(permitRequest)
	permitReply := memberCall("app-binding-permit", permitRaw)
	var permit control.AppBindingPermit
	if json.Unmarshal(permitReply.Data, &permit) != nil || permit.Task != taskSource || permit.Inputs.Key != inputKey {
		t.Fatal("current binding permit")
	}
	decoded, e := deployment.DecodeBinding(permit.Binding)
	if e != nil || decoded.Digest() != bound.Digest() {
		t.Fatal("permit changed binding", e)
	}
	foreign, foreignErr := cluster.CallManagement(ctx, mesh, proof, clusterID, peer, cluster.ManagementRequest{Method: "app-binding-permit", Latest: true, Input: permitRaw})
	if foreignErr == nil && foreign.Code == "ok" {
		t.Fatal("user obtained owner binding permit")
	}
	// New actual consumer: the Runtime fetches the exact public read-set from
	// its installed Vault reader and publishes private files through the same
	// Materialize/ProjectionStore used by the native workload provider.
	lagged := permit
	lagged.CommandIndex = read().Index() + 1
	if _, e = policy.AppInputReads(read(), runtime.Identity.Public, permitRequest, lagged); e == nil {
		t.Fatal("local replica below quorum permit was adopted")
	}
	wrongSet := permit
	wrongSet.ReadSet[0] ^= 1
	if _, e = policy.AppInputReads(read(), runtime.Identity.Public, permitRequest, wrongSet); e == nil {
		t.Fatal("foreign public read-set was adopted")
	}
	inputFiles := func() []string {
		t.Helper()
		var files []string
		path := filepath.Join(cfg.Node.StateDir, "workload", "inputs-memory")
		err := filepath.WalkDir(path, func(path string, d fs.DirEntry, err error) error {
			if os.IsNotExist(err) {
				return nil
			}
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.HasPrefix(d.Name(), "file-") {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return files
	}
	pauseValue.Store(true)
	prepared := make(chan error, 1)
	go func() { _, e := runtime.PrepareAppInputs(ctx, permitRequest); prepared <- e }()
	select {
	case <-valueEntered:
	case <-ctx.Done():
		t.Fatal("actual bound provider read", ctx.Err())
	}
	inputResources, e := policy.Resources(read())
	if e != nil {
		t.Fatal(e)
	}
	inputLimit, _ := inputResources.Quotas.Limit("other", "node-a")
	inputRevision := inputLimit.Revision
	inputLimit.Revision = 0
	inputLimit.MaxConsumers = 0
	apply("input-fetch-shrink", "set-node-quota", inputRevision, inputLimit, state.Applied)
	close(valueContinue)
	select {
	case e := <-prepared:
		if e == nil {
			t.Fatal("post-fetch quota revocation published private inputs")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if len(inputFiles()) != 0 {
		t.Fatal("rejected post-fetch gate created private value files")
	}
	inputResources, _ = policy.Resources(read())
	inputLimit, _ = inputResources.Quotas.Limit("other", "node-a")
	inputRevision = inputLimit.Revision
	inputLimit.Revision = 0
	inputLimit.MaxConsumers = 8
	apply("input-fetch-restore", "set-node-quota", inputRevision, inputLimit, state.Applied)
	projectionRef, e := runtime.PrepareAppInputs(ctx, permitRequest)
	if e != nil || projectionRef.Binding != bound.Digest() || projectionRef.Generation != taskSource.Generation {
		t.Fatal("actual bound private input preparation", e)
	}
	files := inputFiles()
	if len(files) != 1 {
		t.Fatal("missing private projection", len(files))
	}
	privateInput, e := os.ReadFile(files[0])
	if e != nil || !bytes.Equal(privateInput, []byte("other-private-value")) {
		t.Fatal("fixed provider version/key projection", e)
	}
	clear(privateInput)
	fileInfo, e := os.Stat(files[0])
	if e != nil || fileInfo.Mode().Perm() != 0400 {
		t.Fatal("private projection mode", e)
	}
	readsBefore := valueReads.Load()
	vault.api("PUT", "sys/seal", nil, nil, vault.admin)
	secondRef, e := runtime.PrepareAppInputs(ctx, permitRequest)
	if e != nil || secondRef != projectionRef || valueReads.Load() != readsBefore {
		t.Fatal("original Applied projection reread sealed provider", e)
	}
	vault.api("PUT", "sys/unseal", map[string]any{"key": vault.unseal}, nil, "")
	registry, _ = policy.Volumes(read())
	core, _ = registry.Volume(volumeScope)
	volumeGone := volumes.Gone{Scope: volumeScope, Consumer: bound.Pins()[0].Consumer, Stopped: true, MountsGone: true}
	volumeGone.Signature = ed25519.Sign(runtime.Identity.Private, volumes.GoneBytes(volumeGone))
	apply("binding-volume-partial-return", "release-volume", core.Revision(), volumeGone, state.Invalid)
	resources, e = policy.Resources(read())
	if e != nil {
		t.Fatal(e)
	}
	limit, _ := resources.Quotas.Limit("other", "node-a")
	limitRevision := limit.Revision
	limit.Revision = 0
	limit.MaxConsumers = 0
	apply("binding-shrink", "set-node-quota", limitRevision, limit, state.Applied)
	if _, e = policy.AppBindingPermit(read(), runtime.Identity.Public, permitRequest); e == nil {
		t.Fatal("zero capacity permitted new activation")
	}
	groupNow, _ = current().Trees["other"].Object("nested")
	apply("binding-revoke", "vault-acl", groupNow.Revision, control.VaultACL{Realm: "other", ID: "nested", Add: secrets.ACL{DenyServices: []string{"web"}}, Remove: secrets.ACL{Services: []string{"web"}}}, state.Applied)
	if e = policy.Validate(read(), read(), state.Command{}); e != nil {
		t.Fatal("revocation lost original snapshot references", e)
	}
	savedBinding := bound.Digest()
	if e = runtime.Engine().Snapshot(ctx); e != nil {
		t.Fatal(e)
	}
	if e = runtime.Close(); e != nil {
		t.Fatal(e)
	}
	runtime = nil
	runtime, e = app.Open(cfg)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = runtime.InstallConfiguration(ctx); e != nil {
		t.Fatal(e)
	}
	a, _, _ = appState()
	bound, ok = a.Binding(taskSource)
	if !ok || bound.Digest() != savedBinding {
		t.Fatal("same DB lost original binding")
	}
	if _, e = policy.AppBindingPermit(read(), runtime.Identity.Public, permitRequest); e == nil {
		t.Fatal("revoked binding activated after restart")
	}
	if _, e = runtime.PrepareAppInputs(ctx, permitRequest); e == nil {
		t.Fatal("revoked input was reactivated after same DB restart")
	}
	if len(inputFiles()) != 1 {
		t.Fatal("revocation/restart erased original private files")
	}
	closed := fact(taskKey, "fixture-task", false)
	closed.Stopped = true
	closed.Gone = true
	closed.Released = true
	closed.Signature = ed25519.Sign(runtime.Identity.Private, deployment.ObservationBytes(closed))
	badClosed := closed
	badClosed.Stopped = false
	if _, e = runtime.RetireAppInputs(ctx, permitRequest, badClosed); e == nil || len(inputFiles()) != 1 {
		t.Fatal("unproven Task termination removed input files", e)
	}
	closure, e := runtime.RetireAppInputs(ctx, permitRequest, closed)
	if e != nil || len(closure.Secrets) != 1 || len(closure.Volumes) != 0 || len(inputFiles()) != 0 {
		t.Fatal("actual file Gone/Secret-only closure after revoke", e)
	}
	if _, e = runtime.RetireAppInputs(ctx, permitRequest, closed); e != nil {
		t.Fatal("original input retirement did not resume", e)
	}
	partial := closure
	partial.Volumes = nil
	progress("release-inputs", taskKey, &closed, &control.AppBindingRelease{Digest: bound.Digest(), Proof: partial}, state.ConditionFailed)
	if _, ok = current().Approvals.Usage(grant); !ok {
		t.Fatal("partial closure returned Secret usage")
	}
	closure.Volumes = []volumes.Gone{volumeGone}
	progress("release-inputs", taskKey, &closed, &control.AppBindingRelease{Digest: bound.Digest(), Proof: closure}, state.Applied)
	a, _, _ = appState()
	registry, _ = policy.Volumes(read())
	core, _ = registry.Volume(volumeScope)
	if _, ok = a.Binding(taskSource); ok || len(core.Consumers()) != 0 {
		t.Fatal("full original closure did not return binding/Volume")
	}
	if _, ok = current().Approvals.Usage(grant); ok {
		t.Fatal("full closure retained Secret usage")
	}
	// Restore policy only for this counterexample: neither the Binding nor the
	// Volume generation floor may be erased by release/restart/permission return.
	resources, _ = policy.Resources(read())
	limit, _ = resources.Quotas.Limit("other", "node-a")
	limitRevision = limit.Revision
	limit.Revision = 0
	limit.MaxConsumers = 8
	apply("binding-restore-capacity", "set-node-quota", limitRevision, limit, state.Applied)
	groupNow, _ = current().Trees["other"].Object("nested")
	apply("binding-restore-acl", "vault-acl", groupNow.Revision, control.VaultACL{Realm: "other", ID: "nested", Remove: secrets.ACL{DenyServices: []string{"web"}}}, state.Applied)
	progress("bind-inputs", taskKey, nil, nil, state.ConditionFailed)
	if puts.Load() != 6 {
		t.Fatal("binding/settlement caused provider writes", puts.Load())
	}
	final, _ = state.Encode(read())
	if bytes.Contains(final, rpcValue) {
		t.Fatal("runtime sensitive input entered shared state")
	}
	if bytes.Contains(final, []byte("other-private-value")) {
		t.Fatal("private projection bytes entered shared FSM")
	}
	for _, path := range mustGlob(t, filepath.Join(cfg.Node.StateDir, "vault", "*.db")) {
		stored, e := os.ReadFile(path)
		if e != nil || bytes.Contains(stored, rpcValue) {
			t.Fatal("private value entered Runtime journal", e)
		}
	}
	t.Log("actual Runtime sensitive SFCP purpose/current quorum grant/installed realm-profile -> real Vault/TLS/ACL/CAS, lost response -> original Unknown/Snapshot/same DB -> explicit recovery without a second PUT -> explicit public reference; public Tree FSM and separate protected verifier; no private values in shared/local journals. actual Group password/current policy approval/first-once reuse/GC are connected; app inputs remain unconnected")
}

func mustGlob(t *testing.T, pattern string) []string {
	t.Helper()
	paths, err := filepath.Glob(pattern)
	if err != nil || len(paths) == 0 {
		t.Fatal("missing runtime provider journal", err)
	}
	return paths
}
