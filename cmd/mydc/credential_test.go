// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/app"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/credentials"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
)

// Actual CLI/runtime/Raft/MYDCP/TLS/SDK, with a scripted KV HTTP server.
// This is not evidence of a real Vault service's storage/auth/unseal behavior.
func TestRealPasswordTokenCLIProtectedBackendAndRevocationRace(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	root, home := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	invoke, loadCredentials := fixtureWallet(t, home)
	const providerToken = "private-installed-provider-token"
	var mu sync.Mutex
	records := map[string]string{}
	available := true
	fetches := 0
	var paused, release chan struct{}
	var pauseOnce sync.Once
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		fetches++
		value, exists := records[r.URL.Path]
		allow := available && exists && r.Method == "GET" && r.URL.Query().Get("version") == "1" && r.Header.Get("X-Vault-Token") == providerToken
		started, done := paused, release
		mu.Unlock()
		if started != nil && strings.HasSuffix(r.URL.Path, "/password") {
			pauseOnce.Do(func() { close(started) })
			select {
			case <-done:
			case <-r.Context().Done():
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if !allow {
			w.WriteHeader(503)
			_, _ = fmt.Fprint(w, `{"errors":["private-provider-error-must-not-leak"]}`)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": map[string]any{"credential": value}, "metadata": map[string]any{"version": 1, "destroyed": false, "deletion_time": ""}}})
	}))
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	caPath, tokenPath := filepath.Join(root, "ca.pem"), filepath.Join(root, "vault.token")
	if err := os.WriteFile(caPath, ca, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte(providerToken+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	adminKey, err := identity.Create(filepath.Join(root, "admin"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(adminKey.Private)
	probe, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.LocalAddr().String()
	_ = probe.Close()
	nodePath := filepath.Join(root, "node.yaml")
	nodeYAML := fmt.Sprintf("version: 1\nnode: {id: local, state_dir: state, identity_dir: node-key, listen: '%s'}\nmodules:\n  network: {enabled: false}\n  workload: {enabled: false}\n  ingress: {enabled: false}\ncredentials: {profile: system, address: '%s', mount: kv, ca_file: ca.pem, token_file: vault.token}\n", address, server.URL)
	if err = os.WriteFile(nodePath, []byte(nodeYAML), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadNode(nodePath)
	if err != nil || cfg.Credentials.CAFile != caPath || cfg.Credentials.TokenFile != tokenPath {
		t.Fatal("local installation paths", err)
	}
	initialized, err := app.Initialize(ctx, cfg, adminKey.Public, "init-credential")
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
	policy := control.Policy{Cluster: clusterID, BootstrapKey: adminKey.Public, TrustRoot: runtime.Identity.Public, Genesis: initialized.Installation.Genesis}
	peer := mydcp.Peer{ID: "local", Endpoint: address, Policy: mydcp.Policy{Key: mydcp.Identity(runtime.Identity.Public), Respond: true}}
	makeClient := func() *userauth.Client {
		t.Helper()
		self, err := identity.Ephemeral()
		if err != nil {
			t.Fatal(err)
		}
		mesh, err := mydcp.NewTransport(self, clusterID, func(k mydcp.Identity) (mydcp.Peer, bool) { return peer, k == peer.Key })
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = mesh.Close(); clear(self.Private) })
		return &userauth.Client{Self: self, Mesh: mesh, Cluster: clusterID, Peers: []mydcp.Peer{peer}}
	}
	admin := makeClient()
	enrolled, err := admin.Enroll(ctx, peer, control.Enrollment{Schema: 1, RequestID: "enroll", User: access.User{ID: "admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: adminKey.Public, Enabled: true}}}}, adminKey.Private)
	if err != nil || enrolled.Result == nil || enrolled.Result.Code != state.Applied {
		t.Fatal("enroll", err)
	}
	adminSession, err := admin.Login(ctx, peer, "admin", adminKey.Private)
	if err != nil {
		t.Fatal(err)
	}
	sequence := 0
	propose := func(action string, expected uint64, payload any) {
		t.Helper()
		sequence++
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		op, err := admin.Prepare(ctx, peer, adminSession, fmt.Sprint("setup-", sequence), control.Change{Schema: 1, Principal: "admin", Action: action, Expected: expected, Payload: raw})
		if err != nil {
			t.Fatal(err)
		}
		r, err := admin.Operation(ctx, peer, op, false)
		if err != nil || r.Result == nil || r.Result.Code != state.Applied {
			t.Fatal(action, r.Result, err)
		}
	}
	password := []byte("private-password-not-shared")
	defer clear(password)
	token := []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{53}, 32)))
	defer clear(token)
	pwRef, tokenRef := "vault/system/system/credentials/alice/password@1", "vault/system/system/credentials/alice/robot@1"
	pw, err := credentials.NewPassword(clusterID, "alice", "password", pwRef, password, bytes.Repeat([]byte{7}, 16), identity.DefaultPasswordCost())
	if err != nil {
		t.Fatal(err)
	}
	defer pw.Destroy()
	robot, err := credentials.NewToken(clusterID, "alice", "robot", tokenRef, token, time.Now().Unix()+300, []access.Scope{{Tenant: "first", Actions: []access.Action{access.Read}}})
	if err != nil {
		t.Fatal(err)
	}
	defer robot.Destroy()
	pwBytes, _ := pw.ProtectedBytes()
	defer clear(pwBytes)
	tokenBytes, _ := robot.ProtectedBytes()
	defer clear(tokenBytes)
	mu.Lock()
	records["/v1/kv/data/system/credentials/alice/password"] = string(pwBytes)
	records["/v1/kv/data/system/credentials/alice/robot"] = string(tokenBytes)
	mu.Unlock()
	approvalKey, err := identity.Create(filepath.Join(root, "alice-approval"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(approvalKey.Private)
	var importOut, importDiagnostic bytes.Buffer
	if code := invoke([]string{"wallet", "import", "--name", "alice-approval", "--key-file", filepath.Join(root, "alice-approval", "key.pem")}, &importOut, &importDiagnostic); code != 0 {
		t.Fatal("explicit wallet approval key import", code, importDiagnostic.String())
	}
	propose("put-user", 0, access.User{ID: "alice", Username: "alice.login", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "password", Method: access.Password, VerifierRef: pwRef, Enabled: true}, {ID: "robot", Method: access.Token, VerifierRef: tokenRef, Enabled: true}, {ID: "approval", Method: access.PrivateKey, PublicKey: approvalKey.Public, Enabled: true}}})
	propose("create-tenant", 0, control.TenantID{ID: "first"})
	// A valid server ticket never replaces the session key's proof of this
	// connection and exact login body. Reject before any provider/KDF work.
	wire := makeClient()
	conn, err := wire.Mesh.Dial(ctx, peer)
	if err != nil {
		t.Fatal(err)
	}
	send := func(request userauth.Request, proofChallenge [32]byte, prove bool) userauth.Reply {
		t.Helper()
		request.Schema, request.Nonce = 1, [32]byte{1}
		body, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(body)
		envelope := userauth.Envelope{Body: body}
		if prove {
			envelope.Signature = credentialProof(wire.Self.Private, clusterID, wire.Self.Public, proofChallenge, body)
		}
		raw, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(raw)
		digest := sha256.Sum256(raw)
		stream, err := conn.Open(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer stream.CancelRead(0)
		defer stream.Close()
		id := wire.Mesh.NextRequest()
		if err = mydcp.WriteFrame(stream, mydcp.Frame{Purpose: mydcp.User, Kind: 1, Request: id, Fields: []mydcp.Field{{Tag: 1, Required: true, Value: raw}, {Tag: 2, Required: true, Value: digest[:]}}}); err != nil {
			t.Fatal(err)
		}
		if err := stream.Close(); err != nil {
			t.Fatal("request EOF", err)
		}
		response, err := mydcp.ReadFrame(stream, 128<<10)
		if err != nil || response.Request != id || !bytes.Equal(response.Fields[1].Value, digest[:]) {
			t.Fatal("wire reply", err)
		}
		var reply userauth.Reply
		if err = json.Unmarshal(response.Fields[0].Value, &reply); err != nil {
			t.Fatal(err)
		}
		return reply
	}
	hello := send(userauth.Request{Method: "credential-challenge", Username: "alice.login", AuthMethod: access.Password}, [32]byte{}, false)
	if hello.Code != "ok" || hello.Ticket == nil {
		t.Fatal("credential ticket", hello.Code)
	}
	for _, attempt := range []struct {
		challenge [32]byte
		prove     bool
	}{{[32]byte{}, false}, {[32]byte{99}, true}} {
		if rejected := send(userauth.Request{Method: "credential-login", Ticket: hello.Ticket, Secret: password}, attempt.challenge, attempt.prove); rejected.Code != "denied" {
			t.Fatal("unbound credential proof accepted", rejected.Code)
		}
	}
	forged := *hello.Ticket
	forged.User = "admin"
	if rejected := send(userauth.Request{Method: "credential-login", Ticket: &forged, Secret: password}, conn.PeerChallenge(), true); rejected.Code != "denied" {
		t.Fatal("forged ticket accepted")
	}
	mu.Lock()
	beforeLoginFetches := fetches
	mu.Unlock()
	if beforeLoginFetches != 0 {
		t.Fatal("invalid proof reached private provider", beforeLoginFetches)
	}
	profilePath := filepath.Join(root, "client.yaml")
	if err = os.WriteFile(profilePath, []byte(fmt.Sprintf("version: 1\nauth: user\ncluster: '%x'\npeers:\n  - {id: local, key: '%s', endpoint: '%s', voter: true}\n", clusterID, runtime.Identity.Actor(), address)), 0600); err != nil {
		t.Fatal(err)
	}
	call := func(want int, input []byte, args ...string) string {
		t.Helper()
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		_, _ = w.Write(input)
		_ = w.Close()
		original := os.Stdin
		os.Stdin = r
		defer func() { os.Stdin = original }()
		var out, diagnostic bytes.Buffer
		code := invoke(append([]string{"--config", profilePath}, args...), &out, &diagnostic)
		if code != want {
			t.Fatal("CLI", args, code, want, out.String(), diagnostic.String())
		}
		combined := out.String() + diagnostic.String()
		for _, sensitive := range []string{string(password), string(token), providerToken, "private-provider-error-must-not-leak", "Signature", "Seed"} {
			if strings.Contains(combined, sensitive) {
				t.Fatal("private material/error printed")
			}
		}
		return out.String()
	}
	call(2, nil, "login", "--username", "alice.login", "--method", "password", "--key-file", "wrong")
	call(2, nil, "login", "--username", "alice.login", "--method", "token", "--password-stdin")
	call(3, []byte("wrong-password\n"), "login", "--username", "alice.login", "--method", "password", "--password-stdin")
	call(0, append(bytes.Clone(password), '\n'), "login", "--username", "alice.login", "--method", "password", "--password-stdin")
	call(0, nil, "whoami")
	profile := userauth.Client{Cluster: clusterID, Peers: []mydcp.Peer{peer}}
	passwordSession, err := loadCredentials(profile, "alice.login")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(passwordSession.Self.Private)
	if passwordSession.Session.Credential != "password" {
		t.Fatal("wrong credential in private state")
	}
	if passwordSession.Session.Approval != nil {
		t.Fatal("password login silently selected an approval key")
	}
	// Keep ordinary password authentication, but require the separate user
	// delegation for management once the shared policy is committed.
	propose("set-node-cli-policy", 0, control.NodeCLIChange{DisableNodeCLIOperation: true})
	call(3, nil, "whoami")
	call(0, append(bytes.Clone(password), '\n'), "login", "--username", "alice.login", "--method", "password", "--password-stdin", "--approval-key", "alice-approval")
	call(0, nil, "whoami")
	approvedPassword, err := loadCredentials(profile, "alice.login")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(approvedPassword.Self.Private)
	if approvedPassword.Session.Credential != "password" || approvedPassword.Session.Approval == nil || approvedPassword.Session.Approval.PublicKey != approvalKey.Public || approvedPassword.Session.Approval.VerifyBinding(approvedPassword.Session) != nil {
		t.Fatal("password approval changed login credential or was not retained")
	}
	wrong := bytes.Clone(token)
	wrong[0] = 'z'
	call(3, wrong, "login", "--username", "alice.login", "--method", "token", "--token-stdin")
	call(0, token, "login", "--username", "alice.login", "--method", "token", "--credential", "robot", "--token-stdin", "--approval-key", "alice-approval")
	saved, err := loadCredentials(profile, "alice.login")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(saved.Self.Private)
	if saved.Session.Credential != "robot" || len(saved.Session.Scopes) != 1 || saved.Session.Scopes[0].Tenant != "first" || saved.Session.ExpiresAt > time.Now().Unix()+300 || saved.Session.Approval == nil || saved.Session.Approval.PublicKey != approvalKey.Public {
		t.Fatal("token scope/expiry widened")
	}
	limited := makeClient()
	limited.Self = saved.Self
	_ = limited.Mesh.Close()
	limited.Mesh, err = mydcp.NewTransport(saved.Self, clusterID, func(k mydcp.Identity) (mydcp.Peer, bool) { return peer, k == peer.Key })
	if err != nil {
		t.Fatal(err)
	}
	defer limited.Mesh.Close()
	raw, _ := json.Marshal(control.TenantID{ID: "escape"})
	op, err := limited.Prepare(ctx, peer, saved.Session, "scope-escape", control.Change{Schema: 1, Principal: "alice", Action: "create-tenant", Payload: raw})
	if err != nil {
		t.Fatal(err)
	}
	reply, err := limited.Operation(ctx, peer, op, false)
	if err != nil || reply.Result == nil || reply.Result.Code != state.Forbidden {
		t.Fatal("limited system-admin token bypassed scopes", err)
	}
	view, err := runtime.Engine().Read(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := state.Encode(view.State)
	for _, sensitive := range [][]byte{password, token, []byte(providerToken), []byte(`"Verifier":`)} {
		if bytes.Contains(encoded, sensitive) {
			t.Fatal("private material entered shared state")
		}
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
	// Re-establish current quorum before the CLI read after normal election.
	for {
		if _, err = runtime.Engine().Read(ctx, true); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	call(0, nil, "whoami")
	// Hold the real HTTPS provider read while the original account is revoked.
	mu.Lock()
	available = false
	mu.Unlock()
	call(3, password, "login", "--username", "alice.login", "--method", "password", "--password-stdin")
	call(0, nil, "whoami")
	mu.Lock()
	available = true
	mu.Unlock()
	mu.Lock()
	paused, release = make(chan struct{}), make(chan struct{})
	started, done := paused, release
	mu.Unlock()
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(done) }) }
	defer unblock()
	raceClient := makeClient()
	outcome := make(chan error, 1)
	go func() {
		_, err := raceClient.LoginCredential(ctx, peer, "alice.login", access.Password, "password", password)
		outcome <- err
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("provider did not receive original read", ctx.Err())
	}
	view, err = runtime.Engine().Read(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := policy.Catalog(view.State)
	if err != nil {
		t.Fatal(err)
	}
	account, _ := catalog.User("alice")
	expected := account.Revision
	account.Revision = 0
	account.Enabled = false
	propose("put-user", expected, account)
	unblock()
	select {
	case err := <-outcome:
		if err == nil {
			t.Fatal("late provider result bypassed account revocation")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	call(3, nil, "whoami")
	// Authentication never wrote the verifier/credential backend or fell back.
	mu.Lock()
	count := fetches
	mu.Unlock()
	if count < 5 {
		t.Fatal("expected exact real SDK reads", count)
	}
	t.Log("actual managed init/admin/current catalog + private password/token CLI + pinned MYDCP proof + real TLS Vault SDK fixture + scoped session/current revocation/Snapshot/same DB; no actual Vault service/native claim")
}

func TestProtectedLoginInputRequiresExplicitPipeAndSingleBoundedValue(t *testing.T) {
	for _, test := range []struct {
		input           []byte
		explicit, valid bool
	}{{[]byte("private\n"), true, true}, {[]byte("private"), true, true}, {[]byte("private\n"), false, false}, {[]byte("a\nb\n"), true, false}, {bytes.Repeat([]byte{'a'}, 1025), true, false}, {nil, true, false}} {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write(test.input)
		_ = w.Close()
		value, err := readLoginSecret(r, test.explicit, &bytes.Buffer{}, access.Password)
		_ = r.Close()
		if (err == nil) != test.valid {
			t.Fatal("invalid protected input result", len(test.input), test.explicit, err)
		}
		clear(value)
	}
}

// Construct a wrong binding independently of the client login helper. This
// helper is used by protocol-boundary tests; no fake algorithm enters product.
func credentialProof(private ed25519.PrivateKey, cluster, key, challenge [32]byte, body []byte) []byte {
	b := append([]byte("mydc-user-credential-login-1\x00"), cluster[:]...)
	b = append(b, key[:]...)
	b = append(b, challenge[:]...)
	digest := sha256.Sum256(body)
	b = append(b, digest[:]...)
	return ed25519.Sign(private, b)
}
