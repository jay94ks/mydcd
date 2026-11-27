// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/app"
	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/secrets"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/workload"
	"github.com/jay94ks/seafield/tests/vaultfixture"
)

func TestComposeGroupInputOptionsAndExplicitFD(t *testing.T) {
	for _, args := range [][]string{{"up", "--operation", "x", "--group-password-fd", "tenant/alpha=3", "--no-input"}, {"resume", "--operation", "x", "--group-password-fd", "/alpha=4"}} {
		if _, err := parseComposeOptions(args, io.Discard); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"ps", "--no-input"}, {"up", "--operation", "x", "--group-password-fd", "tenant/alpha=0"}, {"resume", "--operation", "x", "--group-password-fd", "tenant/alpha=3", "--group-password-fd", "tenant/bravo=3"}, {"resume", "--operation", "x", "--group-password-fd", "tenant/alpha=3", "--group-password-fd", "tenant/alpha=4"}} {
		if _, err := parseComposeOptions(args, io.Discard); err == nil {
			t.Fatal("accepted invalid Group options", args)
		}
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	_, _ = writer.Write([]byte("bounded-private-input\n"))
	_ = writer.Close()
	o := composeOptions{noInput: true, passwordFDs: groupPasswordFDs{values: map[string]int{"tenant/alpha": int(reader.Fd())}}}
	var diagnostic bytes.Buffer
	value, err := readGroupPassword(o, secrets.Target{Realm: "tenant", Group: "alpha"}, &diagnostic)
	if err != nil || string(value) != "bounded-private-input" || diagnostic.Len() != 0 {
		t.Fatal("explicit FD", err)
	}
	clear(value)
	if _, err := reader.Stat(); err != nil {
		t.Fatal("borrowed descriptor was closed", err)
	}
}

func TestRealComposeGroupApprovalsFDResumeAndOriginalRequester(t *testing.T) {
	testRealComposeGroups(t, false)
}

func TestRealComposeGroupUnknownPreservesOriginalWithoutPasswordReplay(t *testing.T) {
	testRealComposeGroups(t, true)
}

func testRealComposeGroups(t *testing.T, unknown bool, secretCLI ...bool) {
	vault := vaultfixture.Open(t)
	var privatePuts atomic.Int32
	var losePrivate atomic.Bool
	providerAddress := vault.Address
	if len(secretCLI) > 0 && secretCLI[0] {
		destination, _ := url.Parse(vault.Address)
		proxy := httputil.NewSingleHostReverseProxy(destination)
		proxy.Transport = vault.Client.Transport
		proxy.ModifyResponse = func(response *http.Response) error {
			if response.Request.Method == "PUT" && strings.HasPrefix(response.Request.URL.Path, "/v1/kv/data/") {
				privatePuts.Add(1)
				if losePrivate.CompareAndSwap(true, false) {
					_ = response.Body.Close()
					response.StatusCode = 503
					response.Status = "503 injected response loss"
					response.Body = io.NopCloser(strings.NewReader(`{"errors":["injected response loss"]}`))
					response.ContentLength = -1
					response.Header.Del("Content-Length")
				}
			}
			return nil
		}
		certificate, e := tls.LoadX509KeyPair(filepath.Join(vault.Root, "tls.pem"), filepath.Join(vault.Root, "tls.key"))
		if e != nil {
			t.Fatal(e)
		}
		server := httptest.NewUnstartedServer(proxy)
		server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
		server.StartTLS()
		defer server.Close()
		providerAddress = server.URL
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	root, home := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	invoke, loadCredentials := fixtureWallet(t, home)
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
	tokenFile := filepath.Join(root, "provider-token")
	if err = os.WriteFile(tokenFile, []byte(vault.Admin), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Node{Version: 1, Common: config.Common{}, Modules: map[string]config.Module{"network": {}, "workload": {}, "ingress": {}}}
	cfg.Node.ID, cfg.Node.Listen = "node-a", address
	cfg.Node.StateDir, cfg.Node.IdentityDir = filepath.Join(root, "state"), filepath.Join(root, "node")
	for _, profile := range []string{"values", "auth"} {
		prefix := "tenant"
		if profile == "auth" {
			prefix = "groups/tenant"
		}
		cfg.Vaults = append(cfg.Vaults, config.VaultBackend{Realm: "tenant", Profile: profile, Address: providerAddress, Mount: "kv", Prefix: prefix, CAFile: filepath.Join(vault.Root, "tls.pem"), TokenFile: tokenFile, Values: profile == "values", Verifiers: profile == "auth"})
	}
	init, err := app.Initialize(ctx, cfg, admin.Public, "init-cli-groups")
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
	clusterID := init.Installation.Root.Cluster
	p := control.Policy{Cluster: clusterID, BootstrapKey: admin.Public, TrustRoot: runtime.Identity.Public, Genesis: init.Installation.Genesis}
	peer := sfcp.Peer{ID: "node-a", Endpoint: address, Policy: sfcp.Policy{Key: sfcp.Identity(runtime.Identity.Public), Respond: true}}
	profile := filepath.Join(root, "client.yaml")
	if err = os.WriteFile(profile, []byte(fmt.Sprintf("version: 1\nauth: user\ncluster: '%x'\npeers:\n - {id: node-a, key: '%x', endpoint: '%s', voter: true}\n", clusterID, peer.Key, address)), 0600); err != nil {
		t.Fatal(err)
	}
	call := func(want int, args ...string) []byte {
		t.Helper()
		var out, diagnostic bytes.Buffer
		if code := invoke(append([]string{"--config", profile}, args...), &out, &diagnostic); code != want {
			t.Fatal("CLI", args, "exit", code, "want", want, out.String(), diagnostic.String())
		}
		if strings.Contains(out.String(), "first-private-password") || strings.Contains(diagnostic.String(), "first-private-password") {
			t.Fatal("private input printed")
		}
		if len(secretCLI) > 0 && secretCLI[0] {
			for _, value := range []string{"private-cli-original-value", "private-cli-after-lost-response", "private-cli-group-password"} {
				if strings.Contains(out.String(), value) || strings.Contains(diagnostic.String(), value) {
					t.Fatal("Secret CLI printed private input")
				}
			}
		}
		return out.Bytes()
	}
	// The new command groups read the current context and the wallet password
	// from SFC_WALLET_PASSWORD_FILE, as a script does.
	t.Setenv("SFC_NONINTERACTIVE", "1")
	cmd := func(want int, stdin string, args ...string) []byte {
		t.Helper()
		var out, diagnostic bytes.Buffer
		if code := cli.Execute(newRoot(&globals{}), append([]string{"-y"}, args...), cli.Env{In: strings.NewReader(stdin), Out: &out, Err: &diagnostic}); code != want {
			t.Fatal("CLI", args, "exit", code, "want", want, out.String(), diagnostic.String())
		}
		for _, value := range []string{"private-cli-original-value", "private-cli-after-lost-response", "private-cli-group-password", "private-external-original"} {
			if strings.Contains(out.String(), value) || strings.Contains(diagnostic.String(), value) {
				t.Fatal("Secret CLI printed private input")
			}
		}
		return out.Bytes()
	}
	if len(secretCLI) > 0 && secretCLI[0] {
		saveTestContext(t, home, "lab", "admin", "sfcp://"+address, clusterID, "node-a", runtime.Identity.Public)
		t.Setenv("SFC_WALLET_PASSWORD_FILE", fixtureWalletPasswordFile(t))
	}
	call(0, "enroll-admin", "--user-id", "admin", "--username", "admin", "--key-file", filepath.Join(root, "admin/key.pem"), "--request-id", "enroll-groups")
	login := func() {
		call(0, "login", "--username", "admin", "--method", "private-key", "--key-file", filepath.Join(root, "admin/key.pem"))
	}
	login()
	var clients []*userauth.Client
	defer func() {
		for _, c := range clients {
			_ = c.Mesh.Close()
			clear(c.Self.Private)
		}
	}()
	currentClient := func() (*userauth.Client, userauth.Stored) {
		t.Helper()
		c := &userauth.Client{Cluster: clusterID, Peers: []sfcp.Peer{peer}}
		stored, e := loadCredentials(*c, "admin")
		if e != nil {
			t.Fatal(e)
		}
		c.Self = stored.Self
		c.Mesh, e = sfcp.NewTransport(c.Self, clusterID, func(k sfcp.Identity) (sfcp.Peer, bool) { return peer, k == peer.Key })
		if e != nil {
			t.Fatal(e)
		}
		clients = append(clients, c)
		return c, stored
	}
	c, stored := currentClient()
	read := func() state.State {
		t.Helper()
		for {
			v, e := runtime.Engine().Read(ctx, true)
			if e == nil {
				return v.State
			}
			select {
			case <-ctx.Done():
				t.Fatal(e)
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	vaultState := func() control.Vault {
		v, e := p.Vault(read())
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	apply := func(id, action string, expected uint64, payload any) {
		t.Helper()
		raw, e := control.ChangeBytes(action, stored.Session.User, expected, payload)
		if e != nil {
			t.Fatal(e)
		}
		var change control.Change
		_ = json.Unmarshal(raw, &change)
		op, e := c.Prepare(ctx, peer, stored.Session, id, change)
		if e != nil {
			t.Fatal(e)
		}
		reply, e := c.Operation(ctx, peer, op, false)
		if e != nil || reply.Result == nil || reply.Result.Code != state.Applied {
			t.Fatal(action, e, reply.Result)
		}
	}
	apply("tenant", "create-tenant", 0, control.TenantID{ID: "tenant"})
	catalog, _ := p.Catalog(read())
	tenant, _ := catalog.Tenant("tenant")
	apply("nodes", "set-nodes", tenant.Revision, control.NodeChangeTo("tenant", tenant.AllowedNodes, []string{"node-a"}))
	for i, scope := range []string{"", "tenant"} {
		apply(fmt.Sprintf("quota-%d", i), "set-node-quota", 0, tenancy.NodeLimit{Tenant: scope, Node: "node-a", Capacity: workload.Resources{CPU: 2e9, Memory: 512 << 20}, Networks: 4, MaxConsumers: 8})
	}
	resources, err := p.Resources(read())
	if err != nil {
		t.Fatal(err)
	}
	apply("shared-lan", "create-tun-network", resources.Networks.Revision(), composeFixtureNetwork())
	apply("vault", "vault-init", 0, control.VaultRealm{Realm: "tenant", Root: "root"})
	for _, object := range []secrets.Object{{ID: "alpha", Parent: "root", Kind: secrets.Group}, {ID: "bravo", Parent: "alpha", Kind: secrets.Group}, {ID: "data", Parent: "bravo", Kind: secrets.Secret, Reference: secrets.Reference{Profile: "values", Object: "tenant/data", Keys: []string{"key"}}}} {
		apply("object-"+object.ID, "vault-create", vaultState().Trees["tenant"].Revision(), control.VaultObject{Realm: "tenant", Object: object})
	}
	for _, id := range []string{"values", "auth"} {
		apply("profile-"+id, "vault-set-profile", vaultState().Trees["tenant"].Revision(), control.VaultProfile{Realm: "tenant", Profile: secrets.WriteProfile{ID: id, Node: "node-a", Key: runtime.Identity.Public, Enabled: true, Values: id == "values", Verifiers: id == "auth"}})
	}
	if len(secretCLI) > 0 && secretCLI[0] {
		restart := func() {
			t.Helper()
			if e := runtime.Engine().Snapshot(ctx); e != nil {
				t.Fatal(e)
			}
			if e := runtime.Close(); e != nil {
				t.Fatal(e)
			}
			runtime = nil
			var e error
			runtime, e = app.Open(cfg)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = runtime.InstallConfiguration(ctx); e != nil {
				t.Fatal(e)
			}
			_ = read()
		}
		fixture := secretManagementFixture{ctx: ctx, home: home, call: call, cmd: cmd, login: login, client: currentClient, current: vaultState, read: read, restart: restart, vault: vault, peer: peer, puts: &privatePuts, lose: &losePrivate, issuer: func() ed25519.PrivateKey { return runtime.Identity.Private }}
		if unknown {
			testSecretManagementCLIOrphanAndCAS(t, fixture, apply)
		} else {
			testSecretManagementCLI(t, fixture)
		}
		return
	}
	write := func(q secrets.WriteRequest, values map[string][]byte) {
		t.Helper()
		q.Epoch = vaultState().Trees["tenant"].WriteEpoch()
		apply(q.ID+"-prepare", "vault-prepare-write", vaultState().Trees["tenant"].Revision(), control.VaultWrite{Realm: "tenant", Request: q})
		apply(q.ID+"-dispatch", "vault-dispatch-write", vaultState().Trees["tenant"].Revision(), control.VaultWriteAction{Realm: "tenant", ID: q.ID, Epoch: q.Epoch})
		reply, e := c.WriteVault(ctx, peer, stored.Session, userauth.SecretRequest{Realm: "tenant", ID: q.ID, Mode: "execute", Values: values})
		if e != nil || reply.VaultObservation == nil || reply.VaultObservation.Outcome != reconcile.EffectApplied {
			t.Fatal("provider", q.ID, e)
		}
		apply(q.ID+"-observe", "vault-observe-write", vaultState().Trees["tenant"].Revision(), control.VaultObserve{Observation: *reply.VaultObservation})
		w, _ := vaultState().Trees["tenant"].Write(q.ID)
		apply(q.ID+"-publish", "vault-publish-write", vaultState().Trees["tenant"].Revision(), control.VaultWriteAction{Realm: "tenant", ID: q.ID, Epoch: q.Epoch, ObjectRevision: w.ExpectedObjectRevision})
	}
	write(secrets.WriteRequest{ID: "value", Object: "data", Profile: "values", ProviderObject: "tenant/data", Kind: secrets.ValueWrite, Keys: []string{"key"}}, map[string][]byte{"key": []byte("actual-private-value")})
	password := []byte("first-private-password")
	defer clear(password)
	for i, group := range []string{"alpha", "bravo"} {
		hash, e := identity.PasswordHash(password, bytes.Repeat([]byte{byte(70 + i)}, 16), identity.DefaultPasswordCost())
		if e != nil {
			t.Fatal(e)
		}
		protected, e := hash.ProtectedBytes()
		if e != nil {
			t.Fatal(e)
		}
		object, _ := vaultState().Trees["tenant"].Object(group)
		write(secrets.WriteRequest{ID: "password-" + group, Object: group, Profile: "auth", ProviderObject: fmt.Sprintf("groups/tenant/%s/%d", group, object.Generation), Kind: secrets.VerifierWrite, Protected: true}, map[string][]byte{"verifier": protected})
		clear(protected)
	}
	apply("issuer", "vault-set-issuer", vaultState().Approvals.Revision(), control.VaultIssuer{Key: runtime.Identity.Public, Enabled: true})
	doc := appComposeDocument(2)
	doc = bytes.ReplaceAll(doc, []byte("x-sfc: {node: node-a}"), []byte("x-sfc: {node: node-a, secrets_from: [data, data]}"))
	file := filepath.Join(root, "compose.yaml")
	if err = os.WriteFile(file, doc, 0600); err != nil {
		t.Fatal(err)
	}
	call(2, "compose", "up", "-f", file, "--tenant", "tenant", "--operation", "groups", "--no-input")
	original, e := userauth.LoadOperation(home, *c, stored.Session, "compose/groups/accept")
	if e != nil || original.Result != nil {
		t.Fatal("original accept not retained before prompt", e)
	}
	origin := original.Operation
	plan := func(origin control.UserOperation) control.VaultApprovalPlan {
		t.Helper()
		v, e := c.PlanVaultApprovals(ctx, peer, stored.Session, "tenant", control.VaultApprovalPlanRequest{Realm: "tenant", ID: "compose/groups", Origin: &origin})
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	first := plan(origin)
	if len(first.Targets) != 2 || len(first.Targets[0].Target.Services) != 2 || first.Targets[0].Approver == nil {
		t.Fatal("deduplicated Group/consumer plan")
	}
	for _, target := range first.Targets {
		if target.Target.RequesterKey != origin.Session.Key || target.Existing != nil {
			t.Fatal("initial target scope")
		}
	}
	if unknown {
		v := first.Targets[0]
		attempt, e := userauth.LoadComposeApproval(home, *c, stored.Session, "groups", origin, v.Target, *v.Approver)
		if !errors.Is(e, userauth.ErrOperationMissing) {
			t.Fatal(e)
		}
		if e = userauth.StageComposeApproval(home, *c, stored.Session, attempt); e != nil {
			t.Fatal(e)
		}
		login()
		c, stored = currentClient()
		reader, writer, e := os.Pipe()
		if e != nil {
			t.Fatal(e)
		}
		defer reader.Close()
		_, _ = writer.Write(append(bytes.Clone(password), '\n'))
		_ = writer.Close()
		before := read().Index()
		call(4, "compose", "resume", "--operation", "groups", "--tenant", "tenant", "--no-input", "--group-password-fd", fmt.Sprintf("tenant/%s=%d", v.Target.Group, reader.Fd()))
		if read().Index() != before {
			t.Fatal("unknown approval reissued a management effect")
		}
		buffer := make([]byte, len(password)+1)
		if n, e := reader.Read(buffer); e != nil || n != len(buffer) || !bytes.Equal(buffer[:len(password)], password) {
			t.Fatal("unknown recovery read or replayed password", e)
		}
		clear(buffer)
		retained, e := userauth.LoadComposeApproval(home, *c, stored.Session, "groups", origin, v.Target, *v.Approver)
		if e != nil || retained.Outcome != "pending" || retained.Origin != attempt.Origin {
			t.Fatal("absence falsely settled original attempt", e)
		}
		for _, target := range plan(origin).Targets {
			if _, e := c.WriteVault(ctx, peer, stored.Session, userauth.SecretRequest{Realm: "tenant", ID: target.Target.ApprovalID, Mode: "approve", Target: &target.Target, Origin: &origin, Password: password}); e != nil {
				t.Fatal("explicit external approval resolution", e)
			}
		}
		call(0, "compose", "resume", "--operation", "groups", "--tenant", "tenant", "--no-input")
		retained, e = userauth.LoadComposeApproval(home, *c, stored.Session, "groups", origin, v.Target, *v.Approver)
		if e != nil || retained.Outcome != "confirmed" {
			t.Fatal("confirmed shared evidence did not settle original", e)
		}
		t.Log("actual CLI/Vault: private BEFORE-SEND pending attempt -> new login -> nil-password original recovery has no authoritative result -> Unknown preserved/no FD read/no management writes -> explicit external scope approval -> same original signed begin resumes without private input replay")
		return
	}
	forged := origin
	forged.Signature = bytes.Clone(origin.Signature)
	forged.Signature[0] ^= 1
	if _, e := c.PlanVaultApprovals(ctx, peer, stored.Session, "tenant", control.VaultApprovalPlanRequest{Realm: "tenant", ID: "bad", Origin: &forged}); e == nil {
		t.Fatal("forged origin accepted")
	}
	rogue, e := identity.Ephemeral()
	if e != nil {
		t.Fatal(e)
	}
	defer clear(rogue.Private)
	forged = origin
	forged.Session.Issuer = rogue.Public
	forged.Session.Signature = ed25519.Sign(rogue.Private, access.SessionBytes(forged.Session))
	forged.Signature = ed25519.Sign(c.Self.Private, control.OperationBytes(forged))
	if _, e := c.PlanVaultApprovals(ctx, peer, stored.Session, "tenant", control.VaultApprovalPlanRequest{Realm: "tenant", ID: "untrusted", Origin: &forged}); e == nil {
		t.Fatal("pending self-issued origin bypassed issuer authority")
	}
	withFDs := func(want int, method string, values map[string][]byte) {
		t.Helper()
		args := []string{"compose", method, "--operation", "groups", "--tenant", "tenant", "--no-input"}
		for _, name := range []string{"alpha", "bravo"} {
			if value, ok := values[name]; ok {
				r, w, e := os.Pipe()
				if e != nil {
					t.Fatal(e)
				}
				defer r.Close()
				_, _ = w.Write(append(bytes.Clone(value), '\n'))
				_ = w.Close()
				args = append(args, "--group-password-fd", fmt.Sprintf("tenant/%s=%d", name, r.Fd()))
			}
		}
		call(want, args...)
	}
	withFDs(4, "up", map[string][]byte{"alpha": password, "bravo": password})
	login()
	c, stored = currentClient()
	if stored.Session.Key == origin.Session.Key {
		t.Fatal("fixture did not change requester")
	}
	withFDs(3, "resume", map[string][]byte{"alpha": password, "bravo": []byte("wrong-password")})
	partial := plan(origin)
	existing := 0
	for _, target := range partial.Targets {
		if target.Existing != nil {
			existing++
		}
	}
	if existing != 1 {
		t.Fatal("partial successful Group approval lost", existing)
	}
	apps, _ := p.Apps(read())
	if len(apps.Records()) != 0 {
		t.Fatal("partial approvals accepted application")
	}
	broader := partial.Targets[1].Target
	broader.Services = append(broader.Services, "foreign")
	slices.Sort(broader.Services)
	if _, e := c.WriteVault(ctx, peer, stored.Session, userauth.SecretRequest{Realm: "tenant", ID: broader.ApprovalID, Mode: "approve", Target: &broader, Password: password, Origin: &origin}); e == nil {
		t.Fatal("origin target broadened")
	}
	withFDs(0, "resume", map[string][]byte{"bravo": password})
	accepted, e := userauth.LoadOperation(home, *c, stored.Session, origin.RequestID)
	if e != nil || accepted.Result == nil || !bytes.Equal(control.OperationBytes(origin), control.OperationBytes(accepted.Operation)) || !bytes.Equal(origin.Signature, accepted.Operation.Signature) {
		t.Fatal("resume replaced original accepted requester/signature", e)
	}
	for _, target := range plan(origin).Targets {
		if target.Existing == nil || target.Target.RequesterKey != origin.Session.Key {
			t.Fatal("original requester approval missing")
		}
	}
	vault.API("PUT", "sys/seal", nil, nil, vault.Admin)
	login()
	c, stored = currentClient()
	call(0, "compose", "resume", "--operation", "groups", "--tenant", "tenant", "--no-input")
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
	call(0, "compose", "resume", "--operation", "groups", "--tenant", "tenant", "--no-input")
	shared, _ := json.Marshal(read().Objects(""))
	if bytes.Contains(shared, password) || bytes.Contains(shared, []byte("actual-private-value")) {
		t.Fatal("private bytes in shared state")
	}
	if err := filepath.WalkDir(home, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			b, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			if bytes.Contains(b, password) || bytes.Contains(b, []byte("actual-private-value")) {
				t.Error("private bytes in local metadata", path)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	t.Log("actual CLI/SFCP/Raft/bbolt/Vault: two nested Groups shared by two services/repeated sources -> one explicit FD each; no-input/default unknown preserve original signed begin; new login -> original requester/partial approval retained -> bad password/scope expansion deny -> explicit resume completes -> sealed/no-input reuse -> Snapshot/same DB; no password/verifier/value in shared or CLI private metadata; native disabled")
}
