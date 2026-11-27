// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/app"
	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/workload"
)

func TestManagementCLIHelpAndInvalidOptionsWithoutIdentity(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	var out, diagnostic bytes.Buffer
	if code := run([]string{"manage", "--help"}, &out, &diagnostic); code != 0 || !strings.Contains(diagnostic.String(), "manage resume") || !strings.Contains(diagnostic.String(), "unknown intents are retained") {
		t.Fatal("manage help required installed identity/session", code, diagnostic.String())
	}
	for _, args := range [][]string{{}, {"other"}, {"prune", "--epoch", "9"}, {"result"}, {"resume", "--request-id", "one", "--change", "other"}, {"apply", "--request-id", "one", "--request-id", "two"}} {
		out.Reset()
		diagnostic.Reset()
		code := runManagement(context.Background(), args, userauth.Client{}, sfcp.Peer{}, access.Session{}, t.TempDir(), &out, &diagnostic)
		if code != 2 {
			t.Fatal("invalid command touched network/private state", args, code)
		}
	}
}

func TestRealManagementCLIOriginalIntentCASRecoveryAndEpochPruning(t *testing.T) {
	realManagementCLI(t)
}

func TestRealNodeCLIPolicyManagement(t *testing.T) {
	realManagementCLI(t, true)
}

func realManagementCLI(t *testing.T, security ...bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	root, home := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	invoke, loadCredentials := fixtureWallet(t, home)
	admin, err := identity.Create(filepath.Join(root, "admin"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(admin.Private)
	alice, err := identity.Create(filepath.Join(root, "alice"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(alice.Private)
	probe, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.LocalAddr().String()
	_ = probe.Close()
	cfg := config.Node{Version: 1, Common: config.Common{}, Modules: map[string]config.Module{"network": {}, "workload": {}, "ingress": {}}}
	cfg.Node.ID, cfg.Node.Listen = "node-a", address
	cfg.Node.StateDir, cfg.Node.IdentityDir = filepath.Join(root, "state"), filepath.Join(root, "node")
	init, err := app.Initialize(ctx, cfg, admin.Public, "init-management")
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
	policy := control.Policy{Cluster: clusterID, BootstrapKey: admin.Public, TrustRoot: runtime.Identity.Public, Genesis: init.Installation.Genesis}
	peer := sfcp.Peer{ID: cfg.Node.ID, Endpoint: address, Policy: sfcp.Policy{Key: sfcp.Identity(runtime.Identity.Public), Respond: true}}
	profile := filepath.Join(root, "client.yaml")
	if err = os.WriteFile(profile, []byte(fmt.Sprintf("version: 1\nauth: user\ncluster: '%x'\npeers:\n  - {id: node-a, key: '%s', endpoint: '%s', voter: true}\n", clusterID, runtime.Identity.Actor(), address)), 0600); err != nil {
		t.Fatal(err)
	}
	selectedUser := ""
	call := func(want int, args ...string) string {
		t.Helper()
		var out, diagnostic bytes.Buffer
		prefix := []string{"--config", profile}
		if selectedUser != "" && len(args) > 0 && args[0] != "login" && args[0] != "enroll-admin" {
			prefix = append(prefix, "--user", selectedUser)
		}
		code := invoke(append(prefix, args...), &out, &diagnostic)
		if code != want {
			t.Fatal("CLI", args, code, want, out.String(), diagnostic.String())
		}
		if strings.Contains(out.String(), "Signature") || strings.Contains(out.String(), "PRIVATE KEY") || strings.Contains(out.String(), "Seed") {
			t.Fatal("private intent leaked")
		}
		return out.String()
	}
	call(0, "enroll-admin", "--user-id", "admin", "--username", "admin", "--key-file", filepath.Join(root, "admin", "key.pem"), "--request-id", "enroll-management")
	// secret is a new-frame command: it reads the current context and
	// SFC_WALLET_PASSWORD_FILE.
	saveTestContext(t, home, "lab", "admin", "sfcp://"+address, clusterID, cfg.Node.ID, runtime.Identity.Public)
	t.Setenv("SFC_WALLET_PASSWORD_FILE", fixtureWalletPasswordFile(t))
	t.Setenv("SFC_NONINTERACTIVE", "1")
	secret := func(want int, args ...string) string {
		t.Helper()
		prefix := []string{"-y"}
		if selectedUser != "" {
			prefix = append(prefix, "--user", selectedUser)
		}
		var out, diagnostic bytes.Buffer
		if code := cli.Execute(newRoot(&globals{}), append(append(prefix, "secret"), args...), cli.Env{In: strings.NewReader(""), Out: &out, Err: &diagnostic}); code != want {
			t.Fatal("CLI secret", args, code, want, out.String(), diagnostic.String())
		}
		return out.String()
	}
	login := func(user string) {
		t.Helper()
		call(0, "login", "--username", user, "--method", "private-key", "--key-file", filepath.Join(root, user, "key.pem"))
		selectedUser = user
	}
	login("admin")
	read := func() cluster.View {
		t.Helper()
		v, err := runtime.Engine().Read(ctx, true)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	waitQuorum := func() {
		t.Helper()
		// Installed configuration is durable metadata, not an elected leader.
		// Wait for the actual quorum barrier without reissuing the operation.
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for {
			if _, err = runtime.Engine().Read(ctx, true); err == nil {
				break
			}
			if !errors.Is(err, raft.ErrNotLeader) && !errors.Is(err, raft.ErrLeadershipLost) && !errors.Is(err, cluster.ErrRecovering) {
				t.Fatal("same DB quorum startup", err)
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-tick.C:
			}
		}
	}
	catalog := func() access.Catalog {
		t.Helper()
		c, err := policy.Catalog(read().State)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	input := func(name, action string, expected uint64, payload any) string {
		t.Helper()
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := json.MarshalIndent(control.ChangeDocument{Schema: 1, Action: action, Expected: expected, Payload: raw}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, name+".json")
		if err = os.WriteFile(path, doc, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	apply := func(id, action string, expected uint64, payload any) string {
		t.Helper()
		path := input(id, action, expected, payload)
		return call(0, "manage", "apply", "--request-id", id, "--change", path)
	}
	apply("tenant-alpha", "create-tenant", 0, control.TenantID{ID: "alpha"})
	tenant, _ := catalog().Tenant("alpha")
	if len(tenant.ImageSources) != 1 || tenant.ImageSources[0].Registry != "docker.io" {
		t.Fatal("tenant default trust changed")
	}
	before := read().State.Index()
	call(0, "manage", "apply", "--request-id", "tenant-alpha", "--change", filepath.Join(root, "missing.json"))
	if read().State.Index() != before {
		t.Fatal("existing ID resubmitted/prepared another change")
	}
	apply("grant-node", "set-nodes", tenant.Revision, control.NodeChangeTo("alpha", tenant.AllowedNodes, []string{"node-a"}))
	credentials := []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: alice.Public, Enabled: true}}
	if len(security) != 0 && security[0] {
		credentials = append(credentials, access.Credential{ID: "password", Method: access.Password, VerifierRef: "fixture-public-reference", Enabled: true})
	}
	apply("create-user", "put-user", 0, access.User{ID: "alice", Username: "alice", Enabled: true, Credentials: credentials})
	apply("manager", "set-membership", 0, access.Membership{Tenant: "alpha", User: "alice", Role: access.Manager, Enabled: true})
	if len(security) != 0 && security[0] {
		// This branch uses the same actual CLI/wallet/TLS/Raft/DB fixture,
		// without starting Docker or modifying routes/firewall/system settings.
		adminRecord, _ := catalog().User("admin")
		apply("policy-on", "set-node-cli-policy", 0, control.NodeCLIChange{DisableNodeCLIOperation: true})
		policyRevision := catalog().NodeCLI().Revision
		if !catalog().NodeCLI().DisableNodeCLIOperation {
			t.Fatal("real management command did not enable the shared policy")
		}
		forger := userauth.Client{Self: runtime.Identity, Cluster: clusterID, Peers: []sfcp.Peer{peer}}
		forger.Mesh, err = sfcp.NewTransport(runtime.Identity, clusterID, func(k sfcp.Identity) (sfcp.Peer, bool) { return peer, k == peer.Key })
		if err != nil {
			t.Fatal(err)
		}
		defer forger.Mesh.Close()
		forged := access.Session{Schema: 1, ID: "node-forged-admin", Cluster: clusterID, User: "admin", Credential: "key", AccountRevision: adminRecord.Revision, Key: runtime.Identity.Public, Issuer: runtime.Identity.Public, IssuerEpoch: 1, IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Unix() + 600, Scopes: []access.Scope{{Tenant: "*", Actions: []access.Action{access.ManageCluster}}}}
		forged.Signature = ed25519.Sign(runtime.Identity.Private, access.SessionBytes(forged))
		payload, _ := json.Marshal(control.TenantID{ID: "node-forged-tenant"})
		op := control.UserOperation{Schema: 1, Session: forged, At: time.Now().Unix(), Epoch: read().State.ModuleEpoch(), RequestID: "node-forgery", RootRevision: read().State.Object(control.CatalogKey).Revision, Change: control.Change{Schema: 1, Principal: "admin", Action: "create-tenant", Payload: payload}}
		op.Signature = ed25519.Sign(runtime.Identity.Private, control.OperationBytes(op))
		if _, err := forger.Operation(ctx, peer, op, false); err == nil {
			t.Fatal("node-only forged administrator passed the real User ingress")
		}
		cmd, err := op.Command()
		if err != nil {
			t.Fatal(err)
		}
		committed, err := runtime.Engine().Submit(ctx, cmd)
		if err != nil || committed.Result.Code != state.Forbidden {
			t.Fatal("replica accepted a forged user operation through direct submit", committed.Result, err)
		}
		if _, err = cluster.CallManagement(ctx, forger.Mesh, runtime.Identity, clusterID, peer, cluster.ManagementRequest{Method: "get", Latest: true, Key: control.CatalogKey}); err == nil {
			t.Fatal("raw node CLI get bypassed the shared policy")
		}
		if _, err = cluster.CallManagement(ctx, forger.Mesh, runtime.Identity, clusterID, peer, cluster.ManagementRequest{Method: "status", Latest: true}); err != nil {
			t.Fatal("policy blocked internal quorum status needed for authentication", err)
		}
		fakeReport, _ := json.Marshal(op)
		if _, err = cluster.CallManagement(ctx, forger.Mesh, runtime.Identity, clusterID, peer, cluster.ManagementRequest{Method: "app-progress", Latest: true, Input: fakeReport}); err == nil {
			t.Fatal("node wrapped a user command as an internal owner report")
		}
		// Exercise the same policy over the real Unix TLS adapter; no UID
		// or node identity exemption may bypass the independent approval.
		unixPeer := peer
		unixPeer.Endpoint = "unix://" + filepath.Join(root, "security.sock")
		if err := runtime.Mesh.ListenUnix(strings.TrimPrefix(unixPeer.Endpoint, "unix://")); err != nil {
			t.Fatal(err)
		}
		stored, err := loadCredentials(userauth.Client{Cluster: clusterID, Peers: []sfcp.Peer{peer}}, "admin")
		if err != nil {
			t.Fatal(err)
		}
		defer clear(stored.Self.Private)
		local := userauth.Client{Self: stored.Self, Cluster: clusterID, Peers: []sfcp.Peer{unixPeer}}
		local.Mesh, err = sfcp.NewTransport(local.Self, clusterID, func(k sfcp.Identity) (sfcp.Peer, bool) { return unixPeer, k == unixPeer.Key })
		if err != nil {
			t.Fatal(err)
		}
		defer local.Mesh.Close()
		if reply, err := local.Query(ctx, unixPeer, stored.Session, "node-cli-policy", ""); err != nil || reply.NodeCLI == nil || !reply.NodeCLI.DisableNodeCLIOperation {
			t.Fatal("independently approved Unix policy query", err)
		}
		if _, err := forger.Whoami(ctx, unixPeer, forged); err == nil {
			t.Fatal("Unix endpoint accepted node-only forged user approval")
		}
		login("alice")
		call(0, "whoami")
		call(3, "manage", "apply", "--request-id", "manager-policy-off", "--change", input("manager-policy-off", "set-node-cli-policy", policyRevision, control.NodeCLIChange{}))
		login("admin")
		if err = runtime.Engine().Snapshot(ctx); err != nil {
			t.Fatal(err)
		}
		if err = runtime.Close(); err != nil {
			t.Fatal(err)
		}
		runtime, err = app.Open(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = runtime.InstallConfiguration(ctx); err != nil {
			t.Fatal(err)
		}
		waitQuorum()
		if !catalog().NodeCLI().DisableNodeCLIOperation || catalog().NodeCLI().Revision != policyRevision {
			t.Fatal("same-DB restart lost shared node CLI policy")
		}
		call(0, "manage", "result", "--request-id", "policy-on")
		apply("policy-off", "set-node-cli-policy", policyRevision, control.NodeCLIChange{})
		if catalog().NodeCLI().DisableNodeCLIOperation {
			t.Fatal("independently approved policy off failed")
		}
		t.Log("actual CLI/wallet/User TLS/Raft/FSM/DB: two user keys, full-account revision revocation, explicit original results, node-only forgery/direct-submit/report rejection, raw node get denied, internal status retained, shared policy restart and approved on/off; native app/CD/lifecycle is a separate owner fixture")
		return
	}
	apply("node-budget", "set-node-quota", 0, tenancy.NodeLimit{Node: "node-a", Capacity: workload.Resources{CPU: 2000000000, Memory: 512 << 20}, Networks: 8})
	apply("tenant-budget", "set-node-quota", 0, tenancy.NodeLimit{Tenant: "alpha", Node: "node-a", Capacity: workload.Resources{CPU: 1000000000, Memory: 256 << 20}, Networks: 4})
	resources, err := policy.Resources(read().State)
	if err != nil {
		t.Fatal(err)
	}
	limit, ok := resources.Quotas.Limit("alpha", "node-a")
	if !ok || limit.Owner != runtime.Identity.Public {
		t.Fatal("committed node key did not own budget")
	}
	// A prepared/staged operation has no possible external effect yet. The
	// default CLI still cannot infer that from a missing remote result.
	baseClient := userauth.Client{Cluster: clusterID, Peers: []sfcp.Peer{peer}}
	stored, err := loadCredentials(baseClient, "admin")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(stored.Self.Private)
	direct := baseClient
	direct.Self = stored.Self
	direct.Mesh, err = sfcp.NewTransport(direct.Self, clusterID, func(k sfcp.Identity) (sfcp.Peer, bool) { return peer, k == peer.Key })
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Mesh.Close()
	stage := func(id, action string, expected uint64, payload any) control.UserOperation {
		t.Helper()
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		op, err := direct.Prepare(ctx, peer, stored.Session, id, control.Change{Schema: 1, Principal: "admin", Action: action, Expected: expected, Payload: raw})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = userauth.StageOperation(home, direct, op); err != nil {
			t.Fatal(err)
		}
		return op
	}
	unsent := stage("unsent", "create-tenant", 0, control.TenantID{ID: "from-original"})
	before = read().State.Index()
	call(4, "manage", "result", "--request-id", unsent.RequestID)
	call(4, "manage", "apply", "--request-id", unsent.RequestID, "--change", input("ignored", "create-tenant", 0, control.TenantID{ID: "never-used"}))
	if read().State.Index() != before {
		t.Fatal("unknown original automatically sent")
	}
	// New login replaces the local proof key, not the original signed actor.
	login("admin")
	call(0, "manage", "resume", "--request-id", unsent.RequestID)
	if _, ok := catalog().Tenant("from-original"); !ok {
		t.Fatal("original resume missing")
	}
	if _, ok := catalog().Tenant("never-used"); ok {
		t.Fatal("repeat apply replaced original payload")
	}
	before = read().State.Index()
	call(0, "manage", "resume", "--request-id", unsent.RequestID)
	if read().State.Index() != before {
		t.Fatal("duplicate original produced another commit")
	}
	current, err := loadCredentials(baseClient, "admin")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(current.Self.Private)
	original, err := userauth.LoadOperation(home, userauth.Client{Cluster: clusterID, Peers: []sfcp.Peer{peer}, Self: current.Self}, current.Session, unsent.RequestID)
	if err != nil || !bytes.Equal(original.Operation.Signature, unsent.Signature) || original.Operation.Session.ID != stored.Session.ID {
		t.Fatal("new login re-signed original", err)
	}
	// A newer commit to the same record cannot silently rebase a retained
	// original CAS (changes to other records no longer conflict, R17 B2a).
	stale := stage("stale", "create-tenant", 0, control.TenantID{ID: "stale-target"})
	apply("advance-cas", "create-tenant", 0, control.TenantID{ID: "stale-target"})
	if got := call(3, "manage", "resume", "--request-id", stale.RequestID); !strings.Contains(got, `"Code":1`) {
		t.Fatal("stale original CAS was not retained", got)
	}
	before = read().State.Index()
	call(3, "manage", "result", "--request-id", stale.RequestID)
	if read().State.Index() != before {
		t.Fatal("rejected result query wrote a new command")
	}
	// Commit through the real SFCP API, then omit local result publication to
	// model termination before the CLI could retain its received reply.
	unobserved := stage("unobserved", "create-tenant", 0, control.TenantID{ID: "unobserved"})
	r, err := direct.Operation(ctx, peer, unobserved, false)
	if err != nil || r.Result == nil || r.Result.Code != state.Applied {
		t.Fatal("real original submission", err)
	}
	before = read().State.Index()
	call(0, "manage", "result", "--request-id", unobserved.RequestID)
	if read().State.Index() != before {
		t.Fatal("reply recovery resubmitted effect")
	}
	unknown := stage("preserve-unknown", "create-tenant", 0, control.TenantID{ID: "not-sent"})
	// Another user cannot take over the administrator's private intent.
	login("alice")
	before = read().State.Index()
	call(1, "manage", "resume", "--request-id", unknown.RequestID)
	if read().State.Index() != before {
		t.Fatal("other user resumed administrator intent")
	}
	// A tenant manager has no cluster-wide tenant creation permission.
	got := call(3, "manage", "apply", "--request-id", "manager-denied", "--change", input("manager-denied", "create-tenant", 0, control.TenantID{ID: "forbidden"}))
	if !strings.Contains(got, `"local_intent_preserved":true`) || !strings.Contains(got, `"Code":4`) {
		t.Fatal("confirmed denial/original discarded")
	}
	if _, ok := catalog().Tenant("forbidden"); ok {
		t.Fatal("manager gained system authority")
	}
	login("admin")
	// Metadata ambiguity is rejected before stage or Raft proposal.
	bad := filepath.Join(root, "bad.json")
	if err = os.WriteFile(bad, []byte(`{"schema":1,"action":"create-tenant","payload":{"ID":"a","ID":"b"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	before = read().State.Index()
	call(2, "manage", "apply", "--request-id", "bad-input", "--change", bad)
	call(2, "--local", "manage", "result", "--request-id", unobserved.RequestID)
	if read().State.Index() != before {
		t.Fatal("invalid/local management wrote shared state")
	}
	// Same original receipt and private journal survive indexed Snapshot and
	// reopening the exact managed database/installation/identity.
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
	waitQuorum()
	call(0, "manage", "result", "--request-id", unobserved.RequestID)
	if _, ok := catalog().Tenant("unobserved"); !ok {
		t.Fatal("same DB lost tenant")
	}
	apply("rotate-window", "rotate-ledger", 1, control.LedgerWindow{NextEpoch: 2})
	before = read().State.Index()
	got = call(0, "manage", "prune")
	if !strings.Contains(got, `"module_epoch":2`) || strings.Contains(got, `"removed":0`) {
		t.Fatal("confirmed old results not pruned", got)
	}
	if read().State.Index() != before {
		t.Fatal("local prune issued a mutation")
	}
	current2, err := loadCredentials(baseClient, "admin")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(current2.Self.Private)
	loader := baseClient
	loader.Self = current2.Self
	retained, err := userauth.LoadOperation(home, loader, current2.Session, unknown.RequestID)
	if err != nil || retained.Result != nil || !bytes.Equal(retained.Operation.Signature, unknown.Signature) {
		t.Fatal("expired Unknown lost", err)
	}
	call(4, "manage", "result", "--request-id", unknown.RequestID)
	if _, err = userauth.LoadOperation(home, loader, current2.Session, "rotate-window"); err == nil {
		t.Fatal("confirmed old epoch intent retained by prune")
	}
	// A retiring tenant denies new work but the real CLI still needs its
	// metadata page to revoke/retire the original Secret Group. No provider or
	// native effect is involved in this management-boundary regression.
	apply("cleanup-read-tenant", "create-tenant", 0, control.TenantID{ID: "cleanup-read"})
	secret(0, "init", "root", "--tenant", "cleanup-read")
	secret(0, "group", "create", "group", "--parent", "root", "--tenant", "cleanup-read")
	// The selected object precedes later tree mutations and is on page two.
	// Revoke/retire compare the object's revision, not the current tree revision.
	for i := range 9 {
		id := fmt.Sprintf("a%02d", i)
		secret(0, "group", "create", id, "--parent", "root", "--tenant", "cleanup-read")
	}
	cleanupTenant, _ := catalog().Tenant("cleanup-read")
	call(0, "--tenant", "cleanup-read", "manage", "apply", "--request-id", "cleanup-read-begin", "--change", input("cleanup-read-begin", "begin-tenant-retirement", cleanupTenant.Revision, control.TenantRetirementSelection{Tenant: "cleanup-read", Operation: "cleanup-read-retire"}))
	secret(0, "list", "--tenant", "cleanup-read")
	// The local management socket and the signed control join endpoint are
	// different addresses of the same pinned node. Exercise both real CLI
	// transports without replacing the original profile or its credentials.
	joining, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(joining.Private)
	// New-frame commands read the current context and the wallet password
	// from SFC_WALLET_PASSWORD_FILE.
	useContext := func(endpoint string) {
		t.Helper()
		saveTestContext(t, home, "lab", "admin", endpoint, clusterID, "node-a", runtime.Identity.Public)
	}
	t.Setenv("SFC_WALLET_PASSWORD_FILE", fixtureWalletPasswordFile(t))
	t.Setenv("SFC_NONINTERACTIVE", "1")
	useContext("sfcp://" + address)
	runNewCLI := func(want int, args ...string) string {
		t.Helper()
		var out, diagnostic bytes.Buffer
		if code := run(append(args, "--user", "admin", "-y"), &out, &diagnostic); code != want {
			t.Fatal("CLI", args, code, want, out.String(), diagnostic.String())
		}
		return out.String()
	}
	runNewCLI(0, "node", "add", "node-b", "--endpoint", "127.0.0.1:7444", "--public-key", joining.Actor(), "--id", "invite-node-b")
	invitation := func() string {
		t.Helper()
		out := runNewCLI(0, "node", "invite", "node-b")
		if _, err := membership.DecodeInvitation([]byte(out)); err != nil {
			t.Fatal("exported invitation is not directly consumable by sfcd join", err)
		}
		return out
	}
	remoteInvitation := invitation()
	unixRoot, err := os.MkdirTemp("", "sfc-inv-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(unixRoot)
	socket := filepath.Join(unixRoot, "m.sock")
	if err := runtime.Mesh.ListenUnix(socket); err != nil {
		t.Fatal(err)
	}
	profile = filepath.Join(root, "unix-client.yaml")
	if err := os.WriteFile(profile, []byte(fmt.Sprintf("version: 1\nauth: user\ncluster: '%x'\npeers:\n  - {id: node-a, key: '%s', endpoint: 'unix://%s', voter: true}\n", clusterID, runtime.Identity.Actor(), socket)), 0600); err != nil {
		t.Fatal(err)
	}
	login("admin")
	useContext("unix://" + socket)
	localInvitation := invitation()
	if localInvitation != remoteInvitation {
		t.Fatal("Unix invitation rewrote the original signed routable join source")
	}
	secret(3, "group", "create", "forbidden-new", "--parent", "root", "--tenant", "cleanup-read")
	secret(0, "revoke", "group", "--tenant", "cleanup-read")
	secret(0, "retire", "group", "--tenant", "cleanup-read")
	secret(0, "list", "--tenant", "cleanup-read")
	t.Log("actual CLI/private journal -> pinned SFCP/User -> Raft/FSM/bbolt; immutable CAS/ID/signature across new login, explicit resume, missing and unobserved outcomes, current authority, indexed Snapshot/same DB and confirmed-only epoch reclamation; retiring tenant retains authorized metadata cleanup while new creation is denied")
}
