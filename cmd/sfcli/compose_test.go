// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/app"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/workload"
)

func appComposeDocument(services int) []byte {
	var b strings.Builder
	b.WriteString("name: app\nservices:\n")
	for i := 0; i < services; i++ {
		fmt.Fprintf(&b, "  service%d:\n    image: docker.io/library/php@sha256:%s\n    cpus: 0.1\n    mem_limit: 16m\n    command: [php, '%s']\n    networks: {app: {ipv4_address: 10.79.0.%d}}\n    x-sfc: {node: node-a}\n", i, strings.Repeat("a", 64), strings.Repeat("x", 300), i+10)
	}
	b.WriteString("networks:\n  app: {external: true, name: shared-lan}\n")
	return []byte(b.String())
}

// Only compatibility/rejection tests may submit the old app-owned CIDR input.
func legacyAppComposeDocument(services int) []byte {
	raw := string(appComposeDocument(services))
	start := strings.Index(raw, "\nnetworks:\n")
	return []byte(raw[:start] + "\nnetworks:\n  app:\n    x-sfc:\n      mtu: 1280\n      pools: {node-a: {cidr: 10.79.0.0/24, gateway: 10.79.0.1}}\n")
}

func composeFixtureNetwork() tenancy.TUNDefinition {
	return tenancy.TUNDefinition{Tenant: "tenant", Name: "shared-lan", Members: []tenancy.TUNNode{{Node: "node-a", Pools: []tenancy.Subnet{{ID: "pool", Prefix: netip.MustParsePrefix("10.79.0.0/24"), Gateway: netip.MustParseAddr("10.79.0.1"), MTU: 1280}}}}}
}

func appReferenceDocument(name string) []byte {
	raw := string(appComposeDocument(1))
	start := strings.Index(raw, "\nnetworks:\n")
	return []byte(raw[:start] + "\nnetworks:\n  app: {external: true, name: " + name + "}\n")
}

func TestComposeConfigLocalAndOptions(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	path := filepath.Join(dir, "compose.yaml")
	raw := appReferenceDocument("shared-lan")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	expected, err := deployment.ParseApp(raw)
	if err != nil {
		t.Fatal(err)
	}
	canonical, _ := expected.Canonical()
	var out, diagnostic bytes.Buffer
	if code := run([]string{"app", "check", "-f", path, "-o", "json"}, &out, &diagnostic); code != 0 || !json.Valid(out.Bytes()) || len(canonical) == 0 {
		t.Fatal("local check", code, diagnostic.String())
	}
	for _, args := range [][]string{{}, {"up"}, {"status"}, {"ps", "-f", path}, {"config", "--node", "node-a"}, {"plan", "-f", path, "--file", path}, {"plan", "extra"}} {
		if _, err := parseComposeOptions(args, &diagnostic); err == nil {
			t.Fatal("invalid options", args)
		}
	}
	if err := os.WriteFile(path, []byte("services: {web: {build: .}}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"app", "check", "-f", path}, &out, &diagnostic); code == 0 {
		t.Fatal("unsupported Compose config accepted", code)
	}
}

// Real user authentication/SFCP/N1 Raft/bbolt/Snapshot, with native modules
// disabled. Planned inventory is not a claim of task creation or Ready.
func TestRealComposePlanUploadAcceptanceOriginalCASAndSameDB(t *testing.T) {
	testRealComposeAppBoundary(t, false, false)
}
func TestRealComposeUpFrozenArtifactExplicitResumeAndSameDB(t *testing.T) {
	testRealComposeAppBoundary(t, true, false)
}
func TestRealComposeDownOriginalCASAndResume(t *testing.T) { testRealComposeAppBoundary(t, true, true) }
func testRealComposeAppBoundary(t *testing.T, up, down bool, mode ...string) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	root, home := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	invoke, loadCredentials := fixtureWallet(t, home)
	key, err := identity.Create(filepath.Join(root, "admin"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key.Private)
	probe, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.LocalAddr().String()
	_ = probe.Close()
	cfg := config.Node{Version: 1, Common: config.Common{}, Modules: map[string]config.Module{"network": {}, "workload": {}, "ingress": {}}}
	cfg.Node.ID, cfg.Node.Listen = "node-a", address
	cfg.Node.StateDir, cfg.Node.IdentityDir = filepath.Join(root, "state"), filepath.Join(root, "node-key")
	init, err := app.Initialize(ctx, cfg, key.Public, "init-app")
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
	policy := control.Policy{Cluster: clusterID, BootstrapKey: key.Public, TrustRoot: runtime.Identity.Public, Genesis: init.Installation.Genesis}
	peer := sfcp.Peer{ID: cfg.Node.ID, Endpoint: address, Policy: sfcp.Policy{Key: sfcp.Identity(runtime.Identity.Public), Respond: true}}
	profile := filepath.Join(root, "client.yaml")
	if err = os.WriteFile(profile, []byte(fmt.Sprintf("version: 1\nauth: user\ncluster: '%x'\npeers:\n - {id: node-a, key: '%s', endpoint: '%s', voter: true}\n", clusterID, runtime.Identity.Actor(), address)), 0600); err != nil {
		t.Fatal(err)
	}
	call := func(want int, args ...string) []byte {
		t.Helper()
		var out, diagnostic bytes.Buffer
		code := invoke(append([]string{"--config", profile}, args...), &out, &diagnostic)
		if code != want {
			t.Fatal("CLI", args, code, want, out.String(), diagnostic.String())
		}
		return out.Bytes()
	}
	call(0, "enroll-admin", "--user-id", "admin", "--username", "admin", "--key-file", filepath.Join(root, "admin/key.pem"), "--request-id", "enroll-app")
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
	current := func() (*userauth.Client, access.Session) {
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
		return c, stored.Session
	}
	client, session := current()
	prepare := func(id, action string, expected uint64, payload any) control.UserOperation {
		t.Helper()
		raw, e := control.ChangeBytes(action, session.User, expected, payload)
		if e != nil {
			t.Fatal(e)
		}
		var ch control.Change
		_ = json.Unmarshal(raw, &ch)
		op, e := client.Prepare(ctx, peer, session, id, ch)
		if e != nil {
			t.Fatal("prepare", id, e)
		}
		return op
	}
	apply := func(op control.UserOperation, want state.Code) state.Result {
		t.Helper()
		reply, e := client.Operation(ctx, peer, op, false)
		if e != nil || reply.Result == nil || reply.Result.Code != want {
			t.Fatal("apply", op.RequestID, reply.Code, reply.Result, want, e)
		}
		return *reply.Result
	}
	submit := func(id, action string, expected uint64, payload any, want state.Code) {
		t.Helper()
		apply(prepare(id, action, expected, payload), want)
	}
	view := func() state.State {
		t.Helper()
		v, e := runtime.Engine().Read(ctx, true)
		if e != nil {
			t.Fatal(e)
		}
		return v.State
	}
	catalog := func() access.Catalog {
		t.Helper()
		v, e := policy.Catalog(view())
		if e != nil {
			t.Fatal(e)
		}
		return v
	}

	submit("tenant", "create-tenant", 0, control.TenantID{ID: "tenant"}, state.Applied)
	tenant, _ := catalog().Tenant("tenant")
	submit("nodes", "set-nodes", tenant.Revision, control.NodeChangeTo("tenant", tenant.AllowedNodes, []string{"node-a"}), state.Applied)
	for i, scope := range []string{"", "tenant"} {
		submit(fmt.Sprintf("quota%d", i), "set-node-quota", 0, tenancy.NodeLimit{Tenant: scope, Node: "node-a", Capacity: workload.Resources{CPU: 4e9, Memory: 1 << 30}, Networks: 4, MaxConsumers: 64}, state.Applied)
	}
	if len(mode) == 1 && mode[0] == "app-scope" {
		verifyComposeAppScopeCLI(t, ctx, root, call, login, current, client, session, peer, policy, view, prepare, apply, &runtime, cfg)
		return
	}
	resources, err := policy.Resources(view())
	if err != nil {
		t.Fatal(err)
	}
	submit("shared-lan", "create-tun-network", resources.Networks.Revision(), composeFixtureNetwork(), state.Applied)
	if len(mode) == 1 && mode[0] == "inspect" {
		verifyComposeInspectCLI(t, ctx, root, call, client, session, peer, runtime.Identity.Private, view)
		return
	}
	if len(mode) == 1 && mode[0] == "stream" {
		verifyComposeStreamCLI(t, ctx, root, call, client, session, peer, runtime.Identity.Private, policy, view)
		return
	}
	if len(mode) == 1 && mode[0] == "create-target" {
		verifyComposeCreateTargetCLI(t, ctx, home, root, call, login, client, session, peer, view, &runtime, cfg)
		return
	}
	if up {
		verifyComposeUpCLI(t, ctx, home, root, call, login, client, session, peer, policy, view, &runtime, cfg)
		if len(mode) == 1 && mode[0] == "operations" {
			reply, err := client.AppOperation(ctx, peer, session, "tenant", control.AppOperationRequest{App: "app", ID: "rollout"})
			if err != nil || reply.AppOperation == nil || !reply.AppOperation.Found || !reply.AppOperation.Current || reply.AppOperation.Operation.Status != "Planned" {
				t.Fatal("current operation query", reply.AppOperation, err)
			}
		}
		if down {
			verifyComposeDownCLI(t, ctx, home, call, login, client, session, peer, policy, view, &runtime, cfg)
		}
		if len(mode) == 1 && mode[0] == "operations" {
			verifyComposeOperationCLI(t, ctx, home, root, call, login, client, session, peer, policy, view, runtime)
		}
		if len(mode) == 1 && mode[0] == "operation-reply" {
			verifyComposeHistoricalUnconfirmedAccept(t, home, call, client, session, view)
		}
		if len(mode) == 1 && mode[0] == "history" {
			verifyComposeHistoryCLI(t, ctx, root, call, client, session, peer, policy, view, &runtime, cfg)
		}
		return
	}
	// A removed user's unfinished upload remains attributable and may only be
	// explicitly aborted by an administrator; ownership does not move to one.
	workerKey, e := identity.Ephemeral()
	if e != nil {
		t.Fatal(e)
	}
	defer clear(workerKey.Private)
	worker := access.User{ID: "worker", Username: "worker", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: workerKey.Public, Enabled: true}}}
	submit("worker-user", "put-user", 0, worker, state.Applied)
	submit("worker-membership", "set-membership", 0, access.Membership{Tenant: "tenant", User: "worker", Role: access.Manager, Enabled: true}, state.Applied)
	candidate := control.AppUploadBegin{Tenant: "tenant", App: "app", Deployment: "app", ID: "orphan", Length: 1, Digest: sha256.Sum256([]byte("x"))}
	submit("admin-candidate", "begin-app-upload", 0, candidate, state.Applied)
	adminSession := session
	session, e = client.Login(ctx, peer, "worker", workerKey.Private)
	if e != nil {
		t.Fatal(e)
	}
	submit("worker-foreign-abort", "abort-app-upload", 1, control.AppUploadSelection{Tenant: "tenant", ID: "orphan", User: "admin"}, state.Forbidden)
	submit("worker-candidate", "begin-app-upload", 0, candidate, state.Applied)
	session = adminSession
	worker, _ = catalog().User("worker")
	submit("worker-disable", "put-user", worker.Revision, access.User{ID: worker.ID, Username: worker.Username}, state.Applied)
	submit("admin-own-part", "put-app-part", 1, control.AppUploadPart{Tenant: "tenant", ID: "orphan", Data: []byte("x")}, state.Applied)
	// The previous part belongs to the admin's own candidate, not the worker's.
	submit("admin-abort-own", "abort-app-upload", 2, control.AppUploadSelection{Tenant: "tenant", ID: "orphan"}, state.Applied)
	orphanPages, e := client.AppUploadPage(ctx, peer, session, "tenant", "")
	if e != nil || len(orphanPages.Uploads) != 0 {
		t.Fatal("foreign uploads disclosed", e)
	}
	submit("admin-explicit-orphan-abort", "abort-app-upload", 1, control.AppUploadSelection{Tenant: "tenant", ID: "orphan", User: "worker"}, state.Applied)
	doc := appComposeDocument(32)
	path := filepath.Join(root, "compose.yaml")
	if len(doc) > deployment.ArtifactPartBytes {
		t.Fatal("fixture input too big", len(doc))
	}
	if err = os.WriteFile(path, doc, 0600); err != nil {
		t.Fatal(err)
	}
	beforePlan := view().Index()
	planned := bytes.TrimSpace(call(0, "compose", "plan", "-f", path, "--tenant", "tenant"))
	plan, err := deployment.DecodeBlueprint(planned)
	if err != nil || len(planned) <= 64<<10 {
		t.Fatal("paged >64KiB plan", len(planned), err)
	}
	if view().Index() != beforePlan {
		t.Fatal("read-only planning mutated state")
	}
	outputPath := filepath.Join(root, "plan.json")
	call(0, "compose", "plan", "-f", path, "--tenant", "tenant", "--out", outputPath)
	savedPlan, e := os.ReadFile(outputPath)
	info, statErr := os.Stat(outputPath)
	if e != nil || statErr != nil || info.Mode().Perm() != 0600 || !bytes.Equal(bytes.TrimSpace(savedPlan), planned) {
		t.Fatal("atomic private plan output", e, statErr)
	}
	// A changed current catalog cannot produce a mixed paged artifact.
	first, e := client.PlanApp(ctx, peer, session, "tenant", control.AppPlanRequest{Document: doc})
	if e != nil || first.AppPlan == nil {
		t.Fatal("first part", e)
	}
	submit("unrelated-tenant", "create-tenant", 0, control.TenantID{ID: "other"}, state.Applied)
	if _, e = client.PlanApp(ctx, peer, session, "tenant", control.AppPlanRequest{Document: doc, Part: 1, Digest: first.AppPlan.Digest}); e == nil {
		t.Fatal("mixed plan pages accepted")
	}
	// Uploading an old valid artifact preserves it, but current revalidation denies Begin.
	upload := func(id string, raw []byte) {
		t.Helper()
		submit(id+"-begin", "begin-app-upload", 0, control.AppUploadBegin{Tenant: "tenant", App: "app", Deployment: "app", ID: id, Length: len(raw), Digest: sha256.Sum256(raw)}, state.Applied)
		revision := uint64(1)
		for part, start := 0, 0; start < len(raw); part, start = part+1, start+deployment.ArtifactPartBytes {
			data := raw[start:min(start+deployment.ArtifactPartBytes, len(raw))]
			// Exercise the human metadata decoder too: base64 part exceeds the ordinary 32KiB limit.
			payload, _ := json.Marshal(control.AppUploadPart{Tenant: "tenant", ID: id, Index: part, Data: data})
			document, _ := json.Marshal(control.ChangeDocument{Schema: 1, Action: "put-app-part", Expected: revision, Payload: payload})
			change, e := control.InputChange(document, session.User)
			if e != nil {
				t.Fatal("typed app part", len(document), e)
			}
			op, e := client.Prepare(ctx, peer, session, fmt.Sprintf("%s-part%d", id, part), change)
			if e != nil {
				t.Fatal(e)
			}
			apply(op, state.Applied)
			revision++
		}
	}
	upload("stale", planned)
	stale := prepare("stale-accept", "begin-app", 0, control.AppBegin{Tenant: "tenant", App: "app", Deployment: "app", Upload: "stale", Operation: "rollout"})
	staleResult := apply(stale, state.ConditionFailed)
	uploads, e := client.AppUploadPage(ctx, peer, session, "tenant", "")
	if e != nil || len(uploads.Uploads) != 1 || len(uploads.Uploads[0].Missing) != 0 {
		t.Fatal("stale artifact lost", e)
	}
	submit("abort-stale", "abort-app-upload", uploads.Uploads[0].Revision, control.AppUploadSelection{Tenant: "tenant", ID: "stale"}, state.Applied)
	planned = bytes.TrimSpace(call(0, "compose", "-f", path, "plan", "--tenant", "tenant"))
	plan, err = deployment.DecodeBlueprint(planned)
	if err != nil {
		t.Fatal(err)
	}
	upload("accepted", planned)
	submit("rotate-open-upload", "rotate-ledger", 1, control.LedgerWindow{NextEpoch: 2}, state.ConditionFailed)
	accept := prepare("accept", "begin-app", 0, control.AppBegin{Tenant: "tenant", App: "app", Deployment: "app", Upload: "accepted", Operation: "rollout"})

	// Deploy alone cannot smuggle management of networks through an app plan.
	limitedDeploy := session
	limitedDeploy.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Deploy}}}
	limitedDeploy.Signature = ed25519.Sign(runtime.Identity.Private, access.SessionBytes(limitedDeploy))
	denied := accept
	denied.RequestID, denied.Session = "scope-denied-accept", limitedDeploy
	denied.Signature = ed25519.Sign(client.Self.Private, control.OperationBytes(denied))
	if reply, err := client.Operation(ctx, peer, denied, false); err == nil || reply.Code != "denied" || reply.Result != nil {
		t.Fatal("scope denial must happen before submission", reply.Code, reply.Result, err)
	}
	original := apply(accept, state.Applied)
	command, _ := accept.Command()
	if rights, _, _, ok := view().Principal(command.Actor); ok && rights != 0 {
		t.Fatal("app admission granted legacy mutation rights")
	}

	page, e := client.AppPage(ctx, peer, session, "tenant", "")
	if e != nil || len(page.Apps) != 1 || page.Apps[0].Operation.Status != "Planned" || page.Apps[0].Claims != 0 || page.Apps[0].Operation.Plan != plan.Digest() {
		t.Fatal("accepted inventory", page, e)
	}
	uploads, e = client.AppUploadPage(ctx, peer, session, "tenant", "")
	if e != nil || len(uploads.Uploads) != 0 {
		t.Fatal("upload not consumed atomically", e)
	}
	for _, step := range plan.Steps() {
		if view().Object(step.Key).Present {
			t.Fatal("accept fabricated native desired/Ready")
		}
	}
	submit("rotate-pending-app", "rotate-ledger", 1, control.LedgerWindow{NextEpoch: 2}, state.ConditionFailed)
	var status struct{ Apps []control.AppView }
	if json.Unmarshal(call(0, "compose", "status", "-p", "app", "--tenant", "tenant"), &status) != nil || len(status.Apps) != 1 || status.Apps[0].Operation.Status != "Planned" {
		t.Fatal("CLI status")
	}
	call(0, "compose", "ps", "--tenant", "tenant")
	call(1, "compose", "status", "-p", "missing", "--tenant", "tenant")
	call(2, "compose", "up", "--tenant", "tenant")
	// Same stable user, different login key: result lookup/resume retains the original command.
	oldActor := accept.Session.Key
	login()
	client, session = current()
	if session.Key == oldActor {
		t.Fatal("relogin did not change transport identity")
	}
	receipt, e := client.Result(ctx, peer, session, accept)
	if e != nil || receipt.Result == nil || *receipt.Result != original {
		t.Fatal("original ACK recovery", e)
	}
	resumed, e := client.Resume(ctx, peer, session, accept)
	if e != nil || resumed.Result == nil || *resumed.Result != original {
		t.Fatal("original resume", e)
	}
	// Scope ceiling must be enforced, even for an account with system-admin policy.
	limited := session
	limited.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}}
	limited.Signature = nil
	// The real issuer signs the restricted session, so this tests scope rather than a bad signature.
	limited.Signature = ed25519.Sign(runtime.Identity.Private, access.SessionBytes(limited))
	if _, e = client.PlanApp(ctx, peer, limited, "tenant", control.AppPlanRequest{Document: doc}); e == nil {
		t.Fatal("read-only session planned deployment")
	}
	if _, e = client.AppPage(ctx, peer, limited, "other", ""); e == nil {
		t.Fatal("session crossed tenant scope")
	}
	// Historical origin must survive credential/session revocation without authorizing new work.
	adminUser, _ := catalog().User("admin")
	submit("revoke-old-session", "revoke-session", adminUser.Revision, control.SessionRevocation{User: "admin", Session: accept.Session.ID}, state.Applied)
	before := view()
	saved, e := policy.Apps(before)
	if e != nil {
		t.Fatal(e)
	}
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
	var restored state.State
	for {
		v, e := runtime.Engine().Read(ctx, true)
		if e == nil {
			restored = v.State
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	after, e := policy.Apps(restored)
	if e != nil || !reflect.DeepEqual(saved, after) || restored.Index() != before.Index() {
		t.Fatal("same DB inventory/original origin", e)
	}
	receipt, e = client.Result(ctx, peer, session, accept)
	if e != nil || receipt.Result == nil || *receipt.Result != original {
		t.Fatal("same DB original accept", e)
	}
	receipt, e = client.Result(ctx, peer, session, stale)
	if e != nil || receipt.Result == nil || *receipt.Result != staleResult {
		t.Fatal("same DB original rejection", e)
	}
	t.Log("actual CLI plan paging >64KiB/current policy -> immutable signed part/CAS -> Inventory.Begin atomically consumes upload -> Planned only -> original result after re-login/revocation/Snapshot/same DB; native modules remain disabled")
}

func TestComposeDefaultFileSelectionAndPrivateArtifact(t *testing.T) {
	t.Chdir(t.TempDir())
	if _, err := composeDocument(""); err == nil {
		t.Fatal("missing input fabricated")
	}
	if err := os.WriteFile("cluster.yaml", []byte("schema: 1\ntenant: other\nchanges: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := composeDocument(""); err == nil {
		t.Fatal("cluster settings auto-selected as an application")
	}
	raw := appComposeDocument(1)
	if err := os.WriteFile("app.yaml", raw, 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := composeDocument(""); err != nil || !bytes.Equal(got, raw) {
		t.Fatal("single default", err)
	}
	if err := os.WriteFile("docker-compose.yml", raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := composeDocument(""); err == nil {
		t.Fatal("ambiguous defaults accepted")
	}
	if got, err := composeDocument("app.yaml"); err != nil || !bytes.Equal(got, raw) {
		t.Fatal("explicit input", err)
	}
	if err := os.WriteFile("plan.json", []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := saveComposePlan("plan.json", []byte("new")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat("plan.json")
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("output permissions", err)
	}
	if err := os.Symlink("plan.json", "linked.json"); err != nil {
		t.Fatal(err)
	}
	if err := saveComposePlan("linked.json", []byte("changed")); err == nil {
		t.Fatal("symlink output accepted")
	}
	if b, _ := os.ReadFile("plan.json"); string(b) != "new\n" {
		t.Fatal("unrelated output changed")
	}
	files, _ := filepath.Glob(".sfc-plan-*")
	if len(files) != 0 {
		t.Fatal("temporary artifacts remain")
	}
}
