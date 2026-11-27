// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/app"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/secrets"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/tests/enginefake"
)

// realNode is one initialized single-node sfcd in this process, with its
// management socket in a short temporary directory. The bootstrap key
// enrolls the first system administrator, as in a real installation.
type realNode struct {
	Config  RealConfig
	Admin   *identity.Identity
	Runtime *app.Runtime
	Engine  *enginefake.Engine
}

func newRealNode(t *testing.T, ctx context.Context) *realNode {
	t.Helper()
	// Unix socket paths are limited to 107 bytes; t.TempDir can be longer.
	root, err := os.MkdirTemp("", "mw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	probe, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.LocalAddr().String()
	if err = probe.Close(); err != nil {
		t.Fatal(err)
	}
	admin, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(root, "sfcd.sock")
	// Network and workload run on the fake Docker engine (devel/refactor/16).
	engine, err := enginefake.Start(filepath.Join(root, "docker"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = engine.Close()
		if u := engine.Unknown(); len(u) > 0 {
			t.Errorf("Docker calls the fake engine does not know: %v", u)
		}
	})
	cfg := engine.Node()
	cfg.Node.ID, cfg.Node.Listen, cfg.Node.ManagementSocket = "node-a", address, socket
	cfg.Node.StateDir, cfg.Node.IdentityDir = filepath.Join(root, "state"), filepath.Join(root, "node-key")
	initialized, err := app.Initialize(ctx, cfg, admin.Public, "init-node-a")
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := app.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	if _, err = runtime.InstallConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	if err = runtime.Mesh.ListenUnix(socket); err != nil {
		t.Fatal(err)
	}
	n := &realNode{Admin: admin, Runtime: runtime, Engine: engine, Config: RealConfig{Socket: socket, Cluster: initialized.Installation.Root.Cluster, Node: "node-a", NodeKey: runtime.Identity.Public}}
	n.enroll(t, ctx, access.User{ID: "u-admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: admin.Public, Enabled: true}}})
	return n
}

func (n *realNode) enroll(t *testing.T, ctx context.Context, user access.User) {
	t.Helper()
	self, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	peer := sfcp.Peer{ID: n.Config.Node, Endpoint: "unix://" + n.Config.Socket, Policy: sfcp.Policy{Key: sfcp.Identity(n.Config.NodeKey), Respond: true}}
	mesh, err := sfcp.NewTransport(self, n.Config.Cluster, func(k sfcp.Identity) (sfcp.Peer, bool) { return peer, k == peer.Key })
	if err != nil {
		t.Fatal(err)
	}
	defer mesh.Close()
	c := userauth.Client{Mesh: mesh, Self: self, Cluster: n.Config.Cluster, Peers: []sfcp.Peer{peer}}
	reply, err := c.Enroll(ctx, peer, control.Enrollment{Schema: 1, RequestID: "enroll-" + user.ID, User: user}, n.Admin.Private)
	if err != nil || reply.Result == nil || reply.Result.Code != state.Applied {
		t.Fatal("enroll", reply.Code, err)
	}
}

// keyLogin logs in through the Conn as the browser does: the daemon gets a
// ticket, the user key signs the proof and then approves the session.
func realKeyLogin(t *testing.T, ctx context.Context, conn Conn, username string, key ed25519.PrivateKey) Session {
	t.Helper()
	pub := [32]byte(key.Public().(ed25519.PublicKey))
	ticket, err := conn.Challenge(ctx, username, pub)
	if err != nil {
		t.Fatal("challenge", err)
	}
	proof := NewKeyProof(ticket)
	proof.Signature = ed25519.Sign(key, KeyProofSigningBytes(proof))
	s, err := conn.Login(ctx, ticket, proof)
	if err != nil {
		t.Fatal("login", err)
	}
	a := NewSessionApproval(s, pub)
	a.Signature = ed25519.Sign(key, SessionApprovalSigningBytes(a))
	if s, err = conn.ApproveSession(ctx, a); err != nil || s.Approval == nil {
		t.Fatal("approve", err)
	}
	return s
}

func realChange(t *testing.T, action, user string, expected uint64, payload any) Change {
	t.Helper()
	raw, err := control.ChangeBytes(action, user, expected, payload)
	if err != nil {
		t.Fatal(err)
	}
	var ch Change
	if err = json.Unmarshal(raw, &ch); err != nil {
		t.Fatal(err)
	}
	return ch
}

func TestRealAdapterLoginAndOperation(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a real sfcd")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	node := newRealNode(t, ctx)
	client, err := NewReal(node.Config)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := client.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	var e *Error
	if _, err := conn.Whoami(ctx); !errors.As(err, &e) || e.Code != CodeNotLoggedIn {
		t.Fatalf("whoami before login: %v", err)
	}
	// No password credential: the challenge is refused by sfcd.
	if _, err := conn.CredentialChallenge(ctx, "admin", MethodPassword, ""); !errors.As(err, &e) || e.Code != CodeDenied {
		t.Fatalf("password challenge: %v", err)
	}
	// A proof for a ticket that is not pending is refused locally.
	if _, err := conn.Login(ctx, Ticket{}, KeyProof{}); !errors.As(err, &e) || e.Code != CodeExpired {
		t.Fatalf("login without ticket: %v", err)
	}

	s := realKeyLogin(t, ctx, conn, "admin", node.Admin.Private)
	if got, ok := conn.Session(); !ok || got.ID != s.ID {
		t.Fatal("session not kept")
	}
	who, err := conn.Whoami(ctx)
	if err != nil || who.User.Username != "admin" || !who.User.SystemAdmin || who.LedgerEpoch != 1 || who.Session.ID != s.ID {
		t.Fatalf("whoami %+v %v", who, err)
	}

	op, err := conn.Prepare(ctx, realChange(t, ActionCreateTenant, s.User, 0, control.TenantID{ID: "shop"}), who.RootFor(ActionCreateTenant))
	if err != nil {
		t.Fatal("prepare", err)
	}
	if _, found, err := conn.Result(ctx, op); err != nil || found {
		t.Fatalf("result before submit: %v %v", found, err)
	}
	res, err := conn.Submit(ctx, op)
	if err != nil || res.Code != ResultApplied {
		t.Fatalf("submit %+v %v", res, err)
	}
	again, found, err := conn.Result(ctx, op)
	if err != nil || !found || again.Code != ResultApplied || again.Revision != res.Revision {
		t.Fatalf("result %+v %v %v", again, found, err)
	}
	if resumed, found, err := conn.Resume(ctx, op); err != nil || !found || resumed.Code != ResultApplied {
		t.Fatalf("resume %+v %v %v", resumed, found, err)
	}
	tenants, err := conn.Tenants(ctx)
	if err != nil || len(tenants) != 1 || tenants[0].ID != "shop" || tenants[0].Role != RoleManager {
		t.Fatalf("tenants %+v %v", tenants, err)
	}
	if v, err := conn.SelectTenant(ctx, "shop"); err != nil || v.Role != RoleManager || v.Revision == 0 {
		t.Fatalf("select %+v %v", v, err)
	}
	if _, err := conn.SelectTenant(ctx, "nope"); !errors.As(err, &e) || e.Code != CodeDenied {
		t.Fatalf("select unknown %v", err)
	}
	// Local services belong to a CD app; there is none here.
	if _, err := conn.AppDeliveryLocal(ctx, "shop", "web"); !errors.As(err, &e) || e.Code != CodeMissing {
		t.Fatalf("app-cd-local %v", err)
	}

	// A second login on another Conn has its own session key.
	other, err := client.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	s2 := realKeyLogin(t, ctx, other, "admin", node.Admin.Private)
	if s2.Key == s.Key || s2.ID == s.ID {
		t.Fatal("logins share a session key")
	}
	// The original belongs to the first session: another session reads its
	// result, but cannot submit it as its own.
	if _, found, err := other.Result(ctx, op); err != nil || !found {
		t.Fatalf("result from another session %v %v", found, err)
	}

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Whoami(ctx); !errors.As(err, &e) || e.Code != CodeClosed {
		t.Fatalf("after close %v", err)
	}
}

func TestNewRealConfig(t *testing.T) {
	good := RealConfig{Socket: "/run/sfcd.sock", Cluster: [32]byte{1}, Node: "node-a", NodeKey: [32]byte{2}}
	if _, err := NewReal(good); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []RealConfig{
		{Socket: "relative.sock", Cluster: good.Cluster, Node: "n", NodeKey: good.NodeKey},
		{Socket: good.Socket, Node: "n", NodeKey: good.NodeKey},
		{Socket: good.Socket, Cluster: good.Cluster, NodeKey: good.NodeKey},
		{Socket: good.Socket, Cluster: good.Cluster, Node: "n"},
	} {
		if _, err := NewReal(bad); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
}

// realAdmin starts a node and logs the bootstrap administrator in.
func realAdmin(t *testing.T) (context.Context, *realNode, Conn, Session) {
	t.Helper()
	if testing.Short() {
		t.Skip("starts a real sfcd")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	node := newRealNode(t, ctx)
	client, err := NewReal(node.Config)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := client.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return ctx, node, conn, realKeyLogin(t, ctx, conn, "admin", node.Admin.Private)
}

func TestRealAdapterAccountAndClusterReads(t *testing.T) {
	ctx, node, conn, s := realAdmin(t)
	if v, err := conn.ServerVersion(ctx); err != nil || v.Protocol == 0 {
		t.Fatalf("server-version %+v %v", v, err)
	}
	if u, err := conn.OwnCredentials(ctx); err != nil || u.Username != "admin" || len(u.Credentials) != 1 {
		t.Fatalf("my-credentials %+v %v", u, err)
	}
	if u, err := conn.UserCredentials(ctx, "admin"); err != nil || u.ID != s.User || u.Credentials[0].PublicKey != node.Admin.Public {
		t.Fatalf("user-credentials %+v %v", u, err)
	}
	if p, err := conn.Users(ctx, ""); err != nil || len(p.Items) != 1 || p.Items[0].Username != "admin" {
		t.Fatalf("users %+v %v", p, err)
	}
	if _, err := conn.NodeCLIPolicy(ctx); err != nil {
		t.Fatalf("node-cli-policy %v", err)
	}
	who, _ := conn.Whoami(ctx)
	op, err := conn.Prepare(ctx, realChange(t, ActionCreateTenant, s.User, 0, control.TenantID{ID: "shop"}), who.RootFor(ActionCreateTenant))
	if err != nil {
		t.Fatal(err)
	}
	if res, err := conn.Submit(ctx, op); err != nil || res.Code != ResultApplied {
		t.Fatalf("create %+v %v", res, err)
	}
	if p, err := conn.TenantMembers(ctx, "shop", ""); err != nil || p.Revision == 0 {
		t.Fatalf("tenant-members %+v %v", p, err)
	}

	m, err := conn.Members(ctx, "")
	if err != nil || len(m.Entries) != 1 || m.Entries[0].Peer.ID != "node-a" || m.RootRevision == 0 || m.LedgerEpoch != 1 || m.NodeVoters != 1 {
		t.Fatalf("members %+v %v", m, err)
	}
	if st, err := conn.RaftStatus(ctx); err != nil || st.Leader == "" || st.Voters != 1 || len(st.Nodes) != 1 {
		t.Fatalf("raft-status %+v %v", st, err)
	}
	if p, err := conn.NodeStorage(ctx, "", ""); err != nil || len(p.Items) != 0 {
		t.Fatalf("node-storage %+v %v", p, err)
	}
	if _, err := conn.NodeShellPolicy(ctx); err != nil {
		t.Fatalf("node-shell-policy %v", err)
	}
	if p, err := conn.NodeShellSessions(ctx, ""); err != nil || len(p.Sessions) != 0 {
		t.Fatalf("node-shell-sessions %+v %v", p, err)
	}
	if _, err := conn.Events(ctx, EventQuery{}); err != nil {
		t.Fatalf("events %v", err)
	}
	if _, err := conn.PlanNodeRemoval(ctx, "node-a"); err != nil {
		t.Fatalf("remove plan %v", err)
	}
	var e *Error
	if _, err := conn.NodeInvitation(ctx, "node-a"); !errors.As(err, &e) || e.Code != CodeDenied {
		t.Fatalf("invitation of an active voter %v", err)
	}

	// The account scope lives on the account record in sfcd.
	bot := access.User{ID: "bot", Username: "bot", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: [32]byte{7}, Enabled: true}}}
	op, err = conn.Prepare(ctx, realChange(t, ActionPutUser, s.User, 0, bot), 0)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := conn.Submit(ctx, op); err != nil || res.Code != ResultApplied {
		t.Fatalf("put-user %+v %v", res, err)
	}
	keyOnly := true
	sc, err := conn.AccountScope(ctx, "bot")
	if err != nil || sc.Revision == 0 || sc.KeyOnly || len(sc.Actions) != 0 {
		t.Fatalf("account-scope %+v %v", sc, err)
	}
	op, err = conn.Prepare(ctx, realChange(t, ActionSetAccountScope, s.User, sc.Revision, AccountScopeChange{User: "bot", Add: []string{"restart-task"}, KeyOnly: &keyOnly}), 0)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := conn.Submit(ctx, op); err != nil || res.Code != ResultApplied {
		t.Fatalf("set-account-scope %+v %v", res, err)
	}
	if got, err := conn.AccountScope(ctx, "bot"); err != nil || !got.KeyOnly || !slices.Equal(got.Actions, []string{"restart-task"}) || got.Revision <= sc.Revision {
		t.Fatalf("account-scope after %+v %v", got, err)
	}
	if own, err := conn.AccountScope(ctx, s.User); err != nil || own.User != s.User || len(own.Actions) != 0 {
		t.Fatalf("own scope %+v %v", own, err)
	}
	if _, err := conn.AccountScope(ctx, "nobody"); !errors.As(err, &e) || e.Code != CodeMissing {
		t.Fatalf("unknown account %v", err)
	}
}

func TestRealAdapterTenantReadsAndClose(t *testing.T) {
	ctx, n, conn, s := realAdmin(t)
	who, _ := conn.Whoami(ctx)
	op, err := conn.PrepareReason(ctx, realChange(t, ActionCreateTenant, s.User, 0, control.TenantID{ID: "shop"}), who.RootFor(ActionCreateTenant), OperationReason{Reason: "autofix", Incident: "inc-1"})
	if err != nil {
		t.Fatal(err)
	}
	if res, err := conn.Submit(ctx, op); err != nil || res.Code != ResultApplied {
		t.Fatalf("create %+v %v", res, err)
	}
	if p, err := conn.Volumes(ctx, "shop", ""); err != nil || len(p.Items) != 0 {
		t.Fatalf("volumes %+v %v", p, err)
	}
	if _, err := conn.RegistryPulls(ctx, "shop", ""); err != nil {
		t.Fatalf("registry-pulls %v", err)
	}
	if p, err := conn.Apps(ctx, "shop", ""); err != nil || len(p.Items) != 0 {
		t.Fatalf("apps %+v %v", p, err)
	}
	if p, err := conn.AppUploads(ctx, "shop", ""); err != nil || len(p.Items) != 0 {
		t.Fatalf("app-uploads %+v %v", p, err)
	}
	if _, err := conn.Lifecycles(ctx, "shop", ""); err != nil {
		t.Fatalf("lifecycles %v", err)
	}
	if p, err := conn.Resources(ctx, "shop", ""); err != nil || slices.ContainsFunc(p.Items, func(e control.ResourceEntry) bool { return e.Network != nil || e.Limit != nil }) {
		t.Fatalf("resources %+v %v", p, err)
	}
	if _, err := conn.Registries(ctx, "shop", ""); err != nil {
		t.Fatalf("registries %v", err)
	}
	if _, err := conn.ExternalRegistryPage(ctx, "shop", ""); err != nil {
		t.Fatalf("external-registries %v", err)
	}
	if _, err := conn.VolumeBackups(ctx, "shop", ""); err != nil {
		t.Fatalf("volume-backups %v", err)
	}
	if _, err := conn.VolumeRestores(ctx, "shop", ""); err != nil {
		t.Fatalf("volume-restores %v", err)
	}
	if _, err := conn.Vault(ctx, "shop", ""); err != nil {
		t.Fatalf("vault %v", err)
	}
	if p, err := conn.Standalones(ctx, "shop", ""); err != nil || len(p.Items) != 0 {
		t.Fatalf("standalones %+v %v", p, err)
	}
	if p, err := conn.Tasks(ctx, TaskFilter{Tenant: "shop"}, ""); err != nil || len(p.Items) != 0 {
		t.Fatalf("tasks %+v %v", p, err)
	}
	doc := []byte("name: web\nservices:\n  php:\n    image: php:8\n    x-sfc:\n      node: node-a\nx-sfc:\n  tenant: shop\n")
	// No network or quota yet: sfcd's input code comes through.
	var bad *Error
	if _, err := conn.AppPlan(ctx, AppPlanRequest{Tenant: "shop", Document: doc}); !errors.As(err, &bad) || bad.Code != CodeInvalid || bad.InputCode == "" {
		t.Fatalf("app-plan %v", err)
	}
	single := []byte("services:\n  debug:\n    image: busybox:1\n    x-sfc:\n      node: node-a\n")
	var badStandalone *Error
	if _, err := conn.AppPlan(ctx, AppPlanRequest{Tenant: "shop", Document: single, Deployment: "deploy",
		Standalone: &control.StandaloneDefinition{Name: "debug", Mode: "entrypoint", Lifetime: "fixed"}}); !errors.As(err, &badStandalone) || badStandalone.Code != CodeInvalid || badStandalone.InputCode == "" {
		t.Fatalf("standalone plan %v", err)
	}
	var missing *Error
	if _, err := conn.AppOperation(ctx, "shop", "web", "op-1"); !errors.As(err, &missing) || missing.Code != CodeMissing {
		t.Fatalf("app-operation %v", err)
	}

	// Private input goes to the pinned node over the socket; an unknown write
	// is refused there, never relayed. The refusal is the reply's code.
	pinned := config.Peer{ID: "node-a", Key: hex.EncodeToString(n.Config.NodeKey[:])}
	if r, err := conn.WriteVault(ctx, "shop", pinned, SecretWrite{Realm: "shop", ID: "w-1", Mode: "recover"}); err != nil || r.Code != "denied" || r.Observation != nil {
		t.Fatalf("write-vault %+v %v", r, err)
	}
	if _, err := conn.WriteVault(ctx, "shop", config.Peer{ID: "node-a", Key: "zz"}, SecretWrite{Realm: "shop", ID: "w-1", Mode: "recover"}); !errors.As(err, &bad) || bad.Code != CodeInvalid {
		t.Fatalf("write-vault bad key %v", err)
	}

	// A shell opens only for a submitted open-node-shell original.
	if _, err := conn.OpenNodeShell(ctx, op); !errors.As(err, &bad) || bad.Code != CodeInvalid {
		t.Fatalf("node-shell from create-tenant %v", err)
	}
	shellOp, err := conn.PrepareRequest(ctx, "shell-1", realChange(t, ActionOpenNodeShell, s.User, 0, OpenNodeShell{Node: "node-a", Cols: 80, Rows: 24}), 0)
	if err != nil {
		t.Fatal(err)
	}
	if sh, err := conn.OpenNodeShell(ctx, shellOp); !errors.As(err, &bad) || bad.Code != CodeForbidden {
		if sh != nil {
			sh.Close()
		}
		t.Fatalf("node-shell without a submitted original %v", err)
	}

	// Close ends calls in flight and wipes the key only after they return.
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var e *Error
			if _, err := conn.Volumes(ctx, "shop", ""); err != nil && (!errors.As(err, &e) || e.Code != CodeClosed && e.Code != CodeTransport && e.Code != CodeUnknown) {
				t.Errorf("volumes during close %v", err)
			}
		}()
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	var e *Error
	if _, err := conn.Volumes(ctx, "shop", ""); !errors.As(err, &e) || e.Code != CodeClosed {
		t.Fatalf("volumes after close %v", err)
	}
}

func TestRealAppViewFlattensCD(t *testing.T) {
	var policy deployment.DeliveryDeclaration
	policy.Source.Repository, policy.Source.Ref, policy.Sync.Mode = "https://git.example/shop", "main", "manual"
	cd := control.AppCDView{Revision: 4, PolicyRevision: 2, Policy: policy, Paused: true, Target: [32]byte{1},
		Running:   &deployment.DeliverySelection{Commit: "aaa"},
		Candidate: &deployment.DeliverySelection{Commit: "bbb", Candidate: [32]byte{2}},
		Status:    &deployment.DeliveryStatus{Sync: "OutOfSync", EffectiveSync: "Paused", LastSuccessCommit: "aaa", SourceError: "boom"}}
	v := appView(control.AppView{Tenant: "shop", App: "web", Revision: 3, Retirement: &control.AppRetirementStatus{ID: "r"}, CD: &cd})
	got := v.CD
	if !v.Retiring || got == nil || got.Repository != policy.Source.Repository || got.Branch != "main" || got.Mode != "manual" || !got.Paused ||
		got.Running != "aaa" || got.Candidate != "bbb" || got.CandidateDigest != [32]byte{2} || got.Sync != "OutOfSync" ||
		got.EffectiveSync != "Paused" || got.SourceError != "boom" || got.Target != [32]byte{1} || got.PolicyRevision != 2 {
		t.Fatalf("%+v %+v", v, got)
	}
	if appView(control.AppView{App: "plain"}).CD != nil {
		t.Fatal("cd without a cd view")
	}
}

func TestRealVaultPaths(t *testing.T) {
	got := vaultViews("shop", []secrets.Object{
		{ID: "app", Parent: "shop", Kind: secrets.Group, Revision: 2, ACL: secrets.ACL{Users: []string{"u2", "u1"}}},
		{ID: "db", Parent: "app", Kind: secrets.Secret, Revision: 3, Reference: secrets.Reference{Profile: "main", Keys: []string{"pw", "user"}}},
		{ID: "shop", Kind: secrets.Group, Revision: 1},
	})
	paths := map[string]VaultView{}
	for _, v := range got {
		paths[v.Path] = v
	}
	if r, ok := paths["shop"]; !ok || r.Parent != "shop" || r.Kind != "group" {
		t.Fatalf("root %+v", got)
	}
	if g := paths["app"]; g.Parent != "shop" || !slices.Equal(g.ACL.Users, []string{"u1", "u2"}) {
		t.Fatalf("group %+v", g)
	}
	if o := paths["app/db"]; o.Kind != "object" || o.Profile != "main" || len(o.Keys) != 2 || o.Revision != 3 {
		t.Fatalf("object %+v", got)
	}
}

func TestRealTaskView(t *testing.T) {
	restarts, exit := uint64(3), int64(137)
	v := taskView(control.TaskView{Tenant: "shop", App: "web", Service: "php", TaskID: "php/1", Observed: "running", RestartCount: &restarts, ExitCode: &exit,
		StartedAt: "2026-11-25T01:02:03.5Z", LastCheck: &containerops.TaskCheck{Checker: "docker-health", Status: "fail"}})
	if v.Instance != "php/1" || v.Restarts != 3 || v.ExitCode != 137 || v.StartedAt != 1795568523 || v.Health != "unhealthy" {
		t.Fatalf("%+v", v)
	}
	if taskView(control.TaskView{Standalone: "dbg"}).App != "dbg" {
		t.Fatal("standalone task")
	}
}

func TestRealContainerShapes(t *testing.T) {
	lines := logLines([]byte("2026-11-25T01:00:02Z b\n2026-11-25T01:00:00Z a\n"), []byte("2026-11-25T01:00:01Z err\n"))
	if len(lines) != 3 || lines[0].Text != "a" || lines[1].Stream != "stderr" || lines[2].Text != "b" {
		t.Fatalf("%+v", lines)
	}
	ps := processes([]string{"UID", "PID", "PPID", "C", "CMD"}, [][]string{{"root", "7", "1", "2", "nginx -g"}})
	if len(ps) != 1 || ps[0].PID != 7 || ps[0].User != "root" || ps[0].Command != "nginx -g" || ps[0].CPU != 2 {
		t.Fatalf("%+v", ps)
	}
	if exitReason(containerops.DetailHistory{Reason: "oom"}) != ExitReasonOOM || exitReason(containerops.DetailHistory{Reason: "signal"}) != ExitReasonExit {
		t.Fatal("exit reason")
	}
}

func TestRealCDShapes(t *testing.T) {
	run := cdHistoryRow(control.AppCDHistoryRecord{Commit: "c1", Status: "executing", Code: "x"})
	rej := cdHistoryRow(control.AppCDHistoryRecord{Commit: "c2", Status: "rejected", Code: "denied", Reason: "too risky"})
	ok := cdHistoryRow(control.AppCDHistoryRecord{Commit: "c3", Status: "succeeded", Reason: "looks fine", PlannedAt: 5})
	if run.Result != CDRunning || rej.Result != CDFailed || rej.Reason != "too risky" || ok.Note != "looks fine" || ok.PlannedAt != 5 {
		t.Fatalf("%+v %+v %+v", run, rej, ok)
	}
	present := deployment.PublicFieldValue{Present: true, Value: json.RawMessage(`"a"`)}
	d := cdChanges(control.AppCDDiff{Tenant: "t", App: "a", ChangeCount: 3, Changes: []deployment.ServiceFieldChange{
		{Service: "db", Action: "added", Path: []string{"services", "db"}, After: present},
		{Service: "old", Action: "removed", Path: []string{"services", "old"}},
		{Service: "web", Action: "changed", Path: []string{"services", "web", "image"}, Before: present},
	}})
	if !slices.Equal(d.Added, []string{"db"}) || !slices.Equal(d.Removed, []string{"old"}) || len(d.Services) != 1 ||
		d.Services[0].Service != "web" || string(d.Services[0].Fields[0].Before) != `"a"` || d.Services[0].Fields[0].After != nil {
		t.Fatalf("%+v", d)
	}
}
