// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/app"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/secrets"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
)

// A single voter is its own majority: a builtin write needs no Vault, keeps
// the value out of Raft, and a lost reply resumes with the sealed original.
func TestBuiltinSecretWriteOnSingleVoter(t *testing.T) {
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
	initialized, err := app.Initialize(ctx, cfg, admin.Public, "init-builtin")
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := app.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
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
	enrolled, err := user.Enroll(ctx, peer, control.Enrollment{Schema: 1, RequestID: "enroll-builtin", User: access.User{ID: "admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: admin.Public, Enabled: true}}}}, admin.Private)
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
	apply := func(id, action string, expected uint64, payload any, want state.Code) {
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
	}
	apply("tenant", "create-tenant", 0, control.TenantID{ID: "tenant"}, state.Applied)
	catalog, _ := policy.Catalog(read())
	tenant, _ := catalog.Tenant("tenant")
	apply("nodes", "set-nodes", tenant.Revision, control.NodeChangeTo("tenant", tenant.AllowedNodes, []string{"node-a"}), state.Applied)
	apply("init", "vault-init", 0, control.VaultRealm{Realm: "tenant", Root: "root"}, state.Applied)
	apply("bad-object", "vault-create", current().Trees["tenant"].Revision(), control.VaultObject{Realm: "tenant", Object: secrets.Object{ID: "runtime", Parent: "root", Kind: secrets.Secret, Reference: secrets.Reference{Profile: secrets.BuiltinProfile, Object: "elsewhere", Keys: []string{"key"}}}}, state.ConditionFailed)
	apply("secret", "vault-create", current().Trees["tenant"].Revision(), control.VaultObject{Realm: "tenant", Object: secrets.Object{ID: "runtime", Parent: "root", Kind: secrets.Secret, Reference: secrets.Reference{Keys: []string{"key"}}}}, state.Applied)
	plan, err := user.PlanVaultWrite(ctx, peer, session, control.VaultWritePlanRequest{Realm: "tenant", ID: "first", Object: "runtime", Kind: secrets.ValueWrite, Keys: []string{"key"}})
	if err != nil || plan.Request.Profile != secrets.BuiltinProfile || plan.Request.ProviderObject != "runtime" {
		t.Fatal("builtin plan", plan.Request, err)
	}
	apply("prepare", "vault-prepare-write", plan.TreeRevision, control.VaultWrite{Realm: "tenant", Request: plan.Request}, state.Applied)
	apply("dispatch", "vault-dispatch-write", current().Trees["tenant"].Revision(), control.VaultWriteAction{Realm: "tenant", ID: "first", Epoch: plan.Request.Epoch}, state.Applied)
	plan, err = user.PlanVaultWrite(ctx, peer, session, control.VaultWritePlanRequest{Realm: "tenant", ID: "first"})
	if err != nil || len(plan.Voters) != 1 || plan.Receiver == nil || plan.Voters[0].ID != "node-a" {
		t.Fatal("builtin writers", plan.Voters, err)
	}
	private := []byte("private-builtin-value")
	write := func(mode string, value []byte) *secrets.WriteObservation {
		t.Helper()
		q := userauth.SecretRequest{Realm: "tenant", ID: "first", Mode: mode}
		if value != nil {
			q.Values = map[string][]byte{"key": value}
		}
		reply, e := user.WriteVault(ctx, peer, session, q)
		if e != nil || reply.VaultObservation == nil {
			t.Fatal(mode, reply.Code, e)
		}
		return reply.VaultObservation
	}
	first := write("execute", private)
	if first.Outcome != reconcile.EffectApplied || first.ProviderRevision != 1 || first.Digest == ([32]byte{}) || len(first.Holders) != 1 || first.Reporter != runtime.Identity.Public {
		t.Fatal("single voter majority", first)
	}
	// The first reply was lost: neither recover nor a second execute with
	// another value seals anything new.
	if again := write("execute", []byte("different-value")); again.Digest != first.Digest {
		t.Fatal("lost reply resealed a new value")
	}
	if again := write("recover", nil); again.Digest != first.Digest {
		t.Fatal("recover changed the value")
	}
	apply("observe", "vault-observe-write", current().Trees["tenant"].Revision(), control.VaultObserve{Observation: *first}, state.Applied)
	w, _ := current().Trees["tenant"].Write("first")
	apply("publish", "vault-publish-write", current().Trees["tenant"].Revision(), control.VaultWriteAction{Realm: "tenant", ID: "first", Epoch: w.Request.Epoch, ObjectRevision: w.ExpectedObjectRevision}, state.Applied)
	object, _ := current().Trees["tenant"].Object("runtime")
	if w, _ = current().Trees["tenant"].Write("first"); w.Status() != "Published" || object.Reference.Revision != 1 {
		t.Fatal("builtin write not published", w.Status(), object.Reference)
	}
	if h, ok := current().Trees["tenant"].BuiltinHolding(secrets.ValueWrite, "runtime", 1); !ok || h.Digest != first.Digest || len(h.Holders) != 1 || h.Holders[0] != runtime.Identity.Public {
		t.Fatal("published holding", h)
	}
	// A second revision supersedes the first, so the first holding is pruned.
	plan, err = user.PlanVaultWrite(ctx, peer, session, control.VaultWritePlanRequest{Realm: "tenant", ID: "second", Object: "runtime", Kind: secrets.ValueWrite, Keys: []string{"key"}})
	if err != nil {
		t.Fatal(err)
	}
	apply("prepare-2", "vault-prepare-write", plan.TreeRevision, control.VaultWrite{Realm: "tenant", Request: plan.Request}, state.Applied)
	apply("dispatch-2", "vault-dispatch-write", current().Trees["tenant"].Revision(), control.VaultWriteAction{Realm: "tenant", ID: "second", Epoch: plan.Request.Epoch}, state.Applied)
	reply, err := user.WriteVault(ctx, peer, session, userauth.SecretRequest{Realm: "tenant", ID: "second", Mode: "execute", Values: map[string][]byte{"key": []byte("private-second-value")}})
	if err != nil || reply.VaultObservation == nil {
		t.Fatal("second write", err)
	}
	apply("observe-2", "vault-observe-write", current().Trees["tenant"].Revision(), control.VaultObserve{Observation: *reply.VaultObservation}, state.Applied)
	w, _ = current().Trees["tenant"].Write("second")
	apply("publish-2", "vault-publish-write", current().Trees["tenant"].Revision(), control.VaultWriteAction{Realm: "tenant", ID: "second", Epoch: w.Request.Epoch, ObjectRevision: w.ExpectedObjectRevision}, state.Applied)
	if hs := current().Trees["tenant"].BuiltinHoldings(); len(hs) != 1 || hs[0].Revision != 2 {
		t.Fatal("superseded holding kept", hs)
	}
	encoded, _ := state.Encode(read())
	if bytes.Contains(encoded, private) {
		t.Fatal("value in shared state")
	}
	local, err := os.ReadFile(filepath.Join(cfg.Node.StateDir, "vault", "builtin.db"))
	if err != nil || bytes.Contains(local, private) || !bytes.Contains(local, []byte(`"Realm":"tenant"`)) {
		t.Fatal("local builtin store", err)
	}
	t.Log("builtin write held by the single voter, published without Vault; value absent from Raft and plain local file; lost reply kept the original")
}
