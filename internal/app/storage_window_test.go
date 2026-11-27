// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/workload"
)

func TestRealManagedLedgerWindowPreservesResourcesPendingAndSameDB(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	root := t.TempDir()
	key := func(name string) *identity.Identity {
		t.Helper()
		v, err := identity.Create(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { clear(v.Private) })
		return v
	}
	adminKey, aliceKey, targetKey := key("admin"), key("alice"), key("target")
	probe, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.LocalAddr().String()
	_ = probe.Close()
	cfg := config.Node{Version: 1, Common: config.Common{}, Modules: map[string]config.Module{"network": {}, "workload": {}, "ingress": {}}}
	cfg.Node.ID, cfg.Node.Listen = "node-a", address
	cfg.Node.StateDir, cfg.Node.IdentityDir = filepath.Join(root, "state"), filepath.Join(root, "node-key")
	initialized, err := Initialize(ctx, cfg, adminKey.Public, "init-window")
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := Open(cfg)
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
	peer := sfcp.Peer{ID: cfg.Node.ID, Endpoint: address, Policy: sfcp.Policy{Key: sfcp.Identity(runtime.Identity.Public), Respond: true}}
	clientFor := func() *userauth.Client {
		t.Helper()
		self, err := identity.Ephemeral()
		if err != nil {
			t.Fatal(err)
		}
		mesh, err := sfcp.NewTransport(self, clusterID, func(k sfcp.Identity) (sfcp.Peer, bool) { return peer, k == peer.Key })
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = mesh.Close(); clear(self.Private) })
		return &userauth.Client{Self: self, Mesh: mesh, Cluster: clusterID, Peers: []sfcp.Peer{peer}}
	}
	admin, alice := clientFor(), clientFor()
	enrolled, err := admin.Enroll(ctx, peer, control.Enrollment{Schema: 1, RequestID: "enroll-window", User: access.User{ID: "admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: adminKey.Public, Enabled: true}}}}, adminKey.Private)
	if err != nil || enrolled.Result == nil || enrolled.Result.Code != state.Applied {
		t.Fatal("enroll", err)
	}
	adminSession, err := admin.Login(ctx, peer, "admin", adminKey.Private)
	if err != nil {
		t.Fatal(err)
	}
	read := func() cluster.View {
		t.Helper()
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for {
			view, err := runtime.Engine().Read(ctx, true)
			if err == nil {
				return view
			}
			if !errors.Is(err, raft.ErrNotLeader) && !errors.Is(err, raft.ErrLeadershipLost) {
				t.Fatal(err)
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-tick.C:
			}
		}
	}
	prepare := func(client *userauth.Client, session access.Session, id, action string, expected uint64, payload any) control.UserOperation {
		t.Helper()
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		op, err := client.Prepare(ctx, peer, session, id, control.Change{Schema: 1, Principal: session.User, Action: action, Expected: expected, Payload: raw})
		if err != nil {
			t.Fatal("prepare", action, err)
		}
		return op
	}
	apply := func(client *userauth.Client, op control.UserOperation, want state.Code) state.Result {
		t.Helper()
		reply, err := client.Operation(ctx, peer, op, false)
		if err != nil || reply.Result == nil || reply.Result.Code != want {
			t.Fatal("apply", op.Change.Action, reply.Code, reply.Result, err)
		}
		return *reply.Result
	}
	propose := func(id, action string, expected uint64, payload any) control.UserOperation {
		t.Helper()
		op := prepare(admin, adminSession, id, action, expected, payload)
		apply(admin, op, state.Applied)
		return op
	}
	catalog := func() access.Catalog {
		t.Helper()
		c, err := policy.Catalog(read().State)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	resources := func() control.Resources {
		t.Helper()
		r, err := policy.Resources(read().State)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	propose("alice", "put-user", 0, access.User{ID: "alice", Username: "alice", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: aliceKey.Public, Enabled: true}}})
	aliceSession, err := alice.Login(ctx, peer, "alice", aliceKey.Private)
	if err != nil {
		t.Fatal(err)
	}
	propose("tenant", "create-tenant", 0, control.TenantID{ID: "first"})
	tenant, _ := catalog().Tenant("first")
	propose("nodes", "set-nodes", tenant.Revision, control.NodeChangeTo("first", tenant.AllowedNodes, []string{cfg.Node.ID}))
	for _, scope := range []string{"", "first"} {
		propose("quota-"+scope, "set-node-quota", 0, tenancy.NodeLimit{Tenant: scope, Node: cfg.Node.ID, Capacity: workload.Resources{CPU: 1000, Memory: 1000}})
	}
	original := propose("reserve", "reserve-task", resources().Quotas.Revision(), tenancy.Reservation{Key: "workload/task/first/app/php", Tenant: "first", Node: cfg.Node.ID, Need: workload.Resources{CPU: 10, Memory: 100}})
	heldResources := resources()
	heldRoot := read().State.Object(control.ResourcesKey)
	// A local intent that has never been sent must also remain distinguishable
	// from an expired command that committed; absence cannot settle either one.
	unsent := prepare(admin, adminSession, "not-sent", "create-tenant", 0, control.TenantID{ID: "unsent"})
	home := t.TempDir()
	if err = userauth.Save(home, *admin, adminSession, ""); err != nil {
		t.Fatal(err)
	}
	pendingLogout := prepare(admin, adminSession, "pending-logout", "revoke-session", adminSession.AccountRevision, control.SessionRevocation{User: "admin", Session: adminSession.ID})
	if err = userauth.StageLogout(home, *admin, pendingLogout); err != nil {
		t.Fatal(err)
	}
	unauthorized := prepare(alice, aliceSession, "forbidden-window", "rotate-ledger", 1, control.LedgerWindow{NextEpoch: 2})
	apply(alice, unauthorized, state.Forbidden)
	if read().State.ModuleEpoch() != 1 {
		t.Fatal("ordinary user advanced global epoch")
	}
	rotate := prepare(admin, adminSession, "window-2", "rotate-ledger", 1, control.LedgerWindow{NextEpoch: 2})
	if rotate.Epoch != 1 {
		t.Fatal("initial epoch")
	}
	witness := apply(admin, rotate, state.Applied)
	view := read()
	if view.State.ModuleEpoch() != 2 || view.State.Object(control.ResourcesKey) != heldRoot || !reflect.DeepEqual(resources(), heldResources) {
		t.Fatal("rotation released/changed held resources")
	}
	if _, _, _, exists := view.State.Principal("user/" + admin.Self.Actor()); exists {
		t.Fatal("retired session actor retained")
	}
	if st, err := policy.Storage(view.State); err != nil || st.Epoch != 2 {
		t.Fatal(st, err)
	}
	index := view.State.Index()
	for _, op := range []control.UserOperation{original, unsent, pendingLogout} {
		for _, mode := range []string{"result", "resume", "submit"} {
			var reply userauth.Reply
			var err error
			switch mode {
			case "result":
				reply, err = admin.Result(ctx, peer, adminSession, op)
			case "resume":
				reply, err = admin.Resume(ctx, peer, adminSession, op)
			case "submit":
				reply, err = admin.Operation(ctx, peer, op, false)
			}
			var rejected *userauth.Error
			if !errors.As(err, &rejected) || rejected.Code != "expired" || reply.Found || reply.Result != nil {
				t.Fatal("expiry fabricated original outcome", mode, reply.Code, err)
			}
		}
	}
	if read().State.Index() != index {
		t.Fatal("expired edge request submitted new Raft command")
	}
	if err = userauth.SettleLogout(home, *admin, pendingLogout, state.Result{Code: state.Expired, Index: index}); err == nil {
		t.Fatal("expiry cleared local pending logout")
	}
	stored, err := userauth.Load(home, *admin)
	if err != nil || stored.Pending == nil || stored.Pending.RequestID != pendingLogout.RequestID {
		t.Fatal("pending lost", err)
	}
	clear(stored.Self.Private)
	// Rotation's own old-epoch response is the one exact retained exception.
	recovered, err := admin.Result(ctx, peer, adminSession, rotate)
	if err != nil || recovered.Result == nil || *recovered.Result != witness {
		t.Fatal("rotation result lost", err)
	}
	recovered, err = admin.Resume(ctx, peer, adminSession, rotate)
	if err != nil || recovered.Result == nil || *recovered.Result != witness || read().State.Index() != index {
		t.Fatal("rotation resume re-executed", err)
	}
	conflict := rotate
	conflict.Change.Payload, _ = json.Marshal(control.LedgerWindow{NextEpoch: 9})
	conflict.Signature = ed25519.Sign(admin.Self.Private, control.OperationBytes(conflict))
	if reply, err := admin.Result(ctx, peer, adminSession, conflict); err == nil || reply.Found {
		t.Fatal("different digest got rotation receipt")
	}
	fresh := propose("new-epoch-tenant", "create-tenant", 0, control.TenantID{ID: "fresh"})
	if fresh.Epoch != 2 {
		t.Fatal("client did not use current committed floor")
	}
	beforeRestart := read().State.Index()
	if err = runtime.Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if err = runtime.Close(); err != nil {
		t.Fatal(err)
	}
	runtime = nil
	runtime, err = Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runtime.InstallConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	restored := read()
	if restored.State.Index() != beforeRestart || restored.State.ModuleEpoch() != 2 || restored.State.Object(control.ResourcesKey) != heldRoot || !reflect.DeepEqual(resources(), heldResources) {
		t.Fatal("same DB/Snapshot lost floor/ownership")
	}
	recovered, err = admin.Result(ctx, peer, adminSession, rotate)
	if err != nil || recovered.Result == nil || *recovered.Result != witness {
		t.Fatal("same DB rotation receipt", err)
	}
	// An approved but unexecuted original join remains a live A2 reference.
	propose("invite-pending", "invite-node", 0, control.NodeInvitation{Peer: config.Peer{ID: "node-b", Key: targetKey.Actor(), Endpoint: "127.0.0.1:19443"}, JoinID: "pending-join"})
	blocked := prepare(admin, adminSession, "window-3-blocked", "rotate-ledger", 2, control.LedgerWindow{NextEpoch: 3})
	apply(admin, blocked, state.ConditionFailed)
	if read().State.ModuleEpoch() != 2 || read().State.Object(control.ResourcesKey) != heldRoot {
		t.Fatal("pending membership erased")
	}
	t.Log("actual SFCP/user proof -> Raft/FSM/bbolt explicit global window; original held budget unchanged; expired result/resume/submit preserve Unknown/local Pending; exact rotation receipt, same DB/Snapshot and live membership guard")
}
