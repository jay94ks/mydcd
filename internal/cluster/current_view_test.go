// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/sfcp"

	"github.com/hashicorp/raft"
)

func currentViewSDKPolicy(nodes []realNode) control.Policy {
	return control.Policy{Cluster: [32]byte{1}, BootstrapKey: nodes[0].identity.Public, TrustRoot: nodes[0].identity.Public, Genesis: config.Peer{ID: "node-1", Endpoint: nodes[0].address, Key: hex.EncodeToString(nodes[0].identity.Public[:]), Voter: true}}
}

func configureCurrentViewSDK(options *Options, nodes []realNode) {
	policy := currentViewSDKPolicy(nodes)
	// Start with real enrollment; managed policy never admits the legacy
	// bootstrap-native mutation used by the ordinary unmanaged fixture.
	options.ModuleID, options.Validate, options.Reduce, options.AdmitModule = policy.ID(), policy.ValidateManaged, policy.Reduce, policy.AdmitModule
}

// Reuses the existing three-voter/nonvoter SDK/bbolt/authenticated SFCP
// fixture. Image/native effects are deliberately absent: current authority
// and exact target checks are the product control core, and ioCalls counts
// only entry into the declared finite effect boundary.
func verifyCurrentViewSDK(t *testing.T, ctx context.Context, nodes []realNode, leader int, wait func(string, func() bool), lookup func(sfcp.Identity) (sfcp.Peer, bool)) {
	t.Helper()
	if leader == 0 {
		if err := nodes[0].engine.TransferLeadership(ctx, nodes[1].options.ID, nodes[1].address); err != nil {
			t.Fatal("place original owner on follower", err)
		}
		wait("owner follower and new leader", func() bool { return nodes[1].engine.IsLeader() && !nodes[0].engine.IsLeader() })
		leader = 1
	}
	owner := &nodes[0]
	p := currentViewSDKPolicy(nodes)
	submit := func(cmd state.Command) Committed {
		t.Helper()
		out, err := nodes[leader].engine.Submit(ctx, cmd)
		if err != nil || out.Result.Code != state.Applied {
			t.Fatal("original command did not commit", cmd.RequestID, cmd.Key, out.Result, err)
		}
		return out
	}
	admin := nodes[0].identity
	enrollment := control.Enrollment{Schema: 1, RequestID: "current-view-enroll", User: access.User{ID: "admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: admin.Public, Enabled: true}}}}
	cmd, err := enrollment.Command(admin.Public)
	if err != nil {
		t.Fatal(err)
	}
	submit(cmd)
	view, err := nodes[leader].engine.Read(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := p.Catalog(view.State)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := catalog.User("admin")
	now := time.Now().Unix()
	session := access.Session{Schema: 1, ID: "current-view-user", Cluster: p.Cluster, User: "admin", Credential: "key", AccountRevision: u.Revision, Key: admin.Public, Issuer: admin.Public, IssuerEpoch: 1, IssuedAt: now, ExpiresAt: now + 600, Scopes: []access.Scope{{Tenant: "*", Actions: []access.Action{access.Read, access.ManageCluster, access.ManageTrust, access.Deploy}}}}
	session.Signature = ed25519.Sign(admin.Private, access.SessionBytes(session))
	sequence := 0
	change := func(action string, expected uint64, value any) {
		t.Helper()
		view, err := nodes[leader].engine.Read(ctx, true)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := control.ChangeBytes(action, session.User, expected, value)
		if err != nil {
			t.Fatal(err)
		}
		var input control.Change
		if err = json.Unmarshal(raw, &input); err != nil {
			t.Fatal(err)
		}
		sequence++
		op := control.UserOperation{Schema: 1, Session: session, At: time.Now().Unix(), Epoch: view.State.ModuleEpoch(), RequestID: fmt.Sprintf("current-view-%d", sequence), RootRevision: view.State.Object(control.CommandKey(action)).Revision, Change: input}
		op.Signature = ed25519.Sign(admin.Private, control.OperationBytes(op))
		cmd, err := op.Command()
		if err != nil {
			t.Fatal(err)
		}
		submit(cmd)
	}
	change("create-tenant", 0, control.TenantID{ID: "tenant"})
	view, err = nodes[leader].engine.Read(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	catalog, _ = p.Catalog(view.State)
	tenant, _ := catalog.Tenant("tenant")
	change("set-trust", tenant.Revision, control.TrustChange{Tenant: "tenant", Add: []access.TrustRule{{Registry: "registry.example.test", Repository: "team/app"}}})
	view, err = CurrentView(ctx, owner.engine, owner.mesh, owner.identity, p.Cluster)
	if err != nil || view.Local || owner.engine.IsLeader() {
		t.Fatal("authenticated current prefix did not reach follower owner", err)
	}
	read, err := p.PlanImageResolve(view.State, session, time.Now().Unix(), "tenant", control.ImageResolveQuery{Ref: "registry.example.test/team/app:release"}, owner.identity.Public)
	if err != nil || read.Target.Code != "" || read.Target.Owner != owner.identity.Public {
		t.Fatal("exact original owner read", read.Target, err)
	}
	// A barrier without another management command advances the Raft floor.
	peer, ok := lookup(sfcp.Identity(nodes[leader].identity.Public))
	if !ok {
		t.Fatal("fixture leader peer missing")
	}
	barrier, err := CallManagement(ctx, owner.mesh, owner.identity, p.Cluster, peer, ManagementRequest{Method: "status", Latest: true})
	if err != nil {
		t.Fatal(err)
	}
	current, err := CurrentView(ctx, owner.engine, owner.mesh, owner.identity, p.Cluster)
	if err != nil || current.State.Index() < barrier.CommandIndex || current.RaftIndex < barrier.RaftIndex || current.Local {
		t.Fatal("command ordinal was confused with Raft barrier position", current.RaftIndex, barrier.RaftIndex, err)
	}
	ioCalls := 0
	consume := func(call context.Context, input control.ImageResolveRead, effect func()) error {
		before, err := CurrentView(call, owner.engine, owner.mesh, owner.identity, p.Cluster)
		if err != nil {
			return err
		}
		if _, err = p.CurrentImageResolve(before.State, input, time.Now().Unix()); err != nil {
			return err
		}
		ioCalls++
		if effect != nil {
			effect()
		}
		after, err := CurrentView(call, owner.engine, owner.mesh, owner.identity, p.Cluster)
		if err != nil {
			return err
		}
		_, err = p.CurrentImageResolve(after.State, input, time.Now().Unix())
		return err
	}
	if err := consume(ctx, read, nil); err != nil || ioCalls != 1 {
		t.Fatal("follower exact source failed before simulated I/O", ioCalls, err)
	}
	wrong := read
	wrong.Target.Owner = nodes[leader].identity.Public
	if err := consume(ctx, wrong, nil); err == nil || ioCalls != 1 {
		t.Fatal("another owner consumed original read", ioCalls, err)
	}
	// A resolver ID cannot rename the authenticated peer that produced the
	// status receipt. The original target remains pinned to that one reply.
	resolve := owner.engine.resolve
	owner.engine.resolve = func(id raft.ServerID, address raft.ServerAddress) (sfcp.Peer, bool) {
		peer, ok := resolve(id, address)
		peer.ID = "different-peer"
		return peer, ok
	}
	err = consume(ctx, read, nil)
	owner.engine.resolve = resolve
	if err == nil || ioCalls != 1 {
		t.Fatal("status reply from another peer ID admitted", ioCalls, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := consume(canceled, read, nil); err == nil || ioCalls != 1 {
		t.Fatal("canceled freshness read entered I/O", ioCalls, err)
	}
	// A status barrier need not create another application command. Hold the
	// owner's publication and commit a real independent management command on
	// the remaining voters so the returned prefix is provably not local yet.
	func() {
		owner.engine.fsm.mu.Lock()
		defer owner.engine.fsm.mu.Unlock()
		change("create-tenant", 0, control.TenantID{ID: "prefix-wait"})
		short, stop := context.WithTimeout(ctx, 100*time.Millisecond)
		defer stop()
		err = consume(short, read, nil)
	}()
	if err == nil || !errors.Is(err, context.DeadlineExceeded) || ioCalls != 1 {
		t.Fatal("unreceived current prefix entered I/O", ioCalls, err)
	}
	view, err = CurrentView(ctx, owner.engine, owner.mesh, owner.identity, p.Cluster)
	if err != nil {
		t.Fatal("owner did not consume the original committed prefix", err)
	}
	read, err = p.PlanImageResolve(view.State, session, time.Now().Unix(), "tenant", control.ImageResolveQuery{Ref: "registry.example.test/team/app:release"}, owner.identity.Public)
	if err != nil {
		t.Fatal("current original target after prefix catch-up", err)
	}
	// Current user/trust checks occur on each newly consumed quorum view.
	// Revocation after the declared finite effect denies its returned value;
	// the next request must be denied before entering another effect.
	if err := consume(ctx, read, func() {
		latest, err := nodes[leader].engine.Read(ctx, true)
		if err != nil {
			t.Fatal(err)
		}
		catalog, _ := p.Catalog(latest.State)
		user, _ := catalog.User("admin")
		expected := user.Revision
		user.Revision = 0
		user.Credentials[0].Label = "changed-current-account"
		change("put-user", expected, user)
	}); err == nil || ioCalls != 2 {
		t.Fatal("post-I/O authority revocation returned stale data", ioCalls, err)
	}
	if err := consume(ctx, read, nil); err == nil || ioCalls != 2 {
		t.Fatal("revoked current user entered another I/O", ioCalls, err)
	}
}
