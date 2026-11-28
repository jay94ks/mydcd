// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
)

// This boundary intentionally does NOT invoke AddNonvoter/AddVoter. It verifies
// real admission/FSM/storage and durable Unknown before connecting that effect.
func TestRealManagedMemberDirectoryApprovalAndUnknownSameDB(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	root := t.TempDir()
	makeID := func(name string) *identity.Identity {
		t.Helper()
		id, err := identity.Create(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { clear(id.Private) })
		return id
	}
	admin, b, ordinary := makeID("admin"), makeID("joining-key"), makeID("ordinary-key")
	vacant := func() string {
		t.Helper()
		p, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address := p.LocalAddr().String()
		_ = p.Close()
		return address
	}
	address := vacant()
	c := config.Node{Version: 1, Common: config.Common{}, Modules: map[string]config.Module{"network": {}, "workload": {}, "ingress": {}}}
	c.Node.ID, c.Node.Listen = "node-a", address
	c.Node.StateDir, c.Node.IdentityDir = filepath.Join(root, "state"), filepath.Join(root, "node-key")
	initialized, err := Initialize(ctx, c, admin.Public, "init-member-test")
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := Open(c)
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
	genesis := initialized.Installation.Genesis
	policy := control.Policy{Cluster: clusterID, BootstrapKey: admin.Public, TrustRoot: initialized.Installation.Root.TrustRoot, Genesis: genesis}
	peer := sfcp.Peer{ID: genesis.ID, Endpoint: address, Policy: sfcp.Policy{Key: sfcp.Identity(runtime.Identity.Public), Respond: true}}
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
		return &userauth.Client{Mesh: mesh, Self: self, Cluster: clusterID, Peers: []sfcp.Peer{peer}}
	}
	client := clientFor()
	enrolled, err := client.Enroll(ctx, peer, control.Enrollment{Schema: 1, RequestID: "enroll-admin", User: access.User{ID: "admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, Enabled: true, PublicKey: admin.Public}}}}, admin.Private)
	if err != nil || enrolled.Result == nil || enrolled.Result.Code != state.Applied {
		t.Fatal("enrollment", enrolled.Code, err)
	}
	session, err := client.Login(ctx, peer, "admin", admin.Private)
	if err != nil {
		t.Fatal(err)
	}
	read := func() cluster.View {
		t.Helper()
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
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
			case <-ticker.C:
			}
		}
	}
	directory := func() membership.Directory {
		t.Helper()
		d, err := policy.Members(read().State)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	change := func(action string, expected uint64, payload any) control.Change {
		t.Helper()
		raw, err := control.ChangeBytes(action, "admin", expected, payload)
		if err != nil {
			t.Fatal(err)
		}
		var out control.Change
		_ = json.Unmarshal(raw, &out)
		return out
	}
	submit := func(id string, ch control.Change) userauth.Reply {
		t.Helper()
		op, err := client.Prepare(ctx, peer, session, id, ch)
		if err != nil {
			t.Fatal("prepare", id, err)
		}
		reply, err := client.Operation(ctx, peer, op, false)
		if err != nil || reply.Result == nil {
			t.Fatal("submit", id, reply.Code, err)
		}
		return reply
	}
	initial, err := client.MemberPage(ctx, peer, session, "")
	if err != nil || len(initial.Members) != 1 || initial.Members[0].Peer != genesis {
		t.Fatal("blank directory", err)
	}
	target := config.Peer{ID: "node-b", Key: b.Actor(), Endpoint: vacant()}
	before := read()
	catalogBefore := before.State.Object(control.CatalogKey)
	inviteChange := change("invite-node", 0, control.NodeInvitation{Peer: target, JoinID: "join-b"})
	op, err := client.Prepare(ctx, peer, session, "invite-b", inviteChange)
	if err != nil {
		t.Fatal(err)
	}
	if op.RootRevision != before.State.Object(control.MembersKey).Revision {
		t.Fatal("used catalog CAS for members")
	}
	approved, err := client.Operation(ctx, peer, op, false)
	if err != nil || approved.Result == nil || approved.Result.Code != state.Applied {
		t.Fatal("invite", approved.Code, err)
	}
	after := read()
	if after.State.Object(control.CatalogKey) != catalogBefore || after.State.Object(control.MembersKey).Revision != approved.Result.Revision {
		t.Fatal("root isolation/atomic receipt")
	}
	duplicate, err := client.Result(ctx, peer, session, op)
	if err != nil || !duplicate.Found || duplicate.Result == nil || *duplicate.Result != *approved.Result || read().State.Index() != after.State.Index() {
		t.Fatal("original approval receipt", err)
	}
	looked, found := runtime.Mesh.Peer(sfcp.Identity(b.Public))
	if !found || !looked.Replicate || !looked.Snapshot || looked.Member || looked.Manage || looked.Read || looked.Report || looked.Tunnel {
		t.Fatal("invitation widened rights", looked)
	}
	current, err := policy.Current(after.State)
	if err != nil || current.Issuer(b.Public).Enabled || !current.Issuer(runtime.Identity.Public).Enabled {
		t.Fatal("provisional issuer accepted", err)
	}
	entry, _ := directory().Entry(target.ID)
	denied := submit("premature-promotion", change("promote-node", entry.Revision, control.NodeSelection{ID: target.ID}))
	if denied.Result.Code != state.ConditionFailed {
		t.Fatal("uninstalled promotion accepted", denied.Result)
	}
	// A valid signed current user op still carries the ORIGINAL member-root CAS.
	stale := op
	stale.RequestID = "stale-member-root"
	stale.Signature = ed25519.Sign(client.Self.Private, control.OperationBytes(stale))
	rejected, err := client.Operation(ctx, peer, stale, false)
	if err != nil || rejected.Result == nil || rejected.Result.Code != state.ConditionFailed {
		t.Fatal("stale member root", rejected.Code, err)
	}
	// A regular account cannot read the node directory or self-authorize invites.
	created := submit("ordinary-account", change("put-user", 0, access.User{ID: "ordinary", Username: "ordinary", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, Enabled: true, PublicKey: ordinary.Public}}}))
	if created.Result.Code != state.Applied {
		t.Fatal(created.Result)
	}
	limited := clientFor()
	limitedSession, err := limited.Login(ctx, peer, "ordinary", ordinary.Private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = limited.Query(ctx, peer, limitedSession, "members", ""); err == nil {
		t.Fatal("ordinary account read member authority")
	}
	attack := op
	attack.Session = limitedSession
	attack.At = time.Now().Unix()
	attack.Change.Principal = "ordinary"
	attack.RequestID = "ordinary-invite"
	attack.RootRevision = read().State.Object(control.MembersKey).Revision
	attack.Signature = ed25519.Sign(limited.Self.Private, control.OperationBytes(attack))
	no, err := limited.Operation(ctx, peer, attack, false)
	if err != nil || no.Result == nil || no.Result.Code != state.Forbidden {
		t.Fatal("ordinary account changed membership", no.Code, err)
	}
	// Signed node reports are persisted by the actual FSM, before native dispatch.
	report := func(signer *identity.Identity, r control.MemberReport) state.Command {
		t.Helper()
		r.Schema, r.Cluster, r.Reporter, r.Epoch = 1, clusterID, signer.Public, 1
		r.RootRevision = read().State.Object(control.MembersKey).Revision
		r.Signature = ed25519.Sign(signer.Private, control.MemberReportBytes(r))
		cmd, err := r.Command()
		if err != nil {
			t.Fatal(err)
		}
		return cmd
	}
	apply := func(cmd state.Command, want state.Code) {
		t.Helper()
		out, err := runtime.Engine().Submit(ctx, cmd)
		if err != nil || out.Result.Code != want {
			t.Fatal("report", out.Result, err)
		}
	}
	entry, _ = directory().Entry(target.ID)
	fake := report(b, control.MemberReport{Action: "observe", Node: target.ID, Expected: entry.Revision, JobID: entry.Job.Pending.ID, ConfigurationIndex: 9, Peer: target, RequestID: "unauthorized-observe"})
	apply(fake, state.Forbidden)
	cfg, err := runtime.Engine().InstalledConfiguration(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	dispatch := report(runtime.Identity, control.MemberReport{Action: "dispatch", Node: target.ID, Expected: entry.Revision, JobID: entry.Job.Pending.ID, ConfigurationIndex: cfg.Index, RequestID: "dispatch-b"})
	apply(dispatch, state.Applied)
	entry, _ = directory().Entry(target.ID)
	// The running member loop also sees the dispatched job, tries the native
	// AddVoter towards the absent node and records the same Unknown itself. Either
	// report may commit first; the other then fails the directory CAS.
	job := entry.Job.Pending.ID
	unknown := report(runtime.Identity, control.MemberReport{Action: "unknown", Node: target.ID, Expected: entry.Revision, JobID: job, RequestID: "unknown-b"})
	reported, err := runtime.Engine().Submit(ctx, unknown)
	if err != nil || reported.Result.Code != state.Applied && reported.Result.Code != state.ConditionFailed {
		t.Fatal("report", reported.Result, err)
	}
	// node-b is not in the committed configuration at or after the dispatch
	// index, and the CAS-guarded add can never commit later, so the member
	// loop settles the Unknown as absent: the same invitation is planned again
	// and can be retried or cancelled.
	deadline := time.Now().Add(10 * time.Second)
	for {
		entry, _ = directory().Entry(target.ID)
		if entry.Job.Pending != nil && entry.Job.Pending.Phase == reconcile.Prepared || time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if entry.Job.Pending == nil || entry.Job.Pending.ID != job || entry.Job.LastID != 1 {
		t.Fatal("absent settle replaced the invitation's job", entry.Job)
	}
	if entry.Phase != membership.Invited || entry.Job.Pending.Phase != reconcile.Prepared || entry.BaseIndex != 0 || entry.Peer.Voter {
		t.Fatal("absent join not planned again", entry.Phase, entry.Job.Pending.Phase, entry.BaseIndex)
	}
	if rights, epoch, _, ok := read().State.Principal("node/" + runtime.Identity.Actor()); !ok || rights != 0 || epoch != 1 {
		t.Fatal("node report actor granted legacy rights")
	}
	saved := directory()
	savedView := read()
	if err = runtime.Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if err = runtime.Close(); err != nil {
		t.Fatal(err)
	}
	runtime = nil
	runtime, err = Open(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runtime.InstallConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	recovered := directory()
	if !reflect.DeepEqual(saved, recovered) {
		t.Fatal("same DB changed pending member job")
	}
	cfgAfter, err := runtime.Engine().InstalledConfiguration(ctx, true)
	if err != nil || len(cfgAfter.Configuration.Servers) != 1 || cfgAfter.Configuration.Servers[0].ID != "node-a" {
		t.Fatal("Unknown auto-submitted native membership", err)
	}
	if receipt, found := read().State.LookupResult(unknown); !found || receipt.Code != reported.Result.Code || receipt != func() state.Result { r, _ := savedView.State.LookupResult(unknown); return r }() {
		t.Fatal("report receipt lost")
	}
	final, err := client.MemberPage(ctx, peer, session, "")
	if err != nil || len(final.Members) != 2 || final.RootRevision != savedView.State.Object(control.MembersKey).Revision {
		t.Fatal("current session/directory after restart", err)
	}
	// Directory replies remain bounded as membership grows. Each page exposes
	// its fixed root CAS so callers can reject a concurrent changed listing.
	for i := 0; i < 9; i++ {
		seed := make([]byte, ed25519.SeedSize)
		seed[0] = byte(100 + i)
		key := ed25519.NewKeyFromSeed(seed)
		other := config.Peer{ID: fmt.Sprintf("node-c%d", i), Key: fmt.Sprintf("%x", key.Public()), Endpoint: fmt.Sprintf("127.0.0.1:%d", 19000+i)}
		clear(key)
		out := submit(fmt.Sprintf("invite-c%d", i), change("invite-node", 0, control.NodeInvitation{Peer: other, JoinID: fmt.Sprintf("join-c%d", i)}))
		if out.Result.Code != state.Applied {
			t.Fatal("additional invitation", out.Result)
		}
	}
	page, err := client.MemberPage(ctx, peer, session, "")
	if err != nil || len(page.Members) != 8 || page.Next != page.Members[7].Peer.ID {
		t.Fatal("first bounded page", err)
	}
	last, err := client.MemberPage(ctx, peer, session, page.Next)
	if err != nil || len(last.Members) != 3 || last.Next != "" || last.RootRevision != page.RootRevision || last.Members[0].Peer.ID <= page.Next {
		t.Fatal("continuation page", err)
	}
	if _, err := client.MemberPage(ctx, peer, session, "bad/cursor"); err == nil {
		t.Fatal("invalid continuation cursor accepted")
	}
	t.Logf("real SFCP user approval; actual Raft/FSM/bbolt receipt+Snapshot; absent join planned again; native configuration N1 remains; no AddNonvoter invoked; %s", fmt.Sprint(entry.Job.Pending.ID))
}
