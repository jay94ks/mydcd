// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// Isolation must leave an active voter for NEW user grants. Native membership
// observations are explicit model input, not evidence of a real Raft cluster.
func cleanupControlIssuer(t *testing.T, f *backupCoreFixture) (ed25519.PrivateKey, lifecycle.Configuration) {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{127}, 32))
	key := [32]byte(private.Public().(ed25519.PublicKey))
	d, err := f.p.Members(f.s)
	if err != nil {
		t.Fatal(err)
	}
	base := uint64(1)
	for _, entry := range d.Entries {
		base = max(base, entry.NativeIndex+1)
	}
	advance := func(next membership.Directory, err error) {
		t.Helper()
		if err != nil {
			t.Fatal("install separate control issuer", err)
		}
		d = next
	}
	peer := config.Peer{ID: "node-control", Key: hex.EncodeToString(key[:]), Endpoint: "127.0.0.1:8999"}
	advance(d.Invite(peer, "cleanup-control", nil))
	entry, _ := d.Entry(peer.ID)
	advance(d.Dispatch(peer.ID, entry.Revision, entry.Job.Pending.ID, base, f.p.TrustRoot))
	entry, _ = d.Entry(peer.ID)
	advance(d.Observe(peer.ID, entry.Revision, entry.Job.Pending.ID, base+1, peer))
	entry, _ = d.Entry(peer.ID)
	ack := membership.Ack{Schema: 1, Cluster: f.p.Cluster, Node: peer.ID, JoinID: entry.JoinID, Key: key, ConfigurationIndex: base + 1, AppliedIndex: base + 1}
	ack.Signature = ed25519.Sign(private, membership.AckBytes(ack))
	advance(d.Installed(ack, entry.Revision))
	entry, _ = d.Entry(peer.ID)
	advance(d.Promote(peer.ID, entry.Revision))
	entry, _ = d.Entry(peer.ID)
	advance(d.Dispatch(peer.ID, entry.Revision, entry.Job.Pending.ID, base+2, f.p.TrustRoot))
	entry, _ = d.Entry(peer.ID)
	peer.Voter = true
	advance(d.Observe(peer.ID, entry.Revision, entry.Job.Pending.ID, base+3, peer))
	writes, code := f.p.memberCheckpoint(f.s, d)
	if code != state.Applied {
		t.Fatal(code)
	}
	cmd := state.Command{Kind: state.Module, Actor: "anchor", Epoch: f.s.ModuleEpoch(), RequestID: "fixture-cleanup-control", Key: MembersKey, Expected: f.s.Object(MembersKey).Revision, Value: "injected installed voter"}
	next, result, err := state.ApplyReduced(f.s, f.s.Index()+1, cmd, f.p.Validate, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, state.Applied })
	if err != nil || result.Code != state.Applied {
		t.Fatal("control issuer checkpoint", result, err)
	}
	f.s = next
	f.session.Issuer = key
	f.session.Signature = ed25519.Sign(private, access.SessionBytes(f.session))
	configuration := lifecycle.Configuration{Index: base + 3}
	for _, entry := range d.Entries {
		if membership.FullMember(entry) {
			key, err := identity.ParseKey(entry.Peer.Key)
			if err != nil {
				t.Fatal(err)
			}
			configuration.Members = append(configuration.Members, lifecycle.Member{ID: entry.Peer.ID, Key: key, Voter: entry.Peer.Voter})
		}
	}
	return private, configuration
}

func nodeCoreReport(t *testing.T, f *backupCoreFixture, r MemberReport, want state.Code) {
	t.Helper()
	r.Schema, r.Cluster, r.Reporter, r.Epoch = 1, f.p.Cluster, f.p.TrustRoot, f.s.ModuleEpoch()
	r.RootRevision = f.s.Object(MembersKey).Revision
	r.RequestID = fmt.Sprintf("report-%s-%d", r.Action, f.s.Index())
	r.Signature = ed25519.Sign(f.node, MemberReportBytes(r))
	cmd, err := r.Command()
	if err != nil {
		t.Fatal(err)
	}
	next, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || result.Code != want {
		t.Fatal(r.Action, result.Code, want, err)
	}
	f.s = next
}

func isolateVolumeCore(t *testing.T, f *backupCoreFixture) {
	t.Helper()
	_, configuration := cleanupControlIssuer(t, f)
	d, err := f.p.Members(f.s)
	if err != nil {
		t.Fatal(err)
	}
	nodeCoreReport(t, f, MemberReport{Action: "configuration", Node: "node-a", Expected: d.Revision, Configuration: &configuration}, state.Applied)
	d, _ = f.p.Members(f.s)
	topology, _ := d.Topology()
	node, _ := topology.Node("node-a")
	f.apply("isolate-volume-owner", "isolate-node", node.Revision, NodeLifecycleChange{ID: "node-a", Operation: "isolate-volume-owner", Epoch: topology.Epoch()}, state.Applied)
}

func TestNodeIsolationRejectsNewVolumeWorkAndPreservesOriginalCleanup(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		f, q := createCore(t)
		f.apply("reserve-create", "begin-volume-create", 0, q, state.Applied)
		commitCreation(t, f, VolumeCreateReport{Scope: q.Scope, Revision: 1, Prepared: true}, state.Applied)
		original, _ := f.view().Creation(q.Scope)
		isolateVolumeCore(t, f)
		fresh := q
		fresh.Scope.ID = "new-after-isolation"
		f.apply("deny-new-create", "begin-volume-create", 0, fresh, state.Forbidden)
		f.apply("deny-raw-registration", "create-volume", 0, volumeFact(t, fresh.Scope, "node-a", f.node), state.Forbidden)
		if _, err := f.p.VolumeCreatePermit(f.s, f.p.TrustRoot, q.Scope); err == nil {
			t.Fatal("original create permit admitted a new native effect")
		}
		f.apply("cancel-original-create", "cancel-volume-create", original.Revision, q.Scope, state.Applied)
		cleanup, err := f.p.VolumeCreatePermit(f.s, f.p.TrustRoot, q.Scope)
		if err != nil || cleanup.Spec != original.Spec || cleanup.Phase != "Cancelling" {
			t.Fatal("original create cleanup identity changed", err)
		}
		owner, err := creationOwner(original.Spec)
		if err != nil {
			t.Fatal(err)
		}
		gone := volumes.NativeRemoved{Schema: 1, Scope: q.Scope, Owner: owner, Key: volumes.NativeKey(original.Spec), Generation: creationNativeGeneration(original.Spec), DeleteRevision: 3}
		gone.Signature = ed25519.Sign(f.node, volumes.NativeRemovedBytes(gone)) // Modeled native closure.
		commitCreation(t, f, VolumeCreateReport{Scope: q.Scope, Revision: 3, Gone: &gone}, state.Applied)
		closed, _ := f.view().Creation(q.Scope)
		if closed.Phase != "Cancelled" || !bytes.Equal(OperationBytes(closed.Origin), OperationBytes(original.Origin)) || closed.Spec != original.Spec {
			t.Fatal("cleanup replaced original or retained unknown work")
		}
	})
	t.Run("backup", func(t *testing.T) {
		f := newBackupCore(t)
		f.limits()
		f.begin("original", state.Applied)
		original, _ := f.view().Backup(f.scope, "original")
		selection := VolumeBackupSelection{Scope: f.scope, ID: "original"}
		isolateVolumeCore(t, f)
		f.begin("fresh", state.Forbidden)
		if _, err := f.p.VolumeBackupPermit(f.s, f.p.TrustRoot, selection, false); err == nil {
			t.Fatal("isolated backup owner admitted a new copy")
		}
		f.apply("cancel-original-backup", "cancel-volume-backup", original.Revision, selection, state.Applied)
		if _, err := f.p.VolumeBackupPermit(f.s, f.p.TrustRoot, selection, true); err != nil {
			t.Fatal("original backup cleanup blocked", err)
		}
		if len(f.core().Consumers()) != 1 {
			t.Fatal("isolation/cancel returned unknown original reader")
		}
		f.commitReport(f.report("original", "failed"), state.Applied)
		closed, _ := f.view().Backup(f.scope, "original")
		if len(f.core().Consumers()) != 0 || closed.Binding.Digest() != original.Binding.Digest() {
			t.Fatal("backup closure lost original binding/reader")
		}
	})
	t.Run("restore", func(t *testing.T) {
		f, q := restoreCore(t)
		restoreLimits(f, q.MaxBytes, 1)
		f.apply("reserve-restore", "begin-volume-restore", 2, q, state.Applied)
		selection := VolumeRestoreSelection{Backup: q.Backup, ID: q.ID}
		original, _ := f.view().Restore(selection)
		isolateVolumeCore(t, f)
		if _, err := f.p.VolumeRestorePermit(f.s, f.p.TrustRoot, selection, false); err == nil {
			t.Fatal("isolated restore owner admitted new IO")
		}
		f.apply("cancel-original-restore", "cancel-volume-restore", original.Revision, selection, state.Applied)
		if _, err := f.p.VolumeRestorePermit(f.s, f.p.TrustRoot, selection, true); err != nil {
			t.Fatal("original restore cleanup blocked", err)
		}
		commitRestoreReport(t, f, restoreReport(t, f, q, "cancelled"), state.Applied)
		closed, _ := f.view().Restore(selection)
		if closed.Binding.Digest() != original.Binding.Digest() || !f.view().Quiescent() {
			t.Fatal("restore cleanup lost original binding or pin")
		}
		fresh := q
		fresh.ID, fresh.Target.Materialization = "fresh-copy", "r-fresh-copy"
		fresh.Target.Scope.ID = "new-after-isolation"
		f.apply("deny-new-restore", "begin-volume-restore", 2, fresh, state.Forbidden)
	})
}

func TestNodeClosureCannotEraseLiveSharedWriterAndCleanupStillWorks(t *testing.T) {
	f := newBackupCore(t)
	f.apply("reserve-writer", "acquire-volume", f.core().Revision(), VolumeAcquire{Scope: f.scope, Consumer: "writer", Generation: 9, Writable: true}, state.Applied)
	_, c := cleanupControlIssuer(t, f)
	d, _ := f.p.Members(f.s)
	nodeCoreReport(t, f, MemberReport{Action: "configuration", Node: "node-a", Expected: d.Revision, Configuration: &c}, state.Applied)
	d, _ = f.p.Members(f.s)
	topology, _ := d.Topology()
	node, _ := topology.Node("node-a")
	f.apply("begin-isolation", "isolate-node", node.Revision, NodeLifecycleChange{ID: "node-a", Operation: "isolate-writer", Epoch: topology.Epoch()}, state.Applied)
	activity, err := f.p.NodeActivity(f.s, f.p.TrustRoot)
	if err != nil || activity.Writers != 1 {
		t.Fatal("shared original writer omitted", activity, err)
	}
	d, _ = f.p.Members(f.s)
	topology, _ = d.Topology()
	node, _ = topology.Node("node-a")
	claim := lifecycle.Proof{Cluster: f.p.Cluster, Node: "node-a", Operation: node.Pending.ID, Generation: node.Generation, Revision: node.Pending.Revision, ConfigurationIndex: c.Index, Closed: true}
	claim.Signature = ed25519.Sign(f.node, lifecycle.ProofBytes(claim))
	nodeCoreReport(t, f, MemberReport{Action: "node-proof", Node: "node-a", Expected: d.Revision, Proof: &claim}, state.ConditionFailed)
	f.apply("new-writer-denied", "acquire-volume", f.core().Revision(), VolumeAcquire{Scope: f.scope, Consumer: "new-writer", Generation: 10, Writable: true}, state.Forbidden)
	original := f.core().Consumers()[0]
	closed := volumes.Gone{Scope: f.scope, Consumer: original, Stopped: true, MountsGone: true}
	closed.Signature = ed25519.Sign(f.node, volumes.GoneBytes(closed)) // Explicit modeled native fact.
	f.apply("original-writer-closure", "release-volume", f.core().Revision(), closed, state.Applied)
	activity, err = f.p.NodeActivity(f.s, f.p.TrustRoot)
	if err != nil || !activity.Empty() {
		t.Fatal("idle retained Volume bytes blocked isolation", activity, err)
	}
	d, _ = f.p.Members(f.s)
	nodeCoreReport(t, f, MemberReport{Action: "node-proof", Node: "node-a", Expected: d.Revision, Proof: &claim}, state.Applied)
}

func TestNodeRestoreKeepsOriginalSignedIntentAndNeedsCurrentAdminGrant(t *testing.T) {
	f := newBackupCore(t)
	issuer, configuration := cleanupControlIssuer(t, f)
	d, _ := f.p.Members(f.s)
	nodeCoreReport(t, f, MemberReport{Action: "configuration", Node: "node-a", Expected: d.Revision, Configuration: &configuration}, state.Applied)
	d, _ = f.p.Members(f.s)
	topology, _ := d.Topology()
	node, _ := topology.Node("node-a")
	f.apply("isolate", "isolate-node", node.Revision, NodeLifecycleChange{ID: "node-a", Operation: "isolate-a", Epoch: topology.Epoch()}, state.Applied)
	d, _ = f.p.Members(f.s)
	if _, err := f.p.workNodeOwner(f.s, "node-a"); err == nil || !d.MemberKey(f.p.TrustRoot) || !d.ReplicationKey(f.p.TrustRoot) {
		t.Fatal("new admission and consensus were not separated")
	}
	proof := func() lifecycle.Proof {
		d, _ := f.p.Members(f.s)
		topology, _ := d.Topology()
		node, _ := topology.Node("node-a")
		p := lifecycle.Proof{Cluster: f.p.Cluster, Node: "node-a", Operation: node.Pending.ID, Generation: node.Generation, Revision: node.Pending.Revision, ConfigurationIndex: topology.Configuration().Index, Closed: node.Pending.Action != lifecycle.Restore, Ready: node.Pending.Action == lifecycle.Restore}
		p.Signature = ed25519.Sign(f.node, lifecycle.ProofBytes(p))
		return p
	}
	closed := proof() // Modeled zero counts, not a real native closure/census.
	nodeCoreReport(t, f, MemberReport{Action: "node-proof", Node: "node-a", Expected: d.Revision, Proof: &closed}, state.Applied)
	d, _ = f.p.Members(f.s)
	topology, _ = d.Topology()
	node, _ = topology.Node("node-a")
	f.apply("restore", "restore-node", node.Revision, NodeLifecycleChange{ID: "node-a", Operation: "restore-a", Epoch: topology.Epoch()}, state.Applied)
	d, _ = f.p.Members(f.s)
	original, _ := d.NodeOperation("restore-a")
	if f.p.CheckNodeEffect(f.s, "restore-a") != nil {
		t.Fatal("current original admin denied")
	}
	secondKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{93}, 32))
	secondPublic := [32]byte(secondKey.Public().(ed25519.PublicKey))
	f.apply("add-second-admin", "put-user", 0, access.User{ID: "second", Username: "second", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: secondPublic, Enabled: true}}}, state.Applied)
	catalog, _ := f.p.Catalog(f.s)
	user, _ := catalog.User("admin")
	userRevision := user.Revision
	user.Revision = 0
	user.SystemAdmin = false
	f.apply("withdraw-original-role", "put-user", userRevision, accountFields(user), state.Applied)
	if f.p.CheckNodeEffect(f.s, "restore-a") == nil {
		t.Fatal("withdrawn admin could activate a restored node")
	}
	d, _ = f.p.Members(f.s)
	ready := proof()
	nodeCoreReport(t, f, MemberReport{Action: "node-proof", Node: "node-a", Expected: d.Revision, Proof: &ready}, state.Forbidden)
	d, _ = f.p.Members(f.s)
	status, _ := d.NodeView("node-a")
	if status.AdmitsWork || status.Node.Phase != lifecycle.Restoring || status.Node.Pending.ID != "restore-a" {
		t.Fatal("rejected proof changed original policy")
	}
	catalog, _ = f.p.Catalog(f.s)
	second, _ := catalog.User("second")
	session := f.session
	session.ID, session.User, session.Key, session.AccountRevision = "second-session", second.ID, secondPublic, second.Revision
	session.Signature = ed25519.Sign(issuer, access.SessionBytes(session))
	payload, _ := json.Marshal(NodeLifecycleChange{ID: "node-a", Operation: "restore-a", Epoch: topology.Epoch()})
	op := UserOperation{Schema: 1, Session: session, At: 2, Epoch: f.s.ModuleEpoch(), RequestID: "renew-restore", RootRevision: f.s.Object(MembersKey).Revision, Change: Change{Schema: 1, Action: "resume-node-operation", Principal: second.ID, Expected: status.Node.Revision, Payload: payload}}
	op.Signature = ed25519.Sign(secondKey, OperationBytes(op))
	command, err := op.Command()
	if err != nil {
		t.Fatal(err)
	}
	next, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, command, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || result.Code != state.Applied {
		t.Fatal("explicit authorization renewal", result, err)
	}
	f.s = next
	d, err = f.p.Members(f.s)
	renewed, _ := d.NodeOperation("restore-a")
	if err != nil || !bytes.Equal(renewed.Origin, original.Origin) || len(renewed.Authorization) == 0 || f.p.CheckNodeEffect(f.s, "restore-a") != nil {
		t.Fatal("renewal lost original signature or new grant", err)
	}
	nodeCoreReport(t, f, MemberReport{Action: "node-proof", Node: "node-a", Expected: d.Revision, Proof: &ready}, state.Applied)
	d, _ = f.p.Members(f.s)
	if !d.WorkKey(f.p.TrustRoot) {
		t.Fatal("current explicit grant plus original modeled readiness did not restore")
	}
	broken := d
	broken.Runtime.Operations[0].Origin = json.RawMessage(`{}`)
	if f.p.validateNodeOrigins(broken) == nil {
		t.Fatal("unsigned original administrator intent accepted")
	}
}
