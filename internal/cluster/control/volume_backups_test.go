// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

type backupCoreFixture struct {
	t           *testing.T
	p           Policy
	s           state.State
	admin, node ed25519.PrivateKey
	session     access.Session
	scope       volumes.Scope
}

func newBackupCore(t *testing.T) *backupCoreFixture {
	t.Helper()
	f := &backupCoreFixture{t: t, admin: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{121}, 32)), node: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{122}, 32))}
	a, n := [32]byte(f.admin.Public().(ed25519.PublicKey)), [32]byte(f.node.Public().(ed25519.PublicKey))
	f.p = Policy{Cluster: [32]byte{123}, BootstrapKey: a, TrustRoot: n, Genesis: config.Peer{ID: "node-a", Key: hex.EncodeToString(n[:]), Endpoint: "127.0.0.1:8001", Voter: true}}
	c, _ := access.New(a)
	var err error
	c, err = c.Enroll(a, access.User{ID: "admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: a, Enabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	c, err = c.CreateTenant("admin", "tenant", 0)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := c.Tenant("tenant")
	c, err = c.SetNodes("admin", "tenant", tenant.Revision, []string{"node-a"})
	if err != nil {
		t.Fatal(err)
	}
	f.s, _ = state.New("anchor")
	writes, code := f.p.checkpoint(f.s, c)
	if code != state.Applied {
		t.Fatal(code)
	}
	f.s, _, err = state.ApplyReduced(f.s, 1, state.Command{Kind: state.Module, Actor: "anchor", Epoch: 1, RequestID: "catalog", Key: CatalogKey, Value: "fixture"}, f.p.Validate, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, state.Applied })
	if err != nil {
		t.Fatal(err)
	}
	u, _ := c.User("admin")
	f.session = access.Session{Schema: 1, ID: "session", Cluster: f.p.Cluster, User: "admin", Credential: "key", AccountRevision: u.Revision, Key: a, Issuer: n, IssuerEpoch: 1, IssuedAt: 1, ExpiresAt: 1001, Scopes: []access.Scope{{Tenant: "*", Actions: []access.Action{access.Read, access.ManageVolumes, access.ManageCluster}}}}
	f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
	f.scope = volumes.Scope{Cluster: f.p.Cluster, Tenant: "tenant", App: "app", ID: "data", Generation: 1}
	f.apply("create", "create-volume", 0, volumeFact(t, f.scope, "node-a", f.node), state.Applied)
	return f
}
func (f *backupCoreFixture) view() Volumes {
	f.t.Helper()
	v, e := f.p.Volumes(f.s)
	if e != nil {
		f.t.Fatal(e)
	}
	return v
}
func (f *backupCoreFixture) core() volumes.State {
	f.t.Helper()
	v, ok := f.view().Volume(f.scope)
	if !ok {
		f.t.Fatal("volume")
	}
	return v
}
func (f *backupCoreFixture) apply(id, action string, expected uint64, payload any, want state.Code) {
	f.t.Helper()
	raw, e := ChangeBytes(action, "admin", expected, payload)
	if e != nil {
		f.t.Fatal(e)
	}
	var change Change
	_ = json.Unmarshal(raw, &change)
	op := UserOperation{Schema: 1, Session: f.session, At: 2, Epoch: f.s.ModuleEpoch(), RequestID: id, RootRevision: f.s.Object(CommandKey(action)).Revision, Change: change}
	op.Signature = ed25519.Sign(f.admin, OperationBytes(op))
	cmd, e := op.Command()
	if e != nil {
		f.t.Fatal(e)
	}
	// Use the same typed related-checkpoint boundary as the product, including
	// catalog changes whose revoked grants retire shared routes atomically.
	next, r, e := state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if e != nil || r.Code != want {
		f.t.Fatal(id, r.Code, want, e)
	}
	f.s = next
}
func (f *backupCoreFixture) limits() {
	for _, tenant := range []string{"", "tenant"} {
		f.apply("limit-"+tenant, "set-volume-backup-limit", 0, VolumeBackupLimit{Tenant: tenant, Node: "node-a", Bytes: 65536, Count: 1}, state.Applied)
	}
}
func (f *backupCoreFixture) begin(id string, want state.Code) {
	f.apply(fmt.Sprintf("begin-%s-%d", id, f.s.Index()), "begin-volume-backup", f.core().Revision(), VolumeBackupBegin{Scope: f.scope, ID: id, MaxBytes: 65536, MaxEntries: 16, Compatibility: [32]byte{1}}, want)
}
func (f *backupCoreFixture) report(id, kind string) VolumeBackupReport {
	f.t.Helper()
	j, ok := f.view().Backup(f.scope, id)
	if !ok {
		f.t.Fatal("job")
	}
	r := VolumeBackupReport{Schema: 1, Scope: f.scope, ID: id, Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(VolumesKey).Revision, Revision: j.Revision, At: 2, Binding: j.Binding.Digest(), Kind: kind}
	if kind == "ready" {
		r.Receipt = volumes.ArchiveReceipt{Schema: 1, Digest: [32]byte{2}, Bytes: 4096, DataBytes: 100, Entries: 2}
		r.DirectorySynced, r.CleanShutdown, r.Compatible = true, true, true
	}
	if kind == "failed" {
		r.DirectorySynced = true
		r.ArtifactGone = true
		r.Failure = "copy-failed"
	}
	if kind == "gone" {
		r.DirectorySynced = true
		r.ArtifactGone = true
	} else {
		g := volumes.Gone{Scope: f.scope, Consumer: j.Binding.Consumer, Stopped: true, MountsGone: true}
		g.Signature = ed25519.Sign(f.node, volumes.GoneBytes(g))
		r.Closed = &g
	}
	r.Signature = ed25519.Sign(f.node, VolumeBackupReportBytes(r))
	return r
}
func (f *backupCoreFixture) commitReport(r VolumeBackupReport, want state.Code) {
	f.t.Helper()
	raw, _ := json.Marshal(r)
	cmd, e := f.p.ResolveVolumeBackupReport(f.s, [32]byte(f.node.Public().(ed25519.PublicKey)), raw)
	if e != nil {
		f.t.Fatal(e)
	}
	next, result, e := state.ApplyAdmitted(f.s, f.s.Index()+1, cmd, f.p.Validate, f.p.Reduce, f.p.AdmitModule)
	if e != nil || result.Code != want {
		f.t.Fatal("report", result.Code, want, e)
	}
	f.s = next
}
func TestVolumeBackupAtomicReaderAndGlobalTenantReservation(t *testing.T) {
	f := newBackupCore(t)
	revision := f.core().Revision()
	f.begin("without-budget", state.ConditionFailed)
	if f.core().Revision() != revision || len(f.core().Consumers()) != 0 {
		t.Fatal("failed admission reserved reader")
	}
	f.limits()
	f.begin("one", state.Applied)
	f.begin("two", state.ConditionFailed)
	if len(f.core().Consumers()) != 1 || len(f.view().Backups()) != 1 {
		t.Fatal("partial budget admission")
	}
	f.apply("writer", "acquire-volume", f.core().Revision(), VolumeAcquire{Scope: f.scope, Consumer: "writer", Generation: 1, Writable: true}, state.ConditionFailed)
	limit := f.view().BackupLimits()[0]
	f.apply("shrink", "set-volume-backup-limit", limit.Revision, VolumeBackupLimit{Tenant: limit.Tenant, Node: limit.Node, Bytes: 1024, Count: 1}, state.ConditionFailed)
	if f.view().Quiescent() || f.p.storageQuiescent(f.s) {
		t.Fatal("pending backup escaped ledger collector")
	}
	store := f.view()
	job, _ := store.Backup(f.scope, "one")
	job.Binding.Origin.Session.Scopes[0].Actions[0] = access.ManageRoutes
	original, _ := store.Backup(f.scope, "one")
	if original.Binding.Origin.Session.Scopes[0].Actions[0] != access.Read {
		t.Fatal("public view shares nested origin slices")
	}
	if _, e := f.p.VolumeBackupPermit(f.s, [32]byte(f.node.Public().(ed25519.PublicKey)), VolumeBackupSelection{f.scope, "one"}, false); e != nil {
		t.Fatal("view mutation changed source", e)
	}
	raw, e := state.Encode(f.s)
	if e != nil {
		t.Fatal(e)
	}
	restored, e := state.Decode(raw)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.p.Volumes(restored); e != nil {
		t.Fatal("typed snapshot", e)
	}
}
func TestVolumeBackupSignedCompletionDeletionAndStableID(t *testing.T) {
	f := newBackupCore(t)
	f.limits()
	f.begin("one", state.Applied)
	valid := f.report("one", "ready")
	for _, mutate := range []func(*VolumeBackupReport){func(r *VolumeBackupReport) { r.CleanShutdown = false }, func(r *VolumeBackupReport) { r.DirectorySynced = false }, func(r *VolumeBackupReport) { r.Compatible = false }, func(r *VolumeBackupReport) { r.Binding[0] ^= 1 }, func(r *VolumeBackupReport) { r.Closed.Consumer.Lease.Token++ }} {
		raw, _ := json.Marshal(valid)
		var bad VolumeBackupReport
		_ = json.Unmarshal(raw, &bad)
		mutate(&bad)
		bad.Signature = ed25519.Sign(f.node, VolumeBackupReportBytes(bad))
		body, _ := json.Marshal(bad)
		if _, e := f.p.ResolveVolumeBackupReport(f.s, [32]byte(f.node.Public().(ed25519.PublicKey)), body); e == nil {
			t.Fatal("unproven completion admitted")
		}
	}
	f.commitReport(valid, state.Applied)
	if len(f.core().Consumers()) != 0 {
		t.Fatal("source reader retained after signed closure")
	}
	job, _ := f.view().Backup(f.scope, "one")
	if job.Phase != "Ready" || !f.view().Quiescent() {
		t.Fatal("ready phase")
	}
	f.apply("delete", "delete-volume-backup", job.Revision, VolumeBackupSelection{f.scope, "one"}, state.Applied)
	if f.view().Quiescent() {
		t.Fatal("delete lost original artifact reference")
	}
	unconfirmed := f.report("one", "gone")
	unconfirmed.DirectorySynced = false
	unconfirmed.Signature = ed25519.Sign(f.node, VolumeBackupReportBytes(unconfirmed))
	badRaw, _ := json.Marshal(unconfirmed)
	if _, err := f.p.ResolveVolumeBackupReport(f.s, [32]byte(f.node.Public().(ed25519.PublicKey)), badRaw); err == nil {
		t.Fatal("unsynced removal released artifact reservation")
	}
	f.commitReport(f.report("one", "gone"), state.Applied)
	job, _ = f.view().Backup(f.scope, "one")
	if job.Phase != "Deleted" || job.Completion == nil || job.Completion.Kind != "ready" || !f.view().Quiescent() {
		t.Fatal("original completion/tombstone lost")
	}
	f.begin("one", state.ConditionFailed)
	f.begin("new", state.Applied)
}
func TestVolumeBackupCancelRaceAndRevokedCopyCleanup(t *testing.T) {
	f := newBackupCore(t)
	f.limits()
	f.begin("one", state.Applied)
	f.apply("cancel", "cancel-volume-backup", 1, VolumeBackupSelection{f.scope, "one"}, state.Applied)
	if len(f.core().Consumers()) != 1 {
		t.Fatal("cancel returned unknown reader")
	}
	selection := VolumeBackupSelection{f.scope, "one"}
	node := [32]byte(f.node.Public().(ed25519.PublicKey))
	if _, e := f.p.VolumeBackupPermit(f.s, node, selection, false); e == nil {
		t.Fatal("cancel allowed copy")
	}
	if _, e := f.p.VolumeBackupPermit(f.s, node, selection, true); e != nil {
		t.Fatal("cancel lost cleanup", e)
	}
	f.commitReport(f.report("one", "ready"), state.Applied)
	job, _ := f.view().Backup(f.scope, "one")
	if job.Phase != "Deleting" || job.Receipt == nil || len(f.core().Consumers()) != 0 {
		t.Fatal("late ready dropped artifact or reader")
	}
	f.commitReport(f.report("one", "gone"), state.Applied)
	f.begin("two", state.Applied)
	c, _ := f.p.Catalog(f.s)
	tenant, _ := c.Tenant("tenant")
	f.apply("revoke", "set-nodes", tenant.Revision, NodeAssignment{Tenant: "tenant"}, state.Applied)
	if _, e := f.p.VolumeBackupPermit(f.s, node, VolumeBackupSelection{f.scope, "two"}, false); e == nil {
		t.Fatal("revoked authority permitted source read")
	}
	if len(f.core().Consumers()) != 1 {
		t.Fatal("revoke returned unknown consumer")
	}
	f.apply("cancel-two", "cancel-volume-backup", 1, VolumeBackupSelection{f.scope, "two"}, state.Applied)
	f.commitReport(f.report("two", "failed"), state.Applied)
	job, _ = f.view().Backup(f.scope, "two")
	if job.Phase != "Cancelled" || len(f.core().Consumers()) != 0 {
		t.Fatal("original no-artifact closure not settled")
	}
}

func TestVolumeBackupAcceptedGrantSurvivesSessionLogoutAndExpiry(t *testing.T) {
	f := newBackupCore(t)
	f.limits()
	f.begin("one", state.Applied)
	c, _ := f.p.Catalog(f.s)
	current, _ := f.p.Current(f.s)
	if c.VerifySession(f.session, f.p.Cluster, current.Issuer(f.session.Issuer), 1002) == nil {
		t.Fatal("expiry precondition")
	}
	user, _ := c.User("admin")
	f.apply("logout", "revoke-session", user.Revision, SessionRevocation{User: "admin", Session: f.session.ID}, state.Applied)
	c, _ = f.p.Catalog(f.s)
	if c.VerifySession(f.session, f.p.Cluster, current.Issuer(f.session.Issuer), 2) == nil {
		t.Fatal("logout precondition")
	}
	if _, err := f.p.VolumeBackupPermit(f.s, [32]byte(f.node.Public().(ed25519.PublicKey)), VolumeBackupSelection{f.scope, "one"}, false); err != nil {
		t.Fatal("accepted job became dependent on departed submit session", err)
	}
	f.commitReport(f.report("one", "ready"), state.Applied)
	job, _ := f.view().Backup(f.scope, "one")
	if job.Phase != "Ready" || job.Binding.Origin.Session.ID != f.session.ID {
		t.Fatal("accepted scope/operation replaced")
	}
}
