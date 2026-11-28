// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/nodestorage"
	"github.com/jay94ks/seafield/internal/volumearchive"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// The owner work (pack, clear, restore) is simulated by signed reports; this
// tests the FSM, holds and root accounting, not the native facts.
type archiveFixture struct {
	*nodeStorageFixture
	t     *testing.T
	scope volumes.Scope
}

func newArchiveFixture(t *testing.T) *archiveFixture {
	t.Helper()
	f := &archiveFixture{nodeStorageFixture: newNodeStorageFixture(t), t: t}
	f.apply("admin", "add-node-storage", 0, nodestorage.Definition{Node: "node-a", ID: "hdd", Path: "/mnt/hdd", Tenants: []string{"tenant"}}, state.Applied)
	f.observe()
	f.scope = volumes.Scope{Cluster: f.p.Cluster, Tenant: "tenant", App: "shop", ID: "data", Generation: 1}
	f.apply("admin", "create-volume", 0, volumeFact(t, f.scope, "node-a", f.node), state.Applied)
	return f
}

func (f *archiveFixture) view() Volumes {
	f.t.Helper()
	v, err := f.p.Volumes(f.s)
	if err != nil {
		f.t.Fatal(err)
	}
	return v
}
func (f *archiveFixture) core() volumes.State {
	f.t.Helper()
	c, ok := f.view().Volume(f.scope)
	if !ok {
		f.t.Fatal("volume")
	}
	return c
}
func (f *archiveFixture) job(id string) VolumeArchive {
	f.t.Helper()
	j, ok := f.view().Archive(f.scope, id)
	if !ok {
		f.t.Fatal("archive", id)
	}
	return j
}

func (f *archiveFixture) keys() {
	f.t.Helper()
	admin := [32]byte{9}
	f.apply("manager", "set-volume-archive-admin-key", 0, VolumeArchiveAdminKey{admin}, state.Forbidden)
	f.apply("admin", "set-volume-archive-admin-key", 0, VolumeArchiveAdminKey{admin}, state.Applied)
	f.apply("admin", "set-volume-archive-admin-key", 1, VolumeArchiveAdminKey{admin}, state.ConditionFailed)
	f.keyReport(f.manager, state.Forbidden)
	f.keyReport(f.node, state.Applied)
	f.keyReport(f.node, state.ConditionFailed)
}

func (f *archiveFixture) keyReport(key ed25519.PrivateKey, want state.Code) {
	f.t.Helper()
	r := VolumeArchiveKeyReport{Operation: "archive-key", Schema: 1, Cluster: f.p.Cluster, Reporter: [32]byte(key.Public().(ed25519.PublicKey)), Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(VolumesKey).Revision, Key: [32]byte{8}}
	r.Signature = ed25519.Sign(key, VolumeArchiveKeyReportBytes(r))
	cmd, err := r.Command()
	if err != nil {
		f.t.Fatal(err)
	}
	f.commit(cmd, want)
}

func (f *archiveFixture) commit(cmd state.Command, want state.Code) {
	f.t.Helper()
	n, result, err := state.ApplyAdmitted(f.s, f.s.Index()+1, cmd, f.p.Validate, f.p.Reduce, f.p.AdmitModule)
	if want == state.Forbidden && err != nil {
		return // refused at admission
	}
	if err != nil || result.Code != want {
		f.t.Fatal("report", result.Code, want, err)
	}
	f.s = n
}

func (f *archiveFixture) begin(id, root string, want state.Code) {
	f.t.Helper()
	f.apply("manager", "archive-volume", f.core().Revision(), VolumeArchiveBegin{Scope: f.scope, ID: id, Root: root, Compression: volumearchive.Zstd, MaxBytes: 1 << 20, MaxEntries: 64}, want)
}

func (f *archiveFixture) manifest(j VolumeArchive) *volumearchive.Manifest {
	m := volumearchive.Manifest{Schema: 1, ID: j.Binding.ID, Scope: f.scope, Compression: j.Binding.Compression, Tar: volumes.ArchiveReceipt{Schema: 1, Digest: [32]byte{2}, Bytes: 4096, DataBytes: 100, Entries: 2}, DataBytes: 3000, DataDigest: [32]byte{3}, Node: f.p.TrustRoot, At: 1}
	m = volumearchive.Sign(m, f.node)
	return &m
}

func (f *archiveFixture) report(id, kind string, edit func(*VolumeArchiveReport), want state.Code) {
	f.t.Helper()
	j := f.job(id)
	r := VolumeArchiveReport{Operation: "archive", Schema: 1, Scope: f.scope, ID: id, Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(VolumesKey).Revision, Revision: j.Revision, At: 2, Binding: j.Binding.Digest(), Kind: kind}
	switch kind {
	case "packed":
		r.Manifest = f.manifest(j)
	case "failed", "unrestored":
		r.Failure = "copy-failed"
	}
	if kind == "failed" || kind == "cancelled" || kind == "restored" || kind == "discarded" {
		g := volumes.Gone{Scope: f.scope, Consumer: j.Binding.Consumer, Stopped: true, MountsGone: true}
		g.Signature = ed25519.Sign(f.node, volumes.GoneBytes(g))
		r.Closed = &g
	}
	signer := f.node
	if edit != nil {
		edit(&r)
		if r.Signature != nil {
			signer, r.Signature = f.manager, nil
		}
	}
	r.Signature = ed25519.Sign(signer, VolumeArchiveReportBytes(r))
	raw, _ := json.Marshal(r)
	cmd, err := f.p.ResolveVolumeArchiveReport(f.s, f.p.TrustRoot, raw)
	if err != nil {
		if want == state.Forbidden {
			return
		}
		f.t.Fatal("resolve", kind, err)
	}
	f.commit(cmd, want)
}

func (f *archiveFixture) reserved() uint64 {
	f.t.Helper()
	n, err := reservedOnRoot(f.view(), f.root().Reference(f.p.Cluster))
	if err != nil {
		f.t.Fatal(err)
	}
	return n
}

// volumeRow checks the Volume's row in the volumes page.
func (f *archiveFixture) volumeRow(phase, id, archivePhase string) {
	f.t.Helper()
	c, err := f.p.Catalog(f.s)
	if err != nil {
		f.t.Fatal(err)
	}
	rows, _, err := f.view().Page(c, "admin", "tenant", "")
	if err != nil || len(rows) != 1 || rows[0].Phase != phase || rows[0].ArchiveID != id || rows[0].ArchivePhase != archivePhase {
		f.t.Fatalf("volume row %+v %v", rows, err)
	}
}

func (f *archiveFixture) phase(id, want string) {
	f.t.Helper()
	if got := f.job(id).Phase; got != want {
		f.t.Fatal("phase", id, got, want)
	}
}

func TestVolumeArchiveHoldsVolumeUntilRestored(t *testing.T) {
	f := newArchiveFixture(t)
	f.begin("a-1", "hdd", state.ConditionFailed) // no recipient keys yet
	f.keys()
	f.begin("a-1", "", state.ConditionFailed) // no archive default, no "default" root
	f.begin("a-1", "hdd", state.Applied)
	f.phase("a-1", "Packing")
	f.volumeRow("Archived", "a-1", "Packing")
	if f.reserved() != archiveBound(1<<20) || !f.view().Archived(f.scope) {
		t.Fatal("packing reservation", f.reserved())
	}
	if b := f.job("a-1").Binding; b.Recipients != [2][32]byte{{8}, {9}} || b.Root.ID != "hdd" {
		t.Fatal("binding", b.Recipients, b.Root.ID)
	}
	// Nothing else may take the Volume while it is held.
	f.apply("manager", "acquire-volume", f.core().Revision(), VolumeAcquire{f.scope, "writer", 1, true}, state.ConditionFailed)
	f.begin("a-2", "hdd", state.ConditionFailed)
	f.apply("admin", "delete-volume", f.core().Revision(), f.scope, state.ConditionFailed)

	// A manifest that is not this binding's is refused.
	f.report("a-1", "packed", func(r *VolumeArchiveReport) { r.Manifest.Compression = volumearchive.None }, state.Forbidden)
	f.report("a-1", "packed", func(r *VolumeArchiveReport) { r.Signature = []byte{1} }, state.Forbidden)
	f.report("a-1", "cleared", nil, state.ConditionFailed)
	f.report("a-1", "packed", nil, state.Applied)
	f.phase("a-1", "Clearing")
	f.report("a-1", "cleared", nil, state.Applied)
	f.phase("a-1", "Archived")
	if f.reserved() != 3000 || !f.view().Quiescent() {
		t.Fatal("archived package charge", f.reserved())
	}
	limit := uint64(2000)
	f.apply("admin", "set-node-storage-policy", f.root().Revision, NodeStoragePolicy{Node: "node-a", ID: "hdd", CapacityBytes: &limit}, state.ConditionFailed)

	f.apply("manager", "unarchive-volume", f.job("a-1").Revision, VolumeArchiveSelection{f.scope, "a-1"}, state.Applied)
	f.report("a-1", "unrestored", nil, state.Applied)
	f.phase("a-1", "Archived")
	f.apply("manager", "unarchive-volume", f.job("a-1").Revision, VolumeArchiveSelection{f.scope, "a-1"}, state.Applied)
	f.report("a-1", "restored", nil, state.Applied)
	f.phase("a-1", "Restored")
	f.volumeRow("Ready", "", "")
	if f.reserved() != 0 || f.view().Archived(f.scope) || len(f.core().Consumers()) != 0 {
		t.Fatal("restored archive still holds", f.reserved())
	}
	f.apply("manager", "acquire-volume", f.core().Revision(), VolumeAcquire{f.scope, "writer", 1, true}, state.Applied)
}

func TestVolumeArchiveCancelFailAndDiscard(t *testing.T) {
	f := newArchiveFixture(t)
	f.keys()
	f.begin("a-1", "hdd", state.Applied)
	f.apply("manager", "discard-volume-archive", 1, VolumeArchiveSelection{f.scope, "a-1"}, state.ConditionFailed)
	f.apply("manager", "cancel-volume-archive", 1, VolumeArchiveSelection{f.scope, "a-1"}, state.Applied)
	f.report("a-1", "packed", nil, state.ConditionFailed)
	f.report("a-1", "cancelled", nil, state.Applied)
	f.phase("a-1", "Cancelled")

	f.begin("a-2", "hdd", state.Applied)
	if _, ok := f.view().Archive(f.scope, "a-1"); ok {
		t.Fatal("finished record of the same Volume kept")
	}
	f.report("a-2", "failed", nil, state.Applied)
	f.phase("a-2", "Failed")

	f.apply("admin", "set-node-archive-default", f.root().Revision, NodeArchiveDefault{Node: "node-a", ID: "hdd", Default: true}, state.Applied)
	f.begin("a-3", "", state.Applied)
	f.report("a-3", "packed", nil, state.Applied)
	f.report("a-3", "cleared", nil, state.Applied)
	f.apply("manager", "discard-volume-archive", f.job("a-3").Revision, VolumeArchiveSelection{f.scope, "a-3"}, state.Applied)
	f.report("a-3", "discarded", nil, state.Applied)
	f.phase("a-3", "Discarded")
	if f.reserved() != 0 || len(f.core().Consumers()) != 0 {
		t.Fatal("discarded archive still holds")
	}
}
