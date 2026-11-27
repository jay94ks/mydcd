// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/nodestorage"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/workload"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// These tests use the PRODUCT FSM/Volume cores with simulated signed native
// inputs. They prove no filesystem, mount, Docker or Raft adapter success.
func fixedRegistrationFixture(t *testing.T) (*nodeStorageFixture, VolumeFixedRegister) {
	t.Helper()
	f := newNodeStorageFixture(t)
	f.apply("admin", "add-node-storage", 0, nodestorage.Definition{Node: "node-a", ID: "hdd", Path: "/mnt/hdd", Tenants: []string{"tenant"}}, state.Applied)
	f.observe()
	for _, tenant := range []string{"", "tenant"} {
		f.apply("admin", "set-node-quota", 0, tenancy.NodeLimit{Tenant: tenant, Node: "node-a", Owner: f.p.TrustRoot, Capacity: workload.Resources{CPU: 100, Memory: 1 << 20}, Networks: 1, MaxConsumers: 4}, state.Applied)
	}
	return f, VolumeFixedRegister{Scope: volumes.Scope{Cluster: f.p.Cluster, Tenant: "tenant", ID: "database", Generation: 1}, Node: "node-a", Storage: "hdd", RootGeneration: f.root().Generation, Path: "/mnt/hdd/database", QuotaMode: "observe"}
}

func (f *nodeStorageFixture) creation(scope volumes.Scope) VolumeCreation {
	f.t.Helper()
	v, err := f.p.Volumes(f.s)
	if err != nil {
		f.t.Fatal(err)
	}
	j, ok := v.Creation(scope)
	if !ok {
		f.t.Fatal("missing original creation")
	}
	return j
}

func (f *nodeStorageFixture) creationReport(scope volumes.Scope, prepared bool, ready *volumes.NativeReady, gone *volumes.NativeRemoved, want state.Code) {
	f.t.Helper()
	j := f.creation(scope)
	r := VolumeCreateReport{Operation: "create", Schema: 1, Scope: scope, Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(VolumesKey).Revision, Revision: j.Revision, At: 2, Prepared: prepared, Ready: ready, Gone: gone}
	r.Signature = ed25519.Sign(f.node, VolumeCreateReportBytes(r))
	raw, _ := json.Marshal(r)
	cmd, err := f.p.ResolveVolumeCreateReport(f.s, f.p.TrustRoot, raw)
	if err != nil {
		if want != state.Forbidden {
			f.t.Fatal("report parse", err)
		}
		return
	}
	n, result, err := state.ApplyAdmitted(f.s, f.s.Index()+1, cmd, f.p.Validate, f.p.Reduce, f.p.AdmitModule)
	if err != nil || result.Code != want {
		f.t.Fatal("creation report", result.Code, want, err)
	}
	f.s = n
}

func (f *nodeStorageFixture) fixedReady(scope volumes.Scope, seed byte) volumes.NativeReady {
	f.t.Helper()
	j := f.creation(scope)
	if j.Fixed == nil {
		f.t.Fatal("not a fixed selection")
	}
	directory := j.Fixed.Root.Directory
	directory.FilesystemPath, directory.Handle, directory.Inode = j.Fixed.FilesystemPath(), bytes.Repeat([]byte{seed}, 8), uint64(seed)
	fixed := nodestorage.FixedDirectory{Root: j.Fixed.Root, RootDirectory: j.Fixed.Root.Directory, Path: j.Fixed.Path, Directory: directory}
	r := volumes.NativeReady{Schema: 1, Spec: j.Spec, Generation: scope.Generation, Owner: volumes.Owner{Node: j.Spec.Node, Key: j.Spec.NodeKey, Native: volumes.FixedNativeName(scope)}, Fixed: &fixed}
	r.Signature = ed25519.Sign(f.node, volumes.NativeReadyBytes(r))
	if r.Verify() != nil {
		f.t.Fatal("invalid simulated physical binding")
	}
	return r
}

func (f *nodeStorageFixture) fixedGone(j VolumeCreation) volumes.NativeRemoved {
	f.t.Helper()
	r := volumes.NativeRemoved{Schema: 1, Scope: j.Spec.Scope, Owner: volumes.Owner{Node: j.Spec.Node, Key: j.Spec.NodeKey, Native: volumes.FixedNativeName(j.Spec.Scope)}, Key: volumes.NativeKey(j.Spec), Generation: j.Spec.Scope.Generation, DeleteRevision: j.Revision, DataRetained: true}
	r.Signature = ed25519.Sign(f.node, volumes.NativeRemovedBytes(r))
	return r
}

func (f *nodeStorageFixture) unregisterReport(scope volumes.Scope, retained bool, want state.Code) {
	f.t.Helper()
	v, err := f.p.Volumes(f.s)
	if err != nil {
		f.t.Fatal(err)
	}
	core, ok := v.Volume(scope)
	if !ok {
		f.t.Fatal("missing fixed Volume")
	}
	owner, _ := core.Owner()
	proof := volumes.NativeRemoved{Schema: 1, Scope: scope, Owner: owner, Key: volumes.FixedNativeKey(scope), Generation: scope.Generation, DeleteRevision: core.DeleteRevision(), DataRetained: retained}
	proof.Signature = ed25519.Sign(f.node, volumes.NativeRemovedBytes(proof))
	r := VolumeDeleteReport{Operation: "delete", Schema: 1, Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(VolumesKey).Revision, At: 2, Proof: proof}
	raw, _ := json.Marshal(r)
	cmd, err := f.p.ResolveVolumeDeleteReport(f.s, f.p.TrustRoot, raw)
	if err != nil {
		if want != state.Forbidden {
			f.t.Fatal(err)
		}
		return
	}
	n, result, err := state.ApplyAdmitted(f.s, f.s.Index()+1, cmd, f.p.Validate, f.p.Reduce, f.p.AdmitModule)
	if err != nil || result.Code != want {
		f.t.Fatal("unregister report", result.Code, want, err)
	}
	f.s = n
}

func TestFixedRegistrationReservesExistingSelectionAndNeverOverwritesNativeFact(t *testing.T) {
	f, q := fixedRegistrationFixture(t)
	bad := q
	bad.RootGeneration++
	f.apply("manager", "register-fixed-volume", 0, bad, state.Forbidden)
	bad = q
	bad.Scope.App = "synthetic-app"
	f.apply("manager", "register-fixed-volume", 0, bad, state.Invalid)
	bad = q
	bad.Path = "/mnt/foreign/database"
	f.apply("manager", "register-fixed-volume", 0, bad, state.Invalid)
	f.apply("manager", "register-fixed-volume", 0, q, state.Applied)
	j := f.creation(q.Scope)
	if j.Fixed == nil || j.Phase != "Reserved" || j.Ready != nil || j.Spec.FixedDigest == "" {
		t.Fatal("reservation fabricated native Ready")
	}
	root := f.root()
	v, _ := f.p.Volumes(f.s)
	if registeredOnRoot(v, root.Reference(f.p.Cluster)) != 1 {
		t.Fatal("pending registration not charged to root")
	}
	bad = q
	bad.Scope.ID = "alias"
	f.apply("manager", "register-fixed-volume", 0, bad, state.ConditionFailed)
	bad.Path += "/child"
	f.apply("manager", "register-fixed-volume", 0, bad, state.ConditionFailed)
	f.creationReport(q.Scope, true, nil, nil, state.Applied)
	ready := f.fixedReady(q.Scope, 10)
	f.creationReport(q.Scope, false, &ready, nil, state.Applied)
	v, err := f.p.Volumes(f.s)
	if err != nil {
		t.Fatal(err)
	}
	core, ok := v.Volume(q.Scope)
	if !ok || !core.Fixed() || core.Scope().App != "" {
		t.Fatal("registration did not use shared tenant Volume core")
	}
	changed := f.fixedReady(q.Scope, 11)
	if sameVolumeNative(ready, changed) || VolumeNativeDigest(ready) == VolumeNativeDigest(changed) {
		t.Fatal("selection digest replaced complete physical binding identity")
	}
	// A node signature on another leaf is another observation, never license
	// to replace the original registered binding after Ready.
	f.creationReport(q.Scope, false, &changed, nil, state.Forbidden)
	v, err = f.p.Volumes(f.s)
	if err != nil {
		t.Fatal(err)
	}
	current, ok := v.Native("tenant", "", "database")
	if !ok || !sameVolumeNative(current, ready) {
		t.Fatal("physical registration overwritten")
	}
	digest := j.Fixed.Digest()
	if j.Spec.FixedDigest != hex.EncodeToString(digest[:]) {
		t.Fatal("accepted selection not frozen before discovery")
	}
	f.apply("manager", "delete-volume", core.Revision(), q.Scope, state.ConditionFailed)
}

func TestFixedUnregisterRetainsOriginalHistoryAndRequiresHigherGeneration(t *testing.T) {
	f, q := fixedRegistrationFixture(t)
	f.apply("manager", "register-fixed-volume", 0, q, state.Applied)
	f.creationReport(q.Scope, true, nil, nil, state.Applied)
	ready := f.fixedReady(q.Scope, 12)
	f.creationReport(q.Scope, false, &ready, nil, state.Applied)
	f.apply("manager", "acquire-volume", 1, VolumeAcquire{Scope: q.Scope, Consumer: "writer", Generation: 1, Writable: true}, state.Applied)
	v, _ := f.p.Volumes(f.s)
	core, _ := v.Volume(q.Scope)
	f.apply("manager", "unregister-fixed-volume", core.Revision(), q.Scope, state.ConditionFailed)
	consumer := core.Consumers()[0]
	closed := volumes.Gone{Scope: q.Scope, Consumer: consumer, Stopped: true, MountsGone: true}
	closed.Signature = ed25519.Sign(f.node, volumes.GoneBytes(closed))
	f.apply("manager", "release-volume", core.Revision(), closed, state.Applied)
	v, _ = f.p.Volumes(f.s)
	core, _ = v.Volume(q.Scope)
	f.apply("manager", "unregister-fixed-volume", core.Revision(), q.Scope, state.Applied)
	f.unregisterReport(q.Scope, false, state.Forbidden)
	f.unregisterReport(q.Scope, true, state.Applied)
	old := f.creation(q.Scope)
	if old.Phase != "Unregistered" || old.Gone == nil || !old.Gone.DataRetained || old.Unregister == nil || old.Unregister.VerifyOriginal(f.p.Cluster) != nil || !sameVolumeNative(*old.Ready, ready) {
		t.Fatal("unregister erased original/physical/history proof")
	}
	f.apply("manager", "register-fixed-volume", 0, q, state.ConditionFailed)
	next := q
	next.Scope.Generation++
	f.apply("manager", "register-fixed-volume", 0, next, state.Applied)
	root := f.root()
	f.apply("admin", "drain-node-storage", root.Revision, NodeStorageSelection{"node-a", "hdd"}, state.Applied)
	if _, err := f.p.VolumeCreatePermit(f.s, f.p.TrustRoot, next.Scope); err == nil {
		t.Fatal("Drain allowed pending native registration to start")
	}
	root = f.root()
	closure := nodestorage.RootClosed{Schema: 1, Root: root.Reference(f.p.Cluster), NoUsers: true, NoPending: true}
	closure.Signature = ed25519.Sign(f.node, nodestorage.RootClosedBytes(closure))
	previous := NodeStorageReport{Schema: 1, Cluster: f.p.Cluster, Reporter: [32]byte(f.node.Public().(ed25519.PublicKey)), Action: "closed", Expected: root.Revision, Epoch: 1, RootRevision: f.s.Object(NodeStorageKey).Revision, Index: f.s.Index(), Closed: &closure}
	previous.Signature = ed25519.Sign(f.node, NodeStorageReportBytes(previous))
	originalCommand, err := previous.Command()
	if err != nil {
		t.Fatal(err)
	}
	f.report(NodeStorageReport{Action: "closed", Expected: root.Revision, Closed: &closure}, f.node, state.ConditionFailed)
	f.apply("manager", "cancel-volume-create", 1, next.Scope, state.Applied)
	if _, err := f.p.VolumeCreatePermit(f.s, f.p.TrustRoot, next.Scope); err != nil {
		t.Fatal("Drain prevented original cleanup", err)
	}
	gone := f.fixedGone(f.creation(next.Scope))
	f.creationReport(next.Scope, false, nil, &gone, state.Applied)
	n, replayed, err := state.ApplyAdmitted(f.s, f.s.Index()+1, originalCommand, f.p.Validate, f.p.Reduce, f.p.AdmitModule)
	if err != nil || replayed.Code != state.ConditionFailed {
		t.Fatal("old closure request lost its original rejection", replayed.Code, err)
	}
	f.s = n
	f.report(NodeStorageReport{Action: "closed", Expected: root.Revision, Closed: &closure}, f.node, state.Applied)
	root = f.root()
	f.apply("admin", "remove-node-storage", root.Revision, NodeStorageSelection{"node-a", "hdd"}, state.Applied)
	encoded, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = state.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if f.creation(q.Scope).Phase != "Unregistered" || f.creation(next.Scope).Phase != "Cancelled" {
		t.Fatal("Snapshot/root removal lost terminal generation floors/history")
	}
}
