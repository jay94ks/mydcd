// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

func mapOriginalCapacity(t *testing.T, f *backupCoreFixture, bytes uint64) {
	t.Helper()
	native, _ := f.view().Native(f.scope.Tenant, f.scope.App, f.scope.ID)
	f.apply(fmt.Sprintf("map-capacity-%d", f.s.Index()), "set-volume-capacity", f.core().Revision(), VolumeCapacity{Scope: f.scope, Native: VolumeNativeDigest(native), Bytes: bytes}, state.Applied)
}
func originalLimit(t *testing.T, f *backupCoreFixture, tenant string, bytes uint64, count uint32, want state.Code) {
	t.Helper()
	old := f.view().backupLimits[backupLimitKey(tenant, "node-a")]
	next := old
	next.Owner = [32]byte{}
	next.Revision = 0
	next.Tenant = tenant
	next.Node = "node-a"
	next.Original = &OriginalVolumeLimit{Bytes: bytes, Count: count}
	f.apply(fmt.Sprintf("original-%s-%d", tenant, f.s.Index()), "set-volume-backup-limit", old.Revision, next, want)
}
func TestVolumeOriginalBudgetRequiresMappingAndBothPolicies(t *testing.T) {
	f, q := createCore(t)
	originalLimit(t, f, "", 96, 2, state.ConditionFailed) // an unknown original is not empty
	native, _ := f.view().Native("tenant", "app", "data")
	bad := VolumeCapacity{Scope: f.scope, Native: [32]byte{1}, Bytes: 64}
	f.apply("bad-mapping", "set-volume-capacity", f.core().Revision(), bad, state.ConditionFailed)
	mapOriginalCapacity(t, f, 64)
	after, _ := f.view().Native("tenant", "app", "data")
	if !sameVolumeNative(native, after) {
		t.Fatal("mapping changed owner-signed native identity")
	}
	q.CapacityBytes = 32
	f.apply("unconfigured", "begin-volume-create", 0, q, state.ConditionFailed)
	originalLimit(t, f, "", 96, 2, state.Applied)
	f.apply("half-policy", "begin-volume-create", 0, q, state.ConditionFailed)
	originalLimit(t, f, "tenant", 96, 2, state.Applied)
	zero := q
	zero.CapacityBytes = 0
	f.apply("missing-reservation", "begin-volume-create", 0, zero, state.ConditionFailed)
	scope := q.Scope
	scope.ID = "raw"
	f.apply("raw-unbudgeted", "create-volume", 0, volumeFact(t, scope, "node-a", f.node), state.ConditionFailed)
	f.apply("budgeted-create", "begin-volume-create", 0, q, state.Applied)
	originalLimit(t, f, "", 95, 2, state.ConditionFailed)
	originalLimit(t, f, "tenant", 96, 1, state.ConditionFailed)
	old := f.view().backupLimits[backupLimitKey("", "node-a")]
	drop := old
	drop.Owner = [32]byte{}
	drop.Revision = 0
	drop.Original = nil
	f.apply("drop-original-policy", "set-volume-backup-limit", old.Revision, drop, state.ConditionFailed)
	page := f.view().BackupLimits()
	page[0].Original.Bytes = 0
	if f.view().backupLimits[backupLimitKey("", "node-a")].Original.Bytes != 96 {
		t.Fatal("limit view aliases mutable policy")
	}
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = state.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if f.view().entries[volumeKey(f.scope)].CapacityBytes != 64 {
		t.Fatal("Snapshot lost explicit original mapping")
	}
}
func TestVolumeOriginalBudgetHeldThroughReadyAndCancellation(t *testing.T) {
	f, q := createCore(t)
	mapOriginalCapacity(t, f, 64)
	for _, tenant := range []string{"", "tenant"} {
		originalLimit(t, f, tenant, 96, 2, state.Applied)
	}
	q.CapacityBytes = 32
	f.apply("create-budget", "begin-volume-create", 0, q, state.Applied)
	job, _ := f.view().Creation(q.Scope)
	commitCreation(t, f, VolumeCreateReport{Scope: q.Scope, Revision: 1, Prepared: true}, state.Applied)
	ready := restoreReady(t, f, job.Spec)
	commitCreation(t, f, VolumeCreateReport{Scope: q.Scope, Revision: 2, Ready: &ready}, state.Applied)
	if f.view().entries[volumeKey(q.Scope)].CapacityBytes != 32 {
		t.Fatal("Ready failed to transfer original reservation")
	}
	next := q
	next.Scope.ID = "other"
	f.apply("competition", "begin-volume-create", 0, next, state.ConditionFailed)
	// Mapping is monotone, independent of caller's reused state revision.
	f.apply("shrink-mapping", "set-volume-capacity", f.core().Revision(), VolumeCapacity{Scope: f.scope, Native: VolumeNativeDigest(f.view().entries[volumeKey(f.scope)].Native), Bytes: 1}, state.ConditionFailed)
	// A separate allocation can be cancelled only after positive Gone.
	for _, tenant := range []string{"", "tenant"} {
		originalLimit(t, f, tenant, 128, 3, state.Applied)
	}
	f.apply("reserve-cancel", "begin-volume-create", 0, next, state.Applied)
	j, _ := f.view().Creation(next.Scope)
	f.apply("cancel-pending", "cancel-volume-create", 1, next.Scope, state.Applied)
	originalLimit(t, f, "", 96, 2, state.ConditionFailed)
	owner, err := restoreTargetOwner(j.Spec)
	if err != nil {
		t.Fatal(err)
	}
	proof := volumes.NativeRemoved{Schema: 1, Scope: next.Scope, Owner: owner, Key: volumes.NativeKey(j.Spec), Generation: 1, DeleteRevision: 2}
	proof.Signature = ed25519.Sign(f.node, volumes.NativeRemovedBytes(proof))
	commitCreation(t, f, VolumeCreateReport{Scope: next.Scope, Revision: 2, Gone: &proof}, state.Applied)
	originalLimit(t, f, "", 96, 2, state.Applied)
}
func TestVolumeOriginalBudgetRestorationRetainsStagingAndSource(t *testing.T) {
	f, q := restoreCore(t)
	restoreLimits(f, q.MaxBytes, 1)
	mapOriginalCapacity(t, f, 65536)
	q.CapacityBytes = q.MaxBytes
	for _, tenant := range []string{"", "tenant"} {
		originalLimit(t, f, tenant, 65536+q.MaxBytes, 2, state.Applied)
	}
	f.apply("restore-capacity", "begin-volume-restore", 2, q, state.Applied)
	originalLimit(t, f, "", 65536, 1, state.ConditionFailed)
	commitRestoreReport(t, f, restoreReport(t, f, q, "restored"), state.Applied)
	if f.view().entries[volumeKey(q.Target.Scope)].CapacityBytes != q.MaxBytes {
		t.Fatal("published target lost original bytes")
	}
	old := f.view().backupLimits[backupLimitKey("", "node-a")]
	old.Owner = [32]byte{}
	rev := old.Revision
	old.Revision = 0
	old.StagingBytes = 0
	old.StagingCount = 0
	f.apply("staging-still-held", "set-volume-backup-limit", rev, old, state.ConditionFailed)
	holds, err := f.view().originalHolds(f.s)
	if err != nil || len(holds) != 2 {
		t.Fatal("Ready double counted or dropped source", holds, err)
	}
}
func TestVolumeOriginalBudgetIncludesUnpublishedAppGoals(t *testing.T) {
	f, _ := createCore(t)
	mapOriginalCapacity(t, f, 64)
	for _, tenant := range []string{"", "tenant"} {
		originalLimit(t, f, tenant, 96, 2, state.Applied)
	}
	key := deployment.ResourceKey("volume", "tenant", "app", "pending")
	retained := true
	goal := deployment.GoalCommand{Schema: 1, Cluster: f.p.Cluster, Tenant: "tenant", App: "app", Kind: "volume", Node: "node-a", Owner: [32]byte(f.node.Public().(ed25519.PublicKey))}
	config := deployment.ComposeVolume{}
	config.Sfc.Node = "node-a"
	config.Sfc.Retain = &retained
	config.Sfc.Quota = "observe"
	check := func(id string, bytes uint64, want state.Code) {
		t.Helper()
		config.Sfc.Capacity = deployment.VolumeSize(bytes)
		goal.Config, _ = json.Marshal(config)
		raw, _ := json.Marshal(goal)
		next, result, err := state.ApplyChecked(f.s, f.s.Index()+1, state.Command{Actor: "anchor", Epoch: 1, RequestID: id, Key: key, Value: string(raw)}, f.p.Validate)
		if err != nil || result.Code != want {
			t.Fatal(id, result, err)
		}
		f.s = next
	}
	check("missing-capacity", 0, state.Invalid)
	check("over-budget", 33, state.Invalid)
	// Check the same ordinary projection directly with fixed Goal data. The
	// full App claim/recipe admission has its own authority and is not bypassed.
	config.Sfc.Capacity = 32
	goal.Config, _ = json.Marshal(config)
	raw, _ := json.Marshal(goal)
	candidate, result, err := state.ApplyChecked(f.s, f.s.Index()+1, state.Command{Actor: "anchor", Epoch: 1, RequestID: "goal-fixed-input", Key: key, Value: string(raw)}, nil)
	if err != nil || result.Code != state.Applied {
		t.Fatal(result, err)
	}
	if f.view().validateOriginalStorage(candidate) != nil {
		t.Fatal("exact app reservation refused")
	}
	holds, err := f.view().originalHolds(candidate)
	if err != nil || len(holds) != 2 || holds["tenant/app/pending"].bytes != 32 {
		t.Fatal(holds, err)
	}
}

func TestVolumeOriginalBudgetPublicReservationMetadata(t *testing.T) {
	f, q := restoreCore(t)
	restoreLimits(f, q.MaxBytes, 1)
	mapOriginalCapacity(t, f, 65536)
	q.CapacityBytes = q.MaxBytes
	for _, tenant := range []string{"", "tenant"} {
		originalLimit(t, f, tenant, 65536+q.MaxBytes, 2, state.Applied)
	}
	f.apply("public-reserved-restore", "begin-volume-restore", 2, q, state.Applied)
	c, _ := f.p.Catalog(f.s)
	originals, _, err := f.view().Page(c, "admin", "tenant", "")
	if err != nil || len(originals) != 1 || originals[0].CapacityBytes != 65536 || originals[0].NativeBinding != VolumeNativeDigest(f.view().entries[volumeKey(f.scope)].Native) {
		t.Fatal("public original mapping metadata", originals, err)
	}
	jobs, _, err := f.view().RestorePage(c, "admin", "tenant", "")
	if err != nil || len(jobs) != 1 || jobs[0].CapacityBytes != q.CapacityBytes || jobs[0].MaxBytes != q.MaxBytes {
		t.Fatal("public staging/original reservation metadata", jobs, err)
	}
	raw, _ := json.Marshal(struct {
		Originals []VolumeView
		Restores  []VolumeRestoreView
	}{originals, jobs})
	for _, private := range []string{"Session", "Signature", "Origin", "Staging", "Materialization"} {
		if bytes.Contains(raw, []byte(`"`+private+`":`)) {
			t.Fatal("private input leaked", private)
		}
	}
}
