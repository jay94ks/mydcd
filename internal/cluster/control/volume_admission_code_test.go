// SPDX-License-Identifier: Apache-2.0

package control

import (
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
)

// A move plan names a missing or full target volume limit instead of leaving
// begin-volume-move to fail with a bare ConditionFailed.
func TestOriginalAdmissionCodeNamesTargetLimit(t *testing.T) {
	owner := [32]byte{7}
	v := Volumes{backupLimits: map[string]VolumeBackupLimit{}}
	var s state.State
	if code := v.originalAdmissionCode(s, "shop", "node-b", owner, 1<<20); code != "TARGET_VOLUME_LIMIT_MISSING" {
		t.Fatal("no limits", code)
	}
	if code := v.originalAdmissionCode(s, "shop", "node-b", owner, 0); code != "" {
		t.Fatal("unreserved volume on a server without limits", code)
	}
	v.backupLimits[backupLimitKey("", "node-b")] = VolumeBackupLimit{Node: "node-b", Owner: owner, Original: &OriginalVolumeLimit{Bytes: 4 << 20, Count: 4}}
	if code := v.originalAdmissionCode(s, "shop", "node-b", owner, 1<<20); code != "TARGET_VOLUME_LIMIT_MISSING" {
		t.Fatal("cluster limit only", code)
	}
	v.backupLimits[backupLimitKey("shop", "node-b")] = VolumeBackupLimit{Tenant: "shop", Node: "node-b", Owner: owner, Original: &OriginalVolumeLimit{Bytes: 2 << 20, Count: 4}}
	if code := v.originalAdmissionCode(s, "shop", "node-b", owner, 1<<20); code != "" {
		t.Fatal("admitted move explained", code)
	}
	if code := v.originalAdmissionCode(s, "shop", "node-b", owner, 3<<20); code != "TARGET_VOLUME_LIMIT_FULL" {
		t.Fatal("over tenant limit", code)
	}
	if code := v.originalAdmissionCode(s, "shop", "node-b", [32]byte{8}, 1<<20); code != "TARGET_VOLUME_LIMIT_OWNER_CHANGED" {
		t.Fatal("stale owner", code)
	}
}

// A move also holds the source backup and the target staging budget; the
// plan names which one (cluster or tenant) has no room.
func TestCopyBudgetFailureNamesMoveBudget(t *testing.T) {
	a, b := [32]byte{1}, [32]byte{2}
	full := func(node string, owner [32]byte, tenant string) VolumeBackupLimit {
		return VolumeBackupLimit{Tenant: tenant, Node: node, Owner: owner, Bytes: 1 << 30, Count: 4, StagingBytes: 512 << 20, StagingCount: 2}
	}
	v := Volumes{backupLimits: map[string]VolumeBackupLimit{
		backupLimitKey("", "node-a"): full("node-a", a, ""), backupLimitKey("shop", "node-a"): full("node-a", a, "shop"),
		backupLimitKey("shop", "node-b"): full("node-b", b, "shop"),
	}}
	move := &moveCharge{tenant: "shop", source: "node-a", target: "node-b", sourceKey: a, targetKey: b, bytes: 256 << 20}
	cluster := full("node-b", b, "")
	cluster.StagingBytes, cluster.StagingCount = 0, 0
	v.backupLimits[backupLimitKey("", "node-b")] = cluster
	if code := v.copyBudgetFailure(move); code != "TARGET_STAGING_LIMIT_CLUSTER" {
		t.Fatal("cluster staging 0", code)
	}
	v.backupLimits[backupLimitKey("", "node-b")] = full("node-b", b, "")
	if code := v.copyBudgetFailure(move); code != "" {
		t.Fatal("budgets with room", code)
	}
	if !v.copyBudgetsOK() {
		t.Fatal("held budgets changed")
	}
	move.bytes = 768 << 20
	if code := v.copyBudgetFailure(move); code != "TARGET_STAGING_LIMIT_CLUSTER" {
		t.Fatal("over staging", code)
	}
	delete(v.backupLimits, backupLimitKey("shop", "node-a"))
	move.bytes = 1 << 20
	if code := v.copyBudgetFailure(move); code != "SOURCE_BACKUP_LIMIT_TENANT" {
		t.Fatal("no source tenant limit", code)
	}
}
