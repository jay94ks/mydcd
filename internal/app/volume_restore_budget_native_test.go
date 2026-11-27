// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/moby/moby/client"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

func TestRealBoundaryVolumeOriginalMappingAndRestoreBudget(t *testing.T) {
	runRealVolumeOwnerBoundary(t, true, true, true, volumeOwnerRestoreBudget)
}
func verifyRestoreOriginalBudget(t *testing.T, ctx context.Context, owner **Runtime, cfg config.Node, docker *engine.Client, root string, admin userauth.Client, peer sfcp.Peer, session access.Session, p control.Policy, read func() cluster.View, source volumes.NativeReady, backup control.VolumeBackup, cli func(...string)) {
	t.Helper()
	view := func() control.Volumes {
		t.Helper()
		v, err := p.Volumes(read().State)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	wait := func(label string, ready func() bool) {
		t.Helper()
		for !ready() {
			select {
			case <-ctx.Done():
				t.Fatal(label, ctx.Err())
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	apply := func(id, action string, expected uint64, payload any) {
		t.Helper()
		if args, ok := nativeMovedChange(id, action, payload); ok {
			cli(args...)
			return
		}
		raw, err := json.Marshal(struct {
			Schema   uint8  `json:"schema"`
			Action   string `json:"action"`
			Expected uint64 `json:"expected"`
			Payload  any    `json:"payload"`
		}{1, action, expected, payload})
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, id+".json")
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		cli("manage", "apply", "--request-id", id, "--change", path)
	}
	core, _ := view().Volume(source.Spec.Scope)
	apply("map-source-bytes", "set-volume-capacity", core.Revision(), control.VolumeCapacity{Scope: source.Spec.Scope, Native: control.VolumeNativeDigest(source), Bytes: 128 << 10})
	original, _ := view().Native(source.Spec.Scope.Tenant, source.Spec.Scope.App, source.Spec.Scope.ID)
	if control.VolumeNativeDigest(original) != control.VolumeNativeDigest(source) {
		t.Fatal("explicit mapping changed owner/native signed identity")
	}
	for _, limit := range view().BackupLimits() {
		rev := limit.Revision
		limit.Owner = [32]byte{}
		limit.Revision = 0
		limit.Original = &control.OriginalVolumeLimit{Bytes: 256 << 10, Count: 2}
		limit.StagingBytes = 128 << 10
		limit.StagingCount = 1
		apply("restore-original-limit-"+limit.Tenant, "set-volume-backup-limit", rev, limit)
	}
	spec := source.Spec
	spec.Scope.ID = "budget-restored"
	spec.Materialization = "r-budget-copy"
	key := volumes.NativeKey(spec)
	// Runtime shutdown runs before this fallback. Only this new exact journal
	// key is eligible for nonforce cleanup; original source remains outer-owned.
	t.Cleanup(func() {
		clean, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		native, err := volumes.OpenNative(filepath.Join(cfg.Node.StateDir, "workload", "volumes.db"), docker)
		if err != nil {
			t.Error(err)
			return
		}
		defer native.Close()
		row, err := native.View(key)
		if err != nil {
			return
		}
		if !row.State.Applied.Present && row.State.Pending == nil {
			return
		}
		if !t.Failed() {
			t.Error("budgeted restore target not settled")
		}
		rev := row.State.Desired.Revision
		if row.State.Desired.Present {
			rev++
		}
		if err = native.DeleteDesired(key, rev, 1); err != nil {
			t.Error(err)
			return
		}
		if err = native.Step(clean, key); err != nil {
			t.Error(err)
		}
	})
	cli("volume", "restore", source.Spec.Scope.App+"/"+source.Spec.Scope.ID, backup.Binding.ID, "--to", source.Spec.Scope.App+"/"+spec.Scope.ID, "--name", "budget-copy", "--max-size", "131072", "--size", "131072", "--id", "restore-budgeted", "--no-wait")
	selection := control.VolumeRestoreSelection{Backup: control.VolumeBackupSelection{Scope: source.Spec.Scope, ID: backup.Binding.ID}, ID: "budget-copy"}
	wait("actual budgeted restore", func() bool { r, ok := view().Restore(selection); return ok && r.Phase == "Restored" })
	job, _ := view().Restore(selection)
	if job.Binding.CapacityBytes != 128<<10 || job.Report == nil || !job.Report.FilesSynced || !job.Report.CopyVerified {
		t.Fatal("actual copied target lost byte reservation")
	}
	target, ok := view().Native(spec.Scope.Tenant, spec.Scope.App, spec.Scope.ID)
	if !ok || target.Spec != spec {
		t.Fatal("wrong original restore target")
	}
	disk, err := (*owner).docker.API.VolumeInspect(ctx, target.Owner.Native, client.VolumeInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if row, err := os.ReadFile(filepath.Join(disk.Volume.Mountpoint, "row")); err != nil || string(row) != "retained volume usage fixture" {
		t.Fatal("actual restored bytes", err)
	}
	cli("volume", "show", spec.Scope.App+"/"+spec.Scope.ID)
	cli("op", "show", "restore-budgeted")
	// A current real user/Raft rejection: acceptance/Restored is not physical
	// Gone, and source plus target and staging must remain charged together.
	limit := view().BackupLimits()[0]
	rev := limit.Revision
	limit.Owner = [32]byte{}
	limit.Revision = 0
	limit.Original = &control.OriginalVolumeLimit{Bytes: 128 << 10, Count: 1}
	limit.StagingBytes = 0
	limit.StagingCount = 0
	raw, _ := control.ChangeBytes("set-volume-backup-limit", session.User, rev, limit)
	var change control.Change
	_ = json.Unmarshal(raw, &change)
	op, err := admin.Prepare(ctx, peer, session, "shrink-live-restore", change)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := admin.Operation(ctx, peer, op, false)
	if err != nil || reply.Result == nil || reply.Result.Code != state.ConditionFailed {
		t.Fatal("live restore budget returned early", reply.Result, err)
	}
	for _, scope := range []volumes.Scope{spec.Scope, source.Spec.Scope} {
		cli("volume", "delete", scope.App+"/"+scope.ID, "--id", "budget-delete-"+scope.ID, "--no-wait")
		wait("exact native Gone", func() bool { core, ok := view().Volume(scope); return ok && core.Deleted() })
	}
	cli("volume", "backup", "delete", source.Spec.Scope.App+"/"+source.Spec.Scope.ID, backup.Binding.ID, "--id", "budget-backup-delete", "--no-wait")
	wait("backup Gone", func() bool {
		b, ok := view().Backup(source.Spec.Scope, backup.Binding.ID)
		return ok && b.Phase == "Deleted"
	})
	for _, limit := range view().BackupLimits() {
		rev := limit.Revision
		limit.Owner = [32]byte{}
		limit.Revision = 0
		limit.Original = &control.OriginalVolumeLimit{}
		limit.StagingBytes = 0
		limit.StagingCount = 0
		apply(fmt.Sprintf("original-zero-%s", limit.Tenant), "set-volume-backup-limit", rev, limit)
	}
	t.Log("actual CLI maps original signed native without identity change -> current global/tenant original+staging admission -> CLI restore/verified bytes -> live shrink rejected -> dedicated exact source/target Gone and artifact Gone -> zero original/staging budget; historical recipe/bindings retained, no SQL/physical quota claim")
}
