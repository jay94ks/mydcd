// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/userauth"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
	"github.com/moby/moby/client"
)

func verifyAutomaticRestoreBoundary(t *testing.T, ctx context.Context, a *Runtime, owner **Runtime, cfg config.Node, root string, admin userauth.Client, peer mydcp.Peer, session access.Session, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), source volumes.NativeReady, docker *engine.Client, gate *volumeUsageGate, backup control.VolumeBackup, cli func(...string)) {
	t.Helper()
	registry := func() control.Volumes {
		t.Helper()
		v, e := p.Volumes(read().State)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	for _, tenant := range []string{"", source.Spec.Scope.Tenant} {
		var old control.VolumeBackupLimit
		for _, limit := range registry().BackupLimits() {
			if limit.Tenant == tenant && limit.Node == source.Owner.Node {
				old = limit
			}
		}
		change("restore-limit-"+tenant, "set-volume-backup-limit", old.Revision, control.VolumeBackupLimit{Tenant: tenant, Node: source.Owner.Node, Bytes: 128 << 10, Count: 2, StagingBytes: 256 << 10, StagingCount: 2})
	}
	makeBegin := func(id, volume string) control.VolumeRestoreBegin {
		spec := source.Spec
		spec.Scope.ID = volume
		spec.Materialization = "r-" + id
		return control.VolumeRestoreBegin{Backup: control.VolumeBackupSelection{Scope: source.Spec.Scope, ID: backup.Binding.ID}, ID: id, Target: spec, MaxBytes: 128 << 10}
	}
	first, second := makeBegin("first", "restored"), makeBegin("second", "cancelled")
	identity := func(q control.VolumeRestoreBegin) engine.Identity {
		t.Helper()
		raw, _ := json.Marshal(q.Target)
		id, e := docker.Identity("volume", volumes.NativeKey(q.Target), reconcile.Resource{Present: true, Generation: 1, Spec: string(raw)})
		if e != nil {
			t.Fatal(e)
		}
		return id
	}
	targets := []engine.Identity{identity(first), identity(second)}
	// Install exact-owner/identity fallback before either target can be created.
	t.Cleanup(func() {
		clean, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		for _, id := range targets {
			got, e := docker.API.VolumeInspect(clean, id.Name, client.VolumeInspectOptions{})
			if cerrdefs.IsNotFound(e) {
				continue
			}
			if e != nil {
				t.Error(e)
				continue
			}
			if !id.Matches(got.Volume.Name, got.Volume.Labels) {
				t.Error("restore rollback ownership mismatch")
				continue
			}
			if !t.Failed() {
				t.Error("product retained owned staging target", id.Name)
			}
			if _, e = docker.API.VolumeRemove(clean, id.Name, client.VolumeRemoveOptions{}); e != nil {
				t.Error(e)
			}
		}
	})
	wait := func(label string, check func() bool) {
		t.Helper()
		for !check() {
			select {
			case <-ctx.Done():
				if *owner != nil {
					(*owner).mu.RLock()
					e := (*owner).volumeBackupError
					(*owner).mu.RUnlock()
					t.Log("restore controller error", e)
				}
				t.Fatal(label, ctx.Err())
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	restoreCLI := func(q control.VolumeRestoreBegin, request string) {
		t.Helper()
		cli("volume", "restore", q.Backup.Scope.App+"/"+q.Backup.Scope.ID, q.Backup.ID, "--to", q.Target.Scope.App+"/"+q.Target.Scope.ID, "--name", q.ID, "--max-size", strconv.FormatUint(q.MaxBytes, 10), "--generation", strconv.FormatUint(q.Target.Scope.Generation, 10), "--id", request, "--no-wait")
	}
	restoreStatus := func(q control.VolumeRestoreBegin) {
		t.Helper()
		cli("volume", "restore", "show", q.ID)
	}
	job := func(q control.VolumeRestoreBegin) control.VolumeRestore {
		t.Helper()
		r, ok := registry().Restore(control.VolumeRestoreSelection{Backup: q.Backup, ID: q.ID})
		if !ok {
			t.Fatal("missing original restore")
		}
		return r
	}
	// Delay a real SDK read only once the original target contains the copied
	// file. No native response/file/receipt is supplied by the gate.
	entered, release := gate.armWhen(targets[0].Name, func() bool {
		v, e := docker.API.VolumeInspect(ctx, targets[0].Name, client.VolumeInspectOptions{})
		if e != nil {
			return false
		}
		data, e := os.ReadFile(filepath.Join(v.Volume.Mountpoint, "row"))
		return e == nil && string(data) == "retained volume usage fixture"
	})
	defer release()
	restoreCLI(first, "restore-first")
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("actual post-copy gate", ctx.Err())
	}
	cli("volume", "restore", "list")
	restoreStatus(first)
	cli("op", "show", "restore-first")
	cli("op", "resume", "restore-first")
	original := job(first)
	if original.Phase != "Reserved" {
		t.Fatal("target published before original verification")
	}
	if _, ok := registry().Native("tenant", "app", "restored"); ok {
		t.Fatal("staging visible before completion")
	}
	artifact, e := (*owner).backupArtifacts.journal.Read(restoreArtifactKey(original.Binding))
	if e != nil || artifact.Consumers[restoreArtifactConsumer(original.Binding)].Token == 0 {
		t.Fatal("source artifact A3 reference absent before interruption", e)
	}
	// The real FSM must reject deleting a backup held by an in-flight restore.
	raw, _ := control.ChangeBytes("delete-volume-backup", "admin", backup.Revision, first.Backup)
	var del control.Change
	_ = json.Unmarshal(raw, &del)
	op, e := admin.Prepare(ctx, peer, session, "delete-held-artifact", del)
	if e != nil {
		t.Fatal(e)
	}
	reply, e := admin.Operation(ctx, peer, op, false)
	if e != nil || reply.Result == nil || reply.Result.Code != state.ConditionFailed {
		t.Fatal("held backup deletion admitted", reply.Result, e)
	}
	if e = (*owner).Close(); e != nil {
		t.Fatal(e)
	}
	*owner = nil
	release()
	journal, e := reconcile.OpenJournal(filepath.Join(cfg.Node.StateDir, "workload", "restores.db"))
	if e != nil {
		t.Fatal(e)
	}
	pending, e := journal.Read(restoreJobKey(original.Binding))
	_ = journal.Close()
	if e != nil || pending.State.Pending == nil || pending.State.Pending.ID != 1 || pending.State.Pending.Phase != reconcile.RecoveryRequired || pending.State.LastID != 1 {
		t.Fatal("original restore Unknown lost on shutdown", e)
	}
	*owner, e = Open(cfg)
	if e != nil {
		t.Fatal(e)
	}
	wait("same target read-only recovery/Restored", func() bool { return job(first).Phase == "Restored" })
	restoreStatus(first)
	completed := job(first)
	if completed.Report == nil || completed.Report.Target == nil || completed.Report.Target.Owner.Native != targets[0].Name || completed.Binding.Digest() != original.Binding.Digest() {
		t.Fatal("changed original restored target/binding")
	}
	local, e := (*owner).volumeRestores.Read(restoreJobKey(original.Binding))
	if e != nil || local.State.Pending != nil || local.State.LastID != 1 || !local.State.Applied.Present {
		t.Fatal("recovery allocated a new copy operation", e)
	}
	got, e := docker.API.VolumeInspect(ctx, targets[0].Name, client.VolumeInspectOptions{})
	if e != nil {
		t.Fatal(e)
	}
	data, e := os.ReadFile(filepath.Join(got.Volume.Mountpoint, "row"))
	info, statErr := os.Stat(filepath.Join(got.Volume.Mountpoint, "row"))
	if e != nil || statErr != nil || string(data) != "retained volume usage fixture" || info.Mode().Perm() != 0640 {
		t.Fatal("actual restored bytes/mode", e, statErr)
	}
	stat := info.Sys().(*syscall.Stat_t)
	if stat.Uid != source.Spec.UID || stat.Gid != source.Spec.GID {
		t.Fatal("actual restored UID/GID")
	}
	artifact, e = (*owner).backupArtifacts.journal.Read(restoreArtifactKey(original.Binding))
	if e != nil || len(artifact.Consumers) != 0 {
		t.Fatal("original artifact reference not returned", e)
	}
	if e = a.Engine().Snapshot(ctx); e != nil {
		t.Fatal(e)
	}
	// Cancel the second original at the real initial Inspect, before Create.
	entered2, release2 := gate.arm(targets[1].Name)
	defer release2()
	restoreCLI(second, "restore-second")
	select {
	case <-entered2:
	case <-ctx.Done():
		t.Fatal("actual pre-create gate", ctx.Err())
	}
	cli("volume", "restore", "cancel", second.ID, "--id", "restore-second-cancel", "--no-wait")
	if e = (*owner).Close(); e != nil {
		t.Fatal(e)
	}
	*owner = nil
	release2()
	*owner, e = Open(cfg)
	if e != nil {
		t.Fatal(e)
	}
	wait("same original cancel/reference settlement", func() bool { return job(second).Phase == "Cancelled" })
	restoreStatus(second)
	cli("op", "show", "restore-second-cancel")
	cancelled := job(second)
	if cancelled.Report == nil || !cancelled.Report.TargetGone || !cancelled.Report.ArtifactReturned {
		t.Fatal("cancel lacks original closure")
	}
	if _, e = docker.API.VolumeInspect(ctx, targets[1].Name, client.VolumeInspectOptions{}); !cerrdefs.IsNotFound(e) {
		t.Fatal("cancelled pre-create target was created", e)
	}
	if _, ok := registry().Native("tenant", "app", "cancelled"); ok {
		t.Fatal("cancelled target published")
	}
	row, e := (*owner).volumeRestores.Read(restoreJobKey(cancelled.Binding))
	if e != nil || row.State.Pending != nil || row.State.LastID != 1 || row.State.Applied.Present {
		t.Fatal("cancel reset/replaced original A2", e)
	}
	for _, spec := range []volumes.NativeSpec{source.Spec, first.Target} {
		key := volumes.NativeKey(spec)
		if e = (*owner).nativeVolumes.DeleteDesired(key, 2, 1); e != nil {
			t.Fatal(e)
		}
		if e = (*owner).nativeVolumes.Step(ctx, key); e != nil {
			t.Fatal(e)
		}
		if gone, e := (*owner).nativeVolumes.Gone(ctx, key, 2, 1); e != nil || !gone {
			t.Fatal("source/restored native cleanup", e)
		}
	}
	cli("volume", "backup", "delete", "app/data", backup.Binding.ID, "--id", "restore-source-backup-delete", "--no-wait")
	wait("artifact delete after restores terminal", func() bool {
		b, ok := registry().Backup(source.Spec.Scope, backup.Binding.ID)
		return ok && b.Phase == "Deleted"
	})
	artifact, e = (*owner).backupArtifacts.journal.Read(restoreArtifactKey(original.Binding))
	if e != nil || len(artifact.Consumers) != 0 {
		t.Fatal("terminal restores retained local artifact references", e)
	}
	cli("op", "show", "restore-first")
	cli("volume", "restore", "list")
	encoded, _ := state.Encode(read().State)
	if bytes.Contains(encoded, []byte("retained volume usage fixture")) {
		t.Fatal("file data published in shared DB")
	}
	t.Log("actual dedicated restore/list/status/result/resume/cancel CLI -> shared restore hold/staging budget -> automatic original native target/copy; real post-copy read gate -> shutdown preserves copy Unknown/A3 artifact token -> same DB/target read verification+sync/owner report/atomic Restored -> original result/target/bytes/UID/GID/mode; second real pre-create gate -> shared cancel/shutdown/reopen with no target creation and original reference return; backup delete held/terminal allowed, original restore lookup after backup/source removal, Snapshot, native cleanup. Same-process independent control/owner Runtime, separate CLI; no SQL/full D2.04 claim")
}
