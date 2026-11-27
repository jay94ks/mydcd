// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

func TestRealBoundaryBackupSyncAndNativeSpaceFailure(t *testing.T) {
	runRealVolumeOwnerBoundary(t, true, true, false, volumeOwnerBackupIO)
}

// This test-only decorator delegates every native operation. It records the
// actual ExportCold errno/call count, never supplies a file or completion fact.
type observedBackupIO struct {
	backupArtifactBackend
	mu       sync.Mutex
	calls    map[string]int
	failures map[string]error
}

func (o *observedBackupIO) Export(ctx context.Context, b control.VolumeBackupBinding, file *os.File) (volumes.ArchiveReceipt, error) {
	receipt, err := o.backupArtifactBackend.Export(ctx, b, file)
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls[b.ID]++
	o.failures[b.ID] = err
	return receipt, err
}
func (o *observedBackupIO) outcome(id string) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.calls[id], o.failures[id]
}
func observeBackupIO(r *Runtime) *observedBackupIO {
	m := r.backupArtifacts
	m.mu.Lock()
	defer m.mu.Unlock()
	o := &observedBackupIO{backupArtifactBackend: m.backend, calls: map[string]int{}, failures: map[string]error{}}
	m.backend = o
	return o
}

func verifyBackupIOBoundary(t *testing.T, ctx context.Context, a *Runtime, owner **Runtime, cfg config.Node, root string, admin userauth.Client, peer sfcp.Peer, session access.Session, p control.Policy, read func() cluster.View, source volumes.NativeReady, cli func(...string)) {
	t.Helper()
	view := func() control.Volumes {
		t.Helper()
		v, err := p.Volumes(read().State)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	job := func(id string) control.VolumeBackup {
		t.Helper()
		j, ok := view().Backup(source.Spec.Scope, id)
		if !ok {
			t.Fatal("original backup missing", id)
		}
		return j
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
	counter := observeBackupIO(*owner)
	var failSync atomic.Bool
	failSync.Store(true)
	var syncFailures atomic.Int64
	m := (*owner).backupArtifacts
	m.mu.Lock()
	m.syncFile = func(f *os.File) error {
		info, err := f.Stat()
		if err != nil {
			return err
		}
		if info.IsDir() {
			dir, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", f.Fd()))
			if err != nil {
				return err
			}
			if _, err = os.Lstat(filepath.Join(dir, "complete.json")); err == nil && failSync.Load() {
				syncFailures.Add(1)
				return syscall.EIO
			}
		}
		return f.Sync()
	}
	m.mu.Unlock()
	cli("volume", "backup", "create", "app/data", "--name", "sync-fault", "--max-size", "131072", "--max-entries", "16", "--id", "sync-fault-begin", "--no-wait")
	wait("Execute and original Recover both blocked by directory sync", func() bool { return syncFailures.Load() >= 2 })
	held := job("sync-fault")
	row, err := m.journal.Read(backupArtifactKey(held.Binding))
	if err != nil || held.Phase != "Reserved" || held.Receipt != nil || row.State.Pending == nil || row.State.Pending.ID != 1 || row.State.Pending.Phase != reconcile.RecoveryRequired {
		t.Fatal("failed sync published Ready or lost Apply1", held.Phase, err)
	}
	if calls, err := counter.outcome("sync-fault"); calls != 1 || err != nil {
		t.Fatal("actual native Export count", calls, err)
	}
	archive := filepath.Join(cfg.Node.StateDir, "workload", "backups", backupArtifactName(held.Binding), "archive.tar")
	before, err := os.Stat(archive)
	if err != nil {
		t.Fatal(err)
	}
	cli("volume", "backup", "show", "app/data", "sync-fault")
	failSync.Store(false)
	cli("op", "resume", "sync-fault-begin")
	wait("same original synced Ready", func() bool { return job("sync-fault").Phase == "Ready" })
	complete := job("sync-fault")
	after, err := os.Stat(archive)
	if err != nil || !os.SameFile(before, after) || complete.Receipt == nil {
		t.Fatal("recovery rewrote original archive", err)
	}
	if calls, _ := counter.outcome("sync-fault"); calls != 1 {
		t.Fatal("recovery recopied archive", calls)
	}
	row, err = m.journal.Read(backupArtifactKey(held.Binding))
	if err != nil || row.State.LastID != 1 || row.State.Pending != nil || !row.State.Applied.Present {
		t.Fatal("changed original Apply1", err)
	}
	if err = a.Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if err = (*owner).Close(); err != nil {
		t.Fatal(err)
	}
	*owner = nil
	*owner, err = Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	row, err = (*owner).backupArtifacts.journal.Read(backupArtifactKey(held.Binding))
	if err != nil || row.State.LastID != 1 || row.State.Pending != nil {
		t.Fatal("same DB original sync recovery", err)
	}
	cli("op", "show", "sync-fault-begin")
	counter = observeBackupIO(*owner)
	// Exercise the actual native free-space check without allocating/filling a
	// filesystem. The finite reservation exceeds this owned filesystem's free
	// space and remains below the product's explicit 1 TiB per-job bound.
	directory, err := (*owner).backupArtifacts.root.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	var space syscall.Statfs_t
	err = syscall.Fstatfs(int(directory.Fd()), &space)
	_ = directory.Close()
	if err != nil || space.Bsize <= 0 {
		t.Fatal("owned filesystem observation", err)
	}
	if space.Bfree >= (1<<40)/uint64(space.Bsize)-64 {
		t.Fatal("owned filesystem too large for bounded nonallocating ENOSPC input")
	}
	reservation := (space.Bfree + 64) * uint64(space.Bsize)
	for _, limit := range view().BackupLimits() {
		rev := limit.Revision
		limit.Revision = 0
		limit.Owner = [32]byte{}
		limit.Bytes = reservation + (1 << 20)
		apply("space-limit-"+limit.Tenant, "set-volume-backup-limit", rev, limit)
	}
	cli("volume", "backup", "create", "app/data", "--name", "no-space", "--max-size", strconv.FormatUint(reservation, 10), "--max-entries", "16", "--id", "no-space-begin", "--no-wait")
	wait("actual native ENOSPC", func() bool { _, err := counter.outcome("no-space"); return errors.Is(err, syscall.ENOSPC) })
	pending := job("no-space")
	local, err := (*owner).backupArtifacts.journal.Read(backupArtifactKey(pending.Binding))
	if err != nil || pending.Phase != "Reserved" || pending.Receipt != nil || local.State.Pending == nil || local.State.LastID != 1 {
		t.Fatal("ENOSPC lost original unknown/hold", err)
	}
	partial := filepath.Join(cfg.Node.StateDir, "workload", "backups", backupArtifactName(pending.Binding), "archive.tar")
	info, err := os.Stat(partial)
	if err != nil || info.Size() != 0 {
		t.Fatal("ENOSPC probe wrote/fills disk", err)
	}
	core, _ := view().Volume(source.Spec.Scope)
	if len(core.Consumers()) != 1 || core.Consumers()[0] != pending.Binding.Consumer {
		t.Fatal("ENOSPC returned shared reader before cancellation")
	}
	limit := view().BackupLimits()[0]
	rev := limit.Revision
	limit.Revision = 0
	limit.Owner = [32]byte{}
	limit.Bytes = complete.Receipt.Bytes
	limit.Count = 1
	raw, _ := control.ChangeBytes("set-volume-backup-limit", session.User, rev, limit)
	var change control.Change
	_ = json.Unmarshal(raw, &change)
	op, err := admin.Prepare(ctx, peer, session, "space-shrink-too-early", change)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := admin.Operation(ctx, peer, op, false)
	if err != nil || reply.Result == nil || reply.Result.Code != state.ConditionFailed {
		t.Fatal("ENOSPC prematurely returned reserved bytes", reply.Result, err)
	}
	cli("op", "resume", "no-space-begin")
	cli("volume", "backup", "cancel", "app/data", "no-space", "--id", "no-space-cancel", "--no-wait")
	wait("original ENOSPC cancellation/Gone", func() bool { return job("no-space").Phase == "Cancelled" })
	if calls, _ := counter.outcome("no-space"); calls != 1 {
		t.Fatal("partial backup recopied", calls)
	}
	if _, err = os.Stat(partial); !os.IsNotExist(err) {
		t.Fatal("cancel retained partial archive", err)
	}
	local, err = (*owner).backupArtifacts.journal.Read(backupArtifactKey(pending.Binding))
	if err != nil || local.State.Pending != nil || local.State.Applied.Present || local.State.LastID != 1 {
		t.Fatal("cancel replaced original Apply1", err)
	}
	core, _ = view().Volume(source.Spec.Scope)
	if len(core.Consumers()) != 0 {
		t.Fatal("cancel did not return original shared reader")
	}
	for _, limit := range view().BackupLimits() {
		rev := limit.Revision
		limit.Revision = 0
		limit.Owner = [32]byte{}
		limit.Bytes = complete.Receipt.Bytes
		limit.Count = 1
		apply("space-returned-"+limit.Tenant, "set-volume-backup-limit", rev, limit)
	}
	cli("volume", "delete", "app/data", "--id", "io-source-delete", "--no-wait")
	wait("original source Gone", func() bool { core, ok := view().Volume(source.Spec.Scope); return ok && core.Deleted() })
	cli("volume", "backup", "delete", "app/data", "sync-fault", "--id", "io-artifact-delete", "--no-wait")
	wait("original synced artifact Gone", func() bool { return job("sync-fault").Phase == "Deleted" })
	for _, limit := range view().BackupLimits() {
		rev := limit.Revision
		limit.Revision = 0
		limit.Owner = [32]byte{}
		limit.Bytes = 0
		limit.Count = 0
		apply("io-zero-"+limit.Tenant, "set-volume-backup-limit", rev, limit)
	}
	t.Log("actual CLI/Raft/SDK/standalone writer -> injected final-directory EIO blocks Ready and original Recover -> same inode/Apply1/one actual Export, resync Ready/Snapshot/same DB; actual native filesystem ENOSPC without allocation -> original Unknown/shared hold and shrink rejection -> no recopy, explicit cancel/Gone/reader+budget return -> exact source/artifact delete/zero. No fabricated native facts or disk filling; full restore I/O/intent-partial/collector remains separate")
}
