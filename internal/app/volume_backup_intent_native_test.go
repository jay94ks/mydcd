// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

func TestRealBoundaryBackupPartialIntentOriginalInodeAndCancel(t *testing.T) {
	runRealVolumeOwnerBoundary(t, true, true, false, volumeOwnerBackupIntentIO)
}

func verifyBackupIntentBoundary(t *testing.T, ctx context.Context, a *Runtime, owner **Runtime, cfg config.Node, root string, p control.Policy, read func() cluster.View, source volumes.NativeReady, cli func(...string)) {
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
			t.Fatal("missing original backup", id)
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
	m := (*owner).backupArtifacts
	counter := observeBackupIO(*owner)
	var fail atomic.Bool
	fail.Store(true)
	var writes atomic.Int64
	m.mu.Lock()
	m.writeBytes = func(file *os.File, raw []byte) (int, error) {
		if filepath.Base(file.Name()) == "intent.json" && fail.Load() {
			writes.Add(1)
			n, err := file.Write(raw[:len(raw)/2])
			return n, errors.Join(syscall.ENOSPC, err)
		}
		return file.Write(raw)
	}
	m.mu.Unlock()
	cli("volume", "backup", "create", "app/data", "--name", "partial-intent", "--max-size", "131072", "--max-entries", "16", "--id", "partial-intent-begin", "--no-wait")
	wait("actual partial intent and original checkpoint", func() bool {
		if writes.Load() != 1 {
			return false
		}
		j := job("partial-intent")
		r, err := m.journal.Read(backupArtifactKey(j.Binding))
		return err == nil && r.Checkpoint != nil && r.State.Pending != nil && r.State.Pending.Phase == reconcile.RecoveryRequired
	})
	original := job("partial-intent")
	key := backupArtifactKey(original.Binding)
	record, err := m.journal.Read(key)
	if err != nil || original.Phase != "Reserved" || original.Receipt != nil || record.Checkpoint == nil || record.State.LastID != 1 || validateBackupDirectoryCheckpoint(original.Binding, record.Checkpoint) != nil {
		t.Fatal("partial intent lost original state", err)
	}
	proof := append([]byte(nil), record.Checkpoint.Data...)
	if calls, _ := counter.outcome("partial-intent"); calls != 0 {
		t.Fatal("data export ran before durable intent", calls)
	}
	path := filepath.Join(cfg.Node.StateDir, "workload", "backups", backupArtifactName(original.Binding))
	originalDirectory, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	partial, err := os.ReadFile(filepath.Join(path, "intent.json"))
	expected, _ := json.Marshal(original.Binding)
	if err != nil || len(partial) == 0 || len(partial) >= len(expected) || !bytes.HasPrefix(expected, partial) {
		t.Fatal("actual partial metadata write absent", err)
	}
	if err = (*owner).Close(); err != nil {
		t.Fatal(err)
	}
	*owner = nil
	*owner, err = Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	m = (*owner).backupArtifacts
	cli("op", "resume", "partial-intent-begin")
	recovered, err := m.journal.Read(key)
	if err != nil || recovered.Checkpoint == nil || !bytes.Equal(proof, recovered.Checkpoint.Data) || recovered.State.LastID != 1 {
		t.Fatal("reopen changed original identity checkpoint", err)
	}
	// Register exact local-name restoration before replacing the directory. The
	// original stays open/existing, so a replacement cannot reuse its inode.
	held := path + "-held-original"
	moved := false
	restore := func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if !moved {
			return
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			t.Error("replacement empty directory rollback", err)
			return
		}
		if err := os.Rename(held, path); err != nil {
			t.Error("original inode rollback", err)
			return
		}
		moved = false
	}
	defer restore()
	m.mu.Lock()
	if err = os.Rename(path, held); err != nil {
		m.mu.Unlock()
		t.Fatal(err)
	}
	moved = true
	if err = os.Mkdir(path, 0700); err != nil {
		m.mu.Unlock()
		t.Fatal(err)
	}
	m.mu.Unlock()
	cli("volume", "backup", "cancel", "app/data", "partial-intent", "--id", "partial-intent-cancel", "--no-wait")
	cancelling := job("partial-intent")
	// Invoke the actual serialized producer once to directly observe the
	// negative boundary; shared success is later posted by the normal worker.
	if _, err = m.Step(ctx, cancelling); err == nil {
		t.Fatal("replacement inode adopted/removed")
	}
	core, _ := view().Volume(source.Spec.Scope)
	if job("partial-intent").Phase != "Cancelling" || len(core.Consumers()) != 1 || core.Consumers()[0] != original.Binding.Consumer {
		t.Fatal("foreign denial returned original shared reader")
	}
	heldInfo, err := os.Stat(held)
	if err != nil || !os.SameFile(originalDirectory, heldInfo) {
		t.Fatal("original partial directory changed", err)
	}
	restore()
	if moved {
		t.Fatal("original inode restoration failed")
	}
	wait("normal Runtime original partial metadata cancellation", func() bool { return job("partial-intent").Phase == "Cancelled" })
	settled, err := m.journal.Read(key)
	if err != nil || settled.Checkpoint != nil || settled.State.Pending != nil || settled.State.Applied.Present || settled.State.LastID != 1 {
		t.Fatal("metadata retirement changed original ID or retained checkpoint", err)
	}
	if _, err = os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("owned partial intent directory retained", err)
	}
	core, _ = view().Volume(source.Spec.Scope)
	if len(core.Consumers()) != 0 {
		t.Fatal("original reader retained after closure")
	}
	cli("op", "show", "partial-intent-begin")
	fail.Store(false)
	cli("volume", "backup", "create", "app/data", "--name", "checkpoint-ready", "--max-size", "131072", "--max-entries", "16", "--id", "checkpoint-ready-begin", "--no-wait")
	wait("explicit new backup Ready", func() bool { return job("checkpoint-ready").Phase == "Ready" })
	ready := job("checkpoint-ready")
	normalKey := backupArtifactKey(ready.Binding)
	row, err := m.journal.Read(normalKey)
	if err != nil || row.Checkpoint == nil || row.State.Pending != nil || row.State.LastID != 1 || !row.State.Applied.Present {
		t.Fatal("normal backup did not retain original object checkpoint", err)
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
	m = (*owner).backupArtifacts
	row, err = m.journal.Read(normalKey)
	if err != nil || row.Checkpoint == nil || validateBackupDirectoryCheckpoint(ready.Binding, row.Checkpoint) != nil || row.State.LastID != 1 {
		t.Fatal("Ready original identity lost on reopen", err)
	}
	cli("volume", "backup", "delete", "app/data", "checkpoint-ready", "--id", "checkpoint-ready-delete", "--no-wait")
	wait("normal original Remove/Gone", func() bool { return job("checkpoint-ready").Phase == "Deleted" })
	row, err = m.journal.Read(normalKey)
	if err != nil || row.Checkpoint != nil || row.State.Pending != nil || row.State.LastID != 2 || row.State.Applied.Present {
		t.Fatal("positive Remove did not return checkpoint", err)
	}
	cli("volume", "delete", "app/data", "--id", "intent-source-delete", "--no-wait")
	wait("exact original native source Gone", func() bool { v, ok := view().Volume(source.Spec.Scope); return ok && v.Deleted() })
	for _, limit := range view().BackupLimits() {
		rev := limit.Revision
		limit.Revision = 0
		limit.Owner = [32]byte{}
		limit.Bytes = 0
		limit.Count = 0
		_ = rev
		args, _ := nativeMovedChange("intent-zero-"+limit.Tenant, "set-volume-backup-limit", limit)
		cli(args...)
	}
	t.Log("actual CLI/Raft/runtime: Mkdir inode checkpoint synced before injected partial intent write -> no Export/Ready, same DB/Apply1/proof on restart -> explicit cancel rejects replacement inode with shared reader retained -> exact original inode restored -> original metadata-only retirement/Gone/reader and budget return; explicit separate successful backup retains checkpoint through Ready/restart then exact Remove clears it. Source/native IDs preserved; no automatic copy or foreign deletion")
}
