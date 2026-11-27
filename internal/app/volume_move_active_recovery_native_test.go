// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// Fail only the final sync of the emptied, originally owned receive directory.
// Data copy, restore, Arm and actual target activation use their normal paths.
// The original Remove remains Unknown while the target can accept new writes.
func armMoveActiveCleanupSyncFailure(t *testing.T, ctx context.Context, target *Runtime, job control.VolumeMove, p control.Policy, read func() cluster.View, wait func(string, func() bool), reopen func() *Runtime) func() *Runtime {
	t.Helper()
	if reopen == nil || target.backupArtifacts == nil {
		t.Fatal("original target store and same-DB Runtime reopen required")
	}
	store := target.backupArtifacts
	var failures atomic.Uint64
	injected := errors.New("owned receive cleanup directory sync failed after target activation")
	store.mu.Lock()
	syncFile := store.syncFile
	store.syncFile = func(file *os.File) error {
		info, err := file.Stat()
		if err != nil {
			return err
		}
		if info.IsDir() && strings.HasPrefix(filepath.Base(filepath.Clean(file.Name())), "receive-") {
			names, err := file.Readdirnames(1)
			if err != nil && !errors.Is(err, io.EOF) {
				return err
			}
			if len(names) == 0 {
				failures.Add(1)
				return injected
			}
		}
		return syncFile(file)
	}
	store.mu.Unlock()
	t.Cleanup(func() {
		store.mu.Lock()
		store.syncFile = syncFile
		store.mu.Unlock()
	})
	return func() *Runtime {
		t.Helper()
		var intent moveReceiveIntent
		wait("actual target is Active while original receive Remove remains Unknown", func() bool {
			if failures.Load() == 0 {
				return false
			}
			registry, err := p.Volumes(read().State)
			if err != nil {
				t.Fatal(err)
			}
			stored, move, ok := registry.Move(job.Selection())
			if !ok || stored.Digest() != job.Digest() || move.Manifest == nil || move.Activated == nil {
				return false
			}
			if move.Phase != volumes.Active || !move.Irreversible || move.CommitRevision == 0 || move.TargetCleanup != nil || move.Activated.Idle || !move.Activated.Running || !move.Activated.Consumer.Writable {
				t.Fatal("failed transfer cleanup changed active writer authority or fabricated completion")
			}
			core, found := registry.Volume(job.Binding.Scope)
			owner, revision := core.Owner()
			if !found || owner != job.Binding.Target || revision != move.CommitRevision || len(core.Consumers()) != 1 || core.Consumers()[0] != move.Activated.Consumer {
				t.Fatal("active cleanup lost the original target writer")
			}
			intent = moveReceiveIntent{Schema: 1, Job: job, Manifest: *move.Manifest}
			row, err := store.journal.Read(moveReceiveKey(intent))
			return err == nil && row.State.Pending != nil && row.State.Pending.Kind == reconcile.Remove && row.State.Pending.Phase == reconcile.RecoveryRequired
		})
		row, err := store.journal.Read(moveReceiveKey(intent))
		if err != nil || row.State.Pending == nil || row.State.Pending.ID != 2 || row.State.LastID != 2 || !row.State.Applied.Present || row.Checkpoint == nil || row.Checkpoint.Operation != 1 || len(row.Consumers) != 0 {
			t.Fatal("unknown cleanup replaced its original transfer journal/receipt", err)
		}
		key := deployment.ResourceKey("task", job.Binding.Scope.Tenant, job.Binding.Scope.App, "web")
		before, err := target.workload.Status(ctx, key)
		beforeRow, rowErr := target.workload.View(key)
		if err != nil || rowErr != nil || !before.Ready || !before.Running || before.NativeID == "" || beforeRow.State.Pending != nil {
			t.Fatal("active target writer unavailable before cleanup recovery", err, rowErr)
		}
		newData := []byte(strings.Repeat("active-target-write-", 512))
		if !bytes.Equal(moveFixtureRequest(t, ctx, target, http.MethodPut, newData), newData) || !bytes.Equal(moveFixtureRequest(t, ctx, target, http.MethodGet, nil), newData) {
			t.Fatal("active target new write was not durable before cleanup recovery")
		}
		target = reopen()
		if target.Identity.Public != job.Binding.Target.Key {
			t.Fatal("active cleanup recovery replaced the original node identity")
		}
		wait("same active target DB resumes original native writer and cleanup", func() bool {
			current, err := target.workload.Status(ctx, key)
			currentRow, rowErr := target.workload.View(key)
			if rowErr != nil || currentRow.State.Pending != nil || currentRow.State.Applied != beforeRow.State.Applied {
				t.Fatal("active recovery replaced the original Task recipe/generation", rowErr)
			}
			if err != nil || !current.Ready || !current.Running {
				return false
			}
			if current.NativeID != before.NativeID {
				t.Fatal("active recovery substituted a new native Task")
			}
			row, err := target.backupArtifacts.journal.Read(moveReceiveKey(intent))
			if err != nil || row.State.LastID != 2 {
				t.Fatal("active recovery lost or replaced the original Remove", err)
			}
			return row.State.Pending == nil && !row.State.Applied.Present && !row.State.Desired.Present && len(row.Consumers) == 0
		})
		if !bytes.Equal(moveFixtureRequest(t, ctx, target, http.MethodGet, nil), newData) {
			t.Fatal("transfer cleanup/target restart lost new application data")
		}
		t.Log("normal target Active/writer -> actual receive-directory sync failure/original Remove2 Unknown -> actual target new write -> same target DB/key Close/Open -> original Remove2 recovery, same native Task/recipe/generation and new data -> normal Completed; no recopy/rehash of writable target or source rollback")
		return target
	}
}
