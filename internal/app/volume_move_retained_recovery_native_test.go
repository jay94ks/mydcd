// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"testing"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/storage"
	"github.com/jay94ks/seafield/internal/workload/volumes"
	"github.com/moby/moby/client"
)

// The reverse move has returned a new writer to this original node. Interrupt
// only its obsolete source deletion after real Remove, then reopen the same
// daemon DB/key. Current writer/data and old source facts are independent.
func deleteRetainedMoveWithRecovery(t *testing.T, ctx context.Context, source *Runtime, root string, selected control.VolumeMoveSelection, obsolete, current volumes.NativeReady, newData []byte, p control.Policy, read func() cluster.View, wait func(string, func() bool), controls managedMoveNativeControls) *Runtime {
	t.Helper()
	if controls.sourceUsage == nil || controls.reopenSource == nil || controls.sourceRuntime == nil || obsolete.Owner == current.Owner || source.Identity.Public != obsolete.Owner.Key || current.Owner.Key != source.Identity.Public {
		t.Fatal("original SDK gate/source reopen and distinct old/current native required")
	}
	key := volumes.NativeKey(obsolete.Spec)
	before, err := source.nativeVolumes.View(key)
	if err != nil || before.State.Pending != nil || !before.State.Applied.Present || len(before.Consumers) != 0 {
		t.Fatal("original retained native journal not settled", err)
	}
	taskKey := deployment.ResourceKey("task", selected.Scope.Tenant, selected.Scope.App, "web")
	writer, err := source.workload.Status(ctx, taskKey)
	writerRow, rowErr := source.workload.View(taskKey)
	if err != nil || rowErr != nil || !writer.Ready || !writer.Running || writer.NativeID == "" || writerRow.State.Pending != nil {
		t.Fatal("returned current writer unavailable", err, rowErr)
	}
	registry, err := p.Volumes(read().State)
	if err != nil {
		t.Fatal(err)
	}
	core, ok := registry.Volume(selected.Scope)
	owner, ownerRevision := core.Owner()
	if !ok || owner != current.Owner || len(core.Consumers()) != 1 {
		t.Fatal("current returned writer/owner required before obsolete deletion")
	}
	consumer := core.Consumers()[0]
	retainedCount := len(core.Retained())
	direct, err := engine.Open(ctx, "unix:///var/run/docker.sock", source.owner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = direct.Close() })
	inspections := 0
	entered, release := controls.sourceUsage.armWhen(obsolete.Owner.Native, func() bool {
		inspections++
		return inspections == 2
	})
	t.Cleanup(release)
	request := "delete-return-source-a"
	deleteRetainedMoveThroughCLI(t, ctx, root, selected, request)
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("original obsolete Remove post-effect SDK readback", ctx.Err())
	}
	// Observe through a different read-only SDK client so this inspection
	// cannot consume/release the deliberately delayed original response.
	if _, err := direct.API.VolumeInspect(ctx, obsolete.Owner.Native, client.VolumeInspectOptions{}); !cerrdefs.IsNotFound(err) {
		t.Fatal("held readback did not follow the actual original Remove", err)
	}
	registry, err = p.Volumes(read().State)
	if err != nil {
		t.Fatal(err)
	}
	stored, pending, found := registry.Move(selected)
	if !found || pending.SourceDeletion == nil || pending.SourceDeletion.Gone != nil {
		t.Fatal("physical absence fabricated committed native Gone")
	}
	originalJob := stored.Digest()
	deleteRevision := pending.SourceDeletion.Revision
	config := source.installation.config
	nativePath := filepath.Join(config.Node.StateDir, "workload", "volumes.db")
	storageKey := "resource/" + key
	var originalRecord []byte
	lostRecord := false
	repairRecord := func() error {
		db, err := storage.Open(nativePath)
		if err != nil {
			return err
		}
		current, err := db.Get(storageKey)
		if errors.Is(err, storage.ErrMissing) {
			err = db.Write(map[string][]byte{storageKey: originalRecord})
		} else if err == nil && !bytes.Equal(current, originalRecord) {
			err = errors.New("original retained native row changed; refusing rollback overwrite")
		}
		err = errors.Join(err, db.Close())
		if err == nil {
			lostRecord = false
		}
		return err
	}
	t.Cleanup(func() {
		if lostRecord {
			// Repair only the original test-owned row, with the current Runtime
			// closed, before the existing native rollback starts. A different
			// row is retained as a failure rather than overwritten.
			if active := controls.sourceRuntime(); active != nil {
				if err := active.Close(); err != nil {
					t.Error(err)
				}
			}
			if err := repairRecord(); err != nil {
				t.Error("restore original retained native journal row", err)
			}
		}
	})
	var originalRemove uint64
	source = controls.reopenSource(func() {
		// Close has joined the SDK worker and released this original DB.
		// Inspect it before Open can settle or replace the pending operation.
		journal, err := volumes.OpenNative(nativePath, direct)
		if err != nil {
			t.Fatal(err)
		}
		record, readErr := journal.View(key)
		closeErr := journal.Close()
		raw, _ := json.Marshal(obsolete.Spec)
		expected := reconcile.Resource{Present: true, Generation: obsolete.Generation, Spec: string(raw)}
		if readErr != nil || closeErr != nil || record.State.Pending == nil || record.State.Pending.Kind != reconcile.Remove || record.State.Pending.Target != expected || record.State.Applied != expected || record.State.Desired.Present || record.State.LastID != before.State.LastID+1 || record.State.Pending.ID != record.State.LastID {
			t.Fatal("same native DB lost/replaced its original unknown Remove", readErr, closeErr)
		}
		originalRemove = record.State.Pending.ID
		db, err := storage.Open(nativePath)
		if err != nil {
			t.Fatal(err)
		}
		originalRecord, err = db.Get(storageKey)
		if err == nil {
			lostRecord = true // Also restore after a failed/uncertain sync.
			err = db.Write(map[string][]byte{storageKey: nil})
		}
		if err = errors.Join(err, db.Close()); err != nil {
			t.Fatal("owned original native journal loss injection", err)
		}
	})
	release()
	if _, err := source.nativeVolumes.View(key); !errors.Is(err, storage.ErrMissing) {
		t.Fatal("missing original retained native history was reconstructed", err)
	}
	registry, err = p.Volumes(read().State)
	if err != nil {
		t.Fatal(err)
	}
	_, missing, found := registry.Move(selected)
	work, err := p.VolumeRetainedDeletePermit(read().State, source.Identity.Public, selected)
	if err != nil || !found || missing.SourceDeletion == nil || missing.SourceDeletion.Gone != nil {
		t.Fatal("lost local native history fabricated shared deletion completion", err)
	}
	if err = source.removeOriginalVolume(ctx, work); !errors.Is(err, storage.ErrMissing) {
		t.Fatal("physical absence bypassed the missing original native journal", err)
	}
	registry, err = p.Volumes(read().State)
	if err != nil {
		t.Fatal(err)
	}
	_, missing, _ = registry.Move(selected)
	blockedCore, _ := registry.Volume(selected.Scope)
	blockedOwner, blockedRevision := blockedCore.Owner()
	if missing.SourceDeletion.Gone != nil || len(blockedCore.Retained()) != retainedCount || blockedOwner != owner || blockedRevision != ownerRevision || len(blockedCore.Consumers()) != 1 || blockedCore.Consumers()[0] != consumer {
		t.Fatal("missing history released the retained physical reservation")
	}
	// Explicitly restore the exact saved original Pending Remove, then let
	// the normal owner settle it. No synthetic Gone/new ID is submitted.
	source = controls.reopenSource(func() {
		if err := repairRecord(); err != nil {
			t.Fatal("restore exact original retained native row", err)
		}
	})
	wait("same source DB settles exact original retained deletion", func() bool {
		v, err := p.Volumes(read().State)
		if err != nil {
			t.Fatal(err)
		}
		_, move, found := v.Move(selected)
		return found && move.SourceDeletion != nil && move.SourceDeletion.Gone != nil
	})
	record, err := source.nativeVolumes.View(key)
	if err != nil || originalRemove == 0 || record.State.Pending != nil || record.State.LastID != originalRemove || record.State.Applied.Present || record.State.Desired.Present || len(record.Consumers) != 0 {
		t.Fatal("retained delete recovery did not settle the original Remove", err)
	}
	registry, err = p.Volumes(read().State)
	if err != nil {
		t.Fatal(err)
	}
	stored, removed, found := registry.Move(selected)
	core, ok = registry.Volume(selected.Scope)
	afterOwner, afterRevision := core.Owner()
	if !found || !ok || stored.Digest() != originalJob || removed.SourceDeletion == nil || removed.SourceDeletion.Revision != deleteRevision || removed.SourceDeletion.Gone == nil || removed.SourceDeletion.Gone.Verify() != nil || removed.SourceDeletion.Gone.Key != key || removed.SourceDeletion.Gone.Generation != obsolete.Generation || afterOwner != owner || afterRevision != ownerRevision || len(core.Consumers()) != 1 || core.Consumers()[0] != consumer {
		t.Fatal("retained native deletion changed original intent/current writer")
	}
	history, err := source.activations.ClosedWriters(obsolete)
	if err != nil || len(history) == 0 {
		t.Fatal("retained deletion erased original writer history", err)
	}
	for _, closed := range history {
		gate, err := source.activations.Checkpoint(closed.Writer)
		if err != nil || gate.Starting != nil || gate.FenceThrough < removed.Binding.SourceOwnerRevision || core.CheckActivation(closed.Writer.Consumer) == nil {
			t.Fatal("retained deletion reset an obsolete writer fence", err)
		}
	}
	wait("same returned writer resumes beside obsolete source deletion", func() bool {
		status, err := source.workload.Status(ctx, taskKey)
		row, rowErr := source.workload.View(taskKey)
		if rowErr != nil || row.State.Pending != nil || row.State.Applied != writerRow.State.Applied {
			t.Fatal("retained deletion replaced the current writer recipe/generation", rowErr)
		}
		if err != nil || !status.Ready || !status.Running {
			return false
		}
		if status.NativeID != writer.NativeID {
			t.Fatal("retained deletion restart recreated current native writer")
		}
		return true
	})
	if !bytes.Equal(moveFixtureRequest(t, ctx, source, http.MethodGet, nil), newData) {
		t.Fatal("obsolete source deletion/restart lost current target writes")
	}
	deleteRetainedMoveThroughCLI(t, ctx, root, selected, request)
	if _, err := direct.API.VolumeInspect(ctx, obsolete.Owner.Native, client.VolumeInspectOptions{}); !cerrdefs.IsNotFound(err) {
		t.Fatal("obsolete native was recreated during original result recovery", err)
	}
	t.Log("separate original retained-source CLI deletion -> actual nonforce Remove/post-effect readback held -> shared Gone absent -> actual source Close/original DB pending Remove ID inspection -> remove only original owned row -> same DB/key Open/missing history blocks Gone despite physical absence -> actual Close/restore exact original row/Open -> original Remove settles/signed Gone/original request and current native writer/consumer/new data preserved")
	return source
}
