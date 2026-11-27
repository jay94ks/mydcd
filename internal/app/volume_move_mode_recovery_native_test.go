// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/workload/volumes"
	"github.com/moby/moby/client"
)

// Fail the real receive adapter's data sync, retaining its original A2 intent,
// inode and unacknowledged tail. Normal Runtime recovery after the actual
// target restart uses its original store; no fake receipt or new transfer is
// provided by this failure injection.
func armMoveTargetSyncFailure(t *testing.T, ctx context.Context, target *Runtime, job control.VolumeMove, p control.Policy, read func() cluster.View, wait func(string, func() bool), reopen func() *Runtime) func() *Runtime {
	t.Helper()
	if reopen == nil || target.backupArtifacts == nil {
		t.Fatal("original target receive store and same-DB Runtime reopen required")
	}
	store := target.backupArtifacts
	var failures atomic.Uint64
	injected := errors.New("owned target archive data sync failed before offset ACK")
	store.mu.Lock()
	syncFile := store.syncFile
	store.syncFile = func(file *os.File) error {
		info, err := file.Stat()
		if err != nil {
			return err
		}
		if filepath.Base(file.Name()) == "archive.tar" && info.Size() > 0 {
			failures.Add(1)
			return injected
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
		var receive reconcile.Record
		wait("actual target receive sync failure retains its original operation", func() bool {
			if failures.Load() == 0 {
				return false
			}
			registry, err := p.Volumes(read().State)
			if err != nil {
				t.Fatal(err)
			}
			stored, move, found := registry.Move(job.Selection())
			if !found || stored.Digest() != job.Digest() || move.Manifest == nil {
				return false
			}
			if move.Phase != volumes.Copying || move.Verified != nil || move.CommitRevision != 0 || move.Activated != nil || move.ReaderClosed != nil {
				t.Fatal("failed data sync produced a verified/committed/active transfer")
			}
			intent = moveReceiveIntent{Schema: 1, Job: job, Manifest: *move.Manifest}
			receive, err = store.journal.Read(moveReceiveKey(intent))
			return err == nil && receive.State.Pending != nil && receive.State.Pending.Phase == reconcile.RecoveryRequired
		})
		store.mu.Lock()
		if receive.State.LastID != 1 || receive.State.Pending.ID != 1 || receive.State.Pending.Kind != reconcile.Apply || receive.State.Applied.Present || receive.Checkpoint == nil || receive.Checkpoint.Operation != 1 {
			store.mu.Unlock()
			t.Fatal("failed receive replaced its original A2 identity/checkpoint")
		}
		directory, err := store.receiveDirectory(intent, receive.Checkpoint.Data)
		if err != nil {
			store.mu.Unlock()
			t.Fatal(err)
		}
		raw, readErr := backupRead(directory, "progress.json", 4096)
		progress, decodeErr := schema.Decode[moveReceiveProgress](raw)
		file, statErr := directory.Stat("archive.tar")
		closeErr := directory.Close()
		store.mu.Unlock()
		if readErr != nil || decodeErr != nil || statErr != nil || closeErr != nil || progress.Schema != 1 || progress.Binding != intent.digest() || progress.Offset != 0 || file.Size() <= 0 {
			t.Fatal("failed data sync advanced the durable offset or lost its unacknowledged original tail", readErr, decodeErr, statErr, closeErr)
		}
		// Close joins the old worker. Open uses the actual original provider
		// configuration/root/key and restores the normal filesystem adapter;
		// the old store's injected failure remains isolated to that old owner.
		target = reopen()
		if target.Identity.Public != job.Binding.Target.Key {
			t.Fatal("target receive recovery replaced the original node identity")
		}
		if err := ctx.Err(); err != nil {
			t.Fatal("target same-DB receive recovery", err)
		}
		t.Log("normal authenticated receive -> actual archive sync failure/no offset advance -> original A2 operation/checkpoint/tail retained -> actual target Close/Open of same DB/key/provider -> normal original recovery/activation continues")
		return target
	}
}

// The original normal producer has already proved readonly/unused activation
// and completed both transfer cleanups. Reopen the actual target and its same
// databases, then observe the original native Tasks and physical Volume. No
// new apply/restore/move or fixture-signed activation is submitted here.
func reopenMoveTargetMode(t *testing.T, ctx context.Context, target *Runtime, ready volumes.NativeReady, job control.VolumeMove, p control.Policy, read func() cluster.View, wait func(string, func() bool), scenario managedAppScenario, reopen func() *Runtime) *Runtime {
	t.Helper()
	if reopen == nil || scenario != managedAppVolumeMoveReadonly && scenario != managedAppVolumeMoveUnused {
		t.Fatal("original readonly/unused target and normal Runtime reopen required")
	}
	encode := func(value any) string {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	registry, err := p.Volumes(read().State)
	if err != nil {
		t.Fatal(err)
	}
	stored, move, found := registry.Move(job.Selection())
	core, haveCore := registry.Volume(job.Binding.Scope)
	if !found || !haveCore || stored.Digest() != job.Digest() || move.Phase != volumes.Completed || move.Manifest == nil || move.Activated == nil || move.SourceCleanup == nil || move.TargetCleanup == nil {
		t.Fatal("target recovery requires original completed transfer evidence")
	}
	originalMove := encode(move)
	originalCore, err := core.Encode()
	if err != nil {
		t.Fatal(err)
	}
	intent := moveReceiveIntent{Schema: 1, Job: job, Manifest: *move.Manifest}
	transfers := func(r *Runtime) map[string]string {
		t.Helper()
		result := map[string]string{}
		for _, entry := range []struct {
			name, key string
			journal   *reconcile.Journal
		}{{"restore", moveRestoreKey(intent), r.volumeRestores}, {"receive", moveReceiveKey(intent), r.backupArtifacts.journal}} {
			row, err := entry.journal.Read(entry.key)
			if err != nil || row.State.Pending != nil || row.State.Applied.Present || row.State.Desired.Present || row.State.GenerationFloor != 1 || row.State.LastID != 2 || len(row.Consumers) != 0 {
				t.Fatal("original transfer journal is not terminal", entry.name, err)
			}
			result[entry.name] = encode(row)
		}
		return result
	}
	originalTransfers := transfers(target)
	services := []string{"web"}
	if scenario == managedAppVolumeMoveReadonly {
		services = append(services, "mirror")
	}
	nativeIDs := map[string]string{}
	resources := map[string]reconcile.Resource{}
	for _, service := range services {
		key := deployment.ResourceKey("task", job.Binding.Scope.Tenant, job.Binding.Scope.App, service)
		status, err := target.workload.Status(ctx, key)
		row, rowErr := target.workload.View(key)
		if err != nil || rowErr != nil || !status.Ready || !status.Running || status.NativeID == "" || row.State.Pending != nil || !row.State.Applied.Present {
			t.Fatal("original target task required", service, err, rowErr)
		}
		nativeIDs[key], resources[key] = status.NativeID, row.State.Applied
	}
	disk, err := target.docker.API.VolumeInspect(ctx, ready.Owner.Native, client.VolumeInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	originalDirectory, err := os.Stat(disk.Volume.Mountpoint)
	if err != nil {
		t.Fatal(err)
	}
	target = reopen()
	if target.Identity.Public != job.Binding.Target.Key {
		t.Fatal("target restart replaced the original identity")
	}
	wait("same readonly/unused target DB resumes original native Tasks", func() bool {
		for key, nativeID := range nativeIDs {
			status, err := target.workload.Status(ctx, key)
			row, rowErr := target.workload.View(key)
			if rowErr != nil || row.State.Pending != nil || row.State.Applied != resources[key] {
				t.Fatal("target restart replaced the original Task recipe/generation", key, rowErr)
			}
			if err != nil || !status.Ready || !status.Running {
				return false
			}
			if status.NativeID != nativeID {
				t.Fatal("target restart substituted a new native Task", key)
			}
		}
		return true
	})
	registry, err = p.Volumes(read().State)
	if err != nil {
		t.Fatal(err)
	}
	stored, move, found = registry.Move(job.Selection())
	core, haveCore = registry.Volume(job.Binding.Scope)
	current, haveNative := registry.Native(job.Binding.Scope.Tenant, job.Binding.Scope.App, job.Binding.Scope.ID)
	currentCore, err := core.Encode()
	if !found || !haveCore || !haveNative || err != nil || stored.Digest() != job.Digest() || encode(move) != originalMove || string(currentCore) != string(originalCore) || control.VolumeNativeDigest(current) != control.VolumeNativeDigest(ready) {
		t.Fatal("target restart changed original activation/consumer/native evidence", err)
	}
	afterTransfers := transfers(target)
	for name, before := range originalTransfers {
		if afterTransfers[name] != before {
			t.Fatal("target restart repeated or replaced original transfer work", name)
		}
	}
	if err = target.nativeVolumes.CheckColdReleased(ready, job.StagingConsumer()); err != nil {
		t.Fatal("target restart reacquired a released staging pin", err)
	}
	idle := scenario == managedAppVolumeMoveUnused
	if idle {
		if !move.Activated.Idle || len(core.Consumers()) != 0 {
			t.Fatal("unused target restart created an activation consumer")
		}
		if err = target.nativeVolumes.CheckIdle(ctx, ready); err != nil {
			t.Fatal("unused target restart has a pin or actual mount", err)
		}
	} else {
		if move.Activated.Idle || len(core.Consumers()) != len(services) {
			t.Fatal("readonly target restart lost an original reader")
		}
		for _, consumer := range core.Consumers() {
			if consumer.Writable || core.CheckActivation(consumer) != nil {
				t.Fatal("readonly target restart gained writer authority")
			}
		}
	}
	mounted, err := target.docker.API.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: client.Filters{}.Add("volume", ready.Owner.Native)})
	if err != nil || idle && len(mounted.Items) != 0 || !idle && len(mounted.Items) != len(services) {
		t.Fatal("target restart changed actual Volume attachments", err)
	}
	for _, container := range mounted.Items {
		known := false
		for _, nativeID := range nativeIDs {
			known = known || container.ID == nativeID
		}
		if !known {
			t.Fatal("unrecorded container attached after target restart", container.ID)
		}
		actual, err := target.docker.API.ContainerInspect(ctx, container.ID, client.ContainerInspectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		for _, mount := range actual.Container.Mounts {
			if mount.Name == ready.Owner.Native && mount.RW {
				t.Fatal("readonly target restart changed its actual mount to writable")
			}
		}
	}
	disk, err = target.docker.API.VolumeInspect(ctx, ready.Owner.Native, client.VolumeInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.Stat(disk.Volume.Mountpoint)
	if err != nil || !os.SameFile(originalDirectory, directory) {
		t.Fatal("target restart replaced the physical Volume", err)
	}
	data, err := os.ReadFile(filepath.Join(disk.Volume.Mountpoint, "move-sentinel"))
	if err != nil || string(data) != "original-data-before-move" {
		t.Fatal("target restart lost original Volume data", err)
	}
	t.Log("normal readonly/unused activation and Completed -> actual target Snapshot/Close/Open using same DB/key/provider configuration -> same native Tasks/recipes/generations/consumer tokens and physical data -> no restore/receive redispatch or writable upgrade -> normal original app down/cleanup")
	return target
}
