// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/moby/moby/client"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

func TestRealBoundaryAutomaticMoveSourceQuorumAndNative(t *testing.T) {
	runRealVolumeOwnerBoundary(t, true, true, false, volumeOwnerMoveSource)
}

func TestRealBoundaryMoveOwnerCASAfterNativeRestore(t *testing.T) {
	runRealVolumeOwnerBoundary(t, true, true, false, volumeOwnerMoveCommit)
}

func verifyAutomaticMoveSource(t *testing.T, ctx context.Context, a *Runtime, owner **Runtime, cfg config.Node, root string, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), ready volumes.NativeReady, source control.VolumeBackupSource, docker *engine.Client, cli func(...string), commitOwner bool, admin userauth.Client, authority sfcp.Peer, session access.Session) {
	t.Helper()
	registry := func() control.Volumes {
		t.Helper()
		v, err := p.Volumes(read().State)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	c, err := p.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := c.Tenant(ready.Spec.Scope.Tenant)
	change("move-nodes", "set-nodes", tenant.Revision, control.NodeChangeTo(tenant.ID, tenant.AllowedNodes, []string{"node-a", "node-b"}))
	core, _ := registry().Volume(ready.Spec.Scope)
	change("move-source-capacity", "set-volume-capacity", core.Revision(), control.VolumeCapacity{Scope: ready.Spec.Scope, Native: control.VolumeNativeDigest(ready), Bytes: 128 << 10})
	for _, node := range []string{"node-a", "node-b"} {
		for _, tenant := range []string{"", ready.Spec.Scope.Tenant} {
			var old control.VolumeBackupLimit
			for _, limit := range registry().BackupLimits() {
				if limit.Node == node && limit.Tenant == tenant {
					old = limit
				}
			}
			change("move-limit-"+node+tenant, "set-volume-backup-limit", old.Revision, control.VolumeBackupLimit{Tenant: tenant, Node: node, Bytes: 128 << 10, Count: 1, StagingBytes: 128 << 10, StagingCount: 1, Original: &control.OriginalVolumeLimit{Bytes: 256 << 10, Count: 2}})
		}
	}
	core, _ = registry().Volume(ready.Spec.Scope)
	_, ownerRevision := core.Owner()
	target := ready.Spec
	target.Node = "node-a"
	target.NodeKey = a.Identity.Public
	target.Materialization = "m-move"
	q := control.VolumeMoveBegin{Scope: ready.Spec.Scope, ID: "move", OwnerRevision: ownerRevision, Target: target, Compatibility: source.Compatibility, MaxBytes: 128 << 10, MaxEntries: 16, CapacityBytes: 128 << 10, ExpiresAt: time.Now().Unix() + 300}
	applyCLI := func(id, action string, expected uint64, payload any) {
		t.Helper()
		path := filepath.Join(root, id+".json")
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(control.ChangeDocument{Schema: 1, Action: action, Expected: expected, Payload: body})
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		cli("manage", "apply", "--request-id", id, "--change", path)
	}
	applyCLI("native-move", "begin-volume-move", core.Revision(), q)
	var job control.VolumeMove
	var move volumes.Move
	var reader volumes.Consumer
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		var ok bool
		job, move, ok = registry().Move(control.VolumeMoveSelection{Scope: ready.Spec.Scope, ID: q.ID})
		core, _ = registry().Volume(ready.Spec.Scope)
		if ok && move.Phase == volumes.Copying && move.Fence != nil && move.Manifest != nil {
			if current, found := core.MoveReader(job.Binding); found {
				reader = current
				break
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal("automatic native artifact/manifest", ctx.Err(), (*owner).volumeBackupError)
		case <-ticker.C:
		}
	}
	// The proof above came from the normal Runtime producer reading the real
	// activation/native journals, never from a fixture-signed state callback.
	cold, err := (*owner).activations.ColdSource(ctx, ready)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := (*owner).activations.Checkpoint(cold.Writer)
	if err != nil || gate.FenceThrough != ownerRevision {
		t.Fatal("automatic shared/native fence mismatch", err)
	}
	if err = (*owner).Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if err = (*owner).Close(); err != nil {
		t.Fatal(err)
	}
	*owner, err = Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for {
		_, leader := (*owner).Engine().Leader()
		if leader != "" {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("reopened source leader discovery", ctx.Err())
		case <-ticker.C:
		}
	}
	permit, err := (*owner).volumeMovePermit(ctx, job, "read")
	if err != nil || permit.Reader == nil || *permit.Reader != reader {
		t.Fatal("same DB lost actual original reader", err)
	}
	cold, err = (*owner).activations.ColdSource(ctx, ready)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := (*owner).activations.Checkpoint(cold.Writer)
	if err != nil || reopened.Boot == gate.Boot || reopened.FenceThrough != gate.FenceThrough {
		t.Fatal("local native fence lost on reboot", err)
	}
	intent := moveArtifactIntent{Schema: 1, Job: job, Reader: reader}
	artifactKey := moveArtifactKey(intent)
	row, err := (*owner).backupArtifacts.journal.Read(artifactKey)
	if err != nil || row.State.Pending != nil || !row.State.Applied.Present || row.State.LastID != 1 || row.Checkpoint == nil {
		t.Fatal("original artifact A2/receipt", err)
	}
	completion, err := (*owner).backupArtifacts.moveCompletion(ctx, intent, row.Checkpoint.Data, true)
	if err != nil || completion.Receipt != move.Manifest.ArchiveReceipt() {
		t.Fatal("shared Manifest not original durable artifact", err)
	}
	// The target has no native Volume yet. Connect the actual product receiver
	// to this installed member's current quorum/transport; do not fake a sink.
	if a.backupArtifacts != nil {
		t.Fatal("unexpected target artifact store")
	}
	receiverPath := filepath.Join(root, "move-target-artifacts")
	openReceiver := func() *backupArtifacts {
		t.Helper()
		m, e := openBackupArtifacts(receiverPath, job.Binding.Scope.Cluster, job.Binding.Target.Key, runtimeBackupBackend{a})
		if e != nil {
			t.Fatal(e)
		}
		return m
	}
	a.backupArtifacts = openReceiver()
	receiveIntent := moveReceiveIntent{Schema: 1, Job: job, Manifest: *move.Manifest}
	receiveKey := moveReceiveKey(receiveIntent)
	syncLost := errors.New("target original data sync failed before offset ACK")
	injected := false
	a.backupArtifacts.syncFile = func(file *os.File) error {
		info, e := file.Stat()
		if e != nil {
			return e
		}
		if !injected && filepath.Base(file.Name()) == "archive.tar" && info.Size() > 0 {
			injected = true
			return syncLost
		}
		return file.Sync()
	}
	if e := a.reconcileVolumeMoveTargets(ctx, read()); !errors.Is(e, syncLost) || !injected {
		t.Fatal("receiver accepted unsynced original data", e)
	}
	receiveRow, e := a.backupArtifacts.journal.Read(receiveKey)
	if e != nil || receiveRow.State.Pending == nil || receiveRow.State.LastID != 1 || receiveRow.Checkpoint == nil {
		t.Fatal("target original A2 uncertainty lost", e)
	}
	targetDir, e := a.backupArtifacts.receiveDirectory(receiveIntent, receiveRow.Checkpoint.Data)
	if e != nil {
		t.Fatal(e)
	}
	targetFile, e := targetDir.Stat("archive.tar")
	_ = targetDir.Close()
	if e != nil {
		t.Fatal(e)
	}
	if e = a.backupArtifacts.Close(); e != nil {
		t.Fatal(e)
	}
	a.backupArtifacts = openReceiver()
	if e = a.reconcileVolumeMoveTargets(ctx, read()); e != nil {
		t.Fatal("actual current-peer original receiver resume", e)
	}
	receiveRow, e = a.backupArtifacts.journal.Read(receiveKey)
	if e != nil || receiveRow.State.Pending != nil || !receiveRow.State.Applied.Present || receiveRow.State.LastID != 1 {
		t.Fatal("receiver replaced original A2", e)
	}
	received, e := a.backupArtifacts.receiveComplete(ctx, receiveIntent, receiveRow.Checkpoint.Data)
	if e != nil || received.Receipt != completion.Receipt {
		t.Fatal("original receiver completion", e)
	}
	targetDir, e = a.backupArtifacts.receiveDirectory(receiveIntent, receiveRow.Checkpoint.Data)
	if e != nil {
		t.Fatal(e)
	}
	targetAgain, e := targetDir.Stat("archive.tar")
	_ = targetDir.Close()
	if e != nil || !os.SameFile(targetFile, targetAgain) {
		t.Fatal("target resume replaced inode", e)
	}
	// A settled receive waits for its actual native consumer; idle controller
	// ticks must not repeatedly read/hash/sync a potentially large archive.
	a.backupArtifacts.syncFile = func(*os.File) error { return errors.New("idle receive attempted file I/O") }
	if e = a.reconcileVolumeMoveTargets(ctx, read()); e != nil {
		t.Fatal("settled receiver did not wait for native consumer", e)
	}
	a.backupArtifacts.syncFile = (*os.File).Sync

	// Attach the existing native/restore adapters on the installed target.
	// The full target daemon/workload/SQL path is a later consumer boundary.
	targetDocker, e := engine.Open(ctx, "unix:///var/run/docker.sock", a.owner)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = targetDocker.Close() })
	a.docker = targetDocker
	targetRaw, _ := json.Marshal(job.Target)
	targetID, e := targetDocker.Identity("volume", volumes.NativeKey(job.Target), reconcile.Resource{Present: true, Generation: 1, Spec: string(targetRaw)})
	if e != nil {
		t.Fatal(e)
	}
	targetFilter := client.Filters{}.Add("label", "org.sfc.owner="+targetDocker.Owner)
	prior, e := targetDocker.API.VolumeList(ctx, client.VolumeListOptions{Filters: targetFilter})
	if e != nil || len(prior.Items) != 0 {
		t.Fatal("target native prestate", e)
	}
	t.Log("nativeOwner=" + targetDocker.Owner)
	t.Cleanup(func() {
		clean, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		all, e := targetDocker.API.VolumeList(clean, client.VolumeListOptions{Filters: targetFilter})
		if e != nil {
			t.Error(e)
			return
		}
		for _, v := range all.Items {
			if !targetID.Matches(v.Name, v.Labels) {
				t.Error("target rollback identity mismatch")
				continue
			}
			if !t.Failed() {
				t.Error("target native not retired by product")
			}
			if _, e = targetDocker.API.VolumeRemove(clean, v.Name, client.VolumeRemoveOptions{}); e != nil {
				t.Error(e)
			}
		}
		left, e := targetDocker.API.VolumeList(clean, client.VolumeListOptions{Filters: targetFilter})
		if e != nil || len(left.Items) != 0 {
			t.Error("target rollback remains", e)
		}
	})
	targetNativePath := filepath.Join(root, "move-target-native.db")
	targetRestorePath := filepath.Join(root, "move-target-restores.db")
	a.nativeVolumes, e = volumes.OpenNative(targetNativePath, targetDocker)
	if e != nil {
		t.Fatal(e)
	}
	a.volumeRestores, e = reconcile.OpenJournal(targetRestorePath)
	if e != nil {
		t.Fatal(e)
	}
	restoreKey := moveRestoreKey(receiveIntent)
	restoreRaw, _ := json.Marshal(receiveIntent)
	restoreResource := reconcile.Resource{Present: true, Generation: 1, Spec: string(restoreRaw)}
	if e = a.volumeRestores.Desired(restoreKey, reconcile.Desired{Revision: 1, Resource: restoreResource}, 1); e != nil {
		t.Fatal(e)
	}
	lostRestore := errors.New("original native restore completion not observed")
	if e = a.volumeRestores.Step(ctx, restoreKey, lostMoveRestoreCompletion{inner: volumeMoveRestoreDriver{a}, lost: lostRestore}); !errors.Is(e, lostRestore) {
		t.Fatal("missing actual native completion loss", e)
	}
	restoreRow, e := a.volumeRestores.Read(restoreKey)
	if e != nil || restoreRow.State.Pending == nil || restoreRow.State.LastID != 1 {
		t.Fatal("original restore Unknown lost", e)
	}
	targetReady, e := a.moveRestoreTarget(ctx, receiveIntent)
	if e != nil {
		t.Fatal(e)
	}
	nativeRow, e := a.nativeVolumes.View(volumes.NativeKey(job.Target))
	if e != nil || nativeRow.State.LastID != 1 || nativeRow.State.Pending != nil {
		t.Fatal("original target native create", e)
	}
	mounted, e := targetDocker.API.VolumeInspect(ctx, targetReady.Owner.Native, client.VolumeInspectOptions{})
	if e != nil {
		t.Fatal(e)
	}
	nativeRootBefore, e := os.Stat(mounted.Volume.Mountpoint)
	if e != nil {
		t.Fatal(e)
	}
	if e = a.volumeRestores.Close(); e != nil {
		t.Fatal(e)
	}
	if e = a.nativeVolumes.Close(); e != nil {
		t.Fatal(e)
	}
	if e = a.backupArtifacts.Close(); e != nil {
		t.Fatal(e)
	}
	a.backupArtifacts = openReceiver()
	a.nativeVolumes, e = volumes.OpenNative(targetNativePath, targetDocker)
	if e != nil {
		t.Fatal(e)
	}
	a.volumeRestores, e = reconcile.OpenJournal(targetRestorePath)
	if e != nil {
		t.Fatal(e)
	}
	if e = a.validateRestoreJournal(); e != nil {
		t.Fatal("same restore DB validation", e)
	}
	if e = a.reconcileVolumeMoveTargets(ctx, read()); e != nil {
		t.Fatal("original target restore recovery", e)
	}
	_, verified, ok := registry().Move(job.Selection())
	if !ok || verified.Phase != volumes.Verified || verified.Verified == nil {
		t.Fatal("actual target CopyProof not committed")
	}
	current, _ := registry().Volume(job.Binding.Scope)
	currentOwner, _ := current.Owner()
	if currentOwner != job.Binding.Source || current.CheckActivation(job.StagingConsumer()) == nil {
		t.Fatal("inactive restore changed writable owner")
	}
	restoreRow, e = a.volumeRestores.Read(restoreKey)
	if e != nil || restoreRow.State.Pending != nil || restoreRow.State.LastID != 1 || !restoreRow.State.Applied.Present {
		t.Fatal("restore recovery replaced original A2", e)
	}
	recoveredReady, e := a.moveRestoreTarget(ctx, receiveIntent)
	if e != nil || control.VolumeNativeDigest(recoveredReady) != control.VolumeNativeDigest(targetReady) {
		t.Fatal("target native identity changed", e)
	}
	nativeRootAfter, e := os.Stat(mounted.Volume.Mountpoint)
	if e != nil || !os.SameFile(nativeRootBefore, nativeRootAfter) {
		t.Fatal("target root changed across recovery", e)
	}
	receiveRow, e = a.backupArtifacts.journal.Read(receiveKey)
	if e != nil || len(receiveRow.Consumers) != 0 {
		t.Fatal("target artifact native consumer not returned", e)
	}
	for {
		row, err = (*owner).backupArtifacts.journal.Read(artifactKey)
		if err != nil {
			t.Fatal(err)
		}
		if len(row.Consumers) == 0 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("source stream exact local reference return", ctx.Err())
		case <-ticker.C:
		}
	}
	if commitOwner {
		for {
			core, _ = registry().Volume(job.Binding.Scope)
			if len(core.Consumers()) == 0 {
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal("Verified source reader settlement", ctx.Err())
			case <-ticker.C:
			}
		}
		commitResult := verifyMoveOwnerCommitUnobservedReply(t, ctx, root, admin, authority, session, job, core.Revision(), recoveredReady)
		core, _ = registry().Volume(job.Binding.Scope)
		newOwner, newRevision := core.Owner()
		_, committed, _ := registry().Move(job.Selection())
		registered, ok := registry().Native(job.Binding.Scope.Tenant, job.Binding.Scope.App, job.Binding.Scope.ID)
		if !ok || newOwner != job.Binding.Target || newRevision != committed.CommitRevision || committed.Phase != volumes.OwnerCommitted || committed.Irreversible || control.VolumeNativeDigest(registered) != control.VolumeNativeDigest(recoveredReady) || core.CheckActivation(job.StagingConsumer()) == nil {
			t.Fatal("authenticated owner/native commit mismatch or premature writer authority")
		}
		if err = a.Engine().Snapshot(ctx); err != nil {
			t.Fatal(err)
		}
		for {
			view, e := (*owner).Engine().Read(ctx, false)
			if e == nil {
				v, e := p.Volumes(view.State)
				if e == nil {
					c, ok := v.Volume(job.Binding.Scope)
					o, _ := c.Owner()
					if ok && o == job.Binding.Target {
						break
					}
				}
			}
			select {
			case <-ctx.Done():
				t.Fatal("source durable committed owner replica", ctx.Err())
			case <-ticker.C:
			}
		}
		if err = (*owner).Close(); err != nil {
			t.Fatal(err)
		}
		*owner, err = Open(cfg)
		if err != nil {
			t.Fatal(err)
		}
		view, e := (*owner).Engine().Read(ctx, false)
		if e != nil {
			t.Fatal(e)
		}
		v, e := p.Volumes(view.State)
		if e != nil {
			t.Fatal(e)
		}
		persisted, ok := v.Volume(job.Binding.Scope)
		persistedOwner, persistedRevision := persisted.Owner()
		persistedNative, found := v.Native(job.Binding.Scope.Tenant, job.Binding.Scope.App, job.Binding.Scope.ID)
		if !ok || !found || persistedOwner != job.Binding.Target || persistedRevision != newRevision || control.VolumeNativeDigest(persistedNative) != control.VolumeNativeDigest(recoveredReady) {
			t.Fatal("same source DB lost committed owner/native")
		}
		originalCold, e := (*owner).activations.ColdSource(ctx, ready)
		if e != nil {
			t.Fatal(e)
		}
		originalGate, e := (*owner).activations.Checkpoint(originalCold.Writer)
		if e != nil || originalGate.FenceThrough != job.Binding.SourceOwnerRevision {
			t.Fatal("source local fence lost after committed owner", e)
		}
		commitResult()
		// Test teardown of the temporary committed cluster is explicit owned
		// rollback, not a product cancel/delete/whole-move success claim.
		cleanupMoveSourceFixture(t, ctx, owner, cfg, ready, docker)
		if err = a.Close(); err != nil {
			t.Fatal(err)
		}
		ownedTarget, e := engine.Open(ctx, "unix:///var/run/docker.sock", targetDocker.Owner)
		if e != nil {
			t.Fatal(e)
		}
		defer ownedTarget.Close()
		ownedNative, e := volumes.OpenNative(targetNativePath, ownedTarget)
		if e != nil {
			t.Fatal(e)
		}
		defer ownedNative.Close()
		key := volumes.NativeKey(job.Target)
		if e = ownedNative.DeleteDesired(key, 2, 1); e != nil {
			t.Fatal(e)
		}
		if e = ownedNative.Step(ctx, key); e != nil {
			t.Fatal(e)
		}
		if gone, e := ownedNative.Gone(ctx, key, 2, 1); e != nil || !gone {
			t.Fatal("owned committed target teardown", e)
		}
		t.Log("actual native source/fence/transfer/receiver/target restore -> target signed CopyProof Verified -> actual source reader closure -> durable authenticated user owner command/reply deliberately unconsumed/Unknown -> fresh login and original Result/Resume -> atomic owner/native/capacity -> same source DB committed owner/native/original result and retained local fence; no Arm/writable/SQL/full app or packet-loss claim; exact owned cluster teardown")
		return
	}
	core, _ = registry().Volume(ready.Spec.Scope)
	applyCLI("native-move-cancel", "cancel-volume-move", core.Revision(), job.Selection())
	for {
		core, _ = registry().Volume(ready.Spec.Scope)
		if len(core.Consumers()) == 0 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("automatic artifact cleanup/reader Gone", ctx.Err(), (*owner).volumeBackupError)
		case <-ticker.C:
		}
	}
	for {
		if err = a.reconcileVolumeMoveTargets(ctx, read()); err != nil && !errors.Is(err, reconcile.ErrPending) {
			t.Fatal("target original cleanup", err)
		}
		_, cancelled, ok := registry().Move(job.Selection())
		if ok && cancelled.Phase == volumes.Cancelled {
			if cancelled.SourceCleanup == nil || cancelled.SourceCleanup.Unchanged || cancelled.CancelledTarget == nil || cancelled.ReaderClosed == nil || cancelled.Fence == nil {
				t.Fatal("fenced cancellation lost original worker/reader/fence evidence")
			}
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("both original cancellation facts", ctx.Err(), (*owner).volumeBackupError)
		case <-ticker.C:
		}
	}
	if _, err = a.backupArtifacts.root.Lstat(moveReceiveName(receiveIntent)); !os.IsNotExist(err) {
		t.Fatal("target receiving files not removed", err)
	}
	if !registry().Quiescent() {
		t.Fatal("both cancellation facts did not settle shared move reservations")
	}
	if _, err = (*owner).backupArtifacts.root.Lstat(moveArtifactName(intent)); !os.IsNotExist(err) {
		t.Fatal("source artifact directory not removed", err)
	}
	cli("manage", "result", "--request-id", "native-move")
	cleanupMoveSourceFixture(t, ctx, owner, cfg, ready, docker)
	t.Log("actual CLI/Raft/normal source native fence+A2 artifact/Manifest -> same source DB/key -> target current quorum and authenticated SFCP -> real receiver file sync failure/no offset ACK -> same receiver DB/A2/inode resume/full archive verification/durable completion -> original CLI cancel/source reader+both artifact stores cleanup; actual native target restore/completion loss/same DB and native ID recovery/CopyProof Verified/source reader return -> real target native Remove, both signed cancellation facts/Cancelled and shared transfer reservation return; source fence retained/new owner revision, no source app restart/owner CAS/writable target/SQL claim")
}

// The wrapper loses only the completion observation AFTER the actual product
// Execute/Verify closed every native FD and returned the original artifact pin.
// It does not synthesize native facts, modify a journal row or reset an ID.
type lostMoveRestoreCompletion struct {
	inner volumeMoveRestoreDriver
	lost  error
}

func (d lostMoveRestoreCompletion) Execute(ctx context.Context, key string, op reconcile.Operation) (reconcile.Outcome, error) {
	out, err := d.inner.Execute(ctx, key, op)
	if err == nil && out == reconcile.EffectApplied {
		return reconcile.EffectUnknown, d.lost
	}
	return out, err
}
func (d lostMoveRestoreCompletion) Recover(ctx context.Context, key string, op reconcile.Operation) (reconcile.Outcome, error) {
	return d.inner.Recover(ctx, key, op)
}

func cleanupMoveSourceFixture(t *testing.T, ctx context.Context, owner **Runtime, cfg config.Node, ready volumes.NativeReady, docker *engine.Client) {
	t.Helper()
	if err := (*owner).Close(); err != nil {
		t.Fatal(err)
	}
	*owner = nil
	native, err := volumes.OpenNative(filepath.Join(cfg.Node.StateDir, "workload", "volumes.db"), docker)
	if err != nil {
		t.Fatal(err)
	}
	defer native.Close()
	key := volumes.NativeKey(ready.Spec)
	if err = native.DeleteDesired(key, 2, ready.Generation); err != nil {
		t.Fatal(err)
	}
	if err = native.Step(ctx, key); err != nil {
		t.Fatal(err)
	}
	if gone, err := native.Gone(ctx, key, 2, ready.Generation); err != nil || !gone {
		t.Fatal("owned native fixture cleanup", err)
	}
}
