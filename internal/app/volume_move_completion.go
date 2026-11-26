// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/workload"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

func (r *Runtime) reportMoveActive(ctx context.Context, job control.VolumeMove) error {
	if r.activations == nil || r.nativeVolumes == nil {
		return mydcp.ErrAdmission
	}
	permit, err := r.volumeMovePermit(ctx, job, "active")
	if err != nil || permit.ActiveIdle == (permit.ActiveTask != nil) {
		return errors.Join(mydcp.ErrAdmission, err)
	}
	sameCandidate := func(other control.VolumeMovePermit) bool {
		if other.ActiveIdle != permit.ActiveIdle {
			return false
		}
		if permit.ActiveIdle {
			return other.ActiveTask == nil
		}
		return other.ActiveTask != nil && *other.ActiveTask == *permit.ActiveTask
	}
	view, err := r.Engine().Read(ctx, false)
	if err != nil {
		return err
	}
	current, err := r.controlPolicy.VolumeMovePermit(view.State, r.Identity.Public, control.VolumeMovePermitRequest{Selection: job.Selection(), Kind: "active"}, time.Now().Unix())
	if err != nil || !sameCandidate(current) || view.State.Object(control.VolumesKey).Revision < permit.RootRevision {
		return mydcp.ErrAdmission
	}
	proof := volumes.ActiveProof{Binding: job.Binding, Idle: permit.ActiveIdle}
	if permit.ActiveIdle {
		ready, err := r.nativeVolumes.Ready(ctx, volumes.NativeKey(job.Target), r.Identity.Private)
		if err != nil || ready.Spec != job.Target || ready.Owner != job.Binding.Target || ready.Generation != 1 {
			return errors.Join(mydcp.ErrAdmission, err)
		}
		if err = r.activations.RetainReady(ctx, volumes.NativeKey(job.Target), job.Binding.Scope, job.Binding.Target); err != nil {
			return err
		}
		if err = r.nativeVolumes.CheckIdle(ctx, ready); err != nil {
			return err
		}
	} else {
		if r.workload == nil {
			return mydcp.ErrAdmission
		}
		candidate := *permit.ActiveTask
		material, err := r.controlPolicy.AppTaskMaterial(view.State, candidate.Task)
		if err != nil || material.Binding.Digest() != candidate.Binding {
			return mydcp.ErrAdmission
		}
		apps, err := r.controlPolicy.ReadApps(view.State)
		if err != nil {
			return err
		}
		execution, found := apps.Execution(job.Binding.Scope.Tenant, job.Binding.Scope.App)
		row, err := r.workload.View(candidate.Task.Key)
		if !found || err != nil || row.State.Pending != nil || !row.State.Applied.Present || row.State.Applied.Generation != candidate.Task.Generation || row.State.Applied != row.State.Desired.Resource {
			return reconcile.ErrPending
		}
		spec, err := workload.DecodeContainer(row.State.Applied.Spec)
		use := material.Binding.Needs().Use
		taskID, idErr := deployment.ResourceIDFromKey("task", use.Tenant, use.App, candidate.Task.Key)
		if err != nil || idErr != nil || !execution.MatchesTaskRecipe(taskID, material, spec) {
			return mydcp.ErrAdmission
		}
		matched := 0
		for _, mount := range spec.Volumes {
			if mount.Scope == job.Binding.Scope {
				if mount.Consumer != candidate.Consumer || mount.NativeKey != volumes.NativeKey(job.Target) || mount.NativeGeneration != 1 {
					return mydcp.ErrAdmission
				}
				matched++
			}
		}
		if matched != 1 {
			return mydcp.ErrAdmission
		}
		// Status checks this original native recipe, mounts, complete activation
		// batch/pins and the original immutable container ID. It never restarts it.
		status, err := r.workload.Status(ctx, candidate.Task.Key)
		if err != nil || !status.Running || status.NativeID == "" {
			return errors.Join(reconcile.ErrPending, err)
		}
		proof.Consumer, proof.Running = candidate.Consumer, true
	}
	latest, err := r.volumeMovePermit(ctx, job, "active")
	if err != nil || !sameCandidate(latest) {
		return mydcp.ErrAdmission
	}
	proof.Signature = ed25519.Sign(r.Identity.Private, volumes.ActiveBytes(proof))
	return r.commitVolumeMoveReport(ctx, control.VolumeMoveReport{Operation: "move", Schema: 1, Selection: job.Selection(), Binding: job.Digest(), Epoch: latest.Epoch, RootRevision: latest.RootRevision, Revision: latest.Revision, At: time.Now().Unix(), Kind: "active", Active: &proof})
}

func (r *Runtime) finishMoveSource(ctx context.Context, job control.VolumeMove) error {
	permit, err := r.volumeMovePermit(ctx, job, "cleanup-source")
	if err != nil {
		return err
	}
	if r.backupArtifacts == nil || r.activations == nil || permit.Move.ReaderClosed == nil {
		return mydcp.ErrAdmission
	}
	intent := moveArtifactIntent{Schema: 1, Job: job, Reader: permit.Move.ReaderClosed.Consumer}
	if err = r.backupArtifacts.moveSourceClosed(ctx, intent); err != nil {
		return err
	}
	cold, err := r.activations.ColdSource(ctx, job.Source)
	if err != nil {
		return err
	}
	gate, err := r.activations.Checkpoint(cold.Writer)
	if err != nil || gate.FenceThrough < job.Binding.SourceOwnerRevision || gate.Starting != nil {
		return mydcp.ErrAdmission
	}
	latest, err := r.volumeMovePermit(ctx, job, "cleanup-source")
	if err != nil {
		return err
	}
	return r.reportMoveCleanup(ctx, latest, "cleanup-source", volumes.CleanupProof{Binding: job.Binding, Owner: job.Binding.Source, TransferClosed: true, RetainedFenced: true})
}

func (r *Runtime) reportMoveCleanup(ctx context.Context, permit control.VolumeMovePermit, kind string, proof volumes.CleanupProof) error {
	proof.Signature = ed25519.Sign(r.Identity.Private, volumes.CleanupBytes(proof))
	return r.commitVolumeMoveReport(ctx, control.VolumeMoveReport{Operation: "move", Schema: 1, Selection: permit.Job.Selection(), Binding: permit.Job.Digest(), Epoch: permit.Epoch, RootRevision: permit.RootRevision, Revision: permit.Revision, At: time.Now().Unix(), Kind: kind, Cleanup: &proof})
}

// A completed restore's target data has already been handed to the running
// Task. Removing this transient A2 responsibility must never call cancellation,
// recopy/rehash a now-writable tree, or remove the active physical volume.
type moveRestoreReceiptDriver struct {
	r      *Runtime
	intent moveReceiveIntent
}

func (d moveRestoreReceiptDriver) Execute(ctx context.Context, key string, op reconcile.Operation) (reconcile.Outcome, error) {
	if key != moveRestoreKey(d.intent) || op.Kind != reconcile.Remove {
		return reconcile.EffectUnknown, mydcp.ErrAdmission
	}
	original, err := d.r.moveRestoreBinding(key, op.Target)
	if err != nil || original.digest() != d.intent.digest() {
		return reconcile.EffectUnknown, mydcp.ErrAdmission
	}
	if _, err = d.r.volumeMovePermit(ctx, d.intent.Job, "cleanup-target"); err != nil {
		return reconcile.EffectUnknown, err
	}
	return reconcile.EffectApplied, nil
}
func (d moveRestoreReceiptDriver) Recover(ctx context.Context, key string, op reconcile.Operation) (reconcile.Outcome, error) {
	return d.Execute(ctx, key, op)
}

// Active cleanup has its own current permission. It cannot fall back from a
// rejected cancellation permission or resume a transfer into a writable target.
type activeMoveReceiver struct{ r *Runtime }

func (d activeMoveReceiver) Authorize(ctx context.Context, b moveReceiveIntent, cleanup bool) error {
	if !cleanup {
		return mydcp.ErrAdmission
	}
	p, err := d.r.volumeMovePermit(ctx, b.Job, "cleanup-target")
	if err != nil {
		return err
	}
	if p.Move.Manifest == nil || p.Move.Manifest.Binding != b.Manifest.Binding || p.Move.Manifest.ArchiveReceipt() != b.Manifest.ArchiveReceipt() {
		return mydcp.ErrAdmission
	}
	return nil
}

func (activeMoveReceiver) Transfer(context.Context, moveReceiveIntent, uint64, [32]byte, mydcp.VolumeSink) error {
	return mydcp.ErrAdmission
}

func (r *Runtime) finishMoveTarget(ctx context.Context, job control.VolumeMove) error {
	r.volumeMoveTargetMu.Lock()
	defer r.volumeMoveTargetMu.Unlock()
	permit, err := r.volumeMovePermit(ctx, job, "cleanup-target")
	if err != nil {
		return err
	}
	if r.backupArtifacts == nil || r.volumeRestores == nil || r.nativeVolumes == nil || permit.Move.Manifest == nil || permit.Move.Preparation == nil {
		return mydcp.ErrAdmission
	}
	b := moveReceiveIntent{Schema: 1, Job: job, Manifest: *permit.Move.Manifest}
	if err = r.nativeVolumes.CheckColdReleased(permit.Move.Preparation.Target, job.StagingConsumer()); err != nil {
		return err
	}
	key := moveRestoreKey(b)
	raw, _ := json.Marshal(b)
	resource := reconcile.Resource{Present: true, Generation: 1, Spec: string(raw)}
	row, err := r.volumeRestores.Read(key)
	if err != nil {
		return err
	}
	if row.State.Pending != nil && (row.State.Pending.Kind != reconcile.Remove || row.State.Pending.Target != resource) {
		return reconcile.ErrPending
	}
	if row.State.Applied.Present && row.State.Applied != resource {
		return mydcp.ErrAdmission
	}
	if !row.State.Applied.Present && (row.State.GenerationFloor != 1 || row.State.Desired.Revision < 2 || row.State.Desired.Present || row.State.Pending != nil || row.State.LastID < 2) {
		return reconcile.ErrPending
	}
	if row.State.Applied.Present || row.State.Pending != nil {
		if err = r.volumeRestores.Desired(key, reconcile.Desired{Revision: 2, Retiring: 1}, 1); err != nil {
			return err
		}
		if err = r.volumeRestores.Step(ctx, key, moveRestoreReceiptDriver{r, b}); err != nil {
			return err
		}
	}
	row, err = r.volumeRestores.Read(key)
	if err != nil || row.State.Pending != nil || row.State.Applied.Present || row.State.Desired.Present || len(row.Consumers) != 0 {
		return errors.Join(reconcile.ErrPending, err)
	}
	if err = r.backupArtifacts.finishReceivedMove(ctx, b, activeMoveReceiver{r}); err != nil {
		return err
	}
	latest, err := r.volumeMovePermit(ctx, job, "cleanup-target")
	if err != nil {
		return err
	}
	return r.reportMoveCleanup(ctx, latest, "cleanup-target", volumes.CleanupProof{Binding: job.Binding, Owner: job.Binding.Target, TransferClosed: true})
}
