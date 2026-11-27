// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/storage"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// The source reconciler has already joined/returned any original archive
// reader. The plan is a current quorum view, never permission to restart it.
func (r *Runtime) cancelMoveSource(ctx context.Context, plan control.VolumeMovePermit) (failure error) {
	job := plan.Job
	stage := "managers"
	defer func() { r.logMoveCancel(job, "source", stage, failure) }()
	if r.activations == nil || r.backupArtifacts == nil || plan.Move.Phase != volumes.Cancelling || plan.Reader != nil {
		return sfcp.ErrAdmission
	}
	if plan.Move.SourceCleanup != nil {
		return nil
	}
	if plan.SourceUnchanged {
		stage = "unchanged-local-fence"
		unfenced, err := r.activations.SourceUnfenced(ctx, job.Source, job.Binding)
		if err != nil {
			return err
		}
		if unfenced {
			stage = "unchanged-source-idle"
			if err = r.backupArtifacts.moveSourceIdle(ctx, job); err != nil {
				return err
			}
			stage = "unchanged-permit"
			latest, err := r.volumeMovePermit(ctx, job, "cancel-source")
			if err != nil || !latest.SourceUnchanged {
				return errors.Join(sfcp.ErrAdmission, err)
			}
			return r.reportMoveCleanup(ctx, latest, "cancel-source", volumes.CleanupProof{Binding: job.Binding, Owner: job.Binding.Source, TransferClosed: true, Unchanged: true})
		}
		// A positive local fence may precede its lost shared report. Recover
		// that original fact; do not treat a missing shared Fence as untouched.
	}
	if plan.Move.Fence == nil {
		stage = "app-quiescence"
		view, err := r.Engine().Read(ctx, false)
		if err != nil {
			return err
		}
		if job.App != nil {
			status, err := r.controlPolicy.MoveAppQuiescence(view.State, job)
			if err != nil {
				return err
			}
			if status != "ready" {
				stage = "app-quiescence-" + status
				return nil // original retirement/Unknown must finish in its owner
			}
		}
		registry, err := r.controlPolicy.Volumes(view.State)
		if err != nil {
			return err
		}
		core, ok := registry.Volume(job.Binding.Scope)
		if !ok || len(core.Consumers()) != 0 {
			return nil
		}
		stage = "fence-permit"
		permit, err := r.volumeMovePermit(ctx, job, "cancel-fence")
		if err != nil {
			return err
		}
		stage = "fence"
		proof, err := r.activations.FenceStoppedSource(ctx, job.Source, job.Binding, func(ctx context.Context, b volumes.Binding) error {
			if b != job.Binding {
				return sfcp.ErrAdmission
			}
			_, err := r.volumeMovePermit(ctx, job, "cancel-fence")
			return err
		}, r.Identity.Private)
		if err != nil {
			return err
		}
		stage = "fence-publish"
		return r.publishVolumeMoveSource(ctx, permit, "fenced", &proof)
	}
	stage = "fenced-permit"
	permit, err := r.volumeMovePermit(ctx, job, "cancel-source")
	if err != nil || permit.SourceUnchanged {
		return errors.Join(sfcp.ErrAdmission, err)
	}
	stage = "fenced-source-idle"
	if permit.Move.ReaderClosed != nil {
		err = r.backupArtifacts.moveSourceClosed(ctx, moveArtifactIntent{Schema: 1, Job: job, Reader: permit.Move.ReaderClosed.Consumer})
	} else {
		// cancel-source denies this branch if a shared reader was EVER
		// acquired, including a legacy release with a missing signed receipt.
		err = r.backupArtifacts.moveSourceIdle(ctx, job)
	}
	if err != nil {
		return err
	}
	stage = "fenced-checkpoint"
	cold, err := r.activations.StoppedSource(ctx, job.Source)
	if err != nil {
		return err
	}
	gate, err := r.activations.Checkpoint(cold.Writer)
	if err != nil || gate.Starting != nil || gate.FenceThrough < job.Binding.SourceOwnerRevision {
		return errors.Join(sfcp.ErrAdmission, err)
	}
	latest, err := r.volumeMovePermit(ctx, job, "cancel-source")
	if err != nil || latest.SourceUnchanged {
		return errors.Join(sfcp.ErrAdmission, err)
	}
	return r.reportMoveCleanup(ctx, latest, "cancel-source", volumes.CleanupProof{Binding: job.Binding, Owner: job.Binding.Source, TransferClosed: true, RetainedFenced: true})
}

func (r *Runtime) cancelMoveTarget(ctx context.Context, job control.VolumeMove) (failure error) {
	stage := "managers"
	defer func() { r.logMoveCancel(job, "target", stage, failure) }()
	r.volumeMoveTargetMu.Lock()
	defer r.volumeMoveTargetMu.Unlock()
	if r.nativeVolumes == nil || r.volumeRestores == nil || r.backupArtifacts == nil {
		return sfcp.ErrAdmission
	}
	stage = "permit"
	permit, err := r.volumeMovePermit(ctx, job, "cancel-target")
	if err != nil {
		return err
	}
	stage = "restore-journal"
	b := moveReceiveIntent{Schema: 1, Job: job}
	if permit.Move.Manifest != nil {
		b.Manifest = *permit.Move.Manifest
	}
	row, err := r.volumeRestores.Read(moveRestoreKey(b))
	if err != nil && !errors.Is(err, storage.ErrMissing) {
		return err
	}
	if err == nil {
		if permit.Move.Manifest == nil {
			return sfcp.ErrAdmission // no transfer could have admitted this intent
		}
		if err = r.stepMoveRestoreLocked(ctx, b, true); err != nil {
			return err
		}
		row, err = r.volumeRestores.Read(moveRestoreKey(b))
		if err != nil || row.State.Pending != nil || row.State.Applied.Present || row.State.Desired.Present || len(row.Consumers) != 0 {
			return errors.Join(reconcile.ErrPending, err)
		}
	} else {
		stage = "prepared-target"
		err = r.cancelMoveRestore(ctx, b)
	}
	if err != nil {
		// Includes prepared-but-not-received native targets. No fabricated
		// restore Apply or placeholder Manifest is submitted for cancellation.
		return err
	}
	stage = "receiver-idle"
	if permit.Move.Manifest != nil {
		err = r.backupArtifacts.cancelReceivedMove(ctx, b, runtimeMoveReceiver{r})
	} else {
		err = r.backupArtifacts.moveTargetIdle(ctx, job)
	}
	if err != nil {
		return err
	}
	stage = "report"
	latest, err := r.volumeMovePermit(ctx, job, "cancel-target")
	if err != nil {
		return err
	}
	proof := volumes.CancelProof{Binding: job.Binding, StagingGone: true, StartsSettled: true, MountsGone: true, TransferClosed: true}
	proof.Signature = ed25519.Sign(r.Identity.Private, volumes.CancelBytes(proof))
	return r.commitVolumeMoveReport(ctx, control.VolumeMoveReport{Operation: "move", Schema: 1, Selection: job.Selection(), Binding: job.Digest(), Epoch: latest.Epoch, RootRevision: latest.RootRevision, Revision: latest.Revision, At: time.Now().Unix(), Kind: "cancel-target", CancelledTarget: &proof})
}

// logMoveCancel names the step a stuck cancellation waits on. Reconcile
// errors are otherwise kept only in the node's observation, so a move could
// stay Cancelling with no log line on either server (KVM). Only the stage
// and a symbolic error class are logged, never provider errors or inputs.
func (r *Runtime) logMoveCancel(job control.VolumeMove, side, stage string, err error) {
	if r.ctx != nil && r.ctx.Err() != nil {
		return
	}
	key := job.Binding.ID + "/" + side
	if err == nil && !strings.HasPrefix(stage, "app-quiescence-") {
		// This pass did not wait: forget the last line, so the map stays
		// bounded and a later stall on the same stage logs again.
		r.moveCancelLog.Delete(key)
		return
	}
	class := "waiting"
	switch {
	case err == nil:
	case errors.Is(err, sfcp.ErrAdmission):
		class = "admission"
	case errors.Is(err, access.ErrDenied):
		class = "denied"
	case errors.Is(err, volumes.ErrActivation):
		class = "activation"
		if reason := volumes.ActivationReason(err); reason != "" {
			class += "-" + reason
		}
	case errors.Is(err, reconcile.ErrPending):
		class = "pending"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		class = "timeout"
	default:
		class = "error"
	}
	// A stuck cancel retries every pass; say it once per stage and class.
	line := fmt.Sprintf("volume move cancel waiting: move=%q side=%s stage=%s class=%s", job.Binding.ID, side, stage, class)
	if previous, ok := r.moveCancelLog.Swap(key, line); ok && previous == line {
		return
	}
	log.Print(line)
}
