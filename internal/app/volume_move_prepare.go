// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

func (r *Runtime) prepareMoveTarget(ctx context.Context, job control.VolumeMove) (failure error) {
	stage := "managers"
	defer func() {
		if failure != nil && (r.ctx == nil || r.ctx.Err() == nil) {
			// Keep the first pre-expiry stage in the owner's journal. A later
			// expired permit must not overwrite the only failure observation.
			// Do not log provider errors or private input material here.
			reason := ""
			if stage == "prepare-authorization" {
				// Permit replies carry no reason; replay the checks locally
				// so a refusal repeating every pass names its condition.
				if v, err := r.Engine().Read(context.Background(), false); err == nil {
					reason = r.controlPolicy.ExplainVolumeMovePrepare(v.State, r.Identity.Public, job.Selection(), time.Now().Unix())
				}
			}
			if reason != "" {
				log.Printf("volume move target preparation failed: move=%q stage=%s reason=%s", job.Binding.ID, stage, reason)
			} else {
				log.Printf("volume move target preparation failed: move=%q stage=%s", job.Binding.ID, stage)
			}
		}
	}()
	r.volumeMoveTargetMu.Lock()
	defer r.volumeMoveTargetMu.Unlock()
	if r.nativeVolumes == nil || r.backupArtifacts == nil || r.volumeRestores == nil {
		return fmt.Errorf("target runtime managers unavailable: %w", sfcp.ErrAdmission)
	}
	stage = "prepare-authorization"
	permit, err := r.volumeMovePermit(ctx, job, "prepare")
	if err != nil {
		return fmt.Errorf("prepare authorization: %w", err)
	}
	if permit.Move.Preparation != nil {
		stage = "existing-input-authorization"
		if job.App == nil || job.App.Target == nil {
			return nil
		}
		current, err := r.volumeMoveInputPermit(ctx, job.Selection())
		if err != nil {
			return err
		}
		now := time.Now().Unix()
		if current.Job.Digest() == job.Digest() && current.Inputs != nil && permit.Move.Preparation.Inputs != nil && *permit.Move.Preparation.Inputs == current.Inputs.ReadSet && permit.Move.Preparation.InputsAt > 0 && permit.Move.Preparation.InputsAt <= now && now-permit.Move.Preparation.InputsAt <= 30 {
			return nil
		}
	}
	stage = "native-desired"
	if _, err = r.nativeVolumes.Desired(job.Target, 1, 1, 1); err != nil {
		return fmt.Errorf("native desired: %w", err)
	}
	stage = "native-materialization"
	if err = r.nativeVolumes.Step(ctx, volumes.NativeKey(job.Target)); err != nil {
		return fmt.Errorf("native materialization: %w", err)
	}
	stage = "native-readiness"
	ready, err := r.moveRestoreTarget(ctx, moveReceiveIntent{Schema: 1, Job: job})
	if err != nil {
		return fmt.Errorf("native readiness: %w", err)
	}
	check := func(ctx context.Context, got volumes.NativeReady, c volumes.Consumer) error {
		if got.Spec != job.Target || got.Owner != job.Binding.Target || got.Generation != 1 || c != job.StagingConsumer() {
			return sfcp.ErrAdmission
		}
		_, err := r.volumeMovePermit(ctx, job, "prepare")
		return err
	}
	stage = "empty-target"
	if err = r.nativeVolumes.PrepareRestoreCold(ctx, ready, job.StagingConsumer(), check, job.Options()); err != nil {
		return fmt.Errorf("empty target preparation: %w", err)
	}
	var inputs *[32]byte
	var inputsAt int64
	if job.App != nil && job.App.Target != nil {
		stage = "inputs"
		digest, observedAt, err := r.prepareVolumeMoveInputs(ctx, job)
		if err != nil {
			return fmt.Errorf("target input preparation: %w", err)
		}
		inputs = &digest
		inputsAt = observedAt
	}
	stage = "final-authorization"
	permit, err = r.volumeMovePermit(ctx, job, "prepare")
	if err != nil {
		return err
	}
	prepared := volumes.TargetPreparation{Binding: job.Binding, Target: ready, Empty: true, NoWriters: true, SpaceChecked: true, ProtocolReady: true, Inputs: inputs, InputsAt: inputsAt}
	prepared.Signature = ed25519.Sign(r.Identity.Private, volumes.TargetPreparationBytes(prepared))
	stage = "prepared-report"
	return r.commitVolumeMoveReport(ctx, control.VolumeMoveReport{Operation: "move", Schema: 1, Selection: job.Selection(), Binding: job.Digest(), Epoch: permit.Epoch, RootRevision: permit.RootRevision, Revision: permit.Revision, At: time.Now().Unix(), Kind: "prepared", Preparation: &prepared})
}
