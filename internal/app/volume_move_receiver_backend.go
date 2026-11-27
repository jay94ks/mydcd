// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

type runtimeMoveReceiver struct{ r *Runtime }

func (d runtimeMoveReceiver) Authorize(ctx context.Context, b moveReceiveIntent, cleanup bool) error {
	kind := "receive"
	if cleanup {
		kind = "receive-cleanup"
	}
	p, err := d.r.volumeMovePermit(ctx, b.Job, kind)
	if err != nil {
		return err
	}
	if !cleanup && (p.Move.Manifest == nil || p.Move.Manifest.ArchiveReceipt() != b.Manifest.ArchiveReceipt() || p.Move.Manifest.Binding != b.Manifest.Binding) {
		return sfcp.ErrAdmission
	}
	return nil
}
func (d runtimeMoveReceiver) Transfer(ctx context.Context, b moveReceiveIntent, offset uint64, prefix [32]byte, sink sfcp.VolumeSink) error {
	if err := d.Authorize(ctx, b, false); err != nil {
		return err
	}
	peer, ok := d.r.resourcePeer(ctx, b.Job.Binding.Source.Node, b.Job.Binding.Source.Key)
	if !ok || !peer.Member {
		return sfcp.ErrAdmission
	}
	session, err := d.r.Mesh.Dial(ctx, peer)
	if err != nil {
		return err
	}
	return session.PullVolume(ctx, sfcp.VolumeTransferRequest{Schema: 1, Metadata: moveTransferMetadata(b.Job), Artifact: b.Manifest.Artifact, Bytes: b.Manifest.Bytes, Offset: offset, Prefix: prefix, ExpiresAt: b.Job.ExpiresAt}, sink)
}

// Receiver files are local progress of the original shared move. Receiving an
// archive is not a CopyProof: native inactive restore/verification must follow.
func (r *Runtime) reconcileVolumeMoveTargets(ctx context.Context, view cluster.View) error {
	if r.backupArtifacts == nil {
		return nil
	}
	registry, err := r.controlPolicy.Volumes(view.State)
	if err != nil {
		return err
	}
	return r.reconcileVolumeMoveTargetsInView(ctx, view, registry)
}

func (r *Runtime) reconcileVolumeMoveTargetsInView(ctx context.Context, view cluster.View, registry control.Volumes) error {
	if r.backupArtifacts == nil {
		return nil
	}
	var failed error
	for _, job := range registry.Moves() {
		if job.Binding.Target.Key != r.Identity.Public {
			continue
		}
		_, move, ok := registry.Move(job.Selection())
		if ok && (move.Phase == volumes.Verified || move.Phase == volumes.OwnerCommitted) && job.App != nil && job.App.Target != nil && r.workload != nil && r.network != nil {
			if r.reportHeld(job.Binding.ID, time.Now()) {
				continue
			}
			permit, e := r.volumeMovePermit(ctx, job, "activate-app")
			stage, reason := "permit", ""
			if e == nil {
				stage = "report"
				report := control.VolumeMoveReport{Operation: "move", Schema: 1, Selection: job.Selection(), Binding: job.Digest(), Epoch: permit.Epoch, RootRevision: permit.RootRevision, Revision: permit.Revision, At: time.Now().Unix(), Kind: "activate-app"}
				if e = r.commitVolumeMoveReport(ctx, report); e != nil {
					reason = r.explainMoveReport(view.State, report)
				}
			}
			if e != nil && reason == "" {
				// Neither a permit reply nor a rejected report carries a
				// reason; replay the checks and the reducer locally.
				if reason = r.controlPolicy.ExplainVolumeMoveActivate(view.State, r.Identity.Public, job.Selection(), time.Now().Unix()); reason == "" {
					reason = "UNEXPLAINED" // passes on this view: a race or a transport error
				}
			}
			r.logMoveActivate(job, stage, reason, e)
			r.holdReport(job.Binding.ID, e, time.Now())
			failed = errors.Join(failed, e)
			continue
		}
		if ok && move.Phase == volumes.Activating && job.App != nil && job.App.Target != nil {
			apps, e := r.controlPolicy.ReadApps(view.State)
			if e != nil {
				failed = errors.Join(failed, e)
				continue
			}
			execution, found := apps.Execution(job.Binding.Scope.Tenant, job.Binding.Scope.App)
			if !found || execution.ActiveOperation() != job.App.Target.Operation || execution.Status() != "Succeeded" {
				continue
			}
			failed = errors.Join(failed, r.reportMoveActive(ctx, job))
			continue
		}
		if ok && move.Phase == volumes.Active {
			if move.TargetCleanup == nil {
				failed = errors.Join(failed, r.finishMoveTarget(ctx, job))
			}
			continue
		}
		if ok && move.Phase == volumes.Prepared {
			if !move.Irreversible && time.Now().Unix() >= job.ExpiresAt {
				// The plan ended before the copy began; no permit can pass
				// until a user cancels it, so do not retry every pass.
				continue
			}
			if err := r.prepareMoveTarget(ctx, job); err != nil {
				failed = errors.Join(failed, fmt.Errorf("volume move %s target prepare: %w", job.Binding.ID, err))
			}
			continue
		}
		if ok && move.Phase == volumes.Cancelling && r.nativeVolumes != nil && r.volumeRestores != nil {
			if move.CancelledTarget == nil {
				failed = errors.Join(failed, r.cancelMoveTarget(ctx, job))
			}
			continue
		}
		if !ok || move.Manifest == nil || move.Phase != volumes.Copying && move.Phase != volumes.Cancelling {
			continue
		}
		b := moveReceiveIntent{Schema: 1, Job: job, Manifest: *move.Manifest}
		native := r.nativeVolumes != nil && r.volumeRestores != nil
		if move.Phase == volumes.Cancelling && native {
			if e := r.stepMoveRestore(ctx, b, true); e != nil {
				failed = errors.Join(failed, e)
				continue
			}
		}
		if move.Phase == volumes.Copying {
			row, e := r.backupArtifacts.journal.Read(moveReceiveKey(b))
			if e == nil && row.State.Pending == nil && row.State.Applied.Present {
				original, e := r.backupArtifacts.receiveBinding(moveReceiveKey(b), row.State.Applied)
				if e != nil || original.digest() != b.digest() {
					failed = errors.Join(failed, errBackupArtifact)
					continue
				}
				// Already received. The next native consumer must verify/open
				// this exact file under its A3 pin; do not hash a large archive
				// again on every idle tick. Only the actual native consumer can
				// publish a CopyProof after verifying the restored target.
				if native {
					failed = errors.Join(failed, r.stepMoveRestore(ctx, b, false))
				}
				continue
			}
		}
		_, err := r.backupArtifacts.StepReceive(ctx, b, runtimeMoveReceiver{r}, move.Phase == volumes.Cancelling)
		if err == nil && native && move.Phase == volumes.Copying {
			err = r.stepMoveRestore(ctx, b, false)
		}
		failed = errors.Join(failed, err)
		if ctx.Err() != nil {
			break
		}
	}
	return failed
}

// logMoveActivate says once per change why a Verified move's target cannot
// start the app. Only fixed codes are logged, never the error text.
func (r *Runtime) logMoveActivate(job control.VolumeMove, stage, reason string, err error) {
	key := job.Binding.ID + "/activate"
	if err == nil || r.ctx != nil && r.ctx.Err() != nil {
		r.moveCancelLog.Delete(key)
		return
	}
	line := fmt.Sprintf("volume move activate waiting: move=%q stage=%s class=%s reason=%s", job.Binding.ID, stage, moveErrorClass(err), reason)
	if previous, ok := r.moveCancelLog.Swap(key, line); ok && previous == line {
		return
	}
	log.Print(line)
}

// moveReportBackoff spaces out a report stream (a move's activate report,
// one app's progress action) that the FSM rejected. Each rejected report is
// still a Raft entry and a ledger receipt, so a node must not resend one on
// every pass. Only an applied report ends the hold.
type moveReportBackoff struct {
	until time.Time
	delay time.Duration
}

const (
	moveReportHoldMin = 5 * time.Second
	moveReportHoldMax = 2 * time.Minute
)

func (r *Runtime) reportHeld(id string, now time.Time) bool {
	v, ok := r.reportHold.Load(id)
	return ok && now.Before(v.(moveReportBackoff).until)
}

func (r *Runtime) holdReport(id string, err error, now time.Time) {
	var rejected moveReportRejected
	if err == nil {
		r.reportHold.Delete(id)
		return
	}
	if !errors.As(err, &rejected) {
		return // a permit or transport failure neither holds nor resets
	}
	delay := moveReportHoldMin
	if v, ok := r.reportHold.Load(id); ok {
		delay = min(2*v.(moveReportBackoff).delay, moveReportHoldMax)
	}
	r.reportHold.Store(id, moveReportBackoff{until: now.Add(delay), delay: delay})
}
