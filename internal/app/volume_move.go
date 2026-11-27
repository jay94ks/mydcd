// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

func (r *Runtime) volumeMovePermit(ctx context.Context, job control.VolumeMove, kind string) (control.VolumeMovePermit, error) {
	body, _ := json.Marshal(control.VolumeMovePermitRequest{Selection: job.Selection(), Kind: kind})
	reply, err := r.appCall(ctx, "volume-move-permit", body)
	if err != nil {
		return control.VolumeMovePermit{}, fmt.Errorf("volume move %s permit %s: %w", job.Binding.ID, kind, err)
	}
	permit, err := schema.Decode[control.VolumeMovePermit](reply.Data)
	if err != nil || reply.Local || reply.RaftIndex == 0 || permit.Job.Digest() != job.Digest() {
		return control.VolumeMovePermit{}, sfcp.ErrAdmission
	}
	return permit, nil
}

func (r *Runtime) publishVolumeMoveSource(ctx context.Context, p control.VolumeMovePermit, kind string, fence *volumes.FenceProof) error {
	report := control.VolumeMoveReport{Operation: "move", Schema: 1, Selection: p.Job.Selection(), Binding: p.Job.Digest(), Epoch: p.Epoch, RootRevision: p.RootRevision, Revision: p.Revision, At: time.Now().Unix(), Kind: kind, Fence: fence}
	return r.commitVolumeMoveReport(ctx, report)
}

func (r *Runtime) commitVolumeMoveReport(ctx context.Context, report control.VolumeMoveReport) error {
	reply, err := r.appCall(ctx, "volume-move-report", r.signedMoveReport(report))
	if err != nil {
		return err
	}
	if reply.Committed == nil || reply.Committed.Result.Code != state.Applied {
		if reply.Committed == nil {
			return reconcile.ErrPending
		}
		return moveReportRejected{report.Kind, reply.Committed.Result.Code}
	}
	return nil
}

func (r *Runtime) signedMoveReport(report control.VolumeMoveReport) []byte {
	report.Signature = ed25519.Sign(r.Identity.Private, control.VolumeMoveReportBytes(report))
	raw, _ := json.Marshal(report)
	return raw
}

// explainMoveReport replays a rejected report on the local view: the module
// step that refuses it, or a full request ledger. "" if it applies here.
func (r *Runtime) explainMoveReport(s state.State, report control.VolumeMoveReport) string {
	p := r.controlPolicy
	cmd, err := p.ResolveVolumeMoveReport(s, r.Identity.Public, r.signedMoveReport(report))
	if err != nil {
		return "REPORT_UNRESOLVED"
	}
	return r.explainModuleCommand(s, cmd)
}

// explainModuleCommand replays a rejected module command on the local view:
// the module step (and validator check) that refuses it, or a full request
// ledger. "" if it applies here. Only fixed codes, never state text.
func (r *Runtime) explainModuleCommand(s state.State, cmd state.Command) string {
	p := r.controlPolicy
	// The module step first: a full ledger takes only a report that applies,
	// so LedgerFull alone would hide why the report itself is refused.
	check := ""
	validate := func(before, after state.State, c state.Command) error {
		var err error
		check, err = p.ValidateManagedStage(before, after, c)
		return err
	}
	if stage := state.ExplainModule(s, cmd, validate, p.Reduce, p.AdmitAppPatch); stage != "" {
		if stage == "validate" && check != "" {
			stage += "_" + check
		}
		return "MODULE_" + strings.ToUpper(strings.NewReplacer("-", "_", "/", "_").Replace(stage))
	}
	if s.ReportLedgerFull(cmd.Actor, cmd.Key) {
		return "LEDGER_FULL"
	}
	return ""
}

// moveReportRejected is a volume move report the FSM did not apply. It is
// still reconcile.ErrPending; Code names the result for this server's log.
type moveReportRejected struct {
	kind string
	code state.Code
}

func (e moveReportRejected) Error() string {
	return fmt.Sprintf("volume move %s result %d: %v", e.kind, e.code, reconcile.ErrPending)
}
func (e moveReportRejected) Is(target error) bool { return target == reconcile.ErrPending }

// moveErrorClass names an error for a move log line without its text.
func moveErrorClass(err error) string {
	var rejected moveReportRejected
	switch {
	case err == nil:
		return "none"
	case errors.As(err, &rejected):
		names := map[state.Code]string{state.ConditionFailed: "condition-failed", state.Invalid: "invalid", state.RequestConflict: "request-conflict", state.Forbidden: "forbidden", state.Expired: "expired"}
		if name, ok := names[rejected.code]; ok {
			return "rejected-" + name
		}
		if reason := state.RejectionReason(rejected.code); reason != "" {
			return "rejected-" + reason
		}
		return "rejected"
	case errors.Is(err, sfcp.ErrAdmission):
		return "admission"
	case errors.Is(err, access.ErrDenied):
		return "denied"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return "timeout"
	case errors.Is(err, reconcile.ErrPending):
		return "pending"
	}
	return "error"
}

// This advances only a positively retired source. Active app writer retirement
// and transfer artifact/controller use the same accepted move; no absence or
// successful metadata request is turned into native closure.
func (r *Runtime) reconcileVolumeMoveSources(ctx context.Context, v cluster.View, registry control.Volumes) error {
	if r.activations == nil {
		return nil
	}
	var failed error
	for _, job := range registry.Moves() {
		if job.Binding.Source.Key != r.Identity.Public {
			continue
		}
		core, ok := registry.Volume(job.Binding.Scope)
		_, move, exists := registry.Move(job.Selection())
		if !ok || !exists {
			failed = errors.Join(failed, sfcp.ErrAdmission)
			continue
		}
		switch move.Phase {
		case volumes.Prepared:
			if job.App != nil {
				status, e := r.controlPolicy.MoveAppQuiescence(v.State, job)
				if e != nil {
					failed = errors.Join(failed, e)
					continue
				}
				if status != "ready" {
					if status == "pending" && move.Preparation != nil {
						permit, e := r.volumeMovePermit(ctx, job, "quiesce")
						if e == nil {
							e = r.publishVolumeMoveSource(ctx, permit, "quiesce", nil)
						}
						failed = errors.Join(failed, e)
					}
					continue
				}
			}
			if len(core.Consumers()) != 0 {
				continue
			}
			permit, e := r.volumeMovePermit(ctx, job, "fence")
			if e == nil {
				var source volumes.ColdSource
				source, e = r.activations.ColdSource(ctx, job.Source)
				if e == nil && !backupSourceMatches(source, control.VolumeBackupBinding{Scope: job.Binding.Scope, Source: job.Source, Compatibility: job.Binding.Compatibility}) {
					e = sfcp.ErrAdmission
				}
			}
			if e == nil {
				var proof volumes.FenceProof
				proof, e = r.activations.FenceSource(ctx, job.Source, job.Binding, func(ctx context.Context, b volumes.Binding) error {
					if b != job.Binding {
						return sfcp.ErrAdmission
					}
					_, err := r.volumeMovePermit(ctx, job, "fence")
					return err
				}, r.Identity.Private)
				if e == nil {
					e = r.publishVolumeMoveSource(ctx, permit, "fenced", &proof)
				}
			}
			failed = errors.Join(failed, e)
		case volumes.SourceFenced:
			permit, e := r.volumeMovePermit(ctx, job, "read")
			if e == nil {
				if permit.Reader == nil {
					e = r.publishVolumeMoveSource(ctx, permit, "reader", nil)
				} else {
					var complete *moveArtifactCompletion
					complete, e = r.backupArtifacts.StepMove(ctx, job, *permit.Reader, false)
					if e == nil {
						permit, e = r.volumeMovePermit(ctx, job, "read")
						if e == nil {
							receipt := complete.Receipt
							manifest := volumes.Manifest{Binding: job.Binding, Artifact: receipt.Digest, Bytes: receipt.Bytes, DataBytes: receipt.DataBytes, Files: receipt.Entries, ReadOnly: true}
							manifest.Signature = ed25519.Sign(r.Identity.Private, volumes.ManifestBytes(manifest))
							e = r.commitVolumeMoveReport(ctx, control.VolumeMoveReport{Operation: "move", Schema: 1, Selection: job.Selection(), Binding: job.Digest(), Epoch: permit.Epoch, RootRevision: permit.RootRevision, Revision: permit.Revision, At: time.Now().Unix(), Kind: "manifest", Manifest: &manifest})
						}
					}
				}
			}
			failed = errors.Join(failed, e)
		case volumes.Active:
			if move.SourceCleanup == nil {
				failed = errors.Join(failed, r.finishMoveSource(ctx, job))
			}
		case volumes.Cancelling, volumes.Verified:
			permit, e := r.volumeMovePermit(ctx, job, "cleanup")
			if e == nil && permit.Reader != nil {
				_, e = r.backupArtifacts.StepMove(ctx, job, *permit.Reader, true)
				if e == nil {
					permit, e = r.volumeMovePermit(ctx, job, "cleanup")
					if e == nil && permit.Reader != nil {
						closed := volumes.Gone{Scope: job.Binding.Scope, Consumer: *permit.Reader, Stopped: true, MountsGone: true}
						closed.Signature = ed25519.Sign(r.Identity.Private, volumes.GoneBytes(closed))
						e = r.commitVolumeMoveReport(ctx, control.VolumeMoveReport{Operation: "move", Schema: 1, Selection: job.Selection(), Binding: job.Digest(), Epoch: permit.Epoch, RootRevision: permit.RootRevision, Revision: permit.Revision, At: time.Now().Unix(), Kind: "reader-gone", Closed: &closed})
					}
				}
			}
			if e == nil && move.Phase == volumes.Cancelling && permit.Reader == nil && move.SourceCleanup == nil {
				e = r.cancelMoveSource(ctx, permit)
			}
			failed = errors.Join(failed, e)
		}
		if ctx.Err() != nil {
			break
		}
	}
	return failed
}
