// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/sfcp"
)

func imageBuildWorkGrant(work control.ImageBuildJobWork) imagebuild.NativeGrant {
	return imagebuild.NativeGrant{Run: work.Run, Allowed: work.Allowed, Index: work.Index, Epoch: work.Epoch}
}
func imageBuildBlockedCode(work control.ImageBuildJobWork) string {
	if work.Run.Cancel {
		return "CANCELLED"
	}
	switch work.Blocked {
	case "WAITING_FOR_CACHE", "WAITING_FOR_SLOT", "WAITING_FOR_BUDGET", "NOT_READY":
		return ""
	case "TIMEOUT":
		return "TIMEOUT"
	}
	return "PERMISSION_REVOKED"
}

func (r *Runtime) stageImageBuildContext(ctx context.Context, spec imagebuild.JobSpec) (failure error) {
	r.life.RLock()
	defer r.life.RUnlock()
	if r.closed || r.nodeRoots == nil || r.reports == nil {
		return sfcp.ErrAdmission
	}
	r.imageBuildMu.Lock()
	defer r.imageBuildMu.Unlock()
	work, err := r.imageBuildJobWork(ctx, spec)
	if err != nil || !work.Allowed {
		return sfcp.ErrAdmission
	}
	pin, err := r.nodeRoots.OpenRecordedPin(spec.Scope.Root, buildArtifactConsumer(spec.Scope))
	if pin.Directory != nil {
		defer func() { failure = errors.Join(failure, pin.Directory.Close()) }()
	}
	if err != nil || pin.Directory == nil {
		return errors.Join(imagebuild.ErrStorage, err)
	}
	spool, err := imagebuild.OpenExistingSpool(pin.Directory.FD(), spec.Scope.Root, r.reports)
	if err != nil {
		return err
	}
	defer func() { failure = errors.Join(failure, spool.Close()) }()
	reader, err := spool.Open(ctx, spec.Scope, spec.Seal)
	if err != nil {
		return err
	}
	defer func() { failure = errors.Join(failure, reader.Close()) }()
	at, ok := reader.(io.ReaderAt)
	if !ok {
		return imagebuild.ErrStorage
	}
	return r.imageBuildNative.StageContext(ctx, spec, at)
}

func (r *Runtime) markImageBuildUncertain(ctx context.Context, spec imagebuild.JobSpec) error {
	work, err := r.imageBuildJobWork(ctx, spec)
	if err != nil {
		return err
	}
	if work.Run.Phase == "unknown" || work.Run.Terminal() {
		return nil
	}
	if work.Run.Phase != "running" {
		return imagebuild.ErrConflict
	}
	return r.publishImageBuildJob(ctx, work, control.ImageBuildJobReport{Action: "uncertain"})
}

// Cleanup uses original local identity and a separate bounded context. It does
// not issue another Create/Copy/Start, infer success from timeout, or release an
// unknown publication. Runtime.Close joins workers before closing these owners.
func (r *Runtime) closeImageBuildNative(spec imagebuild.JobSpec) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	native := r.imageBuildNative
	if err := native.ObserveExit(ctx, spec, true); err != nil {
		return err
	}
	record, err := native.Record(spec)
	if err != nil {
		return err
	}
	if record.NativeID != "" && !record.Removed {
		if err := native.Remove(ctx, spec); err != nil {
			return err
		}
	}
	if record.Publication != nil {
		if _, err := native.CloseUnsentPublication(spec, "CANCELLED"); err != nil {
			return err
		}
	}
	if record.Workspace != nil {
		if _, err := native.FinishWorkspace(ctx, spec); err != nil {
			return err
		}
	}
	return r.returnImageBuildRoot(native, spec)
}

func (r *Runtime) finishImageBuild(ctx context.Context, spec imagebuild.JobSpec, result imagebuild.JobResult) error {
	if err := r.imageBuildNative.RecordOutcome(spec, result); err != nil {
		return err
	}
	if err := r.closeImageBuildNative(spec); err != nil {
		return err
	}
	if ctx.Err() != nil || r.ctx.Err() != nil {
		return errors.Join(ctx.Err(), r.ctx.Err())
	}
	return r.completeImageBuild(ctx, r.imageBuildNative, spec, result)
}

func imageBuildFailure(err error, deadline bool) imagebuild.JobResult {
	code := "BUILD_FAILED"
	switch {
	case deadline || errors.Is(err, context.DeadlineExceeded):
		code = "TIMEOUT"
	case errors.Is(err, imagebuild.ErrUntrustedBase):
		code = "UNTRUSTED_BASE"
	case errors.Is(err, imagebuild.ErrSourceFetch):
		code = "SOURCE_FETCH"
	case errors.Is(err, imagebuild.ErrStorage) || errors.Is(err, imagebuild.ErrDigest):
		code = "STORAGE_UNAVAILABLE"
	}
	return imagebuild.JobResult{Code: code}
}

func (r *Runtime) consumeImageBuildJob(ctx context.Context, spec imagebuild.JobSpec) (failure error) {
	native := r.imageBuildNative
	var logs *imageBuildLogSession
	defer func() {
		if logs != nil {
			failure = errors.Join(failure, logs.Close())
		}
		if ctx.Err() != nil || failure != nil && !errors.Is(failure, reconcile.ErrPending) {
			// A process-wide interruption must not leak a running original.
			// Keep unknown publication and all its durable references intact.
			if record, err := native.Record(spec); err == nil && record.Completion == nil && (ctx.Err() != nil || record.CreateSent) {
				if record.Outcome == nil && record.Publication == nil {
					result := imageBuildFailure(failure, false)
					failure = errors.Join(failure, native.RecordOutcome(spec, result))
				}
				failure = errors.Join(failure, r.closeImageBuildNative(spec))
			}
		}
	}()
	work, err := r.imageBuildJobWork(ctx, spec)
	if err != nil {
		return err
	}
	if !work.Allowed && !work.Run.Terminal() {
		code := imageBuildBlockedCode(work)
		if code == "" {
			return reconcile.ErrPending
		}
		if err := native.AcceptForCleanup(imageBuildWorkGrant(work)); err != nil {
			return err
		}
		record, err := native.Record(spec)
		if err != nil {
			return err
		}
		if record.Publication == nil {
			if record.Outcome != nil {
				return r.finishImageBuild(ctx, spec, *record.Outcome)
			}
			return r.finishImageBuild(ctx, spec, imagebuild.JobResult{Code: code})
		}
	}
	if err := native.Accept(imageBuildWorkGrant(work)); err != nil {
		return err
	}
	record, err := native.Record(spec)
	if err != nil {
		return err
	}
	if record.Completion != nil {
		return r.completeImageBuild(ctx, native, spec, record.Completion.Result)
	}
	if record.Outcome != nil {
		return r.finishImageBuild(ctx, spec, *record.Outcome)
	}
	if work.Run.Terminal() {
		return imagebuild.ErrConflict
	}
	deadline := time.Unix(int64(spec.CreatedAt+spec.Policy.Seconds), 0)
	jobctx, stop := context.WithDeadline(ctx, deadline)
	defer stop()
	if work.Run.Phase == "queued" {
		inputs, builder, local, err := r.freezeImageBuildInputs(jobctx, spec)
		if err != nil {
			return r.finishImageBuild(ctx, spec, imageBuildFailure(err, jobctx.Err() != nil))
		}
		if err := r.prepareImageBuildWorkspace(jobctx, native, spec); err != nil {
			if errors.Is(err, imagebuild.ErrUsed) {
				return reconcile.ErrPending
			}
			return r.finishImageBuild(ctx, spec, imageBuildFailure(err, jobctx.Err() != nil))
		}
		work, err = r.imageBuildJobWork(jobctx, spec)
		if err != nil {
			return err
		}
		if work.Run.Phase == "queued" {
			if !work.Allowed {
				return reconcile.ErrPending
			}
			view, err := r.currentView(jobctx)
			if err != nil || view.Local {
				return sfcp.ErrAdmission
			}
			sources, err := r.controlPolicy.ImageBuildBeginSources(view.State, r.Identity.Public, control.ImageBuildJobWorkQuery{Tenant: spec.Tenant, ID: spec.ID, At: time.Now().Unix()}, inputs, builder, local)
			if err != nil {
				return err
			}
			if err := r.publishImageBuildJob(jobctx, work, control.ImageBuildJobReport{Action: "begin", Inputs: inputs, Builder: builder, BuilderLocal: local, Sources: sources}); err != nil {
				return err
			}
		}
		work, err = r.imageBuildJobWork(jobctx, spec)
		if err != nil {
			return err
		}
	}
	record, err = native.Record(spec)
	if err != nil {
		return err
	}
	if record.Solve == nil && !record.CreateSent {
		if err := native.UseSDK(jobctx, spec); err != nil {
			return err
		}
		record, err = native.Record(spec)
		if err != nil {
			return err
		}
	}
	if record.Solve != nil {
		return r.consumeImageBuildSDK(ctx, jobctx, spec)
	}
	if record.StartSent {
		if err := native.MarkLogGap(spec); err != nil {
			return err
		}
	}
	if !record.StartSent && !record.Removed {
		if work.Run.Phase == "unknown" {
			return r.finishImageBuild(ctx, spec, imagebuild.JobResult{Code: "BUILD_FAILED"})
		}
		if !record.CreateSent {
			if err := r.pullImageBuildBuilder(jobctx, spec, work.Run); err != nil {
				return r.finishImageBuild(ctx, spec, imageBuildFailure(err, jobctx.Err() != nil))
			}
		}
		if err := native.Create(jobctx, spec); err != nil {
			latest, cause := native.Record(spec)
			if cause == nil && latest.CreateSent && !latest.CreateNotSent {
				return errors.Join(err, r.markImageBuildUncertain(ctx, spec))
			}
			return r.finishImageBuild(ctx, spec, imageBuildFailure(err, jobctx.Err() != nil))
		}
		record, err = native.Record(spec)
		if err != nil {
			return err
		}
		if !record.ContextDone {
			if err := r.stageImageBuildContext(jobctx, spec); err != nil {
				return r.finishImageBuild(ctx, spec, imageBuildFailure(err, jobctx.Err() != nil))
			}
		}
		logs, err = r.prepareImageBuildLogs(jobctx, native, spec)
		if err != nil {
			return r.finishImageBuild(ctx, spec, imageBuildFailure(err, jobctx.Err() != nil))
		}
		select {
		case <-logs.stream.Done():
			_ = logs.Wait()
			logs = nil
			return r.finishImageBuild(ctx, spec, imagebuild.JobResult{Code: "STORAGE_UNAVAILABLE"})
		default:
		}
		if err := native.Start(jobctx, spec); err != nil {
			if cause := r.markImageBuildUncertain(ctx, spec); cause != nil {
				return errors.Join(err, cause)
			}
		}
	}
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		work, err = r.imageBuildJobWork(ctx, spec)
		if err != nil {
			return err
		}
		record, err = native.Record(spec)
		if err != nil {
			return err
		}
		if record.Publication != nil {
			return r.resumeImageBuildPublication(ctx, spec, work)
		}
		if !work.Allowed {
			if logs != nil {
				_ = logs.Close()
				logs = nil
			}
			code := imageBuildBlockedCode(work)
			if code == "" {
				return reconcile.ErrPending
			}
			return r.finishImageBuild(ctx, spec, imagebuild.JobResult{Code: code})
		}
		if !record.Removed {
			err = native.ObserveExit(jobctx, spec, false)
			if err != nil && !errors.Is(err, reconcile.ErrPending) {
				if jobctx.Err() != nil {
					if logs != nil {
						_ = logs.Close()
						logs = nil
					}
					return r.finishImageBuild(ctx, spec, imagebuild.JobResult{Code: "TIMEOUT"})
				}
				return errors.Join(err, r.markImageBuildUncertain(ctx, spec))
			}
			record, err = native.Record(spec)
			if err != nil {
				return err
			}
		}
		if record.Waited || record.Removed {
			if !record.Removed {
				if err := native.Remove(ctx, spec); err != nil {
					return errors.Join(err, r.markImageBuildUncertain(ctx, spec))
				}
			}
			var logErr error
			if logs != nil {
				drain, cancel := context.WithTimeout(ctx, 3*time.Second)
				logErr = logs.Drain(drain)
				cancel()
				logs = nil
			}
			if !record.Exited || record.ExitCode != 0 {
				result := imageBuildFailure(logErr, record.ExitCode == 124 || !time.Now().Before(deadline))
				return r.finishImageBuild(ctx, spec, result)
			}
			if logErr != nil && !errors.Is(logErr, context.Canceled) {
				return r.finishImageBuild(ctx, spec, imagebuild.JobResult{Code: "STORAGE_UNAVAILABLE"})
			}
			result, err := r.publishImageBuildOutput(jobctx, spec, native)
			if err == nil {
				return r.finishImageBuild(ctx, spec, result)
			}
			latest, cause := native.Record(spec)
			if cause != nil {
				return errors.Join(err, cause)
			}
			if latest.Publication == nil && !errors.Is(err, reconcile.ErrPending) {
				return r.finishImageBuild(ctx, spec, imageBuildFailure(err, jobctx.Err() != nil))
			}
			return errors.Join(err, r.markImageBuildUncertain(ctx, spec))
		}
		if logs != nil {
			if err := logs.Flush(); err != nil {
				_ = logs.Close()
				logs = nil
				return r.finishImageBuild(ctx, spec, imagebuild.JobResult{Code: "STORAGE_UNAVAILABLE"})
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}
