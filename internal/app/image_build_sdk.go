// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"time"

	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/reconcile"
)

// Consume the original finite daemon and SDK solve. The SDK result and native
// process closure are distinct. Recovery never reissues a previously sent solve.
func (r *Runtime) consumeImageBuildSDK(ctx, jobctx context.Context, spec imagebuild.JobSpec) (failure error) {
	native := r.imageBuildNative
	var solve *imagebuild.NativeSolveSession
	var auth *imagebuild.BuildKitPullAuth
	var filter *containerops.Redactor
	var writer *imagebuild.LogWriter
	closeSession := func() error {
		var err error
		if solve != nil {
			select {
			case <-solve.Done():
			default:
				if cause := native.MarkLogGap(spec); cause != nil {
					err = imagebuild.ErrStorage
				}
			}
			err = errors.Join(err, solve.Close())
			solve = nil
		}
		if auth != nil {
			auth.Close()
			auth = nil
		}
		if filter != nil {
			filter.Destroy()
			filter = nil
		}
		if writer != nil {
			if writer.Close() != nil {
				err = errors.Join(err, imagebuild.ErrStorage)
			}
			writer = nil
		}
		return err
	}
	defer func() { failure = errors.Join(failure, closeSession()) }()
	record, err := native.Record(spec)
	if err != nil || record.Solve == nil {
		return imagebuild.ErrStorage
	}
	if record.Solve.Returned {
		page, err := imagebuild.ReadNativeLogs(r.reports, spec, 0, 1)
		if err != nil {
			return err
		}
		if page.Unclosed {
			if err := native.MarkLogGap(spec); err != nil {
				return err
			}
		}
	}
	if !record.Solve.Sent && !record.Solve.Stopping {
		work, err := r.imageBuildJobWork(jobctx, spec)
		if err != nil {
			return err
		}
		if work.Run.Phase == "unknown" {
			return r.finishImageBuild(ctx, spec, imagebuild.JobResult{Code: "BUILD_FAILED"})
		}
		if !record.CreateSent {
			if err := r.pullImageBuildBuilder(jobctx, spec, work.Run); err != nil {
				return r.finishImageBuild(ctx, spec, imageBuildFailure(err, jobctx.Err() != nil))
			}
		}
		if err := native.Create(jobctx, spec); err != nil {
			return errors.Join(err, r.markImageBuildUncertain(ctx, spec))
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
		writer, err = native.OpenLogWriter(jobctx, spec)
		if err != nil {
			return err
		}
		filter, err = r.stageImageBuildSecrets(jobctx, spec, native, writer)
		if err != nil {
			_ = closeSession()
			return r.finishImageBuild(ctx, spec, imageBuildFailure(err, jobctx.Err() != nil))
		}
		auth, err = r.imageBuildSessionAuth(jobctx, spec)
		if err != nil {
			return err
		}
		if err := native.Start(jobctx, spec); err != nil {
			return errors.Join(err, r.markImageBuildUncertain(ctx, spec))
		}
	} else if !record.Solve.Returned && record.Solve.Sent {
		// Lost original RPC/journal completion is not permission to retry the
		// solve. Positive native shutdown settles its possible local effects.
		if err := native.MarkLogGap(spec); err != nil {
			return err
		}
		return r.finishImageBuild(ctx, spec, imagebuild.JobResult{Code: "BUILD_FAILED"})
	}
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		work, err := r.imageBuildJobWork(ctx, spec)
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
		if !work.Allowed && !work.Run.Terminal() {
			_ = closeSession()
			code := imageBuildBlockedCode(work)
			if code == "" {
				return reconcile.ErrPending
			}
			return r.finishImageBuild(ctx, spec, imagebuild.JobResult{Code: code})
		}
		if solve != nil {
			select {
			case <-solve.Done():
				_ = solve.Wait() // persisted original result, not this error, selects outcome
				if err := closeSession(); errors.Is(err, imagebuild.ErrStorage) {
					return err
				}
				record, err = native.Record(spec)
				if err != nil {
					return err
				}
			default:
			}
		}
		if record.Solve.Returned && solve != nil {
			_ = solve.Wait()
			if err := closeSession(); errors.Is(err, imagebuild.ErrStorage) {
				return err
			}
		}
		if record.Solve.Returned || record.Solve.Stopping {
			if !record.Solve.Returned || record.Solve.Code != "OK" {
				code := record.Solve.Code
				if code == "" {
					code = "BUILD_FAILED"
				}
				return r.finishImageBuild(ctx, spec, imagebuild.JobResult{Code: code})
			}
			stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			err = native.StopSDK(stopCtx, spec)
			if err == nil {
				err = native.Remove(stopCtx, spec)
			}
			cancel()
			if err != nil {
				return errors.Join(err, r.markImageBuildUncertain(ctx, spec))
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
		if solve == nil {
			observed := native.ObserveExit(jobctx, spec, false)
			if observed != nil && !errors.Is(observed, reconcile.ErrPending) {
				return observed
			}
			latest, err := native.Record(spec)
			if err != nil {
				return err
			}
			if latest.Waited || latest.Removed {
				_ = closeSession()
				return r.finishImageBuild(ctx, spec, imagebuild.JobResult{Code: "BUILD_FAILED"})
			}
			solve, err = native.StartSolve(jobctx, spec, auth, filter)
			if err != nil && !errors.Is(err, reconcile.ErrPending) {
				return err
			}
		}
		if writer != nil {
			if err := writer.Flush(); err != nil {
				return err
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-jobctx.Done():
			_ = closeSession()
			return r.finishImageBuild(ctx, spec, imagebuild.JobResult{Code: "TIMEOUT"})
		case <-tick.C:
		}
	}
}
