// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/reconcile"
)

func cachePruneWaiting(code string) bool {
	return code == "WAITING_FOR_CACHE" || code == "WAITING_FOR_SLOT" || code == "WAITING_FOR_BUDGET" || code == "NOT_READY"
}
func cachePruneFailureCode(code string) string {
	if code == "TIMEOUT" {
		return "TIMEOUT"
	}
	return "PERMISSION_REVOKED"
}

func cachePruneNativeOutcomeCode(row imagebuild.NativeCachePruneRecord) string {
	if row.Outcome != nil {
		return row.Outcome.Code
	}
	if row.SDKSucceeded() {
		return "OK"
	}
	return "FAILED"
}

// A known original is stopped and closed even when current quorum/user work
// is unavailable. Shared completion remains a separate fresh owner report.
func (r *Runtime) closeImageBuildCachePrune(s imagebuild.NativeCachePruneSpec) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	native := r.imageBuildNative
	if err := native.StopCachePrune(ctx, s, nil, true); err != nil {
		return err
	}
	row, err := native.CachePruneRecord(s)
	if err != nil {
		return err
	}
	if row.Daemon != nil && row.Daemon.Effects.NativeID != "" && !row.Daemon.Effects.Removed {
		if err := native.RemoveCachePrune(ctx, s); err != nil {
			return err
		}
	}
	if _, err := native.FinishCachePrune(ctx, s); err != nil {
		return err
	}
	_, err = native.SealCachePruneCompletion(s, uint64(time.Now().Unix()), r.Identity.Private)
	return err
}
func (r *Runtime) finishImageBuildCachePrune(ctx context.Context, s imagebuild.NativeCachePruneSpec) error {
	if err := r.closeImageBuildCachePrune(s); err != nil {
		return err
	}
	if ctx.Err() != nil || r.ctx.Err() != nil {
		return errors.Join(ctx.Err(), r.ctx.Err())
	}
	row, err := r.imageBuildNative.CachePruneRecord(s)
	if err != nil || row.Completion == nil {
		return errors.Join(imagebuild.ErrStorage, err)
	}
	c := row.Completion
	work, err := r.imageBuildCachePruneWork(ctx, s)
	if err != nil {
		return err
	}
	if !work.Record.Pending() {
		if len(work.Record.Reports) == 0 {
			return imagebuild.ErrStorage
		}
		last := work.Record.Reports[len(work.Record.Reports)-1]
		if last.Action != "complete" || last.Native == nil || *last.Native != c.Native || last.Code != c.Result.Code || last.ClosedAt != c.At || last.RemovedCount != c.Result.RemovedCount || last.ReportedBytes != c.Result.ReportedBytes {
			return imagebuild.ErrConflict
		}
		return nil
	}
	return r.publishImageBuildCachePrune(ctx, work, control.ImageBuildCachePruneReport{Action: "complete", Native: &c.Native, Code: c.Result.Code, ClosedAt: c.At, RemovedCount: c.Result.RemovedCount, ReportedBytes: c.Result.ReportedBytes})
}
func (r *Runtime) failImageBuildCachePrune(ctx context.Context, s imagebuild.NativeCachePruneSpec, code string, cause error) error {
	if row, err := r.imageBuildNative.CachePruneRecord(s); err == nil && row.SDKSucceeded() {
		code = cachePruneNativeOutcomeCode(row)
	}
	if err := r.imageBuildNative.RecordCachePruneOutcome(s, code); err != nil {
		return errors.Join(cause, err)
	}
	if err := r.finishImageBuildCachePrune(ctx, s); err != nil {
		return errors.Join(cause, err)
	}
	if code == "OK" {
		return cause
	} // independent observation/cleanup diagnostic
	return nil // the original operation reports failure; native closure succeeded
}
func (r *Runtime) markImageBuildCachePruneUnknown(ctx context.Context, s imagebuild.NativeCachePruneSpec) error {
	work, err := r.imageBuildCachePruneWork(ctx, s)
	if err != nil {
		return err
	}

	if work.Record.State == "unknown" {
		return nil
	}
	if work.Record.State != "running" {
		return imagebuild.ErrConflict
	}
	return r.publishImageBuildCachePrune(ctx, work, control.ImageBuildCachePruneReport{Action: "uncertain"})
}

func (r *Runtime) consumeImageBuildCachePrune(ctx context.Context, s imagebuild.NativeCachePruneSpec) (failure error) {
	native := r.imageBuildNative
	row, recordErr := native.CachePruneRecord(s)
	if recordErr != nil && !errors.Is(recordErr, imagebuild.ErrNativeMissing) {
		return recordErr
	}
	// Preserve the result/closure before consulting new execution permission.
	if recordErr == nil && (row.Outcome != nil || row.RPC != nil) {
		if row.Outcome == nil {
			code := cachePruneNativeOutcomeCode(row)
			if err := native.RecordCachePruneOutcome(s, code); err != nil {
				return err
			}
		}
		return r.finishImageBuildCachePrune(ctx, s)
	}
	work, err := r.imageBuildCachePruneWork(ctx, s)
	if err != nil {
		return err
	}
	if !work.Record.Pending() {
		// Native completion was durable before the shared report. Missing local
		// evidence is corruption, never an empty replacement or fabricated close.
		return imagebuild.ErrStorage
	}
	if work.Record.State == "queued" && !work.Allowed && cachePruneWaiting(work.Blocked) {
		return reconcile.ErrPending
	}
	grant, err := work.NativeGrant()
	if err != nil {
		return err
	}
	if errors.Is(recordErr, imagebuild.ErrNativeMissing) {
		if grant.Phase != "queued" {
			return imagebuild.ErrNativeMissing
		}
		if grant.Allowed {
			err = native.AcceptCachePrune(grant)
		} else {
			err = native.AcceptCachePruneForCleanup(grant)
		}
		if err != nil {
			return err
		}
	}
	// Shutdown joins an active SDK call before this deferred original cleanup.
	defer func() {
		if ctx.Err() == nil && r.ctx.Err() == nil {
			return
		}
		if row, err := native.CachePruneRecord(s); err == nil {
			if row.Outcome == nil {
				code := cachePruneNativeOutcomeCode(row)
				failure = errors.Join(failure, native.RecordCachePruneOutcome(s, code))
			}
			failure = errors.Join(failure, r.closeImageBuildCachePrune(s))
		}
	}()
	if !work.Allowed {
		return r.failImageBuildCachePrune(ctx, s, cachePruneFailureCode(work.Blocked), nil)
	}
	if grant.Phase == "queued" {
		if err := r.publishImageBuildCachePrune(ctx, work, control.ImageBuildCachePruneReport{Action: "begin"}); err != nil {
			return err
		}
		work, err = r.imageBuildCachePruneWork(ctx, s)
		if err != nil {
			return err
		}
		if !work.Allowed {
			return r.failImageBuildCachePrune(ctx, s, cachePruneFailureCode(work.Blocked), nil)
		}
	}
	row, err = native.CachePruneRecord(s)
	if err != nil {
		return err
	}
	if work.Record.State == "unknown" || row.Daemon != nil && row.Daemon.Stopping {
		return r.failImageBuildCachePrune(ctx, s, "FAILED", nil)
	}
	if !row.Claimed {
		if err := r.claimImageBuildCachePruneRoot(work); err != nil {
			if errors.Is(err, imagebuild.ErrUsed) {
				return reconcile.ErrPending
			}
			return r.failImageBuildCachePrune(ctx, s, "FAILED", err)
		}
	}
	row, err = native.CachePruneRecord(s)
	if err != nil {
		return err
	}
	if row.Daemon == nil || !row.Daemon.Ready {
		if err := native.PrepareCachePruneWorkspace(ctx, s, r.imageBuildCachePruneAuthority); err != nil {
			return r.failImageBuildCachePrune(ctx, s, "FAILED", err)
		}
	}
	if err := native.CreateCachePrune(ctx, s, r.imageBuildCachePruneAuthority); err != nil {
		if errors.Is(err, reconcile.ErrPending) {
			return errors.Join(err, r.markImageBuildCachePruneUnknown(ctx, s))
		}
		return r.failImageBuildCachePrune(ctx, s, "FAILED", err)
	}
	if err := native.StartCachePrune(ctx, s, r.imageBuildCachePruneAuthority); err != nil {
		if errors.Is(err, reconcile.ErrPending) {
			return errors.Join(err, r.markImageBuildCachePruneUnknown(ctx, s))
		}
		return r.failImageBuildCachePrune(ctx, s, "FAILED", err)
	}
	if err := native.RunCachePrune(ctx, s, r.imageBuildCachePruneAuthority); err != nil {
		if errors.Is(err, reconcile.ErrPending) {
			return err
		} // private socket readiness
		return r.failImageBuildCachePrune(ctx, s, "FAILED", err)
	}
	if err := native.RecordCachePruneOutcome(s, "OK"); err != nil {
		return err
	}
	return r.finishImageBuildCachePrune(ctx, s)
}

// Between readiness polls an original may have no active worker. Scan and
// settle all known maintenance only after the scheduler's workers have joined,
// while the native DB/RootManager are still alive. No shared success is minted.
func (r *Runtime) shutdownImageBuildCachePrunes() error {
	rows, err := r.imageBuildNative.CachePruneRecords()
	if err != nil {
		return err
	}
	var failure error
	for _, row := range rows {
		if row.Completion != nil {
			continue
		}
		if row.Outcome == nil {
			code := cachePruneNativeOutcomeCode(row)
			if err := r.imageBuildNative.RecordCachePruneOutcome(row.Spec, code); err != nil {
				failure = errors.Join(failure, err)
				continue
			}
		}
		failure = errors.Join(failure, r.closeImageBuildCachePrune(row.Spec))
	}
	return failure
}
