// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"errors"
	"time"

	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/moby/moby/client"
)

// RunCachePrune borrows the original daemon/SDK/FDS through the complete RPC
// and writes the selection/Sent before dispatch. Any retained step, including
// UNKNOWN or a lost completion commit, forbids another dispatch.
func (n *NativeJobs) RunCachePrune(ctx context.Context, s NativeCachePruneSpec, authorize NativeCachePruneAuthority) (failure error) {
	n.mu.Lock()
	r, err := n.loadCachePrune(s)
	if err != nil {
		n.mu.Unlock()
		return err
	}
	if _, err := n.currentCachePrune(ctx, &r, authorize, false); err != nil {
		n.mu.Unlock()
		return err
	}
	if r.RPC != nil || r.Daemon == nil || !r.Daemon.Effects.StartSent || r.Daemon.Effects.Removed || n.solving[s.Intent] {
		n.mu.Unlock()
		return ErrConflict
	}
	files, err := n.openCachePruneWorkspace(r)
	if err != nil {
		n.mu.Unlock()
		return err
	}
	fail := func(err error) error { n.mu.Unlock(); return errors.Join(err, files.Close()) }
	id, opts, err := planCachePrune(s, n.docker.Owner)
	if err != nil {
		return fail(err)
	}
	got, err := n.docker.API.ContainerInspect(ctx, r.Daemon.Effects.NativeID, client.ContainerInspectOptions{})
	if err != nil {
		return fail(nativeFailure(ctx))
	}
	if !matchNativeContainerOptions(got.Container, id, r.Daemon.Effects.ImageID, r.Daemon.Effects.NativeID, opts) || !got.Container.State.Running {
		return fail(engine.ErrOwnership)
	}
	sdk, err := openBuildKitClient(ctx, files.leaves[1])
	if err != nil {
		return fail(err)
	}
	n.solving[s.Intent] = true
	n.readers[s.Intent]++
	n.mu.Unlock()
	defer func() {
		closeErr := errors.Join(sdk.Close(), files.Close())
		n.mu.Lock()
		delete(n.solving, s.Intent)
		if closeErr == nil {
			n.readers[s.Intent]--
			if n.readers[s.Intent] == 0 {
				delete(n.readers, s.Intent)
			}
		}
		n.mu.Unlock()
		failure = errors.Join(failure, closeErr)
	}()
	usage, err := n.sampleManualCacheObservation(ctx, s, sdk)
	if err != nil {
		return err
	}
	if usage == nil {
		return ErrStorage
	}
	if s.Automatic != nil {
		return n.runPolicyCachePrune(ctx, s, authorize, sdk, *usage)
	}
	selection, err := SelectCachePrune(s.Source, *usage, s.Filter)
	if err != nil {
		return err
	}
	if err := n.beginManualCachePrune(ctx, s, selection, authorize); err != nil {
		return err
	}
	if len(selection.IDs) == 0 {
		return nil
	}
	acks, complete := invokeSDKCachePrune(ctx, sdk, selection)
	if err := n.finishManualCachePrune(s, selection, acks, complete); err != nil {
		return err
	}
	// A readback updates observation only. It cannot turn an UNKNOWN prune
	// into success, and observation failure cannot rewrite its durable ACK.
	_, observationErr := n.sampleManualCacheObservation(ctx, s, sdk)
	if !complete {
		return errors.Join(ErrStorage, observationErr)
	}
	return observationErr
}

func (n *NativeJobs) beginManualCachePrune(ctx context.Context, s NativeCachePruneSpec, selection CacheCleanupSelection, authorize NativeCachePruneAuthority) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	r, err := n.loadCachePrune(s)
	if err != nil {
		return err
	}
	if !selection.valid() || !s.selectionKind(selection.Kind) || *cachePruneStepSlot(&r, selection.Kind) != nil || selection.Kind == "size" && (!cachePruneStepSucceeded(r.RPC) || selection.MaxUsedSpace != cacheCleanupTarget(s.Limits())) || !n.solving[s.Intent] || n.readers[s.Intent] == 0 {
		return ErrConflict
	}
	if _, err := n.currentCachePrune(ctx, &r, authorize, false); err != nil {
		return err
	}
	// Recheck the original mount paths/owner after DiskUsage and before Sent.
	files, err := n.openCachePruneWorkspace(r)
	if err != nil {
		return err
	}
	if err := files.Close(); err != nil {
		return ErrStorage
	}
	step := CacheCleanupStep{Kind: selection.Kind, Snapshot: selection.Snapshot, Selection: selection.Digest(), Selected: uint32(len(selection.IDs)), MaxUsedSpace: selection.MaxUsedSpace, Code: "SKIPPED"}
	if len(selection.IDs) > 0 {
		step.Code = "UNKNOWN"
		step.SentAt = uint64(time.Now().Unix())
	}
	*cachePruneStepSlot(&r, selection.Kind) = &step
	return n.saveCachePrune(r)
}
func (n *NativeJobs) finishManualCachePrune(s NativeCachePruneSpec, selection CacheCleanupSelection, acks *cacheCleanupAcks, complete bool) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	r, err := n.loadCachePrune(s)
	if err != nil {
		return err
	}
	step := *cachePruneStepSlot(&r, selection.Kind)
	if !s.selectionKind(selection.Kind) || step == nil || step.Kind != selection.Kind || step.Code != "UNKNOWN" || step.ReturnedAt != 0 || step.Selection != selection.Digest() || !n.solving[s.Intent] || n.readers[s.Intent] == 0 {
		return ErrConflict
	}
	step.ReturnedAt = uint64(time.Now().Unix())
	step.RemovedCount, step.ReportedBytes = acks.count, acks.bytes
	if complete && !acks.invalid {
		step.Code = "OK"
	}
	return n.saveCachePrune(r)
}
