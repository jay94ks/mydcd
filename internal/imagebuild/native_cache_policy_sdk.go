// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"errors"
	"math"

	bkclient "github.com/moby/buildkit/client"
)

func cachePruneStepSlot(row *NativeCachePruneRecord, kind string) **CacheCleanupStep {
	if kind == "size" {
		return &row.PolicySize
	}
	return &row.RPC
}

func cachePruneStepSucceeded(step *CacheCleanupStep) bool {
	return step != nil && (step.Code == "OK" || step.Code == "SKIPPED")
}

// SDKSucceeded is the RPC outcome only. Actual daemon/FD/cache-owner closure
// and the original signed completion remain separate admission requirements.
func (r NativeCachePruneRecord) SDKSucceeded() bool {
	return cachePruneStepSucceeded(r.RPC) && (r.Spec.Automatic == nil || cachePruneStepSucceeded(r.PolicySize))
}

// A new read is required between age and size. Neither the old snapshot nor
// an UNKNOWN/failed step authorizes the next mutation. RunCachePrune refuses
// any retained primary receipt on reentry, so neither step can be replayed.
func (n *NativeJobs) runPolicyCachePrune(ctx context.Context, s NativeCachePruneSpec, authorize NativeCachePruneAuthority, sdk *bkclient.Client, usage CacheUsage) error {
	for _, kind := range []string{"age", "size"} {
		selection, err := SelectCacheCleanupPolicy(s.Source, usage, kind, *s.Automatic)
		if err != nil {
			return err
		}
		byteLimit := int64(math.MaxInt64)
		if kind == "size" {
			row, err := n.CachePruneRecord(s)
			if err != nil {
				return err
			}
			if !cachePruneStepSucceeded(row.RPC) {
				return ErrConflict
			}
			byteLimit -= row.RPC.ReportedBytes
		}
		if err := n.beginManualCachePrune(ctx, s, selection, authorize); err != nil {
			return err
		}
		complete := true
		if len(selection.IDs) != 0 {
			var acks *cacheCleanupAcks
			acks, complete = invokeSDKCachePruneBudget(ctx, sdk, selection, byteLimit)
			if err := n.finishManualCachePrune(s, selection, acks, complete); err != nil {
				return err
			}
		}
		// This updates evidence even after a partial stream; it never resolves
		// that mutation or enables size after a failed/unknown age operation.
		next, err := n.sampleManualCacheObservation(ctx, s, sdk)
		if !complete {
			return errors.Join(ErrStorage, err)
		}
		if err != nil {
			return err
		}
		if next == nil {
			return ErrStorage
		}
		usage = *next
	}
	return nil
}
