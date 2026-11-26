// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"math"
	"time"

	bkclient "github.com/moby/buildkit/client"
)

// This is the single SDK stream consumer for automatic and explicit cache
// maintenance. The caller owns the cache and writes Sent
// before entry; neither an RPC error nor readback authorizes a retry.
func invokeSDKCachePrune(ctx context.Context, sdk *bkclient.Client, s CacheCleanupSelection) (*cacheCleanupAcks, bool) {
	return invokeSDKCachePruneBudget(ctx, sdk, s, math.MaxInt64)
}

// The second policy step shares the first step's public int64 byte budget.
// An overflowing/unexpected ACK invalidates that stream before aggregation;
// original per-step receipts and actual process closure remain available.
func invokeSDKCachePruneBudget(ctx context.Context, sdk *bkclient.Client, s CacheCleanupSelection, byteLimit int64) (*cacheCleanupAcks, bool) {
	acks := newCacheCleanupAcks(s)
	acks.byteLimit = byteLimit
	opts, err := s.PruneOptions()
	if err != nil || sdk == nil || byteLimit < 0 {
		acks.invalid = true
		return acks, false
	}
	pruneCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	rows := make(chan bkclient.UsageInfo, 16)
	done := make(chan error, 1)
	go func() { err := sdk.Prune(pruneCtx, rows, opts...); close(rows); done <- err }()
	for row := range rows {
		if !acks.add(row) {
			cancel()
		}
		// The adopted SDK sends directly. Always drain and join after cancellation.
	}
	err = <-done
	return acks, err == nil && !acks.invalid
}
