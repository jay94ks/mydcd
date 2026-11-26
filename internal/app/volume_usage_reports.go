// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"slices"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/observability"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

// Periodic volume usage (observability.VolumeUsage). It is an owner
// observation, never Raft state: each observation cycle scans at most one
// owned volume (the one without a sample, else the oldest past
// volumeUsageInterval) and republishes the other current samples, so the
// node's scan work stays one bounded walk per cycle.
const (
	volumeUsageInterval = uint64(5 * 60_000) // Unix ms between scans of one volume
	volumeUsageScanTime = 10 * time.Second
)

var volumeUsageLimits = volumes.UsageLimits{Entries: 100_000, Depth: 64}

func (r *Runtime) volumeUsageSamples(ctx context.Context, v cluster.View, p control.Policy, node string, stored []observability.Report) []observability.VolumeUsage {
	holds := func(key [32]byte) bool { _, ok := r.nativeOwner(key); return ok }
	owned, err := p.OwnedVolumes(v.State, holds)
	if err != nil || len(owned) == 0 {
		return nil
	}
	last := map[string]observability.VolumeUsage{}
	for _, report := range stored {
		if u := report.Volume; u != nil && report.Node == node && report.Key == r.Identity.Public && u.ScannedAt > last[u.Key].ScannedAt {
			last[u.Key] = *u
		}
	}
	out, scan := planVolumeUsage(owned, last, uint64(time.Now().UnixMilli()))
	if scan < 0 {
		return out
	}
	o := owned[scan]
	u, err := r.scanOwnedVolume(ctx, o)
	if err != nil {
		return out
	}
	// The volume must still be the same owned materialization after the walk.
	if after, e := r.Engine().Read(ctx, false); e != nil || !slices.ContainsFunc(mustOwned(p, after, holds), func(x control.OwnedVolume) bool {
		return x.Key == o.Key && control.VolumeNativeDigest(x.Ready) == u.Binding
	}) {
		return out
	}
	out = slices.DeleteFunc(out, func(x observability.VolumeUsage) bool { return x.Key == o.Key })
	return append(out, u)
}

// planVolumeUsage keeps each owned volume's sample of its current
// materialization while it is within VolumeUsageMaxAge, and picks the one
// volume to scan now: one without a sample first, else the oldest sample past
// volumeUsageInterval (-1: nothing to scan).
func planVolumeUsage(owned []control.OwnedVolume, last map[string]observability.VolumeUsage, now uint64) ([]observability.VolumeUsage, int) {
	out := []observability.VolumeUsage{}
	scan, oldest := -1, uint64(0)
	for i, o := range owned {
		prev, ok := last[o.Key]
		if !ok || prev.Binding != control.VolumeNativeDigest(o.Ready) || prev.ScannedAt > now {
			prev, ok = observability.VolumeUsage{}, false // no sample of this materialization
		}
		if ok && now-prev.ScannedAt <= observability.VolumeUsageMaxAge {
			out = append(out, prev) // shown until a rescan replaces it
		}
		if ok && now-prev.ScannedAt < volumeUsageInterval {
			continue
		}
		if scan < 0 || prev.ScannedAt < oldest {
			scan, oldest = i, prev.ScannedAt
		}
	}
	return out, scan
}

func mustOwned(p control.Policy, v cluster.View, holds func([32]byte) bool) []control.OwnedVolume {
	owned, _ := p.OwnedVolumes(v.State, holds)
	return owned
}

// scanOwnedVolume walks one owned volume with the same bounded scanner and
// single-scan lock as the volume-usage read. A busy lock or an incomplete
// walk gives no sample (the row stays unknown), never zero.
func (r *Runtime) scanOwnedVolume(ctx context.Context, o control.OwnedVolume) (observability.VolumeUsage, error) {
	owner, ok := r.nativeOwner(o.Ready.Owner.Key)
	if !ok || !owner.volumeUsageMu.TryLock() {
		return observability.VolumeUsage{}, volumes.ErrVolumeUsage
	}
	defer owner.volumeUsageMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, volumeUsageScanTime)
	defer cancel()
	owner.life.RLock()
	if owner.closed || owner.nativeVolumes == nil {
		owner.life.RUnlock()
		return observability.VolumeUsage{}, volumes.ErrVolumeUsage
	}
	value, err := owner.nativeVolumes.Usage(ctx, volumes.NativeKey(o.Ready.Spec), volumeUsageLimits)
	owner.life.RUnlock()
	if err != nil || !value.Matches(o.Ready) {
		return observability.VolumeUsage{}, volumes.ErrVolumeUsage
	}
	return observability.VolumeUsage{Key: o.Key, Binding: control.VolumeNativeDigest(o.Ready), Entries: value.Entries, Files: value.Files, Directories: value.Directories,
		LogicalBytes: value.LogicalBytes, AllocatedBytes: value.AllocatedBytes, ScannedAt: uint64(time.Now().UnixMilli())}, nil
}
