// SPDX-License-Identifier: Apache-2.0

package app

import (
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/observability"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

func TestPlanVolumeUsage(t *testing.T) {
	const now = uint64(100 * 60_000)
	a := control.OwnedVolume{Key: "a", Ready: volumes.NativeReady{Generation: 1}}
	b := control.OwnedVolume{Key: "b", Ready: volumes.NativeReady{Generation: 2}}
	c := control.OwnedVolume{Key: "c", Ready: volumes.NativeReady{Generation: 3}}
	sample := func(o control.OwnedVolume, age uint64) observability.VolumeUsage {
		return observability.VolumeUsage{Key: o.Key, Binding: control.VolumeNativeDigest(o.Ready), ScannedAt: now - age}
	}
	owned := []control.OwnedVolume{a, b, c}

	// a volume without a sample is scanned first
	keep, scan := planVolumeUsage(owned, map[string]observability.VolumeUsage{"a": sample(a, 60_000), "c": sample(c, 10*60_000)}, now)
	if scan != 1 || len(keep) != 2 {
		t.Fatalf("missing first: scan %d keep %+v", scan, keep)
	}
	// else the oldest sample past the interval; fresh ones are only kept
	keep, scan = planVolumeUsage(owned, map[string]observability.VolumeUsage{"a": sample(a, 60_000), "b": sample(b, 6*60_000), "c": sample(c, 10*60_000)}, now)
	if scan != 2 || len(keep) != 3 {
		t.Fatalf("oldest: scan %d keep %+v", scan, keep)
	}
	keep, scan = planVolumeUsage(owned, map[string]observability.VolumeUsage{"a": sample(a, 0), "b": sample(b, 0), "c": sample(c, 0)}, now)
	if scan != -1 || len(keep) != 3 {
		t.Fatalf("all fresh: scan %d keep %+v", scan, keep)
	}
	// a sample of another materialization or past the age limit is dropped
	other := sample(b, 0)
	other.Binding = [32]byte{7}
	keep, scan = planVolumeUsage([]control.OwnedVolume{a, b}, map[string]observability.VolumeUsage{"a": sample(a, observability.VolumeUsageMaxAge+1), "b": other}, now)
	if len(keep) != 0 || scan != 1 {
		t.Fatalf("dropped: scan %d keep %+v", scan, keep)
	}
}
