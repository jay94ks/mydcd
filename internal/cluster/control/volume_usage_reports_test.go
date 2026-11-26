// SPDX-License-Identifier: Apache-2.0

package control

import (
	"testing"

	"github.com/jay94ks/mydcd/internal/observability"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

func TestAttachVolumeUsage(t *testing.T) {
	const now = uint64(10_000_000)
	row := func() []VolumeView {
		return []VolumeView{{Key: "t/@tenant/a", Owner: volumes.Owner{Node: "node-a"}, NativeBinding: [32]byte{1}}, {Key: "t/@tenant/b", Owner: volumes.Owner{Node: "node-a"}}}
	}
	report := func(node, key string, binding byte, at, scanned uint64) observability.Report {
		return observability.Report{Node: node, At: at, Volume: &observability.VolumeUsage{Key: key, Binding: [32]byte{binding}, AllocatedBytes: 8192, ScannedAt: scanned}}
	}
	rows := row()
	AttachVolumeUsage(rows, []observability.Report{report("node-a", "t/@tenant/a", 1, now, now-1000), report("node-a", "t/@tenant/b", 0, now, now)}, now)
	if rows[0].UsedBytes == nil || *rows[0].UsedBytes != 8192 || rows[0].UsageObservedAt != now-1000 {
		t.Fatalf("matched row %+v", rows[0])
	}
	if rows[1].UsedBytes != nil {
		t.Fatalf("row without a native binding got usage %+v", rows[1])
	}
	for name, r := range map[string]observability.Report{
		"other node":    report("node-b", "t/@tenant/a", 1, now, now),
		"other binding": report("node-a", "t/@tenant/a", 2, now, now),
		"stale owner":   report("node-a", "t/@tenant/a", 1, now-observability.MaxAge-1, now-observability.MaxAge-1),
		"old scan":      report("node-a", "t/@tenant/a", 1, now, now-observability.VolumeUsageMaxAge-1),
		"future scan":   report("node-a", "t/@tenant/a", 1, now, now+1),
	} {
		rows := row()
		AttachVolumeUsage(rows, []observability.Report{r}, now)
		if rows[0].UsedBytes != nil {
			t.Fatalf("%s: usage attached %+v", name, rows[0])
		}
	}
	rows = row()
	newer := report("node-a", "t/@tenant/a", 1, now, now-10)
	newer.Volume.AllocatedBytes = 512
	AttachVolumeUsage(rows, []observability.Report{newer, report("node-a", "t/@tenant/a", 1, now, now-20)}, now)
	if *rows[0].UsedBytes != 512 {
		t.Fatalf("newest scan not kept %+v", rows[0])
	}
}
