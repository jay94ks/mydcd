// SPDX-License-Identifier: Apache-2.0

package containerops

import (
	"math"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
)

func TestObservationQueryRejectsMixedFieldsAndUnboundedOutput(t *testing.T) {
	valid := Query{Schema: 1, Selection: Selection{App: "app", Service: "web"}, Kind: "logs", Tail: 200, Stdout: true, Stderr: true, MaxBytes: 16384}
	if valid.Validate() != nil {
		t.Fatal("valid logs")
	}
	for _, change := range []func(*Query){
		func(q *Query) { q.Schema = 0 }, func(q *Query) { q.Selection.App = "../app" }, func(q *Query) { q.Selection.Service = "" }, func(q *Query) { q.Kind = "exec" }, func(q *Query) { q.MaxBytes = 0 }, func(q *Query) { q.MaxBytes = MaxOutput + 1 }, func(q *Query) { q.Tail = 0 }, func(q *Query) { q.Tail = 10001 }, func(q *Query) { q.Stdout = false; q.Stderr = false }, func(q *Query) { q.Since = "yesterday" }, func(q *Query) { q.Until = "2026-01-01T00:00:00Z"; q.Since = "2026-01-02T00:00:00Z" }, func(q *Query) { q.Kind = "stats" },
	} {
		q := valid
		change(&q)
		if q.Validate() == nil {
			t.Fatalf("invalid query accepted: %+v", q)
		}
	}
	for _, kind := range []string{"top", "stats"} {
		q := valid
		q.Kind, q.Tail, q.Stdout, q.Stderr = kind, 0, false, false
		if q.Validate() != nil {
			t.Fatal(kind)
		}
	}
}

func TestInspectObservationKeepsDetailSeparateFromStatsAndStreams(t *testing.T) {
	target, _, _ := logPageFixture()
	query := Query{Schema: 1, Selection: Selection{App: "app", Service: "web"}, Kind: "inspect", MaxBytes: MaxOutput, HistoryLimit: 20}
	if query.Validate() != nil {
		t.Fatal("bounded detail query")
	}
	result := Result{Schema: 1, Kind: "inspect", Target: target, ObservedAt: time.Unix(100, 0).UTC(), Detail: &ContainerDetail{}}
	if err := result.Validate(query, target); err != nil {
		t.Fatal("detail required an unrelated stats payload", err)
	}
	result.Stats = &Stats{}
	if result.Validate(query, target) == nil {
		t.Fatal("mixed detail/stats response")
	}
	result.Detail = nil
	result.Kind = "stats"
	query.Kind = "stats"
	query.HistoryLimit = 0
	if err := result.Validate(query, target); err != nil {
		t.Fatal("stats validation regressed", err)
	}
	result.Stats = nil
	if result.Validate(query, target) == nil {
		t.Fatal("missing actual stats accepted")
	}
	query.Kind = "inspect"
	query.HistoryLimit = 101
	if query.Validate() == nil {
		t.Fatal("unbounded history accepted")
	}
}
func TestObservationTargetNeverRebindsAnInstance(t *testing.T) {
	original := Target{Cluster: [32]byte{1}, Owner: [32]byte{2}, Binding: [32]byte{3}, Tenant: "tenant", App: "app", Service: "web", Node: "node-a", Instance: "workload/task/tenant/app/web", Generation: 1, Revision: 1}
	actual := original
	actual.NativeID = "native-one"
	actual.StartedAt = "2026-01-01T00:00:00Z"
	if !original.Valid() || !actual.Matches(original) {
		t.Fatal("first materialization rejected")
	}
	for _, mutate := range []func(*Target){func(q *Target) { q.Owner = [32]byte{4} }, func(q *Target) { q.Generation++ }, func(q *Target) { q.Binding = [32]byte{5} }, func(q *Target) { q.Tenant = "other" }, func(q *Target) { q.NativeID = "native-two" }, func(q *Target) { q.StartedAt = "2026-01-02T00:00:00Z" }} {
		changed := actual
		mutate(&changed)
		if changed.Matches(actual) {
			t.Fatal("replacement matched original")
		}
	}
}
func TestObservationStatsRequireTwoMonotonicSamples(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC)
	sample := container.StatsResponse{OSType: "linux", Read: now, PreRead: now.Add(-time.Second), CPUStats: container.CPUStats{CPUUsage: container.CPUUsage{TotalUsage: 150}, SystemUsage: 1000, OnlineCPUs: 2}, PreCPUStats: container.CPUStats{CPUUsage: container.CPUUsage{TotalUsage: 100}, SystemUsage: 800}, MemoryStats: container.MemoryStats{Usage: 500, Limit: 1000, Stats: map[string]uint64{"inactive_file": 100}}, Networks: map[string]container.NetworkStats{"a": {RxBytes: 20, TxBytes: 30}, "b": {RxBytes: 2, TxBytes: 3}}, PidsStats: container.PidsStats{Current: 2}, BlkioStats: container.BlkioStats{IoServiceBytesRecursive: []container.BlkioStatEntry{{Op: "Read", Value: 10}, {Op: "Write", Value: 12}, {Op: "Total", Value: 22}}}}
	got := Summarize(sample)
	if got.CPUPercent == nil || *got.CPUPercent != 50 || got.CPUStatus != "ok" || got.MemoryWorkingSetBytes == nil || *got.MemoryWorkingSetBytes != 400 || *got.NetworkRXBytes != 22 || *got.NetworkTXBytes != 33 || *got.BlockReadBytes != 10 || *got.BlockWriteBytes != 12 || *got.PIDs != 2 {
		t.Fatalf("incorrect stats: %+v", got)
	}
	for _, tc := range []struct {
		name, status string
		change       func(*container.StatsResponse)
	}{
		{"first", "warming-up", func(s *container.StatsResponse) { s.PreRead = time.Time{} }},
		{"reset", "counter-reset", func(s *container.StatsResponse) { s.CPUStats.CPUUsage.TotalUsage = 1 }},
		{"system-reset", "counter-reset", func(s *container.StatsResponse) { s.CPUStats.SystemUsage = 1 }},
		{"zero-denominator", "unavailable", func(s *container.StatsResponse) { s.CPUStats.SystemUsage = s.PreCPUStats.SystemUsage }},
		{"missing-cpus", "unavailable", func(s *container.StatsResponse) { s.CPUStats.OnlineCPUs = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := sample
			tc.change(&copy)
			got := Summarize(copy)
			if got.CPUPercent != nil || got.CPUStatus != tc.status {
				t.Fatal(got)
			}
		})
	}
	empty := Summarize(container.StatsResponse{})
	if empty.MemoryBytes != nil || empty.NetworkRXBytes != nil || empty.BlockReadBytes != nil || empty.PIDs != nil {
		t.Fatal("missing fields became zero")
	}
	sample.Networks = map[string]container.NetworkStats{"a": {RxBytes: math.MaxUint64}, "b": {RxBytes: 1}}
	if got := Summarize(sample); got.NetworkRXBytes != nil {
		t.Fatal("overflow became valid total")
	}
}
