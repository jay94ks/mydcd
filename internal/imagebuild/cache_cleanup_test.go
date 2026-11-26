// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"math"
	"slices"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/pkg/filters"
	bkclient "github.com/moby/buildkit/client"
)

func TestAutomaticCacheSelectionHonorsAgeFallbackAndNeverUsesAnEmptyAllFilter(t *testing.T) {
	spec, _ := testJobSpec(t)
	spec.Policy.Cleanup.UnusedDays = 1
	spec.Policy.CacheBytes = 100
	at := uint64(200_000)
	timep := func(seconds int64) *time.Time { v := time.Unix(seconds, 0); return &v }
	u, err := NewCacheUsage(spec, at, []*bkclient.UsageInfo{
		{ID: "old", Size: 3, LastUsedAt: timep(int64(at) - 86400)},
		{ID: "born-old", Size: 4, CreatedAt: time.Unix(100, 0)},
		{ID: "young", Size: 5, CreatedAt: time.Unix(int64(at)-86399, 0)},
		{ID: "unknown-age", Size: 6}, {ID: "future", Size: 7, LastUsedAt: timep(int64(at) + 1)},
		{ID: "busy", Size: 100, CreatedAt: time.Unix(100, 0), InUse: true},
		{ID: "shared", Size: 100, CreatedAt: time.Unix(100, 0), Shared: true},
		{ID: "frontend", Size: 100, CreatedAt: time.Unix(100, 0), RecordType: bkclient.UsageRecordTypeFrontend},
	})
	if err != nil {
		t.Fatal(err)
	}
	age, err := SelectCacheCleanup(spec, u, "age")
	if err != nil || !slices.Equal(age.IDs, []string{"born-old", "old"}) {
		t.Fatal(age, err)
	}
	opts, err := age.PruneOptions()
	if err != nil {
		t.Fatal(err)
	}
	info := &bkclient.PruneInfo{}
	for _, opt := range opts {
		opt.SetPruneOption(info)
	}
	if info.All || info.KeepDuration != 0 || info.MaxUsedSpace != 0 || len(info.Filter) != 2 {
		t.Fatal("unexpected prune scope", info)
	}
	parsed, err := filters.ParseAll(info.Filter...)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"born-old", "old", "busy", "foreign"} {
		match := parsed.Match(filters.AdapterFunc(func(fields []string) (string, bool) { return id, len(fields) == 1 && fields[0] == "id" }))
		if match != (id == "born-old" || id == "old") {
			t.Fatal("SDK filter changed ID union", id, match)
		}
	}
	age.IDs = nil
	if _, err := age.PruneOptions(); err == nil {
		t.Fatal("empty selection became unbounded prune")
	}
	size, err := SelectCacheCleanup(spec, u, "size")
	if err != nil || size.MaxUsedSpace != 80 || slices.Contains(size.IDs, "shared") || slices.Contains(size.IDs, "busy") || slices.Contains(size.IDs, "frontend") {
		t.Fatal(size, err)
	}
	spec.Policy.CacheBytes = math.MaxInt64
	if got := cacheCleanupTarget(spec.Policy); got != math.MaxInt64/100*80+math.MaxInt64%100*80/100 {
		t.Fatal("target overflow", got)
	}
	spec.Policy.CacheBytes = 1
	if got := cacheCleanupTarget(spec.Policy); got != 1 {
		t.Fatal("zero SDK target means unlimited", got)
	}
}

func TestCacheCleanupAcksRejectForeignDuplicateAndActiveRecordsWithoutHidingKnownPrefix(t *testing.T) {
	s := CacheCleanupSelection{IDs: []string{"one", "two"}}
	for _, bad := range []bkclient.UsageInfo{{ID: "foreign", Size: 10}, {ID: "one", Size: 10}, {ID: "two", Size: -1}, {ID: "two", Size: 10, InUse: true}, {ID: "two", Size: 10, Shared: true}} {
		acks := newCacheCleanupAcks(s)
		if !acks.add(bkclient.UsageInfo{ID: "one", Size: 5}) || acks.add(bad) || !acks.invalid || acks.count != 1 || acks.bytes != 5 {
			t.Fatal("invalid stream erased trusted prefix", acks)
		}
	}
}

func TestCacheCleanupReceiptDoesNotTreatSentAsCompletedOrSkipAnUnknownPhase(t *testing.T) {
	step := CacheCleanupStep{Kind: "age", Snapshot: [32]byte{1}, Selection: [32]byte{2}, Selected: 2, SentAt: 100, Code: "UNKNOWN"}
	status := CacheCleanupStatus{Schema: 1, Cache: [32]byte{3}, Job: [32]byte{4}, Steps: []CacheCleanupStep{step}}
	if !status.Valid(status.Cache) {
		t.Fatal("original unknown intent rejected")
	}
	size := CacheCleanupStep{Kind: "size", Snapshot: [32]byte{1}, Selection: [32]byte{2}, Selected: 0, MaxUsedSpace: 10, Code: "SKIPPED"}
	status.Steps = append(status.Steps, size)
	if status.Valid(status.Cache) {
		t.Fatal("unknown age silently bypassed")
	}
	status.Steps = status.Steps[:1]
	status.Steps[0].Code = "OK"
	if status.Valid(status.Cache) {
		t.Fatal("missing completion fabricated success")
	}
	status.Steps[0].ReturnedAt = 101
	if !status.Valid(status.Cache) {
		t.Fatal("positive stream EOF rejected")
	}
}
