// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"math"
	"slices"
	"testing"
	"time"

	bkclient "github.com/moby/buildkit/client"
)

func TestManualCacheSelectionScopesEntriesAndAgeWithoutDeletingLiveSharedOrInternal(t *testing.T) {
	spec, _ := testJobSpec(t)
	at := uint64(200000)
	used := time.Unix(int64(at)-86400, 0)
	u, err := NewCacheUsage(spec, at, []*bkclient.UsageInfo{
		{ID: "a-old", Size: 1, LastUsedAt: &used},
		{ID: "b-born", Size: 2, CreatedAt: time.Unix(1, 0)},
		{ID: "c-young", Size: 3, CreatedAt: time.Unix(int64(at)-86399, 0)},
		{ID: "d-unknown", Size: 4},
		{ID: "e-future", Size: 5, CreatedAt: time.Unix(int64(at)+1, 0)},
		{ID: "f-live", Size: 6, InUse: true, CreatedAt: time.Unix(1, 0)},
		{ID: "g-shared", Size: 7, Shared: true, CreatedAt: time.Unix(1, 0)},
		{ID: "h-internal", Size: 8, RecordType: bkclient.UsageRecordTypeInternal, CreatedAt: time.Unix(1, 0)},
		{ID: "i-frontend", Size: 9, RecordType: bkclient.UsageRecordTypeFrontend, CreatedAt: time.Unix(1, 0)},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		filter CachePruneFilter
		want   []string
	}{
		{CachePruneFilter{Mode: "all"}, []string{"a-old", "b-born", "c-young", "d-unknown", "e-future"}},
		{CachePruneFilter{Mode: "unused", UnusedDays: 1}, []string{"a-old", "b-born"}},
		{CachePruneFilter{Mode: "entries", IDs: []string{"a-old", "f-live", "g-shared", "h-internal", "missing"}}, []string{"a-old"}},
		{CachePruneFilter{Mode: "unused", UnusedDays: math.MaxUint32}, nil},
	} {
		s, err := SelectCachePrune(spec, u, row.filter)
		if err != nil || !s.valid() || !slices.Equal(s.IDs, row.want) || s.MaxUsedSpace != 0 {
			t.Fatal(s, row.want, err)
		}
		opts, err := s.PruneOptions()
		if len(s.IDs) == 0 {
			if err == nil {
				t.Fatal("empty selection became all prune")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		info := &bkclient.PruneInfo{}
		for _, opt := range opts {
			opt.SetPruneOption(info)
		}
		if info.All || info.MaxUsedSpace != 0 || info.KeepDuration != 0 || len(info.Filter) != len(s.IDs) {
			t.Fatal(info)
		}
	}
	newer := spec.Own()
	newer.ID = "another-job"
	if _, err := SelectCachePrune(newer, u, CachePruneFilter{Mode: "all"}); err != nil {
		t.Fatal("representative job changed same cache", err)
	}
	u.Cache[0] ^= 1
	if _, err := SelectCachePrune(spec, u, CachePruneFilter{Mode: "all"}); err == nil {
		t.Fatal("foreign cache accepted")
	}
}

func TestManualSDKStreamSharesBoundedScopeAndPreservesPartialOrForeignResults(t *testing.T) {
	for _, mode := range []string{"", "partial", "foreign"} {
		t.Run(mode, func(t *testing.T) {
			f, sdk, server := cacheCleanupFixture(t)
			server.mode = mode
			rows, err := sdk.DiskUsage(f.ctx())
			if err != nil {
				t.Fatal(err)
			}
			u, err := NewCacheUsage(f.spec, uint64(time.Now().Unix()), rows)
			if err != nil {
				t.Fatal(err)
			}
			s, err := SelectCachePrune(f.spec, u, CachePruneFilter{Mode: "all"})
			if err != nil || !slices.Equal(s.IDs, []string{"old-one", "old-two"}) {
				t.Fatal(s, err)
			}
			acks, complete := invokeSDKCachePrune(f.ctx(), sdk, s)
			if complete != (mode == "") || mode == "" && (acks.count != 2 || acks.bytes != 21) || mode == "partial" && (acks.count != 1 || acks.bytes == 0) || mode == "foreign" && (!acks.invalid || acks.count != 0) {
				t.Fatal(mode, complete, acks)
			}
			if len(server.requests) != 1 || len(server.requests[0].Filter) != 2 {
				t.Fatal("scope changed", server.requests)
			}
			// The consumer itself also refuses empty/malformed filters: a caller
			// mistake cannot turn an empty selection into SDK prune-all.
			s.IDs = nil
			if a, ok := invokeSDKCachePrune(f.ctx(), sdk, s); ok || !a.invalid {
				t.Fatal("empty invoked prune")
			}
			if len(server.requests) != 1 {
				t.Fatal("empty request reached SDK")
			}
		})
	}
}
