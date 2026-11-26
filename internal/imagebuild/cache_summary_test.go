// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"testing"

	bkclient "github.com/moby/buildkit/client"
)

func TestCacheSummaryGroupsSDKKindsWithoutDoubleCountingSharedRecords(t *testing.T) {
	spec, _ := testJobSpec(t)
	u, err := NewCacheUsage(spec, 100, []*bkclient.UsageInfo{{ID: "one", Size: 3, RecordType: bkclient.UsageRecordTypeRegular, InUse: true}, {ID: "two", Size: 5, RecordType: bkclient.UsageRecordTypeRegular, Shared: true}, {ID: "three", Size: 7, RecordType: bkclient.UsageRecordTypeCacheMount}})
	if err != nil {
		t.Fatal(err)
	}
	s, err := u.Summary(true, true, true)
	if err != nil || !s.Valid(u.Cache) || s.Count != 3 || s.ReportedBytes != 15 || len(s.Kinds) != 2 || s.Kinds[1].Kind != "regular" || s.Kinds[1].InUse != 1 || s.Kinds[1].SharedBytes != 5 || s.Kinds[1].ReportedBytes != 8 {
		t.Fatal(s, err)
	}
	if _, err := u.Summary(false, false, false); err == nil {
		t.Fatal("observation without original allocation accepted")
	}
	copy := s
	copy.Kinds = append([]CacheKindUsage(nil), s.Kinds...)
	copy.Kinds[0].ReportedBytes++
	if copy.Valid(u.Cache) {
		t.Fatal("incorrect grouped total accepted")
	}
	missing := CacheSummary{Schema: 1, Cache: u.Cache}
	if !missing.Valid(u.Cache) {
		t.Fatal("unrecorded namespace rejected")
	}
	missing.LastAttemptCode = "OK"
	if missing.Valid(u.Cache) {
		t.Fatal("missing namespace fabricated an empty observation")
	}
}
