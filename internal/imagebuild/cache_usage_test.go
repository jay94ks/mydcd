// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	bkclient "github.com/moby/buildkit/client"
)

func TestCacheUsageOmitsOpaqueDescriptionsAndRejectsAmbiguousInventory(t *testing.T) {
	spec, _ := testJobSpec(t)
	rows := []*bkclient.UsageInfo{{ID: "record-one", Size: 31, RecordType: bkclient.UsageRecordTypeRegular, Description: "RUN PASSWORD=never-persist-this", CreatedAt: time.Unix(100, 0), Shared: true}}
	u, err := NewCacheUsage(spec, 200, rows)
	if err != nil || u.ReportedBytes != 31 || len(u.Entries) != 1 || !u.Entries[0].Shared {
		t.Fatal(u, err)
	}
	raw, _ := json.Marshal(u)
	if strings.Contains(string(raw), "PASSWORD") || strings.Contains(string(raw), "never-persist-this") || strings.Contains(string(raw), "RUN") {
		t.Fatal("opaque SDK description retained")
	}
	for _, bad := range [][]*bkclient.UsageInfo{
		{nil}, {rows[0], rows[0]}, {{ID: "../escape", Size: 1}}, {{ID: "valid", Size: -1}},
		{{ID: "a", Size: math.MaxInt64}, {ID: "b", Size: 1}}, {{ID: "a", UsageCount: -1}},
	} {
		if _, err := NewCacheUsage(spec, 201, bad); err == nil {
			t.Fatal("invalid SDK inventory accepted")
		}
	}
	rows[0].ID = "changed"
	if u.Entries[0].ID != "record-one" {
		t.Fatal("SDK input aliases durable observation")
	}
}

func TestCachePagesBindTheOriginalObservationAndKeepUnavailableDistinctFromEmpty(t *testing.T) {
	spec, _ := testJobSpec(t)
	var rows []*bkclient.UsageInfo
	for i := 0; i < CachePageItems+1; i++ {
		rows = append(rows, &bkclient.UsageInfo{ID: fmt.Sprintf("record-%03d", i), Size: 1})
	}
	u, err := NewCacheUsage(spec, 200, rows)
	if err != nil {
		t.Fatal(err)
	}
	p, err := u.Page(0, [32]byte{}, true)
	if err != nil || !p.Borrowed || p.Next != CachePageItems {
		t.Fatal(p, err)
	}
	p.Entries[0].ID = "caller-mutated"
	if u.Entries[0].ID == p.Entries[0].ID {
		t.Fatal("page aliases stored inventory")
	}
	last, err := u.Page(p.Next, p.Snapshot, false)
	if err != nil || len(last.Entries) != 1 || last.Next != 0 {
		t.Fatal(last, err)
	}
	u.At++
	if _, err := u.Page(p.Next, p.Snapshot, false); err != ErrConflict {
		t.Fatal("new observation accepted old cursor", err)
	}
	empty, err := NewCacheUsage(spec, 202, nil)
	if err != nil {
		t.Fatal(err)
	}
	page, err := empty.Page(0, [32]byte{}, false)
	if err != nil || !page.Available || page.Count != 0 || page.Snapshot == ([32]byte{}) {
		t.Fatal("actual empty cache not observed", page, err)
	}
	unobserved := CachePage{Schema: 1, Cache: CacheIdentity(spec)}
	if !unobserved.Valid(CacheIdentity(spec), 0, [32]byte{}) || unobserved.Valid(CacheIdentity(spec), 1, [32]byte{1}) {
		t.Fatal("unobserved/old cursor conflated")
	}
	page.LastAttemptCode = ""
	if page.Valid(CacheIdentity(spec), 0, [32]byte{}) {
		t.Fatal("observation without attempt accepted")
	}
}

func TestCacheObservationProvenancePreservesLegacyBytesAndRejectsUnknownKinds(t *testing.T) {
	spec, _ := testJobSpec(t)
	u, err := NewCacheUsage(spec, 200, nil)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := json.Marshal(struct {
		Schema        uint8
		Cache, Job    [32]byte
		At            uint64
		ReportedBytes int64
		Entries       []CacheEntry
	}{u.Schema, u.Cache, u.Job, u.At, u.ReportedBytes, u.Entries})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(u)
	if string(raw) != string(legacy) {
		t.Fatal("nil maintenance changed legacy schema-1 bytes", string(raw))
	}
	oldHash := u.Digest()
	intent := [32]byte{9}
	u.Maintenance = &intent
	if !u.valid(u.Cache) || u.Digest() == oldHash {
		t.Fatal("maintenance provenance not bound in snapshot")
	}
	page, err := u.Page(0, [32]byte{}, false)
	if err != nil || page.ObservedKind != "cache-prune" || page.ObservedBy != intent {
		t.Fatal(page, err)
	}
	summary, err := u.Summary(true, true, false)
	if err != nil || summary.ObservedKind != page.ObservedKind || summary.Snapshot != page.Snapshot {
		t.Fatal(summary, err)
	}
	page.ObservedKind = "future"
	if page.Valid(u.Cache, 0, [32]byte{}) {
		t.Fatal("unknown observation kind accepted")
	}
	summary.Available = false
	if summary.Valid(u.Cache) {
		t.Fatal("unavailable summary retained fake producer")
	}
	zero := [32]byte{}
	u.Maintenance = &zero
	if u.valid(u.Cache) {
		t.Fatal("empty maintenance identity accepted")
	}
}
