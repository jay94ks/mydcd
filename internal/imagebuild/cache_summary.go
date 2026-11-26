// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"math"
	"slices"
	"strings"
)

type CacheKindUsage struct {
	Kind                       string
	Count, InUse               uint32
	ReportedBytes, SharedBytes int64
}

// Recorded/Allocated refer to the original native journal, not a new live
// filesystem walk. All size/category fields are from the timestamped SDK read.
type CacheSummary struct {
	Schema                                   uint8
	Cache, Snapshot, ObservedBy              [32]byte
	Recorded, Allocated, Available, Borrowed bool
	ObservedAt, LastAttemptAt                uint64
	LastAttemptCode                          string
	ReportedBytes                            int64
	Count                                    uint32
	Kinds                                    []CacheKindUsage
	Cleanup                                  *CacheCleanupStatus `json:",omitempty"`
	ObservedKind                             string              `json:",omitempty"`
}

func (u CacheUsage) Summary(recorded, allocated, borrowed bool) (CacheSummary, error) {
	if !u.valid(u.Cache) || !recorded || !allocated {
		return CacheSummary{}, ErrStorage
	}
	out := CacheSummary{Schema: 1, Cache: u.Cache, Snapshot: u.Digest(), ObservedBy: u.Job, Recorded: recorded, Allocated: allocated, Available: true, Borrowed: borrowed, ObservedAt: u.At, LastAttemptAt: u.At, LastAttemptCode: "OK", ReportedBytes: u.ReportedBytes, Count: uint32(len(u.Entries))}
	out.ObservedBy, out.ObservedKind = u.observer()
	byKind := map[string]CacheKindUsage{}
	for _, e := range u.Entries {
		k := byKind[e.Kind]
		k.Kind = e.Kind
		k.Count++
		k.ReportedBytes += e.Bytes
		if e.InUse {
			k.InUse++
		}
		if e.Shared {
			k.SharedBytes += e.Bytes
		}
		byKind[e.Kind] = k
	}
	for _, k := range byKind {
		out.Kinds = append(out.Kinds, k)
	}
	slices.SortFunc(out.Kinds, func(a, b CacheKindUsage) int { return strings.Compare(a.Kind, b.Kind) })
	if !out.Valid(u.Cache) {
		return CacheSummary{}, ErrStorage
	}
	return out, nil
}

func (s CacheSummary) Valid(cache [32]byte) bool {
	if s.Schema != 1 || cache == ([32]byte{}) || s.Cache != cache || s.Allocated && !s.Recorded || s.Borrowed && !s.Recorded || s.LastAttemptCode != "" && s.LastAttemptCode != "OK" && s.LastAttemptCode != "UNAVAILABLE" || (s.LastAttemptAt == 0) != (s.LastAttemptCode == "") || s.LastAttemptAt != 0 && !s.Recorded || s.Cleanup != nil && (!s.Recorded || !s.Cleanup.Valid(cache)) || s.ObservedKind != "" && s.ObservedKind != "cache-prune" || !s.Available && s.ObservedKind != "" {
		return false
	}
	if !s.Available {
		return s.LastAttemptCode != "OK" && s.Snapshot == ([32]byte{}) && s.ObservedBy == ([32]byte{}) && s.ObservedAt == 0 && s.ReportedBytes == 0 && s.Count == 0 && len(s.Kinds) == 0
	}
	if !s.Recorded || !s.Allocated || s.Snapshot == ([32]byte{}) || s.ObservedBy == ([32]byte{}) || s.ObservedAt == 0 || s.LastAttemptAt == 0 || s.LastAttemptCode == "" || s.LastAttemptCode == "OK" && s.LastAttemptAt != s.ObservedAt || s.ReportedBytes < 0 || s.Count > MaxCacheEntries || len(s.Kinds) > 7 {
		return false
	}
	var count uint32
	var bytes int64
	for i, k := range s.Kinds {
		if !cacheKindValid(k.Kind) || k.Count == 0 || k.Count > MaxCacheEntries-count || k.InUse > k.Count || k.ReportedBytes < 0 || k.ReportedBytes > math.MaxInt64-bytes || k.SharedBytes < 0 || k.SharedBytes > k.ReportedBytes || i > 0 && s.Kinds[i-1].Kind >= k.Kind {
			return false
		}
		count += k.Count
		bytes += k.ReportedBytes
	}
	return count == s.Count && bytes == s.ReportedBytes
}
