// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"encoding/json"
	"math"
	"slices"
	"strings"
	"unicode"

	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	bkclient "github.com/moby/buildkit/client"
)

const (
	MaxCacheEntries    = 16_384
	CachePageItems     = 32
	maxCacheUsageBytes = 16 << 20
)

type CacheQuery struct {
	Job   string
	Cache *[32]byte `json:",omitempty"`
	Node  string    `json:",omitempty"`
}

func (q CacheQuery) Valid() bool {
	if q.Job != "" {
		return lifecycle.ValidID(q.Job) && q.Cache == nil && q.Node == ""
	}
	return q.Cache != nil && *q.Cache != ([32]byte{}) && lifecycle.ValidID(q.Node)
}

// Description is deliberately not copied from BuildKit: it may include old
// RUN arguments, URLs or secrets from a previous job. Kind is the safe summary.
type CacheEntry struct {
	ID, Kind               string
	Bytes                  int64
	CreatedAt, LastUsedAt  int64
	Uses                   uint64
	InUse, Mutable, Shared bool
}

func cacheEntryID(id string) bool {
	return id != "" && len(id) <= 256 && strings.IndexFunc(id, func(r rune) bool {
		return r > unicode.MaxASCII || !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_.:-", r))
	}) < 0
}

func cacheKind(kind bkclient.UsageRecordType) string {
	switch kind {
	case bkclient.UsageRecordTypeInternal, bkclient.UsageRecordTypeFrontend, bkclient.UsageRecordTypeLocalSource, bkclient.UsageRecordTypeGitCheckout, bkclient.UsageRecordTypeCacheMount, bkclient.UsageRecordTypeRegular:
		return string(kind)
	}
	return "other"
}

func (e CacheEntry) valid() bool {
	return cacheEntryID(e.ID) && e.Bytes >= 0 && e.CreatedAt >= 0 && e.LastUsedAt >= 0 && cacheKindValid(e.Kind)
}

func cacheKindValid(kind string) bool {
	return kind == "other" || cacheKind(bkclient.UsageRecordType(kind)) == kind
}

type CacheUsage struct {
	Schema     uint8
	Cache, Job [32]byte
	At         uint64
	// ReportedBytes is a sum of SDK record sizes, including shared records.
	// It is neither filesystem allocated bytes nor a hard quota measurement.
	ReportedBytes int64
	Entries       []CacheEntry
	Maintenance   *[32]byte `json:",omitempty"`
}

func NewCacheUsage(spec JobSpec, at uint64, rows []*bkclient.UsageInfo) (CacheUsage, error) {
	u := CacheUsage{Schema: 1, Cache: CacheIdentity(spec), Job: spec.Digest(), At: at}
	if spec.Validate() != nil || at == 0 || len(rows) > MaxCacheEntries {
		return CacheUsage{}, ErrInvalid
	}
	for _, row := range rows {
		if row == nil || row.UsageCount < 0 || row.Size < 0 || row.Size > math.MaxInt64-u.ReportedBytes {
			return CacheUsage{}, ErrStorage
		}
		e := CacheEntry{ID: row.ID, Kind: cacheKind(row.RecordType), Bytes: row.Size, Uses: uint64(row.UsageCount), InUse: row.InUse, Mutable: row.Mutable, Shared: row.Shared}
		if !row.CreatedAt.IsZero() {
			e.CreatedAt = row.CreatedAt.Unix()
		}
		if row.LastUsedAt != nil && !row.LastUsedAt.IsZero() {
			e.LastUsedAt = row.LastUsedAt.Unix()
		}
		if !e.valid() {
			return CacheUsage{}, ErrStorage
		}
		u.ReportedBytes += e.Bytes
		u.Entries = append(u.Entries, e)
	}
	slices.SortFunc(u.Entries, func(a, b CacheEntry) int { return strings.Compare(a.ID, b.ID) })
	if !u.valid(u.Cache) {
		return CacheUsage{}, ErrStorage
	}
	return u, nil
}

func (u CacheUsage) valid(cache [32]byte) bool {
	if u.Schema != 1 || cache == ([32]byte{}) || u.Cache != cache || u.Job == ([32]byte{}) || u.At == 0 || u.ReportedBytes < 0 || len(u.Entries) > MaxCacheEntries || u.Maintenance != nil && *u.Maintenance == ([32]byte{}) {
		return false
	}
	var total int64
	for i, e := range u.Entries {
		if !e.valid() || i > 0 && u.Entries[i-1].ID >= e.ID || e.Bytes > math.MaxInt64-total {
			return false
		}
		total += e.Bytes
	}
	return total == u.ReportedBytes
}

func (u CacheUsage) Digest() [32]byte { return digestJSON("sfc-imagebuild-cache-usage-1", u) }

func (u CacheUsage) observer() ([32]byte, string) {
	if u.Maintenance != nil {
		return *u.Maintenance, "cache-prune"
	}
	return u.Job, ""
}

type CachePage struct {
	Schema                      uint8
	Cache, Snapshot, ObservedBy [32]byte
	Available, Borrowed         bool
	LastAttemptAt               uint64
	LastAttemptCode             string
	ObservedAt                  uint64
	ReportedBytes               int64
	Count, Offset, Next         uint32
	Entries                     []CacheEntry
	Cleanup                     *CacheCleanupStatus `json:",omitempty"`
	ObservedKind                string              `json:",omitempty"`
}

func (p CachePage) Valid(cache [32]byte, offset uint32, snapshot [32]byte) bool {
	if p.Schema != 1 || p.Cache != cache || cache == ([32]byte{}) || p.Offset != offset || len(p.Entries) > CachePageItems || p.LastAttemptCode != "" && p.LastAttemptCode != "OK" && p.LastAttemptCode != "UNAVAILABLE" || (p.LastAttemptAt == 0) != (p.LastAttemptCode == "") || p.Cleanup != nil && !p.Cleanup.Valid(cache) || p.ObservedKind != "" && p.ObservedKind != "cache-prune" || !p.Available && p.ObservedKind != "" {
		return false
	}
	if !p.Available {
		return p.LastAttemptCode != "OK" && offset == 0 && snapshot == ([32]byte{}) && p.Snapshot == ([32]byte{}) && p.ObservedBy == ([32]byte{}) && p.ObservedAt == 0 && p.ReportedBytes == 0 && p.Count == 0 && p.Next == 0 && len(p.Entries) == 0
	}
	if p.LastAttemptAt == 0 || p.LastAttemptCode == "" || p.LastAttemptCode == "OK" && p.LastAttemptAt != p.ObservedAt || p.Snapshot == ([32]byte{}) || snapshot != ([32]byte{}) && p.Snapshot != snapshot || p.ObservedBy == ([32]byte{}) || p.ObservedAt == 0 || p.ReportedBytes < 0 || p.Count > MaxCacheEntries || offset > p.Count {
		return false
	}
	end := min(p.Count, offset+CachePageItems)
	if uint32(len(p.Entries)) != end-offset || end < p.Count && p.Next != end || end == p.Count && p.Next != 0 {
		return false
	}
	var total int64
	for i, e := range p.Entries {
		if !e.valid() || i > 0 && p.Entries[i-1].ID >= e.ID || e.Bytes > math.MaxInt64-total {
			return false
		}
		total += e.Bytes
	}
	return total <= p.ReportedBytes
}

func (u CacheUsage) Page(offset uint32, snapshot [32]byte, borrowed bool) (CachePage, error) {
	if !u.valid(u.Cache) || offset > uint32(len(u.Entries)) {
		return CachePage{}, ErrStorage
	}
	hash := u.Digest()
	if snapshot != ([32]byte{}) && snapshot != hash {
		return CachePage{}, ErrConflict
	}
	end := min(uint32(len(u.Entries)), offset+CachePageItems)
	p := CachePage{Schema: 1, Cache: u.Cache, Snapshot: hash, ObservedBy: u.Job, Available: true, Borrowed: borrowed, ObservedAt: u.At, LastAttemptAt: u.At, LastAttemptCode: "OK", ReportedBytes: u.ReportedBytes, Count: uint32(len(u.Entries)), Offset: offset, Entries: slices.Clone(u.Entries[offset:end])}
	p.ObservedBy, p.ObservedKind = u.observer()
	if end < p.Count {
		p.Next = end
	}
	raw, err := json.Marshal(p)
	if err != nil || len(raw) > 24<<10 || !p.Valid(u.Cache, offset, snapshot) {
		return CachePage{}, ErrStorage
	}
	return p, nil
}
