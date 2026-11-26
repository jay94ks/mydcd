// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"math"
	"slices"
	"strconv"

	bkclient "github.com/moby/buildkit/client"
)

// CacheCleanupSelection is ephemeral. Only its digest/count and fixed SDK
// options go into the original operation's native receipt, never RUN descriptions.
type CacheCleanupSelection struct {
	Kind         string
	Snapshot     [32]byte
	IDs          []string
	MaxUsedSpace int64
}

func cacheCleanupTarget(p Policy) int64 {
	// Avoid overflow for the full valid int64 policy range. SDK 0 means
	// unlimited, so the smallest positive capacity has a one-byte target.
	return max(1, p.CacheBytes/100*int64(p.Cleanup.HighWaterPercent)+p.CacheBytes%100*int64(p.Cleanup.HighWaterPercent)/100)
}

func SelectCacheCleanup(spec JobSpec, u CacheUsage, kind string) (CacheCleanupSelection, error) {
	return SelectCacheCleanupPolicy(spec, u, kind, spec.Policy)
}

func cachePolicyMatchesSource(spec JobSpec, policy Policy) bool {
	return policy.Validate(spec.Cluster) == nil && policy.Tenant == spec.Tenant && policy.BuilderImage == spec.Policy.BuilderImage && slices.Contains(policy.Nodes, NodeRoot{Node: spec.Scope.Root.Node, Root: spec.Scope.Root})
}

// A periodic pass uses today's accepted cleanup policy while retaining the
// original immutable cache/job identity. Never edit a JobSpec to select it.
func SelectCacheCleanupPolicy(spec JobSpec, u CacheUsage, kind string, policy Policy) (CacheCleanupSelection, error) {
	out := CacheCleanupSelection{Kind: kind, Snapshot: u.Digest()}
	if spec.Validate() != nil || !cachePolicyMatchesSource(spec, policy) || !u.valid(CacheIdentity(spec)) || u.Job != spec.Digest() || kind != "age" && kind != "size" {
		return CacheCleanupSelection{}, ErrInvalid
	}
	var private int64
	for _, e := range u.Entries {
		if !e.Shared {
			private += e.Bytes
		}
	}
	if kind == "size" {
		out.MaxUsedSpace = cacheCleanupTarget(policy)
		if private <= out.MaxUsedSpace {
			return out, nil
		}
	}
	age := uint64(policy.Cleanup.UnusedDays) * 86400
	for _, e := range u.Entries {
		if e.InUse || e.Shared || e.Kind == "internal" || e.Kind == "frontend" {
			continue
		}
		if kind == "age" {
			used := e.LastUsedAt
			if used == 0 {
				used = e.CreatedAt
			}
			if used <= 0 || age > u.At || uint64(used) > u.At-age {
				continue
			}
		}
		out.IDs = append(out.IDs, e.ID)
	}
	return out, nil
}

func (s CacheCleanupSelection) valid() bool {
	if s.Snapshot == ([32]byte{}) || len(s.IDs) > MaxCacheEntries {
		return false
	}
	switch s.Kind {
	case "size":
		if s.MaxUsedSpace <= 0 {
			return false
		}
	case "age", "manual-all", "manual-unused", "manual-entries":
		if s.MaxUsedSpace != 0 {
			return false
		}
	default:
		return false
	}
	for i, id := range s.IDs {
		if !cacheEntryID(id) || i > 0 && s.IDs[i-1] >= id {
			return false
		}
	}
	return true
}
func (s CacheCleanupSelection) Digest() [32]byte {
	return digestJSON("mydc-imagebuild-cache-cleanup-selection-1", s)
}
func (s CacheCleanupSelection) PruneOptions() ([]bkclient.PruneOption, error) {
	if !s.valid() || len(s.IDs) == 0 {
		return nil, ErrInvalid
	}
	var filters []string
	for _, id := range s.IDs {
		filters = append(filters, "id=="+strconv.Quote(id))
	}
	// Separate filters mean OR in the adopted SDK. Empty filters mean ALL and
	// are therefore refused above. Do not enable PruneAll/shared deletion.
	return []bkclient.PruneOption{bkclient.WithFilter(filters), bkclient.WithKeepOpt(0, 0, s.MaxUsedSpace, 0)}, nil
}

type CacheCleanupStep struct {
	Kind                string
	Snapshot, Selection [32]byte
	Selected            uint32
	MaxUsedSpace        int64
	SentAt, ReturnedAt  uint64
	Code                string
	// Only positively received SDK records. Partial/unknown streams do not
	// prove total reclaimed bytes or absence of additional removed records.
	RemovedCount  uint32
	ReportedBytes int64
}

func (s CacheCleanupStep) valid() bool {
	if !(CacheCleanupSelection{Kind: s.Kind, Snapshot: s.Snapshot, MaxUsedSpace: s.MaxUsedSpace}).valid() || s.Selection == ([32]byte{}) || s.Selected > MaxCacheEntries || s.RemovedCount > s.Selected || s.ReportedBytes < 0 {
		return false
	}
	switch s.Code {
	case "SKIPPED":
		return s.Selected == 0 && s.SentAt == 0 && s.ReturnedAt == 0 && s.RemovedCount == 0 && s.ReportedBytes == 0
	case "NOT_AUTHORIZED":
		return s.Selected > 0 && s.SentAt == 0 && s.ReturnedAt == 0 && s.RemovedCount == 0 && s.ReportedBytes == 0
	case "OK":
		return s.Selected > 0 && s.SentAt > 0 && s.ReturnedAt > 0
	case "UNKNOWN":
		return s.Selected > 0 && s.SentAt > 0 && (s.ReturnedAt > 0 || s.RemovedCount == 0 && s.ReportedBytes == 0)
	}
	return false
}

type CacheCleanupStatus struct {
	Schema     uint8
	Cache, Job [32]byte
	Steps      []CacheCleanupStep
}

func (s CacheCleanupStatus) Valid(cache [32]byte) bool {
	if s.Schema != 1 || cache == ([32]byte{}) || s.Cache != cache || s.Job == ([32]byte{}) || len(s.Steps) == 0 || len(s.Steps) > 2 {
		return false
	}
	for i, step := range s.Steps {
		if !step.valid() || i == 0 && step.Kind != "age" || i == 1 && (step.Kind != "size" || s.Steps[0].Code != "OK" && s.Steps[0].Code != "SKIPPED") {
			return false
		}
	}
	return true
}

type cacheCleanupAcks struct {
	selected, seen map[string]bool
	count          uint32
	bytes          int64
	byteLimit      int64
	invalid        bool
}

func newCacheCleanupAcks(s CacheCleanupSelection) *cacheCleanupAcks {
	a := &cacheCleanupAcks{selected: map[string]bool{}, seen: map[string]bool{}, byteLimit: math.MaxInt64}
	for _, id := range s.IDs {
		a.selected[id] = true
	}
	return a
}
func (a *cacheCleanupAcks) add(row bkclient.UsageInfo) bool {
	if a.invalid || !a.selected[row.ID] || a.seen[row.ID] || row.InUse || row.Shared || row.Size < 0 || row.Size > a.byteLimit-a.bytes {
		a.invalid = true
		return false
	}
	a.seen[row.ID] = true
	a.count++
	a.bytes += row.Size
	return true
}
