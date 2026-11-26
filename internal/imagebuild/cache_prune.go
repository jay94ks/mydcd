// SPDX-License-Identifier: Apache-2.0

package imagebuild

import "slices"

// CachePruneFilter is the user's exact intent, not a cached InUse verdict.
// Live SDK selection and prune still run under the original cache owner.
type CachePruneFilter struct {
	Mode       string
	IDs        []string `json:",omitempty"`
	UnusedDays uint32   `json:",omitempty"`
}

func (f CachePruneFilter) Valid() bool {
	switch f.Mode {
	case "all":
		return len(f.IDs) == 0 && f.UnusedDays == 0
	case "unused":
		return len(f.IDs) == 0 && f.UnusedDays > 0
	case "entries":
		if len(f.IDs) == 0 || len(f.IDs) > 64 || f.UnusedDays != 0 {
			return false
		}
		for i, id := range f.IDs {
			if !cacheEntryID(id) || i > 0 && f.IDs[i-1] >= id {
				return false
			}
		}
		return true
	}
	return false
}
func (f CachePruneFilter) Own() CachePruneFilter { f.IDs = slices.Clone(f.IDs); return f }

// SelectCachePrune consumes a fresh owner-held SDK inventory. An older build
// may have produced the observation in the same cache namespace; its Job ID
// is not a request to recreate or rerun it. Native dispatch must still own
// the cache and durably record this selection before invoking the SDK.
func SelectCachePrune(spec JobSpec, u CacheUsage, f CachePruneFilter) (CacheCleanupSelection, error) {
	if spec.Validate() != nil || !u.valid(CacheIdentity(spec)) || !f.Valid() {
		return CacheCleanupSelection{}, ErrInvalid
	}
	out := CacheCleanupSelection{Kind: "manual-" + f.Mode, Snapshot: u.Digest()}
	for _, e := range u.Entries {
		if e.InUse || e.Shared || e.Kind == "internal" || e.Kind == "frontend" {
			continue
		}
		if f.Mode == "entries" {
			if _, found := slices.BinarySearch(f.IDs, e.ID); !found {
				continue
			}
		}
		if f.Mode == "unused" {
			used := e.LastUsedAt
			if used == 0 {
				used = e.CreatedAt
			}
			age := uint64(f.UnusedDays) * 86400
			if used <= 0 || age > u.At || uint64(used) > u.At-age {
				continue
			}
		}
		out.IDs = append(out.IDs, e.ID)
	}
	return out, nil
}
