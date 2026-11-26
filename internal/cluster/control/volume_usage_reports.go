// SPDX-License-Identifier: Apache-2.0

package control

import (
	"slices"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/observability"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

// OwnedVolume is a current, converged volume whose native owner key is one
// the caller holds. Key is the volumes row key (Scope.Key()).
type OwnedVolume struct {
	Key   string
	Ready volumes.NativeReady
}

// OwnedVolumes lists, in key order, the live volumes whose registered native
// owner is still the current owner of its node and is held by the caller
// (holds). The periodic usage scan uses it; it grants no read or writer.
func (p Policy) OwnedVolumes(s state.State, holds func([32]byte) bool) ([]OwnedVolume, error) {
	policy, err := p.Current(s)
	if err != nil {
		return nil, err
	}
	p = policy
	v, err := p.Volumes(s)
	if err != nil {
		return nil, err
	}
	var out []OwnedVolume
	for key, e := range v.entries {
		if e.State.Deleted() || e.State.Deleting() || e.Native.Verify() != nil {
			continue
		}
		owner, _ := e.State.Owner()
		if e.Native.Owner != owner || !holds(owner.Key) {
			continue
		}
		current, err := p.nodeOwner(s, owner.Node)
		if err != nil || !p.ownsResource(s, current, owner.Key) {
			continue
		}
		out = append(out, OwnedVolume{Key: key, Ready: e.Native})
	}
	slices.SortFunc(out, func(a, b OwnedVolume) int {
		if a.Key < b.Key {
			return -1
		}
		if a.Key > b.Key {
			return 1
		}
		return 0
	})
	return out, nil
}

// AttachVolumeUsage fills UsedBytes/UsageObservedAt of `volumes` rows from
// the owner's volume usage reports: the report must come from the row's
// owner node, name the row key and its exact native binding, be fresh (the
// owner is still publishing) and its scan no older than
// observability.VolumeUsageMaxAge. Anything else leaves the row unknown
// (UsedBytes nil); unknown is never zero.
func AttachVolumeUsage(rows []VolumeView, reports []observability.Report, now uint64) {
	at := map[string]int{}
	for i, r := range rows {
		if r.NativeBinding != ([32]byte{}) {
			at[r.Key] = i
		}
	}
	for _, report := range reports {
		u := report.Volume
		if u == nil {
			continue
		}
		i, ok := at[u.Key]
		if !ok {
			continue
		}
		row := &rows[i]
		if report.Node != row.Owner.Node || u.Binding != row.NativeBinding || !observability.Fresh(report.At, now) || u.ScannedAt > now || now-u.ScannedAt > observability.VolumeUsageMaxAge || u.ScannedAt <= row.UsageObservedAt {
			continue
		}
		bytes := u.AllocatedBytes
		row.UsedBytes, row.UsageObservedAt = &bytes, u.ScannedAt
	}
}
