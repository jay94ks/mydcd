// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/json"
	"strings"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// OriginalVolumeLimit is an admission reservation. It is never a filesystem
// quota. A nil policy on an old checkpoint is unreserved observation, not zero
// measured usage. An explicit zero limit denies new reservations.
type OriginalVolumeLimit struct {
	Bytes uint64
	Count uint32
}

// VolumeCapacity maps an already registered native to an explicit reservation.
// The original owner-signed NativeReady digest fences identity replacement.
type VolumeCapacity struct {
	Scope  volumes.Scope
	Native [32]byte
	Bytes  uint64
}

type volumeStorageHold struct {
	tenant, node string
	owner        [32]byte
	bytes        uint64
}

func (v Volumes) originalHolds(s state.State) (map[string]volumeStorageHold, error) {
	holds := map[string]volumeStorageHold{}
	for key, e := range v.entries {
		if e.CapacityBytes > 1<<40 {
			return nil, ErrCatalog
		}
		if !e.State.Deleted() {
			holds[key] = volumeStorageHold{e.Native.Spec.Scope.Tenant, e.Native.Spec.Node, e.Native.Spec.NodeKey, e.CapacityBytes}
		}
	}
	add := func(scope volumes.Scope, node string, owner [32]byte, bytes uint64) error {
		key := volumeKey(scope)
		if _, duplicate := holds[key]; duplicate {
			return ErrCatalog
		}
		holds[key] = volumeStorageHold{scope.Tenant, node, owner, bytes}
		return nil
	}
	for _, j := range v.creations {
		if creationPending(j.Phase) {
			bytes, err := creationBytes(j)
			if err != nil || add(j.Spec.Scope, j.Spec.Node, j.Spec.NodeKey, bytes) != nil {
				return nil, ErrCatalog
			}
		}
	}
	for _, j := range v.restores {
		if restorePending(j.Phase) && add(j.Binding.Target.Scope, j.Binding.Target.Node, j.Binding.Target.NodeKey, j.Binding.CapacityBytes) != nil {
			return nil, ErrCatalog
		}
	}
	for _, j := range v.moves {
		_, m, ok := v.Move(j.Selection())
		if !ok {
			return nil, ErrCatalog
		}
		if m.Phase == volumes.Cancelled {
			continue
		}
		if m.SourceDeletion != nil && m.SourceDeletion.Gone != nil {
			continue
		}
		owner, bytes := j.Binding.Target, j.CapacityBytes
		if m.CommitRevision != 0 {
			owner, bytes = j.Binding.Source, j.SourceCapacity
		}
		// A physical target/source copy is additional storage for the same
		// logical Volume; it must not overwrite that Volume's original hold.
		key := "move/" + moveKey(j.Selection())
		holds[key] = volumeStorageHold{j.Binding.Scope.Tenant, owner.Node, owner.Key, bytes}
	}
	for key, object := range s.Objects("workload/volume/") {
		if !object.Present {
			continue
		}
		var g deployment.GoalCommand
		if json.Unmarshal([]byte(object.Value), &g) != nil || g.Kind != "volume" {
			continue
		} // old raw native objects have no managed Goal
		id := key[strings.LastIndex(key, "/")+1:]
		logical := volumeKey(volumes.Scope{Tenant: g.Tenant, App: g.App, ID: id})
		if key != deployment.ResourceKey("volume", g.Tenant, g.App, id) {
			return nil, ErrCatalog
		}
		var q deployment.ComposeVolume
		if canonical(g.Config, &q) != nil || uint64(q.Sfc.Capacity) > 1<<40 {
			return nil, ErrCatalog
		}
		if e, exists := v.entries[logical]; exists {
			// A retained Goal is not a second physical volume, even after explicit Gone.
			if e.Native.Spec.Node != g.Node || e.Native.Spec.NodeKey != g.Owner {
				if !v.originalGoalRetainedByMove(e.State.Scope(), g, uint64(q.Sfc.Capacity)) {
					return nil, ErrCatalog
				}
				continue
			}
			if uint64(q.Sfc.Capacity) > e.CapacityBytes {
				return nil, ErrCatalog
			}
			continue
		}
		if !v.admitOriginal(g.Tenant, g.Node, g.Owner, uint64(q.Sfc.Capacity)) {
			return nil, ErrCatalog
		}
		if add(volumes.Scope{Tenant: g.Tenant, App: g.App, ID: id}, g.Node, g.Owner, uint64(q.Sfc.Capacity)) != nil {
			return nil, ErrCatalog
		}
	}
	return holds, nil
}

// A committed move retains the old physical source and its old Goal. This
// preserves that historical reference without rewriting the app/Inventory or
// granting the old placement authority over the new registered native copy.
func (v Volumes) originalGoalRetainedByMove(scope volumes.Scope, g deployment.GoalCommand, capacity uint64) bool {
	for _, j := range v.moves {
		if j.Binding.Scope != scope || j.Source.Spec.Node != g.Node || j.Source.Spec.NodeKey != g.Owner || capacity > j.SourceCapacity {
			continue
		}
		_, m, ok := v.Move(j.Selection())
		if ok && m.CommitRevision != 0 {
			return true
		}
	}
	return false
}

func (v Volumes) validateOriginalStorage(s state.State) error {
	holds, err := v.originalHolds(s)
	if err != nil {
		return err
	}
	for _, limit := range v.backupLimits {
		if limit.Original == nil {
			continue
		}
		if limit.Original.Bytes > 1<<50 || limit.Original.Count > maxVolumes {
			return ErrCatalog
		}
		var bytes uint64
		var count uint32
		for _, h := range holds {
			if h.node != limit.Node || limit.Tenant != "" && h.tenant != limit.Tenant {
				continue
			}
			if h.bytes == 0 || h.bytes > 1<<40 || h.owner != limit.Owner || h.bytes > limit.Original.Bytes || bytes > limit.Original.Bytes-h.bytes || count >= limit.Original.Count {
				return ErrCatalog
			}
			bytes += h.bytes
			count++
		}
	}
	return nil
}

// originalAdmissionCode names why a new volume of bytes on node would not be
// admitted, as a bounded symbolic code a plan can return to the user. It is
// "" when admitOriginal holds and the node and tenant limits have room.
func (v Volumes) originalAdmissionCode(s state.State, tenant, node string, owner [32]byte, bytes uint64) string {
	if v.admitOriginal(tenant, node, owner, bytes) {
		if bytes == 0 {
			// No reservation, admitted only where neither limit exists.
			return ""
		}
		holds, err := v.originalHolds(s)
		if err != nil {
			return ""
		}
		for _, limit := range []VolumeBackupLimit{v.backupLimits[backupLimitKey("", node)], v.backupLimits[backupLimitKey(tenant, node)]} {
			var used uint64
			var count uint32
			for _, h := range holds {
				if h.node == node && (limit.Tenant == "" || h.tenant == limit.Tenant) {
					used += h.bytes
					count++
				}
			}
			if used > limit.Original.Bytes || bytes > limit.Original.Bytes-used || count >= limit.Original.Count {
				return "TARGET_VOLUME_LIMIT_FULL"
			}
		}
		return ""
	}
	g, gok := v.backupLimits[backupLimitKey("", node)]
	t, tok := v.backupLimits[backupLimitKey(tenant, node)]
	if !gok || !tok || g.Original == nil || t.Original == nil {
		return "TARGET_VOLUME_LIMIT_MISSING"
	}
	return "TARGET_VOLUME_LIMIT_OWNER_CHANGED"
}

// New reservations require BOTH the current node and tenant policy. Legacy
// requests with no reservation may only use nodes with no original policy at
// either level. Enabling a policy never turns an unknown old volume into zero.
func (v Volumes) admitOriginal(tenant, node string, owner [32]byte, bytes uint64) bool {
	g, gok := v.backupLimits[backupLimitKey("", node)]
	t, tok := v.backupLimits[backupLimitKey(tenant, node)]
	if bytes == 0 {
		return g.Original == nil && t.Original == nil
	}
	return bytes <= 1<<40 && gok && tok && g.Owner == owner && t.Owner == owner && g.Original != nil && t.Original != nil
}

func (p Policy) reduceVolumeCapacity(s state.State, v Volumes, op UserOperation) (map[string][]byte, state.Code) {
	var q VolumeCapacity
	if canonical(op.Change.Payload, &q) != nil || q.Bytes == 0 || q.Bytes > 1<<40 {
		return nil, state.Invalid
	}
	e, ok := v.entries[volumeKey(q.Scope)]
	if !ok || e.State.Scope() != q.Scope || e.State.Revision() != op.Change.Expected || e.State.DeleteRevision() != 0 || VolumeNativeDigest(e.Native) != q.Native || q.Bytes <= e.CapacityBytes {
		return nil, state.ConditionFailed
	}
	if fixed := e.Native.Fixed; fixed != nil {
		// A fixed volume's growth also counts against its root's limit.
		roots, err := p.NodeStorage(s)
		if err != nil {
			return nil, state.Invalid
		}
		ref := fixed.Root.Root
		root, ok := roots.Root(ref.Node, ref.ID)
		if !ok || root.Reference(p.Cluster) != ref || !rootAdmits(root, v, ref, q.Bytes-e.CapacityBytes) {
			return nil, state.ConditionFailed
		}
	}
	// This maps/reserves bytes only. It neither adopts data nor changes the
	// native spec, signed identity, generation, journal, consumer or writer.
	e.CapacityBytes = q.Bytes
	v.entries[volumeKey(q.Scope)] = e
	return p.volumeCheckpoint(s, v)
}
