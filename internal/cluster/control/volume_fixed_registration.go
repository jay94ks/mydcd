// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/nodestorage"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

// VolumeFixedRegister is tenant management input, never app/CD input. The
// explicit root generation prevents a queued/signed request from following a
// same-name storage root replacement. The directory must already exist.
type VolumeFixedRegister struct {
	Scope               volumes.Scope
	Node, Storage, Path string
	RootGeneration      uint64
	QuotaMode           string
	CapacityBytes       uint64 `json:",omitempty"`
}

func fixedSpec(scope volumes.Scope, selection nodestorage.FixedSelection) volumes.NativeSpec {
	digest := selection.Digest()
	return volumes.NativeSpec{Schema: 1, Scope: scope, Node: selection.Root.Root.Node, NodeKey: selection.Root.Root.Key, Retain: true, Kind: "node-fixed", FixedDigest: hex.EncodeToString(digest[:])}
}

func creationNativeGeneration(spec volumes.NativeSpec) uint64 {
	if spec.Kind == "node-fixed" {
		return spec.Scope.Generation
	}
	return 1
}

func creationOwner(spec volumes.NativeSpec) (volumes.Owner, error) {
	if spec.Kind == "node-fixed" {
		if spec.Validate() != nil {
			return volumes.Owner{}, ErrCatalog
		}
		return volumes.Owner{Node: spec.Node, Key: spec.NodeKey, Native: volumes.FixedNativeName(spec.Scope)}, nil
	}
	return restoreTargetOwner(spec)
}

func creationBytes(j VolumeCreation) (uint64, error) {
	if j.Fixed != nil {
		var q VolumeFixedRegister
		if canonical(j.Origin.Change.Payload, &q) != nil {
			return 0, ErrCatalog
		}
		return q.CapacityBytes, nil
	}
	var q VolumeCreate
	if canonical(j.Origin.Change.Payload, &q) != nil {
		return 0, ErrCatalog
	}
	return q.CapacityBytes, nil
}

func fixedSelectionEqual(a, b nodestorage.FixedSelection) bool {
	return a.Path == b.Path && bytes.Equal(nodestorage.RootFactBytes(a.Root), nodestorage.RootFactBytes(b.Root)) && bytes.Equal(a.Root.Signature, b.Root.Signature)
}

func (p Policy) reduceFixedRegistration(s state.State, users access.Catalog, v Volumes, op UserOperation) (map[string][]byte, state.Code) {
	var q VolumeFixedRegister
	if canonical(op.Change.Payload, &q) != nil || op.Change.Expected != 0 || q.Scope.Cluster != p.Cluster || !q.Scope.TenantManaged() || q.QuotaMode != "observe" || q.RootGeneration == 0 || len(v.creations) >= maxVolumes {
		return nil, state.Invalid
	}
	roots, err := p.NodeStorage(s)
	if err != nil {
		return nil, state.Invalid
	}
	root, err := roots.CanUse(users, op.Session.User, q.Scope.Tenant, q.Node, q.Storage, q.RootGeneration)
	if err != nil {
		return nil, state.Forbidden
	}
	key, err := p.workNodeOwner(s, q.Node)
	if err != nil || key != root.Definition.Key {
		return nil, state.Forbidden
	}
	selection := nodestorage.FixedSelection{Root: *root.Attestation, Path: q.Path}.Clone()
	spec := fixedSpec(q.Scope, selection)
	if selection.Validate() != nil || spec.Validate() != nil {
		return nil, state.Invalid
	}
	if registeredOnRoot(v, root.Reference(p.Cluster)) >= root.Definition.MaxVolumes || !v.restoreTargetAvailable(q.Scope) || v.volumeReservations() >= maxVolumes || v.volumeMetadataSlots() >= maxVolumes {
		return nil, state.ConditionFailed
	}
	if old, exists := v.entries[volumeKey(q.Scope)]; exists && (!old.State.Fixed() || !old.State.Deleted() || old.State.Scope().Generation >= q.Scope.Generation) {
		return nil, state.ConditionFailed
	}
	// Reserve physical subtree identity before native dispatch, across all
	// tenants. A second registration cannot manufacture another writer core
	// for an alias/ancestor/descendant of the same backing data.
	for _, other := range v.entries {
		if other.Native.Fixed != nil && !other.State.Deleted() && selection.Overlaps(other.Native.Fixed.Selection()) {
			return nil, state.ConditionFailed
		}
	}
	for _, other := range v.creations {
		if other.Fixed != nil && creationPending(other.Phase) && selection.Overlaps(*other.Fixed) {
			return nil, state.ConditionFailed
		}
	}
	if !v.admitOriginal(q.Scope.Tenant, q.Node, key, q.CapacityBytes) {
		return nil, state.ConditionFailed
	}
	capacity, err := p.createCapacity(s, spec)
	if err != nil {
		return nil, state.Forbidden
	}
	v.creations[creationKey(q.Scope)] = VolumeCreation{Spec: spec, Origin: op, Revision: 1, Capacity: capacity, Phase: "Reserved", Fixed: &selection}
	return p.volumeCheckpoint(s, v)
}

func (p Policy) validateFixedCreation(users access.Catalog, v Volumes, key string, j VolumeCreation) error {
	var q VolumeFixedRegister
	if j.Fixed == nil || j.Fixed.Validate() != nil || j.Origin.VerifyOriginal(p.Cluster) != nil || j.Origin.Change.Action != "register-fixed-volume" || j.Origin.Change.Expected != 0 || canonical(j.Origin.Change.Payload, &q) != nil || q.QuotaMode != "observe" || q.Scope.Cluster != p.Cluster || !q.Scope.TenantManaged() || q.RootGeneration == 0 || q.Scope != j.Spec.Scope || key != creationKey(q.Scope) || j.Fixed.Root.Root.Cluster != p.Cluster || j.Fixed.Root.Root.Node != q.Node || j.Fixed.Root.Root.ID != q.Storage || j.Fixed.Root.Root.Generation != q.RootGeneration || j.Fixed.Path != q.Path || fixedSpec(q.Scope, *j.Fixed) != j.Spec || j.Spec.Validate() != nil || j.Capacity < 1 || j.Capacity > maxVolumes {
		return ErrCatalog
	}
	if _, exists := users.Tenant(q.Scope.Tenant); !exists {
		return ErrCatalog
	}
	if prepared := j.Preparation; prepared != nil {
		if prepared.Operation != "create" || prepared.Schema != 1 || prepared.Scope != j.Spec.Scope || !prepared.Prepared || prepared.Revision != 1 || prepared.Epoch == 0 || prepared.At < 0 || prepared.Ready != nil || prepared.Gone != nil || !ed25519.Verify(j.Spec.NodeKey[:], VolumeCreateReportBytes(*prepared), prepared.Signature) {
			return ErrCatalog
		}
	}
	entry, published := v.entries[volumeKey(q.Scope)]
	olderClosed := published && entry.State.Deleted() && entry.State.Scope().Generation < q.Scope.Generation
	if creationPending(j.Phase) {
		expected := uint64(1)
		if j.Preparation != nil {
			expected++
		}
		if j.Phase == "Cancelling" {
			expected++
		}
		if j.Revision != expected || j.Phase == "Reserved" && j.Preparation != nil || j.Phase == "Creating" && j.Preparation == nil || j.Ready != nil || j.Gone != nil || j.Unregister != nil || published && !olderClosed {
			return ErrCatalog
		}
		for otherKey, other := range v.creations {
			if otherKey != key && creationPending(other.Phase) && volumeKey(other.Spec.Scope) == volumeKey(q.Scope) {
				return ErrCatalog
			}
		}
		return nil
	}
	if j.Phase == "Cancelled" {
		expected := uint64(3)
		if j.Preparation != nil {
			expected++
		}
		gone := j.Gone
		if j.Revision != expected || j.Ready != nil || j.Unregister != nil || gone == nil || gone.Verify() != nil || !gone.DataRetained || gone.Scope != q.Scope || gone.Owner != (volumes.Owner{Node: j.Spec.Node, Key: j.Spec.NodeKey, Native: volumes.FixedNativeName(q.Scope)}) || gone.Key != volumes.NativeKey(j.Spec) || gone.Generation != creationNativeGeneration(j.Spec) || gone.DeleteRevision != j.Revision-1 || published && !olderClosed && entry.State.Scope().Generation <= q.Scope.Generation {
			return ErrCatalog
		}
		return nil
	}
	ready := j.Ready
	if j.Preparation == nil || ready == nil || ready.Verify() != nil || ready.Spec != j.Spec || ready.Generation != creationNativeGeneration(j.Spec) || ready.Fixed == nil || !fixedSelectionEqual(ready.Fixed.Selection(), *j.Fixed) {
		return ErrCatalog
	}
	switch j.Phase {
	case "Ready":
		if j.Revision != 3 || j.Gone != nil || j.Unregister != nil || !published || !sameVolumeNative(entry.Native, *ready) {
			return ErrCatalog
		}
	case "Unregistered":
		gone := j.Gone
		if j.Revision != 4 || gone == nil || gone.Verify() != nil || !gone.DataRetained || gone.Scope != q.Scope || gone.Owner != ready.Owner || gone.Key != volumes.NativeKey(j.Spec) || gone.Generation != ready.Generation {
			return ErrCatalog
		}
		var original volumes.Scope
		if j.Unregister == nil || j.Unregister.VerifyOriginal(p.Cluster) != nil || j.Unregister.Change.Action != "unregister-fixed-volume" || canonical(j.Unregister.Change.Payload, &original) != nil || original != q.Scope || j.Unregister.Change.Expected == ^uint64(0) || j.Unregister.Change.Expected+1 != gone.DeleteRevision {
			return ErrCatalog
		}
		if published && entry.State.Scope() == q.Scope {
			actual, ok := entry.State.Removal()
			if !ok || !bytes.Equal(volumes.NativeRemovedBytes(actual), volumes.NativeRemovedBytes(*gone)) || !bytes.Equal(actual.Signature, gone.Signature) {
				return ErrCatalog
			}
		} else if published && entry.State.Scope().Generation <= q.Scope.Generation {
			return ErrCatalog
		}
	default:
		return ErrCatalog
	}
	return nil
}
