// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// VolumeReference freezes one pre-registered tenant Volume without copying a
// host path into the application. It is borrowed by the existing Task Binding,
// never an app-owned creation/deletion Step or an independent native owner.
type VolumeReference struct {
	Schema           uint8
	Scope            volumes.Scope
	Owner            volumes.Owner
	NativeGeneration uint64
	Native           [32]byte
	// Share is the volume-shares mode (volumes.ShareSingleWriter or
	// volumes.ShareShared) recorded for this exact Scope when planned. With
	// it, a task may run on another server than Owner and reach the data
	// over VolumeFS; Reserve checks the share again against current state.
	Share string `json:",omitempty"`
}

func (r VolumeReference) Valid() bool {
	return (r.Share == "" || r.Share == volumes.ShareSingleWriter || r.Share == volumes.ShareShared) && r.Schema == 1 && r.Scope.Cluster != ([32]byte{}) && r.Scope.TenantManaged() && identifier(r.Scope.Tenant) && identifier(r.Scope.ID) && r.Scope.Generation > 0 && identifier(r.Owner.Node) && r.Owner.Key != ([32]byte{}) && r.Owner.Native == volumes.FixedNativeName(r.Scope) && r.NativeGeneration == r.Scope.Generation && r.Native != ([32]byte{})
}
func (r VolumeReference) Matches(ready volumes.NativeReady) bool {
	return r.Valid() && ready.Verify() == nil && ready.Fixed != nil && ready.Spec.Scope == r.Scope && ready.Owner == r.Owner && ready.Generation == r.NativeGeneration && volumes.NativeBindingDigest(ready) == r.Native
}
func (r VolumeReference) MatchesState(s volumes.State) bool {
	owner, _ := s.Owner()
	return r.Valid() && s.Fixed() && s.RetainsData() && s.DeleteRevision() == 0 && s.Scope() == r.Scope && owner == r.Owner
}

// VolumeShare is one committed volume-shares record as planning sees it.
type VolumeShare struct {
	Scope volumes.Scope
	Mode  string
}

func fixedVolumePolicy(v ComposeVolume) bool {
	return v.External && v.Driver == "" && v.Sfc.Driver == "local" && v.Sfc.Access == "single-writer" && v.Sfc.Retain != nil && *v.Sfc.Retain && v.Sfc.Quota == "observe" && v.Sfc.UID == 0 && v.Sfc.GID == 0 && v.Sfc.Mode == "" && v.Sfc.Capacity == 0 && v.Sfc.Backup == nil && v.Sfc.Migration == nil
}

func resolveFixedVolume(alias, tenant string, v ComposeVolume, ctx PlanningContext) (VolumeReference, bool, error) {
	if !v.External {
		return VolumeReference{}, false, nil
	}
	name := v.Name
	if name == "" {
		name = alias
	}
	key := (volumes.Scope{Tenant: tenant, ID: name}).Key()
	current, exists := ctx.Volumes[key]
	if !exists {
		return VolumeReference{}, false, nil
	}
	ready, ok := ctx.FixedVolumes[key]
	ref := VolumeReference{Schema: 1, Scope: ready.Spec.Scope, Owner: ready.Owner, NativeGeneration: ready.Generation, Native: volumes.NativeBindingDigest(ready)}
	if share, shared := ctx.Shares[key]; shared && share.Scope == ready.Spec.Scope {
		ref.Share = share.Mode
	}
	if !ok || !fixedVolumePolicy(v) || !ref.Matches(ready) || !ref.MatchesState(current) || ref.Scope.Cluster != ctx.Cluster || ref.Scope.Tenant != tenant || ref.Scope.ID != name {
		return ref, true, inputError("FIXED_VOLUME_REFERENCE_UNAVAILABLE", alias)
	}
	return ref, true, nil
}

// CheckVolumeNeeds ties the recorded Task declaration to the original shared
// Binding without requiring current permissions. Revocation must not erase
// this structural provenance or prevent original cleanup.
func (s ComposeService) CheckVolumeNeeds(n Needs) error {
	if !validInputMetadata(n) || len(s.Volumes) != len(n.Volumes) {
		return ErrInputs
	}
	used := map[string]bool{}
	for i, m := range s.Volumes {
		want := n.Use.Tenant + "/" + n.Use.App + "/" + m.Source
		if ref, fixed := s.FixedVolumes[m.Source]; fixed {
			want = ref.Scope.Key()
			if !ref.Valid() || n.FixedVolumes[want] != ref {
				return ErrInputs
			}
			used[want] = true
		}
		if n.Volumes[i].Key != want || n.Volumes[i].Writable == m.ReadOnly {
			return ErrInputs
		}
	}
	if len(used) != len(n.FixedVolumes) || len(used) != len(s.FixedVolumes) {
		return ErrInputs
	}
	return nil
}

func taskVolumeReferences(service ComposeService, refs map[string]VolumeReference) map[string]VolumeReference {
	var selected map[string]VolumeReference
	for _, mount := range service.Volumes {
		if ref, ok := refs[mount.Source]; ok {
			if selected == nil {
				selected = map[string]VolumeReference{}
			}
			selected[mount.Source] = ref
		}
	}
	return selected
}

func frozenTaskService(service ComposeService, refs map[string]VolumeReference) ComposeService {
	service.FixedVolumes = taskVolumeReferences(service, refs)
	return service
}

func (b Blueprint) volumeKey(alias string) string {
	if ref, ok := b.d.FixedVolumes[alias]; ok {
		return ref.Scope.Key()
	}
	return b.d.Tenant + "/" + b.d.App + "/" + alias
}
