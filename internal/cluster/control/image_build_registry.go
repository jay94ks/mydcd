// SPDX-License-Identifier: Apache-2.0

package control

import (
	"slices"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/registry"
)

type ImageBuildRegistryRequest struct {
	Tenant, Job   string
	Snapshot      [32]byte
	Action, Image string
	At            int64
}
type ImageBuildRegistryPermit struct {
	Subject      registry.BuildSubject
	Run          RegistryRunRef
	Repository   string
	Index, Epoch uint64
}

// A native builder uses its retained job grant, not a refreshed user session
// and not an invented app Task. Pull preflight is bounded by current tenant
// trust; the actual executable FROM pins are fixed by the signed begin report.
func (p Policy) ImageBuildRegistryPermit(s state.State, caller [32]byte, q ImageBuildRegistryRequest) (ImageBuildRegistryPermit, error) {
	p, err := p.Current(s)
	if err != nil {
		return ImageBuildRegistryPermit{}, err
	}
	if !validID(q.Tenant) || !validID(q.Job) || q.Snapshot == ([32]byte{}) || q.At <= 0 || q.Action != "pull" && q.Action != "push" || q.Action == "push" && q.Image != "" || q.Action == "pull" && q.Image == "" {
		return ImageBuildRegistryPermit{}, access.ErrInvalid
	}
	work, err := p.ImageBuildJobWork(s, caller, ImageBuildJobWorkQuery{Tenant: q.Tenant, ID: q.Job, At: q.At})
	if err != nil || !work.Allowed || work.Run.Spec.Digest() != q.Snapshot || q.Action == "push" && work.Run.Phase != "running" && work.Run.Phase != "unknown" {
		return ImageBuildRegistryPermit{}, access.ErrDenied
	}
	spec := work.Run.Spec
	authority := spec.RegistryAuthority
	repository := spec.Context.Repository
	if q.Action == "pull" {
		image, err := access.PinImage(q.Image)
		if err != nil || image.Reference != q.Image {
			return ImageBuildRegistryPermit{}, access.ErrInvalid
		}
		c, err := p.Catalog(s)
		if err != nil {
			return ImageBuildRegistryPermit{}, err
		}
		if _, err := c.CheckImageTrust(q.Tenant, q.Image); err != nil || p.imageCacheAvailable(s, spec.Scope.Root.Node, q.Image) != nil {
			return ImageBuildRegistryPermit{}, access.ErrDenied
		}
		authority = image.Registry
		repository = image.Repository
		if work.Run.Phase != "queued" && !slices.ContainsFunc(work.Run.Frozen(), func(input imagebuild.FrozenSource) bool { return input.Image == q.Image }) {
			return ImageBuildRegistryPermit{}, access.ErrDenied
		}
	}
	book, err := p.Registries(s)
	if err != nil {
		return ImageBuildRegistryPermit{}, err
	}
	var selected *RegistryEntry
	for _, entry := range book.Entries() {
		if entry.Spec.Authority != authority && (entry.Active == nil || entry.Active.Spec.Authority != authority) {
			continue
		}
		if selected != nil || entry.Spec.Tenant != q.Tenant {
			return ImageBuildRegistryPermit{}, access.ErrDenied
		}
		copy := entry
		selected = &copy
	}
	if selected == nil || selected.Deleted || !selected.Spec.Enabled || selected.Active == nil || selected.Active.Draining || selected.Active.Ready == nil || selected.Active.Spec != selected.Spec {
		return ImageBuildRegistryPermit{}, access.ErrConflict
	}
	entry := *selected
	if q.Action == "pull" && work.Run.Phase != "queued" {
		builds, err := p.ImageBuilds(s)
		if err != nil {
			return ImageBuildRegistryPermit{}, err
		}
		row, _ := builds.Job(q.Tenant, q.Job)
		if !slices.ContainsFunc(row.Sources, func(source ImageBuildSourceBinding) bool {
			return source.Image == q.Image && source.Managed != nil && source.Managed.ID == entry.Spec.ID && source.Managed.Generation == entry.Active.Generation && source.Managed.Definition == entry.Spec.Digest() && source.Owner == entry.Active.Owner
		}) {
			return ImageBuildRegistryPermit{}, access.ErrDenied
		}
	}
	if q.Action == "push" && (entry.Spec.ID != spec.Policy.Registry || entry.Generation != spec.RegistryGeneration || entry.Spec.Digest() != spec.RegistrySpec) {
		return ImageBuildRegistryPermit{}, access.ErrDenied
	}
	current, err := p.RegistryWork(s, entry.Active.Owner, RegistryWorkRequest{RegistrySelection: RegistrySelection{Tenant: q.Tenant, ID: entry.Spec.ID}, At: q.At})
	if err != nil || !current.MayStart || current.Entry.Active == nil || current.Entry.Active.Generation != entry.Active.Generation {
		return ImageBuildRegistryPermit{}, access.ErrDenied
	}
	return ImageBuildRegistryPermit{Subject: registry.BuildSubject{Tenant: q.Tenant, Job: q.Job, Snapshot: q.Snapshot, Node: caller, Image: q.Image}, Run: entry.Active.Reference(), Repository: repository, Index: s.Index(), Epoch: s.ModuleEpoch()}, nil
}
