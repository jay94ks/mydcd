// SPDX-License-Identifier: Apache-2.0

package control

import (
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/registryclient"
)

// Public original references only. Neither credentials nor issued tokens enter
// Raft. The signed begin reserves the reader until positive job completion.
type ImageBuildSourceBinding struct {
	Image    string
	Owner    [32]byte
	External *ExternalRegistryReadSelection `json:",omitempty"`
	ReadSet  [32]byte                       `json:",omitempty"`
	Managed  *ImageBuildManagedSource       `json:",omitempty"`
}

type ImageBuildManagedSource struct {
	ID         string
	Generation uint64
	Definition [32]byte
}

func imageBuildSourceBinding(t ImageResolveTarget) (ImageBuildSourceBinding, bool) {
	b := ImageBuildSourceBinding{Image: t.Normalized, Owner: t.Owner}
	if t.External != nil {
		selection := *t.External
		b.External, b.ReadSet = &selection, t.ExternalReadSet
		return b, true
	}
	if t.Managed != nil {
		b.Managed = &ImageBuildManagedSource{ID: t.Managed.Spec.ID, Generation: t.Managed.Generation, Definition: t.Managed.Spec.Digest()}
		return b, true
	}
	return ImageBuildSourceBinding{}, false
}

func validImageBuildSources(spec imagebuild.JobSpec, inputs []imagebuild.FrozenSource, sources []ImageBuildSourceBinding) bool {
	last := ""
	for _, source := range sources {
		normalized, _, _, err := registryclient.Normalize(source.Image)
		if err != nil || normalized != source.Image || !strings.Contains(source.Image, "@sha256:") || source.Image <= last || source.Owner == ([32]byte{}) || (source.External == nil) == (source.Managed == nil) {
			return false
		}
		if !slices.ContainsFunc(inputs, func(input imagebuild.FrozenSource) bool { return input.Image == source.Image }) {
			return false
		}
		if source.External != nil {
			q := source.External
			if q.Tenant != spec.Tenant || !validID(q.ID) || q.Generation == 0 || source.ReadSet == ([32]byte{}) {
				return false
			}
		} else if !validID(source.Managed.ID) || source.Managed.Generation == 0 || source.Managed.Definition == ([32]byte{}) || source.ReadSet != ([32]byte{}) {
			return false
		}
		last = source.Image
	}
	return true
}

func (p Policy) imageBuildSourceBindings(s state.State, c access.Catalog, spec imagebuild.JobSpec, inputs []imagebuild.FrozenSource, at int64) ([]ImageBuildSourceBinding, error) {
	var sources []ImageBuildSourceBinding
	seen := map[string]bool{}
	for _, input := range inputs {
		if seen[input.Image] {
			continue
		}
		seen[input.Image] = true
		target, err := p.imageResolveTarget(s, c, at, spec.Tenant, input.Image, spec.Scope.Root.Key)
		if err != nil || target.Code != "" {
			return nil, access.ErrDenied
		}
		if source, bound := imageBuildSourceBinding(target); bound {
			sources = append(sources, source)
		}
	}
	slices.SortFunc(sources, func(a, b ImageBuildSourceBinding) int { return strings.Compare(a.Image, b.Image) })
	return sources, nil
}

// ImageBuildBeginSources is a local deterministic projection of the same
// fresh quorum state used by begin admission; it performs no registry I/O.
func (p Policy) ImageBuildBeginSources(s state.State, caller [32]byte, q ImageBuildJobWorkQuery, inputs []imagebuild.FrozenSource, builder *imagebuild.FrozenSource, local string) ([]ImageBuildSourceBinding, error) {
	work, err := p.ImageBuildJobWork(s, caller, q)
	if err != nil || !work.Allowed || work.Run.Phase != "queued" || imagebuild.ValidateJobInputs(work.Run.Spec, inputs) != nil || imagebuild.ValidateJobBuilder(work.Run.Spec, builder, local) != nil {
		return nil, access.ErrDenied
	}
	c, err := p.Catalog(s)
	if err != nil {
		return nil, err
	}
	read := ImageBuildJobReport{Inputs: inputs, Builder: builder, BuilderLocal: local}.read()
	return p.imageBuildSourceBindings(s, c, work.Run.Spec, read, q.At)
}

func (p Policy) ExternalRegistryImageBuildsPending(s state.State, selection ExternalRegistryReadSelection) (bool, error) {
	book, err := p.ImageBuilds(s)
	if err != nil {
		return false, err
	}
	for _, job := range book.Jobs {
		if job.Run.Terminal() {
			continue
		}
		for _, source := range job.Sources {
			if source.External != nil && *source.External == selection {
				return true, nil
			}
		}
	}
	return false, nil
}

// Retained original references must survive cancellation, source withdrawal
// and restore. Current permission/read-set checks are intentionally separate:
// withdrawal stops fresh I/O but cannot release an in-flight job's grant.
func (p Policy) validateImageBuildSourceRefs(s state.State, book ImageBuildCatalog) error {
	var external []ExternalRegistryEntry
	var registries Registries
	loaded := false
	for _, job := range book.Jobs {
		if job.Run.Terminal() || len(job.Sources) == 0 {
			continue
		}
		if !loaded {
			var err error
			external, err = p.ExternalRegistries(s)
			if err != nil {
				return err
			}
			registries, err = p.Registries(s)
			if err != nil {
				return err
			}
			loaded = true
		}
		for _, source := range job.Sources {
			if source.External != nil {
				found := slices.ContainsFunc(external, func(entry ExternalRegistryEntry) bool {
					return entry.Spec.Tenant == source.External.Tenant && entry.Spec.ID == source.External.ID && entry.Reader != nil && entry.Reader.Generation == source.External.Generation && entry.Reader.Owner == source.Owner
				})
				if !found {
					return ErrCatalog
				}
			} else if source.Managed != nil {
				entry, ok := registries.Entry(job.Run.Spec.Tenant, source.Managed.ID)
				if !ok || entry.Active == nil || entry.Active.Generation != source.Managed.Generation || entry.Active.Owner != source.Owner || entry.Active.Spec.Digest() != source.Managed.Definition {
					return ErrCatalog
				}
			}
		}
	}
	return nil
}
