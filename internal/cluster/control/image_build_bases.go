// SPDX-License-Identifier: Apache-2.0

package control

import (
	"slices"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagebuild"
)

type ImageBuildBaseQuery struct {
	Tenant, Job string
	Snapshot    [32]byte
	Source      imagebuild.Source
	At          int64
}

func (q ImageBuildBaseQuery) Valid() bool {
	return validID(q.Tenant) && validID(q.Job) && q.Snapshot != ([32]byte{}) && q.Source.Valid() && q.At > 0
}

type ImageBuildBaseRead struct {
	Cluster, Builder [32]byte
	Query            ImageBuildBaseQuery
	Target           ImageResolveTarget
	Index, Epoch     uint64
}
type ImageBuildBaseResult struct {
	Schema           uint8
	Cluster, Builder [32]byte
	Tenant, Job      string
	Snapshot         [32]byte
	Source           imagebuild.Source
	Result           ImageResolveResult
}

func (r ImageBuildBaseRead) Result(result ImageResolveResult) ImageBuildBaseResult {
	return ImageBuildBaseResult{Schema: 1, Cluster: r.Cluster, Builder: r.Builder, Tenant: r.Query.Tenant, Job: r.Query.Job, Snapshot: r.Query.Snapshot, Source: r.Query.Source, Result: result}
}
func (r ImageBuildBaseResult) Valid(read ImageBuildBaseRead) bool {
	return r.Schema == 1 && r.Cluster == read.Cluster && r.Builder == read.Builder && r.Tenant == read.Query.Tenant && r.Job == read.Query.Job && r.Snapshot == read.Query.Snapshot && r.Source == read.Query.Source && r.Result.Valid(ImageResolveRead{Query: ImageResolveQuery{Ref: read.Query.Source.Reference}, Target: read.Target})
}

// Credential values remain with the original source reader. This grant lets
// the accepted job resolve public manifest/digest metadata before shared begin.
// A running job may only recheck a source already fixed by its begin report.
func (p Policy) ImageBuildBaseRead(s state.State, caller [32]byte, q ImageBuildBaseQuery) (ImageBuildBaseRead, error) {
	p, err := p.Current(s)
	if err != nil {
		return ImageBuildBaseRead{}, err
	}
	if !q.Valid() {
		return ImageBuildBaseRead{}, access.ErrInvalid
	}
	work, err := p.ImageBuildJobWork(s, caller, ImageBuildJobWorkQuery{Tenant: q.Tenant, ID: q.Job, At: q.At})
	if err != nil || !work.Allowed || work.Run.Spec.Digest() != q.Snapshot || !slices.Contains(work.Run.Spec.Policy.Platforms, q.Source.Platform) {
		return ImageBuildBaseRead{}, access.ErrDenied
	}
	reference := q.Source.Reference
	if work.Run.Phase != "queued" {
		index := slices.IndexFunc(work.Run.Inputs, func(input imagebuild.FrozenSource) bool { return input.Source == q.Source })
		if index < 0 {
			return ImageBuildBaseRead{}, access.ErrDenied
		}
		reference = work.Run.Inputs[index].Image
	}
	c, err := p.Catalog(s)
	if err != nil {
		return ImageBuildBaseRead{}, err
	}
	target, err := p.imageResolveTarget(s, c, q.At, q.Tenant, reference, caller)
	if err != nil {
		return ImageBuildBaseRead{}, err
	}
	if target.Code == "" && p.imageCacheAvailable(s, work.Run.Spec.Scope.Root.Node, target.Normalized) != nil {
		return ImageBuildBaseRead{}, access.ErrDenied
	}
	if work.Run.Phase != "queued" {
		book, err := p.ImageBuilds(s)
		if err != nil {
			return ImageBuildBaseRead{}, err
		}
		row, _ := book.Job(q.Tenant, q.Job)
		bound, hasBinding := imageBuildSourceBinding(target)
		found := slices.IndexFunc(row.Sources, func(source ImageBuildSourceBinding) bool { return source.Image == reference })
		if hasBinding && (found < 0 || !buildJSONEqual(row.Sources[found], bound)) || !hasBinding && found >= 0 {
			return ImageBuildBaseRead{}, access.ErrDenied
		}
	}
	return ImageBuildBaseRead{Cluster: p.Cluster, Builder: caller, Query: q, Target: target, Index: s.Index(), Epoch: s.ModuleEpoch()}, nil
}
func (p Policy) CurrentImageBuildBaseRead(s state.State, read ImageBuildBaseRead, at int64) (ImageBuildBaseRead, error) {
	if read.Cluster != p.Cluster || read.Builder == ([32]byte{}) || !read.Query.Valid() || read.Index == 0 || read.Epoch == 0 {
		return ImageBuildBaseRead{}, access.ErrInvalid
	}
	q := read.Query
	q.At = at
	current, err := p.ImageBuildBaseRead(s, read.Builder, q)
	if err != nil {
		return ImageBuildBaseRead{}, err
	}
	if current.Cluster != read.Cluster || current.Epoch != read.Epoch || current.Index < read.Index || !current.Target.Same(read.Target) {
		return ImageBuildBaseRead{}, access.ErrDenied
	}
	return current, nil
}
func (p Policy) ValidateImageBuildBaseResult(s state.State, read ImageBuildBaseRead, result ImageBuildBaseResult, at int64) error {
	if !result.Valid(read) {
		return access.ErrInvalid
	}
	if _, err := p.CurrentImageBuildBaseRead(s, read, at); err != nil {
		return err
	}
	if result.Result.Image == nil {
		return nil
	}
	c, err := p.Catalog(s)
	if err != nil {
		return err
	}
	if _, err := c.CheckImageTrust(read.Query.Tenant, result.Result.Image.Pinned); err != nil {
		return access.ErrDenied
	}
	work, err := p.ImageBuildJobWork(s, read.Builder, ImageBuildJobWorkQuery{Tenant: read.Query.Tenant, ID: read.Query.Job, At: at})
	if err != nil || !work.Allowed || p.imageCacheAvailable(s, work.Run.Spec.Scope.Root.Node, result.Result.Image.Pinned) != nil {
		return access.ErrDenied
	}
	return nil
}
