// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagebuild"
)

// ImageBuildCacheRetirementGrant derives cache disposal from the existing
// original tenant retirement, not policy/context deletion or a node CLI action.
func (p Policy) ImageBuildCacheRetirementGrant(s state.State, owner [32]byte, source imagebuild.JobSpec) (imagebuild.NativeCacheRetirementGrant, error) {
	p, err := p.Current(s)
	if err != nil {
		return imagebuild.NativeCacheRetirementGrant{}, err
	}
	if source.Validate() != nil || source.Cluster != p.Cluster || source.Scope.Root.Key != owner {
		return imagebuild.NativeCacheRetirementGrant{}, access.ErrDenied
	}
	work, err := p.TenantRetirementWork(s, owner, source.Tenant)
	if err != nil || work.Complete || work.Remaining != 0 {
		return imagebuild.NativeCacheRetirementGrant{}, access.ErrDenied
	}
	c, err := p.Catalog(s)
	if err != nil {
		return imagebuild.NativeCacheRetirementGrant{}, err
	}
	tenant, found := c.Tenant(source.Tenant)
	if !found || p.tenantRetirementEvidence(s, tenant) != nil {
		return imagebuild.NativeCacheRetirementGrant{}, access.ErrDenied
	}
	book, err := p.ImageBuilds(s)
	if err != nil {
		return imagebuild.NativeCacheRetirementGrant{}, err
	}
	job, found := book.Job(source.Tenant, source.ID)
	if !found || !job.Deleted || !job.Run.Terminal() || job.Run.Spec.Digest() != source.Digest() {
		return imagebuild.NativeCacheRetirementGrant{}, access.ErrDenied
	}
	g := imagebuild.NativeCacheRetirementGrant{Source: source.Own(), Operation: work.Operation, InventoryHash: work.InventoryHash, OwnersHash: work.OwnersHash, StartedRevision: work.StartedRevision, Index: work.Index, Epoch: work.Epoch}
	if !g.Valid() {
		return g, ErrCatalog
	}
	return g, nil
}
