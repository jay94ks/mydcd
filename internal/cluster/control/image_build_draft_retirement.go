// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/reconcile"
)

func (p Policy) ImageBuildDraftRetirementGrant(s state.State, owner [32]byte, scope imagebuild.DraftScope) (imagebuild.DraftRetirementGrant, error) {
	p, err := p.Current(s)
	if err != nil {
		return imagebuild.DraftRetirementGrant{}, err
	}
	book, err := p.ImageBuilds(s)
	if err != nil {
		return imagebuild.DraftRetirementGrant{}, err
	}
	return book.DraftRetirementGrant(p.Cluster, owner, scope, s.Index(), s.ModuleEpoch())
}

func (book ImageBuildCatalog) DraftRetirementGrant(cluster, owner [32]byte, scope imagebuild.DraftScope, index, epoch uint64) (imagebuild.DraftRetirementGrant, error) {
	if scope.Validate() != nil || scope.Root.Cluster != cluster || scope.Root.Key != owner {
		return imagebuild.DraftRetirementGrant{}, access.ErrDenied
	}
	context, exists := book.Context(scope.Tenant, scope.Context)
	policy, configured := book.Policy(scope.Tenant)
	if !exists || !configured || context.Spec.Kind != "draft" || context.Spec.Root != scope.Root || context.Revision < scope.ContextRevision || policy.Revision < scope.PolicyRevision || context.DraftGeneration() < scope.Data().Generation {
		return imagebuild.DraftRetirementGrant{}, access.ErrConflict
	}
	if !context.Deleted && context.DraftGeneration() == scope.Data().Generation {
		return imagebuild.DraftRetirementGrant{}, reconcile.ErrPending
	}
	g := imagebuild.DraftRetirementGrant{Scope: scope, ContextRevision: context.Revision, Generation: context.DraftGeneration(), Deleted: context.Deleted, Index: index, Epoch: epoch}
	if !g.Valid() {
		return g, ErrCatalog
	}
	return g, nil
}
