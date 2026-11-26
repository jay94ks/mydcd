// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagebuild"
)

func (p Policy) ImageBuildGitStageGrant(s state.State, owner [32]byte, plan imagebuild.GitSavePlan) (imagebuild.GitStageGrant, error) {
	p, err := p.Current(s)
	if err != nil {
		return imagebuild.GitStageGrant{}, err
	}
	book, err := p.ImageBuilds(s)
	if err != nil {
		return imagebuild.GitStageGrant{}, err
	}
	return book.GitStageGrant(p.Cluster, owner, plan, s.Index(), s.ModuleEpoch())
}

// Equal revisions authorize only a verified native transfer to its independent
// archive. A monotonic committed change may also discard the fenced source.
func (book ImageBuildCatalog) GitStageGrant(cluster, owner [32]byte, plan imagebuild.GitSavePlan, index, epoch uint64) (imagebuild.GitStageGrant, error) {
	if plan.Validate() != nil || plan.Root.Cluster != cluster || plan.Root.Key != owner {
		return imagebuild.GitStageGrant{}, access.ErrDenied
	}
	context, exists := book.Context(plan.Tenant, plan.Context)
	policy, configured := book.Policy(plan.Tenant)
	if !exists || !configured || context.Spec.Kind != "git" || context.Spec.Root != plan.Root || context.Revision < plan.ContextRevision || policy.Revision < plan.PolicyRevision || context.Revision == plan.ContextRevision && context.Spec.Dockerfile != plan.Dockerfile || policy.Revision == plan.PolicyRevision && policy.Spec.WorkspaceBytes != plan.ExpandedLimit {
		return imagebuild.GitStageGrant{}, access.ErrConflict
	}
	g := imagebuild.GitStageGrant{Plan: plan, ContextRevision: context.Revision, PolicyRevision: policy.Revision, Deleted: context.Deleted, Index: index, Epoch: epoch}
	if !g.Valid() {
		return g, ErrCatalog
	}
	return g, nil
}
