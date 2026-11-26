// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagebuild"
)

// ImageBuildFreezeObsolete proves a monotonic configuration fence. Wall clock
// expiry alone does not establish that an original publication cannot commit.
func (p Policy) ImageBuildFreezeObsolete(s state.State, owner [32]byte, plan imagebuild.DraftFreezePlan) (bool, error) {
	p, err := p.Current(s)
	if err != nil {
		return false, err
	}
	book, err := p.ImageBuilds(s)
	if err != nil {
		return false, err
	}
	return book.DraftFreezeObsolete(p.Cluster, owner, plan)
}

// DraftFreezeObsolete reuses an already validated immutable catalog for a
// bounded owner pass, without decoding the whole checkpoint for each ZIP.
func (book ImageBuildCatalog) DraftFreezeObsolete(cluster, owner [32]byte, plan imagebuild.DraftFreezePlan) (bool, error) {
	scope := plan.Scope
	if plan.Validate() != nil || scope.Root.Cluster != cluster || scope.Root.Key != owner {
		return false, access.ErrDenied
	}
	context, found := book.Context(scope.Tenant, scope.Context)
	policy, configured := book.Policy(scope.Tenant)
	if !found || !configured || context.Spec.Kind != "draft" || context.Spec.Root != scope.Root || context.Revision < scope.ContextRevision || policy.Revision < scope.PolicyRevision || context.DraftGeneration() < scope.Data().Generation {
		return false, access.ErrConflict
	}
	if context.Deleted || policy.Deleted || context.Revision > scope.ContextRevision || policy.Revision > scope.PolicyRevision {
		return true, nil
	}
	if context.DraftGeneration() != scope.Data().Generation || context.Spec.Dockerfile != scope.Dockerfile || policy.Spec.WorkspaceBytes != scope.ExpandedLimit {
		return false, access.ErrConflict
	}
	return false, nil
}
