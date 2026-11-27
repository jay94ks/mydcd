// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/reconcile"
)

func (p Policy) ImageBuildGeneratedArchiveGrant(s state.State, owner [32]byte, artifact imagebuild.GeneratedArtifact) (imagebuild.GeneratedArchiveGrant, error) {
	p, err := p.Current(s)
	if err != nil {
		return imagebuild.GeneratedArchiveGrant{}, err
	}
	book, err := p.ImageBuilds(s)
	if err != nil {
		return imagebuild.GeneratedArchiveGrant{}, err
	}
	return book.GeneratedArchiveGrant(p.Cluster, owner, artifact, s.Index(), s.ModuleEpoch())
}

// A committed monotonic fence makes the original publish impossible. A
// previously accepted publish is visible in this same state and excluded.
func (book ImageBuildCatalog) GeneratedArchiveGrant(cluster, owner [32]byte, artifact imagebuild.GeneratedArtifact, index, epoch uint64) (imagebuild.GeneratedArchiveGrant, error) {
	scope := artifact.Scope
	if !artifact.Valid() || scope.Root.Cluster != cluster || scope.Root.Key != owner {
		return imagebuild.GeneratedArchiveGrant{}, access.ErrDenied
	}
	if upload, found := book.Upload(scope.Tenant, scope.Upload); found {
		if upload.Scope != scope {
			return imagebuild.GeneratedArchiveGrant{}, access.ErrConflict
		}
		return imagebuild.GeneratedArchiveGrant{}, imagebuild.ErrUsed
	}
	context, exists := book.Context(scope.Tenant, scope.Context)
	policy, configured := book.Policy(scope.Tenant)
	if !exists || !configured || context.Spec.Root != scope.Root || context.Revision < scope.ContextRevision || policy.Revision < scope.PolicyRevision || artifact.Draft != nil && context.Spec.Kind != "draft" || artifact.Git != nil && context.Spec.Kind != "git" {
		return imagebuild.GeneratedArchiveGrant{}, access.ErrConflict
	}
	if !context.Deleted && context.Revision == scope.ContextRevision && policy.Revision == scope.PolicyRevision {
		return imagebuild.GeneratedArchiveGrant{}, reconcile.ErrPending
	}
	g := imagebuild.GeneratedArchiveGrant{Artifact: artifact, ContextRevision: context.Revision, PolicyRevision: policy.Revision, Deleted: context.Deleted, Index: index, Epoch: epoch}
	if !g.Valid() {
		return g, ErrCatalog
	}
	return g, nil
}
