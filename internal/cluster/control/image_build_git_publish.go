// SPDX-License-Identifier: Apache-2.0

package control

import (
	"math"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"
)

type ImageBuildGitPublish struct {
	Tenant, Context string
	Saved           imagebuild.SavedGit
}

func (p Policy) publishBuildGit(s state.State, c access.Catalog, b *ImageBuildCatalog, op UserOperation, put func(string, string, string, any) bool) state.Code {
	pub, valid := generatedBuildPublication(op)
	if !valid || pub.Kind != "git" || pub.Scope.Cluster != p.Cluster || op.Change.Expected != pub.Expected || op.At <= 0 || uint64(op.At) < pub.CreatedAt || uint64(op.At) >= pub.ExpiresAt {
		return state.Invalid
	}
	context, ok := b.Context(pub.Scope.Tenant, pub.Scope.Context)
	policy, configured := b.Policy(pub.Scope.Tenant)
	if !ok || !configured || context.Deleted || policy.Deleted || context.Spec.Kind != "git" || !context.Spec.Under(policy.Spec) || context.NextVersion == math.MaxUint64 || pub.Scope.Root != context.Spec.Root || pub.Scope.ContextRevision != context.Revision || pub.Scope.PolicyRevision != policy.Revision || pub.Scope.Dockerfile != context.Spec.Dockerfile || pub.Scope.ExpandedLimit != policy.Spec.WorkspaceBytes || p.buildRootCurrent(s, c, op.Session, op.At, pub.Scope.Tenant, pub.Scope.Root) != nil {
		return state.ConditionFailed
	}
	return publishBuildArchive(b, context, policy, op, pub.Scope, pub.Fact, pub.Commit, put)
}
