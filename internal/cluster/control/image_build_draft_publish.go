// SPDX-License-Identifier: Apache-2.0

package control

import (
	"math"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagebuild"
)

type ImageBuildDraftPublish struct {
	Tenant, Context string
	Frozen          imagebuild.FrozenDraft
}

func (p Policy) publishBuildDraft(s state.State, c access.Catalog, b *ImageBuildCatalog, op UserOperation, put func(string, string, string, any) bool) state.Code {
	var q ImageBuildDraftPublish
	if canonical(op.Change.Payload, &q) != nil || !q.Frozen.Valid() || q.Tenant != q.Frozen.Scope.Tenant || q.Context != q.Frozen.Scope.Context || q.Frozen.Plan.Creator != op.Session.User || q.Frozen.Scope.Cluster != p.Cluster || op.Change.Expected != q.Frozen.Plan.Revision || op.At <= 0 || uint64(op.At) < q.Frozen.Plan.CreatedAt || uint64(op.At) >= q.Frozen.Plan.ExpiresAt {
		return state.Invalid
	}
	context, ok := b.Context(q.Tenant, q.Context)
	policy, configured := b.Policy(q.Tenant)
	source := q.Frozen.Plan.Scope
	if !ok || !configured || context.Deleted || policy.Deleted || context.Spec.Kind != "draft" || !context.Spec.Under(policy.Spec) || context.NextVersion == math.MaxUint64 || source.Root != context.Spec.Root || source.Data().Generation != context.DraftGeneration() || source.ContextRevision != context.Revision || source.PolicyRevision != policy.Revision || source.Dockerfile != context.Spec.Dockerfile || source.ExpandedLimit != policy.Spec.WorkspaceBytes || p.buildRootCurrent(s, c, op.Session, op.At, q.Tenant, source.Root) != nil {
		return state.ConditionFailed
	}
	return publishBuildArchive(b, context, policy, op, q.Frozen.Scope, q.Frozen.Fact, "", put)
}

func validGeneratedBuildUpload(r ImageBuildUploadRecord, context ImageBuildContextRecord, cluster [32]byte) bool {
	if r.Automatic != nil {
		report := r.Automatic
		return validAutomaticGitOrigin(r.Begin, *report, cluster) && buildJSONEqual(r.Begin, r.Origin) && r.Scope == report.Saved.Scope && r.Revision == 1 && r.Closed && r.Received == 0 && r.Version == imagebuild.VersionID(report.Saved.Fact) && r.Expiry == nil && r.ExpiryReceived == 0 && context.Spec.Kind == "git" && context.Spec.Root == r.Scope.Root && r.Scope.ContextRevision <= context.Revision
	}
	pub, ok := generatedBuildPublication(r.Begin)
	if !ok || r.Begin.VerifyOriginal(cluster) != nil || r.Origin.VerifyOriginal(cluster) != nil || !buildJSONEqual(r.Begin, r.Origin) || r.Scope != pub.Scope || r.Scope.Cluster != cluster || r.Revision != 1 || !r.Closed || r.Received != 0 || r.Version != imagebuild.VersionID(pub.Fact) || r.Expiry != nil || r.ExpiryReceived != 0 || r.Scope.Creator != r.Begin.Session.User || r.Begin.Change.Expected != pub.Expected || r.Begin.At <= 0 || uint64(r.Begin.At) < pub.CreatedAt || uint64(r.Begin.At) >= pub.ExpiresAt {
		return false
	}
	return context.Spec.Kind == pub.Kind && context.Spec.Root == r.Scope.Root && r.Scope.ContextRevision <= context.Revision && (r.Scope.ContextRevision != context.Revision || context.Spec.Dockerfile == r.Scope.Dockerfile)
}

func validBuildVersionOrigin(v ImageBuildVersionRecord, u ImageBuildUploadRecord, cluster [32]byte) bool {
	if v.Origin.VerifyOriginal(cluster) != nil || v.Origin.Session.User != u.Scope.Creator {
		return false
	}
	if u.Automatic != nil {
		r := u.Automatic
		return validAutomaticGitOrigin(u.Begin, *r, cluster) && buildJSONEqual(v.Origin, u.Begin) && v.Commit == r.Saved.Plan.Commit && v.Upload == u.Scope.Upload && v.Tenant == u.Scope.Tenant && v.Context == u.Scope.Context && v.ID == u.Version && buildJSONEqual(v.Fact, r.Saved.Fact)
	}
	if v.Origin.Change.Action == "publish-build-draft" || v.Origin.Change.Action == "publish-build-git" {
		pub, ok := generatedBuildPublication(v.Origin)
		return ok && pub.Commit == v.Commit && pub.Scope.Tenant == v.Tenant && pub.Scope.Context == v.Context && pub.Scope == u.Scope && pub.Scope.Upload == v.Upload && buildJSONEqual(pub.Fact, v.Fact) && buildJSONEqual(v.Origin, u.Begin)
	}

	var q ImageBuildZIPConsume
	return v.Commit == "" && u.Begin.Change.Action == "begin-build-zip-upload" && v.Origin.Change.Action == "upload-build-zip" && buildJSONEqual(v.Origin, u.Origin) && canonical(v.Origin.Change.Payload, &q) == nil && q.Tenant == v.Tenant && q.ID == v.Context && q.Upload == v.Upload && buildJSONEqual(q.Fact, v.Fact)
}
