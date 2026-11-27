// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"encoding/json"
	"math"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"
)

type generatedBuildArchive struct {
	Scope                          imagebuild.UploadScope
	Fact                           imagebuild.SealReceipt
	Kind, Commit                   string
	Expected, CreatedAt, ExpiresAt uint64
}

// Decode source-specific signed evidence once. Authority remains the creator's
// UserOperation; node evidence never creates a version independently.
func generatedBuildPublication(op UserOperation) (generatedBuildArchive, bool) {
	var out generatedBuildArchive
	switch op.Change.Action {
	case "publish-build-draft":
		var q ImageBuildDraftPublish
		if canonical(op.Change.Payload, &q) != nil || !q.Frozen.Valid() || q.Tenant != q.Frozen.Scope.Tenant || q.Context != q.Frozen.Scope.Context || q.Frozen.Plan.Creator != op.Session.User {
			return out, false
		}
		out = generatedBuildArchive{Scope: q.Frozen.Scope, Fact: q.Frozen.Fact, Kind: "draft", Expected: q.Frozen.Plan.Revision, CreatedAt: q.Frozen.Plan.CreatedAt, ExpiresAt: q.Frozen.Plan.ExpiresAt}
	case "publish-build-git":
		var q ImageBuildGitPublish
		if canonical(op.Change.Payload, &q) != nil || !q.Saved.Valid() || q.Tenant != q.Saved.Scope.Tenant || q.Context != q.Saved.Scope.Context || q.Saved.Plan.Creator != op.Session.User {
			return out, false
		}
		out = generatedBuildArchive{Scope: q.Saved.Scope, Fact: q.Saved.Fact, Kind: "git", Commit: q.Saved.Plan.Commit, Expected: q.Saved.Plan.ContextRevision, CreatedAt: q.Saved.Plan.CreatedAt, ExpiresAt: q.Saved.Plan.ExpiresAt}
	default:
		return out, false
	}
	return out, true
}

// Same closed artifact/version/next number transaction for both sources. It
// creates no raw body, invented part receipt or duplicate native archive.
func publishBuildArchive(b *ImageBuildCatalog, context ImageBuildContextRecord, policy ImageBuildPolicyRecord, op UserOperation, scope imagebuild.UploadScope, fact imagebuild.SealReceipt, commit string, put func(string, string, string, any) bool) state.Code {
	if _, exists := b.Upload(scope.Tenant, scope.Upload); exists {
		return state.ConditionFailed
	}
	versionID := imagebuild.VersionID(fact)
	if _, exists := b.Version(scope.Tenant, versionID); exists {
		return state.ConditionFailed
	}
	if scope.Length > policy.Spec.CacheBytes || b.storedBytes(scope.Tenant) > policy.Spec.CacheBytes-scope.Length {
		return state.ConditionFailed
	}
	u := ImageBuildUploadRecord{Scope: scope, Revision: 1, Closed: true, Version: versionID, Begin: op, Origin: op}
	// Reserve future cleanup metadata without persisting fabricated evidence.
	reserve := u
	var maxHash [32]byte
	for i := range maxHash {
		maxHash[i] = 255
	}
	reserve.Reclaimed = &imagebuild.ReclaimReceipt{Schema: 1, Scope: scope.Hash(), Version: versionID, Native: maxHash, At: math.MaxInt64, Signature: bytes.Repeat([]byte{255}, 64)}
	if raw, err := json.Marshal(reserve); err != nil || len(raw) > 64<<10 {
		return state.ConditionFailed
	}
	context.NextVersion++
	v := ImageBuildVersionRecord{Tenant: scope.Tenant, Context: scope.Context, Upload: scope.Upload, Number: context.NextVersion, ID: versionID, Fact: fact, Origin: op, Commit: commit}
	b.Uploads = append(b.Uploads, u)
	b.Versions = append(b.Versions, v)
	if !put("context", scope.Tenant, scope.Context, context) || !put("upload", scope.Tenant, scope.Upload, u) || !put("version", scope.Tenant, buildVersionName(versionID), v) {
		return state.Invalid
	}
	return state.Applied
}
