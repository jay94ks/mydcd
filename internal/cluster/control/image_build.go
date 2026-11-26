// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strings"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/nodestorage"
)

func buildChangeSelection(change Change) (tenant, node string, err error) {
	switch change.Action {
	case ImageBuildCachePruneAction:
		var q ImageBuildCachePruneChange
		if canonical(change.Payload, &q) != nil || !q.Valid() {
			return "", "", access.ErrInvalid
		}
		return q.Tenant, q.Node, nil
	case "publish-build-git":
		var q ImageBuildGitPublish
		if canonical(change.Payload, &q) != nil || !validID(q.Tenant) || !validID(q.Context) || !q.Saved.Valid() || q.Saved.Scope.Tenant != q.Tenant || q.Saved.Scope.Context != q.Context {
			return "", "", access.ErrInvalid
		}
		return q.Tenant, q.Saved.Scope.Root.Node, nil
	case "publish-build-draft":
		var q ImageBuildDraftPublish
		if canonical(change.Payload, &q) != nil || !validID(q.Tenant) || !validID(q.Context) || !q.Frozen.Valid() || q.Frozen.Scope.Tenant != q.Tenant || q.Frozen.Scope.Context != q.Context {
			return "", "", access.ErrInvalid
		}
		return q.Tenant, q.Frozen.Scope.Root.Node, nil
	case "begin-image-build":
		var q ImageBuildJobStart
		if canonical(change.Payload, &q) != nil || !validID(q.Tenant) || !validID(q.ID) || !validID(q.Context) || q.Version == ([32]byte{}) || q.Snapshot == ([32]byte{}) || q.At == 0 {
			return "", "", access.ErrInvalid
		}
		return q.Tenant, "", nil
	case "cancel-image-build", "delete-image-build-job":
		var q ImageBuildJobSelection
		if canonical(change.Payload, &q) != nil || !validID(q.Tenant) || !validID(q.ID) {
			return "", "", access.ErrInvalid
		}
		return q.Tenant, "", nil
	case "delete-build-version":
		var q ImageBuildVersionSelection
		if canonical(change.Payload, &q) != nil || !validID(q.Tenant) || q.ID == ([32]byte{}) {
			return "", "", access.ErrInvalid
		}
		return q.Tenant, "", nil
	case "set-image-build-policy":
		var q ImageBuildPolicyPut
		if canonical(change.Payload, &q) != nil {
			return "", "", access.ErrInvalid
		}
		return q.Spec.Tenant, "", nil
	case "put-build-context":
		var q ImageBuildContextPut
		if canonical(change.Payload, &q) != nil || q.Spec.Validate() != nil {
			return "", "", access.ErrInvalid
		}
		return q.Spec.Tenant, q.Spec.Root.Node, nil
	case "delete-image-build-policy", "delete-build-context":
		var q ImageBuildSelection
		if canonical(change.Payload, &q) != nil || !validID(q.Tenant) || change.Action == "delete-build-context" && !validID(q.ID) || change.Action == "delete-image-build-policy" && q.ID != "" {
			return "", "", access.ErrInvalid
		}
		return q.Tenant, "", nil
	case "begin-build-zip-upload":
		var q ImageBuildUploadBegin
		if canonical(change.Payload, &q) != nil || !validID(q.Tenant) || !validID(q.Context) || !validID(q.Upload) || q.ChunkBytes != 0 && q.ChunkBytes != imagebuild.UploadPartBytes {
			return "", "", access.ErrInvalid
		}
		return q.Tenant, "", nil
	case "put-build-zip-part":
		var q ImageBuildUploadPart
		if canonical(change.Payload, &q) != nil || !validID(q.Tenant) || !validID(q.Upload) {
			return "", "", access.ErrInvalid
		}
		return q.Tenant, "", nil
	case "abort-build-zip-upload":
		var q ImageBuildUploadSelection
		if canonical(change.Payload, &q) != nil || !validID(q.Tenant) || !validID(q.Upload) {
			return "", "", access.ErrInvalid
		}
		return q.Tenant, "", nil
	case "upload-build-zip":
		var q ImageBuildZIPConsume
		if canonical(change.Payload, &q) != nil || !validID(q.Tenant) || !validID(q.ID) || !validID(q.Upload) {
			return "", "", access.ErrInvalid
		}
		return q.Tenant, "", nil
	}
	return "", "", access.ErrInvalid
}
func (p Policy) authorizeImageBuild(c access.Catalog, op UserOperation) error {
	tenant, node, err := buildChangeSelection(op.Change)
	if err != nil || !validID(tenant) || c.OperationAllowed(op.Session, op.Change.Action) != nil {
		return access.ErrDenied
	}
	if op.Change.Action == "cancel-image-build" || op.Change.Action == "delete-image-build-job" || op.Change.Action == "delete-build-version" || op.Change.Action == "abort-build-zip-upload" || op.Change.Action == "delete-build-context" || op.Change.Action == "delete-image-build-policy" {
		return c.AuthorizeSessionCleanup(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, tenant, access.ManageRegistry)
	}
	return c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, tenant, access.ManageRegistry, node)
}
func (p Policy) buildRootCurrent(s state.State, c access.Catalog, session access.Session, at int64, tenant string, ref nodestorage.Reference) error {
	if c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.ManageRegistry, ref.Node) != nil {
		return access.ErrDenied
	}
	return p.buildRootPlacement(s, c, session.User, tenant, ref)
}

// Callers must establish that this exact grant belongs to a committed origin.
func (p Policy) buildRootAccepted(s state.State, c access.Catalog, session access.Session, acceptedAt int64, tenant string, ref nodestorage.Reference) error {
	if c.AuthorizeAccepted(session, p.Cluster, acceptedAt, tenant, access.ManageRegistry, ref.Node) != nil {
		return access.ErrDenied
	}
	return p.buildRootPlacement(s, c, session.User, tenant, ref)
}

func (p Policy) buildRootPlacement(s state.State, c access.Catalog, user, tenant string, ref nodestorage.Reference) error {
	owner, err := p.workNodeOwner(s, ref.Node)
	if err != nil || owner != ref.Key {
		return access.ErrDenied
	}
	roots, err := p.NodeStorage(s)
	if err != nil {
		return err
	}
	root, err := roots.CanBuild(c, user, tenant, ref.Node, ref.ID, ref.Generation)
	if err != nil || root.Reference(p.Cluster) != ref {
		return access.ErrDenied
	}
	return nil
}
func (b ImageBuildCatalog) storedBytes(tenant string) int64 {
	var n int64
	for _, r := range b.Uploads {
		if r.Scope.Tenant == tenant && r.Reclaimed == nil {
			n += r.Scope.Length
		}
	}
	return n
}
func (p Policy) reduceImageBuilds(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	if cmd.Kind == state.ModuleReport {
		if _, _, err := p.imageBuildCacheAutomaticReport(s, cmd); err == nil {
			return p.reduceImageBuildCacheAutomatic(s, cmd)
		}
		if _, _, err := p.imageBuildAutomaticGitReport(s, cmd); err == nil {
			return p.reduceImageBuildAutomaticGit(s, cmd)
		}
		if _, _, err := p.imageBuildGitObservationReport(s, cmd); err == nil {
			return p.reduceImageBuildGitObservation(s, cmd)
		}
		if _, _, err := p.imageBuildCachePruneReport(s, cmd); err == nil {
			return p.reduceImageBuildCachePruneReport(s, cmd)
		}
		if _, _, err := p.imageBuildJobReport(s, cmd); err == nil {
			return p.reduceImageBuildJobReport(s, cmd)
		}
		return p.reduceImageBuildOwner(s, cmd)
	}
	if (cmd.Kind != state.Module && cmd.Kind != state.ModuleUpload) || !strings.HasPrefix(cmd.Actor, "user/") {
		return nil, state.Forbidden
	}
	current, err := p.Current(s)
	if err != nil {
		return nil, state.Invalid
	}
	p = current
	c, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	op, err := p.Operation(c, cmd, false)
	if err != nil || op.At <= 0 || p.authorizeImageBuild(c, op) != nil {
		return nil, state.Forbidden
	}
	b, err := p.ImageBuilds(s)
	if err != nil {
		return nil, state.Invalid
	}
	writes := map[string][]byte{}
	put := func(kind, tenant, id string, value any) bool {
		return writeBuildRecord(writes, kind, tenant, id, value) == nil
	}
	switch op.Change.Action {
	case ImageBuildCachePruneAction:
		var code state.Code
		b, code = p.reduceImageBuildCachePrune(s, b, op, writes)
		if code != state.Applied {
			return nil, code
		}
	case "begin-image-build", "cancel-image-build", "delete-image-build-job":
		var code state.Code
		b, code = p.reduceImageBuildJob(s, b, op, writes)
		if code != state.Applied {
			return nil, code
		}
	case "delete-build-version":
		var q ImageBuildVersionSelection
		if canonical(op.Change.Payload, &q) != nil {
			return nil, state.Invalid
		}
		v, ok := b.Version(q.Tenant, q.ID)
		if !ok || v.Deleted || v.Number != op.Change.Expected || b.VersionUsed(q.Tenant, q.ID) {
			return nil, state.ConditionFailed
		}
		v.Deleted, v.DeletedBy = true, &op
		if !put("version", q.Tenant, buildVersionName(q.ID), v) {
			return nil, state.Invalid
		}
	case "set-image-build-policy", "delete-image-build-policy":
		var spec imagebuild.Policy
		var tenant string
		if op.Change.Action == "set-image-build-policy" {
			var q ImageBuildPolicyPut
			if canonical(op.Change.Payload, &q) != nil || q.Spec.Validate(p.Cluster) != nil {
				return nil, state.Invalid
			}
			spec, tenant = q.Spec, q.Spec.Tenant
		} else {
			var q ImageBuildSelection
			_ = canonical(op.Change.Payload, &q)
			tenant = q.Tenant
		}
		r, found := b.Policy(tenant)
		if r.Revision != op.Change.Expected || r.Revision == math.MaxUint64 {
			return nil, state.ConditionFailed
		}
		if op.Change.Action == "delete-image-build-policy" {
			if !found || r.Deleted {
				return nil, state.ConditionFailed
			}
			for _, ctx := range b.Contexts {
				if ctx.Spec.Tenant == tenant && !ctx.Deleted {
					return nil, state.ConditionFailed
				}
			}
			for _, u := range b.Uploads {
				if u.Scope.Tenant == tenant && !u.Closed {
					return nil, state.ConditionFailed
				}
			}
			r.Deleted = true
		} else {
			if b.storedBytes(tenant) > spec.CacheBytes {
				return nil, state.ConditionFailed
			}
			if _, err := c.CheckImageTrust(tenant, spec.BuilderImage); err != nil {
				return nil, state.Forbidden
			}
			registries, err := p.Registries(s)
			if err != nil {
				return nil, state.Invalid
			}
			entry, ok := registries.Entry(tenant, spec.Registry)
			if !ok || entry.Deleted {
				return nil, state.ConditionFailed
			}
			for _, n := range spec.Nodes {
				if p.buildRootCurrent(s, c, op.Session, op.At, tenant, n.Root) != nil {
					return nil, state.Forbidden
				}
			}
			r.Spec, r.Deleted, r.Definition = spec, false, op
		}
		r.Revision++
		r.Origin = op
		if !found {
			b.Policies = append(b.Policies, r)
		}
		if !put("policy", tenant, "policy", r) {
			return nil, state.Invalid
		}
	case "put-build-context", "delete-build-context":
		var q ImageBuildContextPut
		var selection ImageBuildSelection
		if op.Change.Action == "put-build-context" {
			if canonical(op.Change.Payload, &q) != nil || q.Spec.Validate() != nil {
				return nil, state.Invalid
			}
			selection = ImageBuildSelection{q.Spec.Tenant, q.Spec.ID}
		} else {
			_ = canonical(op.Change.Payload, &selection)
		}
		r, found := b.Context(selection.Tenant, selection.ID)
		if r.Revision != op.Change.Expected || r.Revision == math.MaxUint64 {
			return nil, state.ConditionFailed
		}
		if op.Change.Action == "delete-build-context" {
			if !found || r.Deleted {
				return nil, state.ConditionFailed
			}
			if r.DataGeneration == 0 {
				r.DataGeneration = r.Revision
			}
			for _, u := range b.Uploads {
				if u.Scope.Tenant == selection.Tenant && u.Scope.Context == selection.ID && !u.Closed {
					return nil, state.ConditionFailed
				}
			}
			for _, v := range b.Versions {
				if v.Tenant == selection.Tenant && v.Context == selection.ID && !v.Deleted {
					return nil, state.ConditionFailed
				}
			}
			r.Deleted = true
		} else {
			policy, ok := b.Policy(q.Spec.Tenant)
			if !ok || policy.Deleted || !q.Spec.Under(policy.Spec) || p.buildRootCurrent(s, c, op.Session, op.At, q.Spec.Tenant, q.Spec.Root) != nil {
				return nil, state.ConditionFailed
			}
			if found && (r.Spec.Root != q.Spec.Root || r.Spec.Kind != q.Spec.Kind) {
				return nil, state.ConditionFailed
			}
			if !found || r.Deleted {
				r.DataGeneration = r.Revision + 1
			} else if r.DataGeneration == 0 {
				r.DataGeneration = r.Revision
			}
			r.Spec, r.Deleted, r.Definition = q.Spec.Own(), false, op
			r.GitObservation = nil // A new definition needs its own source observation.
		}
		r.Revision++
		r.Origin = op
		if !found {
			b.Contexts = append(b.Contexts, r)
		}
		if !put("context", selection.Tenant, selection.ID, r) {
			return nil, state.Invalid
		}
	case "publish-build-draft":
		if code := p.publishBuildDraft(s, c, &b, op, put); code != state.Applied {
			return nil, code
		}
	case "publish-build-git":
		if code := p.publishBuildGit(s, c, &b, op, put); code != state.Applied {
			return nil, code
		}
	case "begin-build-zip-upload":
		var q ImageBuildUploadBegin
		_ = canonical(op.Change.Payload, &q)
		if op.Change.Expected != 0 {
			return nil, state.ConditionFailed
		}
		if _, exists := b.Upload(q.Tenant, q.Upload); exists {
			return nil, state.ConditionFailed
		}
		context, ok := b.Context(q.Tenant, q.Context)
		policy, hasPolicy := b.Policy(q.Tenant)
		if !ok || context.Deleted || context.Spec.Kind != "upload" || !hasPolicy || policy.Deleted || !context.Spec.Under(policy.Spec) || p.buildRootCurrent(s, c, op.Session, op.At, q.Tenant, context.Spec.Root) != nil {
			return nil, state.ConditionFailed
		}
		active := 0
		for _, u := range b.Uploads {
			if u.Scope.Tenant == q.Tenant && !u.Closed {
				active++
			}
		}
		if active >= 16 || q.Length <= 0 || q.Length > imagebuild.MaxZIPBytes || q.Length > policy.Spec.CacheBytes || b.storedBytes(q.Tenant) > policy.Spec.CacheBytes-q.Length {
			return nil, state.ConditionFailed
		}
		scope := imagebuild.UploadScope{Schema: 1, Cluster: p.Cluster, Tenant: q.Tenant, Context: q.Context, Upload: q.Upload, Creator: op.Session.User, Root: context.Spec.Root, ContextRevision: context.Revision, PolicyRevision: policy.Revision, Length: q.Length, Digest: q.Digest, Dockerfile: context.Spec.Dockerfile, ExpandedLimit: policy.Spec.WorkspaceBytes, ExpiresAt: q.ExpiresAt, ChunkBytes: q.ChunkBytes}
		u, err := imagebuild.BeginUpload(scope, uint64(op.At))
		if err != nil {
			return nil, state.Invalid
		}
		r := ImageBuildUploadRecord{Scope: scope, Revision: u.Revision, Begin: op, Origin: op}
		b.Uploads = append(b.Uploads, r)
		if !put("upload", q.Tenant, q.Upload, r) {
			return nil, state.Invalid
		}
	case "put-build-zip-part", "abort-build-zip-upload", "upload-build-zip":
		var tenant, upload string
		var part ImageBuildUploadPart
		var consume ImageBuildZIPConsume
		if op.Change.Action == "put-build-zip-part" {
			_ = canonical(op.Change.Payload, &part)
			tenant, upload = part.Tenant, part.Upload
		} else if op.Change.Action == "upload-build-zip" {
			_ = canonical(op.Change.Payload, &consume)
			tenant, upload = consume.Tenant, consume.Upload
		} else {
			var q ImageBuildUploadSelection
			_ = canonical(op.Change.Payload, &q)
			tenant, upload = q.Tenant, q.Upload
		}
		r, found := b.Upload(tenant, upload)
		if !found || r.Scope.Creator != op.Session.User || r.Revision != op.Change.Expected || r.Closed {
			return nil, state.ConditionFailed
		}
		u, err := hydrateBuildUpload(s, r)
		if err != nil {
			return nil, state.Invalid
		}
		if op.Change.Action == "abort-build-zip-upload" {
			u, err = u.Abort(op.Session.User, op.Change.Expected)
		} else {
			if p.currentBuildUpload(s, c, op.Session, op.At, b, r) != nil {
				return nil, state.ConditionFailed
			}
			if op.Change.Action == "put-build-zip-part" {
				u, err = u.Put(op.Session.User, op.Change.Expected, uint64(op.At), part.Receipt)
				if err == nil {
					writes[buildPartKey(tenant, upload, part.Receipt.Index)] = []byte(hex.EncodeToString(part.Receipt.Digest[:]))
				}
			} else {
				u, err = u.Consume(op.Session.User, consume.ID, op.Change.Expected, uint64(op.At), consume.Fact)
				if err == nil {
					context, _ := b.Context(tenant, consume.ID)
					if context.NextVersion == math.MaxUint64 {
						return nil, state.ConditionFailed
					}
					context.NextVersion++
					version := ImageBuildVersionRecord{Tenant: tenant, Context: consume.ID, Upload: upload, Number: context.NextVersion, ID: u.Version, Fact: consume.Fact, Origin: op}
					b.Versions = append(b.Versions, version)
					if !put("context", tenant, consume.ID, context) || !put("version", tenant, buildVersionName(u.Version), version) {
						return nil, state.Invalid
					}
				}
			}
		}
		if err != nil {
			return nil, state.ConditionFailed
		}
		if u.Closed {
			for key, obj := range s.Objects(buildPartPrefix(tenant, upload)) {
				if obj.Present {
					writes[key] = nil
				}
			}
		}
		r = buildUploadRecord(r, u, op)
		if !put("upload", tenant, upload, r) {
			return nil, state.Invalid
		}
	default:
		return nil, state.Invalid
	}
	raw, err := b.root(p.Cluster)
	if err != nil {
		return nil, state.ConditionFailed
	}
	writes[ImageBuildKey] = raw
	return writes, state.Applied
}

func (p Policy) currentBuildUpload(s state.State, c access.Catalog, session access.Session, at int64, b ImageBuildCatalog, r ImageBuildUploadRecord) error {
	context, ok := b.Context(r.Scope.Tenant, r.Scope.Context)
	policy, hasPolicy := b.Policy(r.Scope.Tenant)
	if !ok || !hasPolicy || context.Deleted || policy.Deleted || context.Revision != r.Scope.ContextRevision || policy.Revision != r.Scope.PolicyRevision || context.Spec.Root != r.Scope.Root || context.Spec.Dockerfile != r.Scope.Dockerfile || !context.Spec.Under(policy.Spec) || r.Scope.Current(session.User, uint64(at)) != nil || r.Closed {
		return access.ErrConflict
	}
	return p.buildRootCurrent(s, c, session, at, r.Scope.Tenant, r.Scope.Root)
}

// validateImageBuildState validates retained ownership on restore and whenever
// a row changes. Unchanged original signatures are not rechecked for each part.
func (p Policy) validateImageBuildState(before, after state.State) error {
	b, err := p.ImageBuilds(after)
	if err != nil {
		return err
	}
	if err := p.validateImageBuildSecretRefs(after, b); err != nil {
		return err
	}
	if err := p.validateImageBuildSourceRefs(after, b); err != nil {
		return err
	}
	for key, obj := range after.Objects(ImageBuildKey + "/records/") {
		if !obj.Present || before.Object(key) == obj {
			continue
		}
		switch {
		case strings.Contains(key, "/records/cache-prune/") || strings.Contains(key, "/records/cache-automatic/"):
			var r ImageBuildCachePruneRecord
			if canonical([]byte(obj.Value), &r) != nil || validateImageBuildCachePrune(b, r, p.Cluster, true) != nil {
				return ErrCatalog
			}
		case strings.Contains(key, "/records/job/"):
			var r ImageBuildJobRecord
			_ = canonical([]byte(obj.Value), &r)
			if validateImageBuildJob(r, p.Cluster) != nil {
				return ErrCatalog
			}
		case strings.Contains(key, "/records/policy/"):
			var r ImageBuildPolicyRecord
			_ = canonical([]byte(obj.Value), &r)
			var q ImageBuildPolicyPut
			if r.Definition.VerifyOriginal(p.Cluster) != nil || r.Origin.VerifyOriginal(p.Cluster) != nil || r.Definition.Change.Action != "set-image-build-policy" || canonical(r.Definition.Change.Payload, &q) != nil || !buildJSONEqual(q.Spec, r.Spec) || r.Definition.Change.Expected >= r.Revision || r.Origin.Change.Expected != r.Revision-1 || r.Deleted != (r.Origin.Change.Action == "delete-image-build-policy") || !r.Deleted && r.Origin.Change.Action != "set-image-build-policy" {
				return ErrCatalog
			}
		case strings.Contains(key, "/records/context/"):
			var r ImageBuildContextRecord
			_ = canonical([]byte(obj.Value), &r)
			var q ImageBuildContextPut
			if r.DataGeneration > r.Revision || !validImageBuildGitObservation(r, p.Cluster) {
				return ErrCatalog
			}
			if oldObject := before.Object(key); oldObject.Present {
				var old ImageBuildContextRecord
				if canonical([]byte(oldObject.Value), &old) != nil {
					return ErrCatalog
				}
				if old.Revision == r.Revision {
					if old.DataGeneration != r.DataGeneration {
						return ErrCatalog
					}
				} else {
					want := old.DraftGeneration()
					if r.Origin.Change.Action != "delete-build-context" && old.Deleted {
						want = r.Revision
					}
					if r.DataGeneration != want {
						return ErrCatalog
					}
				}
			}

			if r.Definition.VerifyOriginal(p.Cluster) != nil || r.Origin.VerifyOriginal(p.Cluster) != nil || r.Definition.Change.Action != "put-build-context" || canonical(r.Definition.Change.Payload, &q) != nil || !buildJSONEqual(q.Spec, r.Spec) || r.Definition.Change.Expected >= r.Revision || r.Origin.Change.Expected != r.Revision-1 || r.Deleted != (r.Origin.Change.Action == "delete-build-context") || !r.Deleted && r.Origin.Change.Action != "put-build-context" {
				return ErrCatalog
			}
		case strings.Contains(key, "/records/upload/"):
			var r ImageBuildUploadRecord
			_ = canonical([]byte(obj.Value), &r)
			actual := r
			if r.Expiry != nil {
				if !r.Closed || r.Version != ([32]byte{}) || !r.Expiry.Valid(r.Scope) || r.Revision < 2 || r.ExpiryReceived > r.Scope.Parts() {
					return ErrCatalog
				}
				r.Closed = false
				r.Revision--
				r.Received = r.ExpiryReceived
			} else if r.ExpiryReceived != 0 {
				return ErrCatalog
			}
			if actual.Reclaimed != nil && (!actual.Closed || !actual.Reclaimed.Valid(actual.Scope, actual.Version) || b.ArtifactReferenced(actual)) {
				return ErrCatalog
			}
			if r.Automatic != nil || r.Begin.Change.Action == "publish-build-draft" || r.Begin.Change.Action == "publish-build-git" {
				if r.Progress != nil {
					return ErrCatalog
				}
				context, exists := b.Context(r.Scope.Tenant, r.Scope.Context)
				if !exists || !validGeneratedBuildUpload(actual, context, p.Cluster) {
					return ErrCatalog
				}
				if _, err := hydrateBuildUpload(after, actual); err != nil {
					return err
				}
				continue
			}
			var q ImageBuildUploadBegin
			if r.Begin.VerifyOriginal(p.Cluster) != nil || r.Origin.VerifyOriginal(p.Cluster) != nil || r.Begin.Change.Action != "begin-build-zip-upload" || canonical(r.Begin.Change.Payload, &q) != nil || q.Tenant != r.Scope.Tenant || q.Context != r.Scope.Context || q.Upload != r.Scope.Upload || q.Length != r.Scope.Length || q.Digest != r.Scope.Digest || q.ExpiresAt != r.Scope.ExpiresAt || q.ChunkBytes != r.Scope.ChunkBytes || r.Begin.Session.User != r.Scope.Creator || r.Begin.Change.Expected != 0 || r.Origin.Session.User != r.Scope.Creator {
				return ErrCatalog
			}
			ctx, exists := b.Context(r.Scope.Tenant, r.Scope.Context)
			if !exists || ctx.Spec.Root != r.Scope.Root || r.Scope.ContextRevision > ctx.Revision || r.Scope.ContextRevision == ctx.Revision && ctx.Spec.Dockerfile != r.Scope.Dockerfile {
				return ErrCatalog
			}
			if r.Progress != nil {
				if !validBuildPartCheckpoint(after, r, actual.Expiry != nil) {
					return ErrCatalog
				}
				if _, err := hydrateBuildUpload(after, actual); err != nil {
					return err
				}
				continue
			}
			switch r.Origin.Change.Action {
			case "begin-build-zip-upload":
				if r.Revision != 1 || r.Received != 0 || r.Closed || !buildJSONEqual(r.Begin, r.Origin) {
					return ErrCatalog
				}
			case "put-build-zip-part":
				var part ImageBuildUploadPart
				if canonical(r.Origin.Change.Payload, &part) != nil || part.Tenant != r.Scope.Tenant || part.Upload != r.Scope.Upload || !part.Receipt.Valid(r.Scope) || r.Closed || r.Origin.Change.Expected != r.Revision-1 && r.Origin.Change.Expected != r.Revision || actual.Expiry == nil && after.Object(buildPartKey(part.Tenant, part.Upload, part.Receipt.Index)).Value != hex.EncodeToString(part.Receipt.Digest[:]) {
					return ErrCatalog
				}
			case "abort-build-zip-upload":
				var selection ImageBuildUploadSelection
				if canonical(r.Origin.Change.Payload, &selection) != nil || selection.Tenant != r.Scope.Tenant || selection.Upload != r.Scope.Upload || !r.Closed || r.Version != ([32]byte{}) || r.Origin.Change.Expected != r.Revision-1 {
					return ErrCatalog
				}
			case "upload-build-zip":
				var consume ImageBuildZIPConsume
				if canonical(r.Origin.Change.Payload, &consume) != nil || consume.Tenant != r.Scope.Tenant || consume.ID != r.Scope.Context || consume.Upload != r.Scope.Upload || !r.Closed || !consume.Fact.Valid(r.Scope) || r.Version != imagebuild.VersionID(consume.Fact) || r.Origin.Change.Expected != r.Revision-1 {
					return ErrCatalog
				}
			default:
				return ErrCatalog
			}
			if _, err := hydrateBuildUpload(after, actual); err != nil {
				return err
			}
		case strings.Contains(key, "/records/version/"):
			var r ImageBuildVersionRecord
			_ = canonical([]byte(obj.Value), &r)
			u, ok := b.Upload(r.Tenant, r.Upload)
			if !ok || !u.Closed || u.Version != r.ID || u.Scope.Context != r.Context || !r.Fact.Valid(u.Scope) || !validBuildVersionOrigin(r, u, p.Cluster) {
				return ErrCatalog
			}
			if r.Deleted != (r.DeletedBy != nil) {
				return ErrCatalog
			}
			if r.DeletedBy != nil {
				var selection ImageBuildVersionSelection
				if r.DeletedBy.VerifyOriginal(p.Cluster) != nil || r.DeletedBy.Change.Action != "delete-build-version" || r.DeletedBy.Change.Expected != r.Number || canonical(r.DeletedBy.Change.Payload, &selection) != nil || selection.Tenant != r.Tenant || selection.ID != r.ID {
					return ErrCatalog
				}
			}
		}
	}
	for _, ctx := range b.Contexts {
		var last uint64
		seen := map[uint64]bool{}
		for _, v := range b.Versions {
			if v.Tenant == ctx.Spec.Tenant && v.Context == ctx.Spec.ID {
				if seen[v.Number] {
					return ErrCatalog
				}
				seen[v.Number] = true
				last = max(last, v.Number)
			}
		}
		if last != ctx.NextVersion {
			return ErrCatalog
		}
	}
	for _, u := range b.Uploads {
		if _, ok := b.Context(u.Scope.Tenant, u.Scope.Context); !ok {
			return ErrCatalog
		}
		// An unchanged archive still reserves its original automatic job.
		// Checking only modified, present records misses a deleted counterpart.
		if u.Automatic != nil {
			job, ok := b.Job(u.Scope.Tenant, u.Scope.Upload)
			if !ok || job.Run.Spec.Version != u.Version || !buildJSONEqual(job.Automatic, u.Automatic) || !buildJSONEqual(job.Origin, u.Begin) {
				return ErrCatalog
			}
		}
		if u.Version != ([32]byte{}) {
			v, ok := b.Version(u.Scope.Tenant, u.Version)
			if !ok || v.Upload != u.Scope.Upload || v.Context != u.Scope.Context {
				return ErrCatalog
			}
		}
	}
	for _, r := range b.Jobs {
		v, ok := b.Version(r.Run.Spec.Tenant, r.Run.Spec.Version)
		if !ok || v.Context != r.Run.Spec.Context.ID || v.Number != r.Run.Spec.Number || !buildJSONEqual(v.Fact, r.Run.Spec.Seal) || !r.Deleted && v.Deleted {
			return ErrCatalog
		}
		u, ok := b.Upload(r.Run.Spec.Tenant, v.Upload)
		if !ok || u.Scope != r.Run.Spec.Scope || !r.Deleted && u.Reclaimed != nil {
			return ErrCatalog
		}
		if r.Automatic != nil && (!buildJSONEqual(u.Automatic, r.Automatic) || !buildJSONEqual(u.Begin, r.Origin)) {
			return ErrCatalog
		}
	}
	for key, obj := range after.Objects(ImageBuildKey + "/slots/") {
		if !obj.Present || before.Object(key) == obj {
			continue
		}
		parts := strings.Split(strings.TrimPrefix(key, ImageBuildKey+"/slots/"), "/")
		if len(parts) != 3 {
			return ErrCatalog
		}
		u, ok := b.Upload(parts[0], parts[1])
		if !ok || u.Closed {
			return ErrCatalog
		}
		var index uint32
		_, err := fmt.Sscanf(parts[2], "%08d", &index)
		raw, decodeErr := hex.DecodeString(obj.Value)
		if err != nil || key != buildPartKey(parts[0], parts[1], index) || index >= u.Scope.Parts() || decodeErr != nil || len(raw) != 32 || hex.EncodeToString(raw) != obj.Value || string(raw) == string(make([]byte, 32)) {
			return ErrCatalog
		}
	}
	return nil
}
func buildJSONEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}
