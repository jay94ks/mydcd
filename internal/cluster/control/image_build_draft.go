// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/nodestorage"
)

type ImageBuildDraftCall struct {
	Session access.Session
	Tenant  string
	Request imagebuild.DraftRequest
	At      int64
}
type ImageBuildDraftWork struct {
	Scope imagebuild.DraftScope
	Root  nodestorage.Root
	Epoch uint64
}

// Draft files are staged owner-local input, like unconsumed upload bytes.
// Current authority comes from Raft; deploying/publishing their immutable
// version still requires the normal signed user operation and FSM transition.
func (p Policy) ImageBuildDraftWork(s state.State, call ImageBuildDraftCall) (ImageBuildDraftWork, error) {
	p, err := p.Current(s)
	if err != nil {
		return ImageBuildDraftWork{}, err
	}
	if !validID(call.Tenant) || call.At <= 0 || !call.Request.Valid() {
		return ImageBuildDraftWork{}, access.ErrInvalid
	}
	b, err := p.ImageBuilds(s)
	if err != nil {
		return ImageBuildDraftWork{}, err
	}
	c, err := p.Catalog(s)
	if err != nil {
		return ImageBuildDraftWork{}, err
	}
	context, exists := b.Context(call.Tenant, call.Request.Context)
	policy, configured := b.Policy(call.Tenant)
	if call.Request.Result() {
		requested := *call.Request.Scope
		if !exists || !configured || context.Spec.Kind != "draft" || context.Spec.Root != requested.Root || requested.Tenant != call.Tenant || requested.ContextRevision > context.Revision || requested.PolicyRevision > policy.Revision || requested.Data().Generation > context.DraftGeneration() {
			return ImageBuildDraftWork{}, access.ErrConflict
		}
		owner, err := p.nodeOwner(s, requested.Root.Node)
		operation := "put-build-context"
		if call.Request.Kind == "freeze-result" {
			operation = "publish-build-draft"
		}
		if err != nil || owner != requested.Root.Key || c.AuthorizeSession(call.Session, p.Cluster, p.Issuer(call.Session.Issuer), call.At, call.Tenant, access.ManageRegistry, requested.Root.Node) != nil || c.OperationAllowed(call.Session, operation) != nil || call.Request.Authorize(requested, call.Session, call.At) != nil {
			return ImageBuildDraftWork{}, access.ErrDenied
		}
		return ImageBuildDraftWork{Scope: requested, Epoch: s.ModuleEpoch()}, nil
	}
	if !exists || !configured || context.Deleted || policy.Deleted || context.Spec.Kind != "draft" || !context.Spec.Under(policy.Spec) {
		return ImageBuildDraftWork{}, access.ErrConflict
	}
	// Draft editors can read and modify source files. Tenant Read alone is
	// reserved for immutable published version inspection, not editing.
	operation := "put-build-context"
	if call.Request.Kind == "freeze" {
		operation = "publish-build-draft"
	}
	if p.buildRootCurrent(s, c, call.Session, call.At, call.Tenant, context.Spec.Root) != nil || c.OperationAllowed(call.Session, operation) != nil {
		return ImageBuildDraftWork{}, access.ErrDenied
	}
	scope := imagebuild.DraftScope{Schema: 1, Tenant: call.Tenant, Context: context.Spec.ID, Root: context.Spec.Root, ContextRevision: context.Revision, PolicyRevision: policy.Revision, Dockerfile: context.Spec.Dockerfile, ExpandedLimit: policy.Spec.WorkspaceBytes, Generation: context.DraftGeneration()}
	if scope.Validate() != nil {
		return ImageBuildDraftWork{}, access.ErrConflict
	}
	if requested := call.Request.Scope; requested != nil {
		// Preserve the signed representation of schema-1 scopes issued before
		// Generation was added, only while every current authority field and
		// the effective data lifetime still agree. Never re-sign/retarget it.
		normalized := *requested
		normalized.Generation = scope.Generation
		if normalized != scope || requested.Data() != scope.Data() {
			return ImageBuildDraftWork{}, access.ErrConflict
		}
		scope = *requested
	}
	if call.Request.Mutation() && call.Request.Authorize(scope, call.Session, call.At) != nil {
		return ImageBuildDraftWork{}, access.ErrDenied
	}
	roots, err := p.NodeStorage(s)
	if err != nil {
		return ImageBuildDraftWork{}, err
	}
	root, found := roots.Root(scope.Root.Node, scope.Root.ID)
	if !found || root.Reference(p.Cluster) != scope.Root {
		return ImageBuildDraftWork{}, access.ErrConflict
	}
	return ImageBuildDraftWork{Scope: scope, Root: root, Epoch: s.ModuleEpoch()}, nil
}
