// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/nodestorage"
)

type ImageBuildGitCall struct {
	Session access.Session
	Tenant  string
	Request imagebuild.GitSaveRequest
	At      int64
}
type ImageBuildGitWork struct {
	Read ImageBuildSourceRead
	Root nodestorage.Root
}

func (p Policy) ImageBuildGitWork(s state.State, call ImageBuildGitCall) (ImageBuildGitWork, error) {
	if !validID(call.Tenant) || !call.Request.Valid() || call.Request.Plan.Tenant != call.Tenant || call.Request.Authorize(call.Session, call.At) != nil {
		return ImageBuildGitWork{}, access.ErrDenied
	}
	if call.Request.Result {
		return p.imageBuildGitResultWork(s, call)
	}
	read, err := p.ImageBuildSourceRead(s, call.Session, call.At, call.Tenant, ImageBuildSourceQuery{ID: call.Request.Plan.Context})
	if err != nil {
		return ImageBuildGitWork{}, err
	}
	plan := call.Request.Plan
	if plan.Root != read.Spec.Root || plan.ContextRevision != read.ContextRevision || plan.PolicyRevision != read.PolicyRevision || plan.Dockerfile != read.Spec.Dockerfile || plan.ExpandedLimit != read.Policy.WorkspaceBytes {
		return ImageBuildGitWork{}, access.ErrConflict
	}
	c, err := p.Catalog(s)
	if err != nil {
		return ImageBuildGitWork{}, err
	}
	if c.OperationAllowed(call.Session, "publish-build-git") != nil {
		return ImageBuildGitWork{}, access.ErrDenied
	}
	roots, err := p.NodeStorage(s)
	if err != nil {
		return ImageBuildGitWork{}, err
	}
	root, ok := roots.Root(plan.Root.Node, plan.Root.ID)
	if !ok || root.Reference(p.Cluster) != plan.Root {
		return ImageBuildGitWork{}, access.ErrConflict
	}
	return ImageBuildGitWork{Read: read, Root: root}, nil
}

func (p Policy) imageBuildGitResultWork(s state.State, call ImageBuildGitCall) (ImageBuildGitWork, error) {
	p, err := p.Current(s)
	if err != nil {
		return ImageBuildGitWork{}, err
	}
	book, err := p.ImageBuilds(s)
	if err != nil {
		return ImageBuildGitWork{}, err
	}
	c, err := p.Catalog(s)
	if err != nil {
		return ImageBuildGitWork{}, err
	}
	plan := call.Request.Plan
	context, exists := book.Context(call.Tenant, plan.Context)
	policy, configured := book.Policy(call.Tenant)
	if !exists || !configured || context.Spec.Kind != "git" || context.Spec.Root != plan.Root || plan.ContextRevision > context.Revision || plan.PolicyRevision > policy.Revision {
		return ImageBuildGitWork{}, access.ErrConflict
	}
	owner, err := p.nodeOwner(s, plan.Root.Node)
	if err != nil || owner != plan.Root.Key || c.AuthorizeSession(call.Session, p.Cluster, p.Issuer(call.Session.Issuer), call.At, call.Tenant, access.ManageRegistry, plan.Root.Node) != nil || c.OperationAllowed(call.Session, "publish-build-git") != nil {
		return ImageBuildGitWork{}, access.ErrDenied
	}
	return ImageBuildGitWork{Read: ImageBuildSourceRead{Session: call.Session, Tenant: call.Tenant, Spec: context.Spec.Own(), Policy: policy.Spec, ContextRevision: context.Revision, PolicyRevision: policy.Revision, Epoch: s.ModuleEpoch()}}, nil
}
