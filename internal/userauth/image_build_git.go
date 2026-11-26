// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

// PlanGitSave reuses source inspection and metadata queries. A raced
// definition/policy fails instead of combining different source snapshots.
func (c Client) PlanGitSave(ctx context.Context, target mydcp.Peer, session access.Session, tenant, contextID, id string) (imagebuild.GitSavePlan, error) {
	if !lifecycle.ValidID(id) {
		return imagebuild.GitSavePlan{}, mydcp.ErrAdmission
	}
	checked, err := c.CheckBuildContext(ctx, target, session, tenant, control.ImageBuildSourceQuery{ID: contextID})
	if err != nil {
		return imagebuild.GitSavePlan{}, err
	}
	if checked.Code == "UNTRUSTED_BASE" {
		return imagebuild.GitSavePlan{}, imagebuild.ErrUntrustedBase
	}
	if checked.Code == "INVALID_CONTEXT" {
		return imagebuild.GitSavePlan{}, imagebuild.ErrInvalid
	}
	if checked.Code != "OK" {
		return imagebuild.GitSavePlan{}, imagebuild.ErrSourceFetch
	}
	contexts, err := c.ImageBuilds(ctx, target, session, tenant, control.ImageBuildQuery{Part: "contexts", ID: contextID}, "")
	if err != nil {
		return imagebuild.GitSavePlan{}, err
	}
	policies, err := c.ImageBuilds(ctx, target, session, tenant, control.ImageBuildQuery{Part: "policy"}, "")
	if err != nil {
		return imagebuild.GitSavePlan{}, err
	}
	if len(contexts.Contexts) != 1 || len(policies.Policies) != 1 || contexts.Contexts[0].Deleted || policies.Policies[0].Deleted || contexts.Contexts[0].Revision != checked.ContextRevision || policies.Policies[0].Revision != checked.PolicyRevision || contexts.Epoch != checked.Epoch || policies.Epoch != checked.Epoch {
		return imagebuild.GitSavePlan{}, imagebuild.ErrConflict
	}
	spec := contexts.Contexts[0].Spec
	if spec.Kind != "git" {
		return imagebuild.GitSavePlan{}, imagebuild.ErrConflict
	}
	at := uint64(time.Now().Unix())
	plan := imagebuild.GitSavePlan{Schema: 1, Tenant: tenant, Context: contextID, ID: id, Creator: session.User, Root: spec.Root, ContextRevision: checked.ContextRevision, PolicyRevision: checked.PolicyRevision, Dockerfile: spec.Dockerfile, ExpandedLimit: policies.Policies[0].Spec.WorkspaceBytes, Commit: checked.Commit, Tree: checked.Tree, CreatedAt: at, ExpiresAt: at + 3600}
	if plan.Validate() != nil {
		return imagebuild.GitSavePlan{}, mydcp.ErrFrame
	}
	return plan, nil
}

// A renewed short proof retries the same plan/ID/commit, never replans it.
func (c Client) SaveGitContext(ctx context.Context, target mydcp.Peer, session access.Session, plan imagebuild.GitSavePlan) (imagebuild.GitSaveResponse, error) {
	return c.requestGitSave(ctx, target, session, plan, false)
}

func (c Client) GitSaveResult(ctx context.Context, target mydcp.Peer, session access.Session, plan imagebuild.GitSavePlan) (imagebuild.GitSaveResponse, error) {
	return c.requestGitSave(ctx, target, session, plan, true)
}

func (c Client) requestGitSave(ctx context.Context, target mydcp.Peer, session access.Session, plan imagebuild.GitSavePlan, result bool) (imagebuild.GitSaveResponse, error) {
	if c.Self == nil || c.Self.Public != session.Key || plan.Validate() != nil || plan.Root.Cluster != c.Cluster || plan.Creator != session.User {
		return imagebuild.GitSaveResponse{}, mydcp.ErrAdmission
	}
	at := time.Now().Unix()
	proof := imagebuild.GitSaveProof{Schema: 1, Plan: plan.Digest(), At: at, ExpiresAt: min(at+120, session.ExpiresAt), Result: result}
	if _, err := rand.Read(proof.Nonce[:]); err != nil {
		return imagebuild.GitSaveResponse{}, err
	}
	proof.Signature = ed25519.Sign(c.Self.Private, imagebuild.GitSaveProofBytes(proof))
	q := imagebuild.GitSaveRequest{Plan: plan, Proof: proof, Result: result}
	reply, err := c.query(ctx, target, session, Request{Method: "save-build-git", Tenant: plan.Tenant, ImageBuildGit: &q})
	if err != nil {
		return imagebuild.GitSaveResponse{}, err
	}
	if reply.ImageBuildGit == nil || !reply.ImageBuildGit.Valid(q) {
		return imagebuild.GitSaveResponse{}, mydcp.ErrFrame
	}
	return *reply.ImageBuildGit, nil
}
