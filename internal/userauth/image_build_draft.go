// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

func (c Client) BuildDraft(ctx context.Context, target mydcp.Peer, session access.Session, tenant string, q imagebuild.DraftRequest) (imagebuild.DraftResponse, error) {
	if tenant == "" || !q.Valid() || q.Scope != nil && (q.Scope.Tenant != tenant || q.Scope.Root.Cluster != c.Cluster) {
		return imagebuild.DraftResponse{}, mydcp.ErrAdmission
	}
	reply, err := c.query(ctx, target, session, Request{Method: "build-draft", Tenant: tenant, ImageBuildDraft: &q})
	if err != nil {
		return imagebuild.DraftResponse{}, err
	}
	if reply.ImageBuildDraft == nil || !reply.ImageBuildDraft.Valid(q) || reply.ImageBuildDraft.Scope.Tenant != tenant || reply.ImageBuildDraft.Scope.Root.Cluster != c.Cluster {
		return imagebuild.DraftResponse{}, mydcp.ErrFrame
	}
	return *reply.ImageBuildDraft, nil
}

// EditBuildDraft signs the fixed scope and exact edit, not a relay-supplied
// native path. A renewed proof retries the SAME edit ID and expected revision.
func (c Client) EditBuildDraft(ctx context.Context, target mydcp.Peer, session access.Session, scope imagebuild.DraftScope, edit imagebuild.DraftEdit, data []byte) (imagebuild.DraftResponse, error) {
	return c.sendDraftEditRequest(ctx, target, session, scope, edit, "edit", data, nil)
}

func (c Client) PutDraftFilePart(ctx context.Context, target mydcp.Peer, session access.Session, scope imagebuild.DraftScope, edit imagebuild.DraftEdit, index uint32, data []byte) (imagebuild.DraftResponse, error) {
	part := &imagebuild.DraftFilePart{Index: index, Length: uint32(len(data)), Digest: sha256.Sum256(data)}
	return c.sendDraftEditRequest(ctx, target, session, scope, edit, "file-part", data, &imagebuild.DraftTransferProof{Kind: "file-part", Part: part})
}

func (c Client) CommitDraftFile(ctx context.Context, target mydcp.Peer, session access.Session, scope imagebuild.DraftScope, edit imagebuild.DraftEdit) (imagebuild.DraftResponse, error) {
	return c.sendDraftEditRequest(ctx, target, session, scope, edit, "file-seal", nil, &imagebuild.DraftTransferProof{Kind: "file-seal"})
}

func (c Client) DraftFileStatus(ctx context.Context, target mydcp.Peer, session access.Session, scope imagebuild.DraftScope, edit imagebuild.DraftEdit, offset uint32) (imagebuild.DraftResponse, error) {
	return c.BuildDraft(ctx, target, session, scope.Tenant, imagebuild.DraftRequest{Context: scope.Context, Kind: "file-status", Scope: &scope, Edit: &edit, Offset: offset})
}

func (c Client) DraftEditResult(ctx context.Context, target mydcp.Peer, session access.Session, scope imagebuild.DraftScope, edit imagebuild.DraftEdit) (imagebuild.DraftResponse, error) {
	return c.sendDraftEditRequest(ctx, target, session, scope, edit, "result", nil, &imagebuild.DraftTransferProof{Kind: "result"})
}

func (c Client) sendDraftEditRequest(ctx context.Context, target mydcp.Peer, session access.Session, scope imagebuild.DraftScope, edit imagebuild.DraftEdit, kind string, data []byte, transfer *imagebuild.DraftTransferProof) (imagebuild.DraftResponse, error) {
	q := imagebuild.DraftRequest{Context: scope.Context, Kind: kind, Scope: &scope, Edit: &edit, Data: data, Proof: &imagebuild.DraftProof{Transfer: transfer}}
	if edit.Validate() != nil {
		return imagebuild.DraftResponse{}, mydcp.ErrAdmission
	}
	return c.sendSignedDraft(ctx, target, session, scope, edit.Digest(), q)
}

func (c Client) FreezeBuildDraft(ctx context.Context, target mydcp.Peer, session access.Session, plan imagebuild.DraftFreezePlan) (imagebuild.DraftResponse, error) {
	return c.requestDraftFreeze(ctx, target, session, plan, "freeze")
}

func (c Client) DraftFreezeResult(ctx context.Context, target mydcp.Peer, session access.Session, plan imagebuild.DraftFreezePlan) (imagebuild.DraftResponse, error) {
	return c.requestDraftFreeze(ctx, target, session, plan, "freeze-result")
}

func (c Client) requestDraftFreeze(ctx context.Context, target mydcp.Peer, session access.Session, plan imagebuild.DraftFreezePlan, kind string) (imagebuild.DraftResponse, error) {
	if plan.Validate() != nil || plan.Creator != session.User {
		return imagebuild.DraftResponse{}, mydcp.ErrAdmission
	}
	q := imagebuild.DraftRequest{Context: plan.Scope.Context, Kind: kind, Scope: &plan.Scope, Freeze: &plan, Proof: &imagebuild.DraftProof{Transfer: &imagebuild.DraftTransferProof{Kind: kind}}}
	return c.sendSignedDraft(ctx, target, session, plan.Scope, plan.Digest(), q)
}

func (c Client) sendSignedDraft(ctx context.Context, target mydcp.Peer, session access.Session, scope imagebuild.DraftScope, subject [32]byte, q imagebuild.DraftRequest) (imagebuild.DraftResponse, error) {
	if c.Self == nil || c.Self.Public != session.Key || scope.Root.Cluster != c.Cluster || scope.Validate() != nil || q.Proof == nil {
		return imagebuild.DraftResponse{}, mydcp.ErrAdmission
	}
	at := time.Now().Unix()
	proof := q.Proof
	proof.Schema, proof.Scope, proof.Edit, proof.At, proof.ExpiresAt = 1, scope.Digest(), subject, at, min(at+120, session.ExpiresAt)
	if !q.Valid() {
		return imagebuild.DraftResponse{}, mydcp.ErrAdmission
	}
	if _, err := rand.Read(proof.Nonce[:]); err != nil {
		return imagebuild.DraftResponse{}, err
	}
	proof.Signature = ed25519.Sign(c.Self.Private, imagebuild.DraftProofBytes(*proof))
	return c.BuildDraft(ctx, target, session, scope.Tenant, q)
}
