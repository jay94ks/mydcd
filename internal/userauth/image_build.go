// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/registryclient"
	"github.com/jay94ks/seafield/internal/sfcp"
)

func (c Client) PlanImageBuildJob(ctx context.Context, target sfcp.Peer, session access.Session, tenant string, q control.ImageBuildJobQuery) (control.ImageBuildJobPlan, error) {
	if tenant == "" || !q.Valid() {
		return control.ImageBuildJobPlan{}, sfcp.ErrAdmission
	}
	plan, err := call(ctx, c, target, session, ImageBuildJobPlanMethod, ImageBuildJobPlanQuery{Tenant: tenant, Query: q})
	if err != nil {
		return control.ImageBuildJobPlan{}, err
	}
	if plan.Schema != 1 || plan.Spec.Cluster != c.Cluster || plan.Spec.Tenant != tenant || plan.Spec.ID != q.ID || plan.Spec.Version != q.Version || plan.Spec.Context.ID != q.Context || plan.Spec.Validate() != nil || plan.Change.Tenant != tenant || plan.Change.ID != q.ID || plan.Change.Context != q.Context || plan.Change.Version != q.Version || plan.Change.At != plan.Spec.CreatedAt || plan.Change.Snapshot != plan.Spec.Digest() || plan.Epoch == 0 || plan.Index == 0 || plan.RootRevision == 0 {
		return control.ImageBuildJobPlan{}, sfcp.ErrFrame
	}
	if !control.ValidImageBuildSecretUses(plan, session) {
		return control.ImageBuildJobPlan{}, sfcp.ErrFrame
	}
	return plan, nil
}

func (c Client) BuildContextContent(ctx context.Context, target sfcp.Peer, session access.Session, tenant string, q imagebuild.ContentQuery, after string) (control.ImageBuildContentPage, error) {
	if tenant == "" || !q.Valid() {
		return control.ImageBuildContentPage{}, sfcp.ErrAdmission
	}
	root, key, err := registryclient.CatalogueCursor(after)
	if err != nil {
		return control.ImageBuildContentPage{}, sfcp.ErrAdmission
	}
	offset := q.Offset
	if after != "" {
		if q.Offset != 0 {
			return control.ImageBuildContentPage{}, sfcp.ErrAdmission
		}
		if _, err := fmt.Sscanf(key, "%010d", &offset); err != nil || fmt.Sprintf("%010d", offset) != key {
			return control.ImageBuildContentPage{}, sfcp.ErrAdmission
		}
	}
	page, err := call(ctx, c, target, session, BuildContextContentMethod, BuildContextContentQuery{Tenant: tenant, Query: q, After: after})
	if err != nil {
		return control.ImageBuildContentPage{}, err
	}
	if !validBuildContentPage(page, q, offset, root) {
		return control.ImageBuildContentPage{}, sfcp.ErrFrame
	}
	return page, nil
}
func validBuildContentPage(page control.ImageBuildContentPage, q imagebuild.ContentQuery, offset uint64, root [32]byte) bool {
	if !page.Page.Valid(q) || page.Page.PageOffset() != offset || page.Root == ([32]byte{}) || page.Epoch == 0 || root != ([32]byte{}) && page.Root != root {
		return false
	}
	if page.Page.PageNext() == 0 {
		return page.Next == ""
	}
	next, key, err := registryclient.CatalogueCursor(page.Next)
	return err == nil && next == page.Root && key == fmt.Sprintf("%010d", page.Page.PageNext())
}

func (c Client) CheckBuildContext(ctx context.Context, target sfcp.Peer, session access.Session, tenant string, q control.ImageBuildSourceQuery) (control.ImageBuildSourceResult, error) {
	if tenant == "" || !q.Valid() {
		return control.ImageBuildSourceResult{}, sfcp.ErrAdmission
	}
	out, err := call(ctx, c, target, session, CheckBuildContextMethod, CheckBuildContextQuery{Tenant: tenant, Query: q})
	if err != nil {
		return control.ImageBuildSourceResult{}, err
	}
	if out.Schema != 1 || out.Context != q.ID || out.ContextRevision == 0 || out.PolicyRevision == 0 || out.Epoch == 0 {
		return control.ImageBuildSourceResult{}, sfcp.ErrFrame
	}
	if out.Code != "OK" && out.Code != "SOURCE_FETCH" && out.Code != "UNTRUSTED_BASE" && out.Code != "INVALID_CONTEXT" {
		return control.ImageBuildSourceResult{}, sfcp.ErrFrame
	}
	return out, nil
}

// PutBuildZIPPart defaults to legacy native staging. Explicit record=true also
// confirms the receipt through the owner's shared progress report, without a
// per-part UserOperation. The original scope fixes every part's size, including
// legacy 24 KiB scopes; it never changes an existing original operation.
func (c Client) PutBuildZIPPart(ctx context.Context, target sfcp.Peer, session access.Session, scope imagebuild.UploadScope, expected uint64, index uint32, data []byte, record ...bool) (control.ImageBuildIOResult, error) {
	if len(record) > 1 || c.Self == nil || c.Self.Public != session.Key || scope.Cluster != c.Cluster || scope.Creator != session.User || scope.Validate() != nil || len(data) != scope.PartLength(index) || len(data) == 0 {
		return control.ImageBuildIOResult{}, sfcp.ErrAdmission
	}
	at := time.Now().Unix()
	proof := imagebuild.PartProof{Schema: 1, Scope: scope.Hash(), Index: index, Length: uint32(len(data)), Digest: sha256.Sum256(data), Expected: expected, At: at, ExpiresAt: min(at+120, session.ExpiresAt)}
	proof.Record = len(record) == 1 && record[0]
	if proof.Record {
		digest := imagebuild.PartSessionDigest(session)
		proof.Session = &digest
	}
	if _, err := rand.Read(proof.Nonce[:]); err != nil {
		return control.ImageBuildIOResult{}, err
	}
	proof.Signature = ed25519.Sign(c.Self.Private, imagebuild.PartProofBytes(proof))
	return c.transferBuildZIP(ctx, target, session, scope, imagebuild.Transfer{Upload: scope.Upload, Kind: "part", Expected: expected, Index: index, Data: data, Proof: &proof, Record: proof.Record})
}
func (c Client) SealBuildZIP(ctx context.Context, target sfcp.Peer, session access.Session, scope imagebuild.UploadScope, expected uint64) (control.ImageBuildIOResult, error) {
	return c.transferBuildZIP(ctx, target, session, scope, imagebuild.Transfer{Upload: scope.Upload, Kind: "seal", Expected: expected})
}
func (c Client) transferBuildZIP(ctx context.Context, target sfcp.Peer, session access.Session, scope imagebuild.UploadScope, q imagebuild.Transfer) (control.ImageBuildIOResult, error) {
	if scope.Validate() != nil || scope.Cluster != c.Cluster || scope.Creator != session.User || !q.Valid() || q.Kind == "part" && len(q.Data) != scope.PartLength(q.Index) {
		return control.ImageBuildIOResult{}, sfcp.ErrAdmission
	}
	out, err := call(ctx, c, target, session, BuildZIPTransferMethod, BuildZIPTransferQuery{Tenant: scope.Tenant, Request: q})
	if err != nil {
		return control.ImageBuildIOResult{}, err
	}
	if !out.Valid(scope, q) {
		return control.ImageBuildIOResult{}, sfcp.ErrFrame
	}
	return out, nil
}

func (c Client) ImageBuilds(ctx context.Context, target sfcp.Peer, session access.Session, tenant string, q control.ImageBuildQuery, after string) (control.ImageBuildPage, error) {
	if tenant == "" || !q.Valid() {
		return control.ImageBuildPage{}, sfcp.ErrAdmission
	}
	if _, _, err := registryclient.CatalogueCursor(after); err != nil {
		return control.ImageBuildPage{}, err
	}
	page, err := call(ctx, c, target, session, ImageBuildsMethod, ImageBuildsQuery{Tenant: tenant, Query: q, After: after})
	if err != nil {
		return control.ImageBuildPage{}, err
	}
	if page.Schema != 1 || page.Tenant != tenant || page.Part != q.Part || page.Epoch == 0 || len(page.Policies)+len(page.Contexts)+len(page.Versions)+len(page.Uploads)+len(page.Jobs)+len(page.CachePrunes) > 8 || len(page.Missing) > 256 {
		return control.ImageBuildPage{}, sfcp.ErrFrame
	}
	if _, _, err := registryclient.CatalogueCursor(page.Next); err != nil {
		return control.ImageBuildPage{}, sfcp.ErrFrame
	}
	if q.Part == "caches" {
		if !control.ValidImageBuildCacheInventoryPage(page, q, after, true) {
			return control.ImageBuildPage{}, sfcp.ErrFrame
		}
	} else if len(page.Caches) != 0 || page.InventoryRoot != nil {
		return control.ImageBuildPage{}, sfcp.ErrFrame
	}
	for _, r := range page.Policies {
		if q.Part != "policy" || r.Spec.Tenant != tenant || r.Spec.Validate(c.Cluster) != nil {
			return control.ImageBuildPage{}, sfcp.ErrFrame
		}
	}
	for _, r := range page.Contexts {
		if q.Part != "contexts" || r.Spec.Tenant != tenant || r.Spec.Root.Cluster != c.Cluster || r.Spec.Validate() != nil || r.DataGeneration > r.Revision || q.ID != "" && r.Spec.ID != q.ID {
			return control.ImageBuildPage{}, sfcp.ErrFrame
		}
	}
	for _, r := range page.Uploads {
		if q.Part != "uploads" || r.Scope.Tenant != tenant || r.Scope.Cluster != c.Cluster || r.Scope.Creator != session.User || r.Scope.Validate() != nil || q.Upload != "" && r.Scope.Upload != q.Upload {
			return control.ImageBuildPage{}, sfcp.ErrFrame
		}
	}
	for _, r := range page.Versions {
		if q.Part != "versions" || r.Context != q.ID || r.ID == ([32]byte{}) || r.Number == 0 || r.Bytes < 0 || r.Bytes > imagebuild.MaxZIPBytes || r.Commit != "" && !imagebuild.ValidGitCommit(r.Commit) {
			return control.ImageBuildPage{}, sfcp.ErrFrame
		}
	}
	for _, r := range page.CachePrunes {
		if q.Part != "cache-prunes" || !r.Valid() || q.ID != "" && r.ID != q.ID || q.Node != "" && r.Node != q.Node {
			return control.ImageBuildPage{}, sfcp.ErrFrame
		}
	}
	for _, r := range page.Jobs {
		if q.Part != "jobs" || !lifecycle.ValidID(r.ID) || !lifecycle.ValidID(r.Context) || !lifecycle.ValidID(r.Node) || !lifecycle.ValidID(r.User) || r.Version == ([32]byte{}) || r.Number == 0 || r.Revision == 0 || r.CreatedAt == 0 || q.Job != "" && r.ID != q.Job || q.ID != "" && r.Context != q.ID {
			return control.ImageBuildPage{}, sfcp.ErrFrame
		}
		switch r.Phase {
		case "queued", "running", "unknown":
			if r.Result != nil || r.ClosedAt != 0 {
				return control.ImageBuildPage{}, sfcp.ErrFrame
			}
		case "succeeded", "failed", "cancelled":
			if r.Result == nil || r.ClosedAt < r.CreatedAt {
				return control.ImageBuildPage{}, sfcp.ErrFrame
			}
		default:
			return control.ImageBuildPage{}, sfcp.ErrFrame
		}
	}
	if q.Part != "missing" && (len(page.Missing) != 0 || page.UploadRevision != 0) {
		return control.ImageBuildPage{}, sfcp.ErrFrame
	}
	if q.Part == "missing" && page.UploadRevision == 0 {
		return control.ImageBuildPage{}, sfcp.ErrFrame
	}
	for index, part := range page.Missing {
		if part >= uint32((imagebuild.MaxZIPBytes+imagebuild.PartBytes-1)/imagebuild.PartBytes) || index > 0 && part <= page.Missing[index-1] {
			return control.ImageBuildPage{}, sfcp.ErrFrame
		}
	}
	return page, nil
}
