// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/nodestorage"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/schema"
)

func draftConsumer(scope imagebuild.DraftScope) string {
	return imagebuild.DraftRootConsumer(scope)
}

func (r *Runtime) imageBuildDraft(ctx context.Context, call control.ImageBuildDraftCall) (imagebuild.DraftResponse, error) {
	call.At = time.Now().Unix()
	view, err := r.currentView(ctx)
	if err != nil || view.Local {
		return imagebuild.DraftResponse{}, mydcp.ErrAdmission
	}
	work, err := r.controlPolicy.ImageBuildDraftWork(view.State, call)
	if err != nil {
		return imagebuild.DraftResponse{}, err
	}
	if call.Request.Kind == "plan" {
		return imagebuild.DraftResponse{Schema: 1, Scope: work.Scope, Code: "PLAN"}, nil
	}
	if work.Scope.Root.Key == r.Identity.Public {
		return r.imageBuildDraftOwner(ctx, call)
	}
	peer, ok := r.Mesh.Peer(mydcp.Identity(work.Scope.Root.Key))
	if !ok || !peer.Member || peer.ID != work.Scope.Root.Node {
		return imagebuild.DraftResponse{}, mydcp.ErrAdmission
	}
	raw, _ := json.Marshal(call)
	reply, err := cluster.CallManagement(ctx, r.Mesh, r.Identity, r.controlPolicy.Cluster, peer, cluster.ManagementRequest{Method: "image-build-draft-owner", Input: raw})
	if err != nil || reply.Code != "ok" {
		return imagebuild.DraftResponse{}, mydcp.ErrAdmission
	}
	if call.Request.Kind == "file" {
		return decodeImageBuildFileDraft(reply.Data, call.Request, work.Scope)
	}

	out, err := schema.Decode[imagebuild.DraftResponse](reply.Data)
	if err != nil || !out.Valid(call.Request) || out.Scope != work.Scope {
		return imagebuild.DraftResponse{}, mydcp.ErrAdmission
	}
	return out, nil
}

func (r *Runtime) imageBuildDraftOwner(ctx context.Context, call control.ImageBuildDraftCall) (imagebuild.DraftResponse, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	current := func() (control.ImageBuildDraftWork, error) {
		view, err := r.currentView(ctx)
		if err != nil || view.Local {
			return control.ImageBuildDraftWork{}, mydcp.ErrAdmission
		}
		call.At = time.Now().Unix()
		work, err := r.controlPolicy.ImageBuildDraftWork(view.State, call)
		if err != nil || work.Scope.Root.Key != r.Identity.Public {
			return control.ImageBuildDraftWork{}, mydcp.ErrAdmission
		}
		return work, nil
	}
	work, err := current()
	if err != nil {
		return imagebuild.DraftResponse{}, err
	}
	r.life.RLock()
	defer r.life.RUnlock()
	if r.closed || r.ctx.Err() != nil || !call.Request.Result() && r.nodeRoots == nil || r.reports == nil {
		return imagebuild.DraftResponse{}, mydcp.ErrAdmission
	}
	r.imageBuildMu.Lock()
	defer r.imageBuildMu.Unlock()
	now, err := current()
	if err != nil || now.Scope != work.Scope || now.Epoch != work.Epoch {
		return imagebuild.DraftResponse{}, mydcp.ErrAdmission
	}
	out := imagebuild.DraftResponse{Schema: 1, Scope: work.Scope, Code: "NOT_INITIALIZED"}
	if call.Request.Kind == "plan" {
		out.Code = "PLAN"
		return out, nil
	}
	if call.Request.Result() {
		var result imagebuild.DraftResponse
		var cause error
		if call.Request.Kind == "freeze-result" {
			result, cause = imagebuild.StoredDraftFreezeResult(r.reports, *call.Request.Freeze, r.Identity.Private)
		} else {
			result, cause = imagebuild.StoredDraftEditResult(r.reports, work.Scope, *call.Request.Edit)
		}
		if cause != nil {
			return imagebuild.DraftResponse{}, cause
		}
		fresh, cause := current()
		if cause != nil || fresh.Scope != work.Scope || fresh.Epoch != work.Epoch || !result.Valid(call.Request) {
			return imagebuild.DraftResponse{}, mydcp.ErrAdmission
		}
		return result, nil
	}
	anchor, exists, cause := imagebuild.DraftStoredScope(r.reports, work.Scope)
	if cause != nil {
		return imagebuild.DraftResponse{}, cause
	}
	consumerScope := work.Scope
	if exists {
		consumerScope = anchor
	}
	consumer := draftConsumer(consumerScope)
	mayCreate := call.Request.Kind == "edit" || call.Request.Kind == "file-part"
	_, recorded, err := r.nodeRoots.RecordedPin(work.Scope.Root, consumer)
	if err != nil {
		return imagebuild.DraftResponse{}, err
	}
	if exists && !recorded {
		return imagebuild.DraftResponse{}, imagebuild.ErrStorage
	}
	var pin nodestorage.RootPin
	if recorded {
		pin, err = r.nodeRoots.OpenRecordedPin(work.Scope.Root, consumer)
	} else if mayCreate {
		if err = r.nodeRoots.Desired(now.Root); err == nil {
			pin, err = r.nodeRoots.Pin(ctx, now.Root, consumer)
		}
	} else {
		return out, nil // No read initializes a native root or a Ready draft.
	}
	if pin.Directory != nil {
		defer pin.Directory.Close()
	}
	if err != nil || pin.Directory == nil {
		return imagebuild.DraftResponse{}, errors.Join(imagebuild.ErrStorage, err)
	}
	var spool *imagebuild.Spool
	if mayCreate {
		spool, err = imagebuild.OpenSpool(pin.Directory.FD(), work.Scope.Root, r.reports)
	} else {
		spool, err = imagebuild.OpenExistingSpool(pin.Directory.FD(), work.Scope.Root, r.reports)
	}
	if err != nil {
		return imagebuild.DraftResponse{}, err
	}
	defer spool.Close()
	store, err := imagebuild.OpenDraftStore(spool, work.Scope, mayCreate)
	if errors.Is(err, imagebuild.ErrDraftMissing) {
		return out, nil
	}
	if err != nil {
		return imagebuild.DraftResponse{}, err
	}
	defer store.Close()
	if call.Request.Kind == "freeze" {
		scope, cause := store.PrepareFreeze(ctx, *call.Request.Freeze)
		if errors.Is(cause, reconcile.ErrPending) {
			out.Code = "PENDING"
		} else if cause != nil {
			return imagebuild.DraftResponse{}, cause
		} else {
			fresh, cause := current()
			if cause != nil || fresh.Scope != work.Scope || fresh.Epoch != work.Epoch {
				return imagebuild.DraftResponse{}, mydcp.ErrAdmission
			}
			archivePin, cause := r.retainBuildRoot(ctx, scope.Root, fresh.Root, buildArtifactConsumer(scope))
			if archivePin.Directory != nil {
				defer archivePin.Directory.Close()
			}
			if cause != nil || archivePin.Directory == nil {
				return imagebuild.DraftResponse{}, errors.Join(imagebuild.ErrStorage, cause)
			}
			frozen, cause := store.AdoptFreeze(ctx, *call.Request.Freeze, r.Identity.Private)
			if cause != nil {
				return imagebuild.DraftResponse{}, cause
			}
			out.Code, out.Frozen = "FROZEN", &frozen
		}
	} else if call.Request.Kind == "file-part" {
		progress, cause := store.StageFilePart(ctx, *call.Request.Edit, call.Request.Proof.Transfer.Part.Index, call.Request.Data)
		if errors.Is(cause, reconcile.ErrPending) {
			out.Code = "PENDING"
		} else if cause != nil {
			return imagebuild.DraftResponse{}, cause
		} else {
			out.Code, out.File = "STAGED", &progress
		}
	} else if call.Request.Kind == "file-status" {
		progress, cause := store.FileStatus(ctx, *call.Request.Edit, call.Request.Offset)
		if errors.Is(cause, imagebuild.ErrDraftMissing) {
			out.Code = "NOT_INITIALIZED"
		} else if cause != nil {
			return imagebuild.DraftResponse{}, cause
		} else {
			out.Code, out.File = "STAGED", &progress
		}
	} else if call.Request.Kind == "edit" || call.Request.Kind == "file-seal" {
		var body *bytes.Reader
		if call.Request.Kind == "edit" && call.Request.Edit.Kind == "put" {
			body = bytes.NewReader(call.Request.Data)
		}
		// Keep a genuinely nil interface for metadata-only edits.
		var result imagebuild.DraftEditResult
		if call.Request.Kind == "file-seal" {
			result, err = store.CommitFile(ctx, *call.Request.Edit)
		} else if body != nil {
			result, err = store.Edit(ctx, *call.Request.Edit, body)
		} else {
			result, err = store.Edit(ctx, *call.Request.Edit, nil)
		}
		if errors.Is(err, imagebuild.ErrDraftMissing) {
			out.Code = "NOT_INITIALIZED"
		} else if errors.Is(err, reconcile.ErrPending) {
			out.Code = "PENDING"
		} else if err != nil {
			return imagebuild.DraftResponse{}, err
		} else {
			out.Code, out.Revision, out.Digest, out.Edit = "OK", result.Revision, &result.Draft, &result
		}
	} else if call.Request.Kind == "file" {
		q := call.Request
		file, cause := store.ReadFile(ctx, q.Revision, *q.Digest, q.Path, q.Offset)
		if errors.Is(cause, reconcile.ErrPending) {
			out.Code = "PENDING"
		} else if cause != nil {
			return imagebuild.DraftResponse{}, cause
		} else {
			out.Code, out.Revision, out.Digest, out.Content = "OK", q.Revision, q.Digest, &file
		}
	} else {
		draft, err := store.Read()
		if err != nil {
			return imagebuild.DraftResponse{}, err
		}
		digest := draft.Digest()
		q := call.Request
		if q.Offset > uint32(len(draft.Entries)) || q.Revision != 0 && (q.Revision != draft.Revision || *q.Digest != digest) {
			return imagebuild.DraftResponse{}, imagebuild.ErrConflict
		}
		out.Code, out.Revision, out.Digest = "OK", draft.Revision, &digest
		out.Offset, out.Total = q.Offset, uint32(len(draft.Entries))
		end := min(out.Total, out.Offset+8)
		out.Entries = slices.Clone(draft.Entries[out.Offset:end])
		if end < out.Total {
			out.Next = end
		}
	}
	// Closing descriptors is distinct from returning the durable draft pin.
	// A failed response retains the original edit receipt and file identity.
	if store.Close() != nil || spool.Close() != nil {
		return imagebuild.DraftResponse{}, imagebuild.ErrStorage
	}
	now, err = current()
	if err != nil || now.Scope != work.Scope || now.Epoch != work.Epoch || !out.Valid(call.Request) {
		return imagebuild.DraftResponse{}, mydcp.ErrAdmission
	}
	return out, nil
}
