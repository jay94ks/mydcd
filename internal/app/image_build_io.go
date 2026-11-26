// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/nodestorage"
	"github.com/jay94ks/mydcd/internal/schema"
)

func buildArtifactConsumer(scope imagebuild.UploadScope) string {
	return imagebuild.ArtifactRootConsumer(scope)
}
func (r *Runtime) imageBuildIOPermit(ctx context.Context, call control.ImageBuildIOCall) (control.ImageBuildIOWork, error) {
	call.At = time.Now().Unix()
	method, raw, err := imageBuildPermitInput(call)
	if err != nil {
		return control.ImageBuildIOWork{}, err
	}
	reply, err := r.appCall(ctx, method, raw)
	if err != nil {
		return control.ImageBuildIOWork{}, err
	}
	work, err := schema.Decode[control.ImageBuildIOWork](reply.Data)
	if err != nil || work.Schema != 1 || work.Cluster != r.controlPolicy.Cluster || work.Scope.Validate() != nil || work.Scope.Cluster != work.Cluster || work.Scope.Root.Key != r.Identity.Public || work.Scope.Tenant != call.Tenant || work.Scope.Upload != call.Request.Upload || work.Expected < call.Request.Expected || work.Expected != call.Request.Expected && !work.Recorded || work.Recorded && (!call.Request.Record || call.Request.Kind != "part") || work.Root.Reference(work.Cluster) != work.Scope.Root || work.Epoch == 0 || work.Index == 0 || call.Request.Record && (work.RootRevision == 0 || work.RootRevision > work.Index) || !call.Request.Record && work.RootRevision != 0 {
		return control.ImageBuildIOWork{}, mydcp.ErrAdmission
	}
	return work, nil
}

func imageBuildPermitInput(call control.ImageBuildIOCall) (string, []byte, error) {
	// Owner calls arrive with full bytes too. A compact permit never skips the
	// effect path's original Transfer.Valid length/SHA check, including ACK recovery.
	if call.Request.Kind == "part" {
		part, err := call.PartPermit()
		if err != nil {
			return "", nil, err
		}
		raw, err := json.Marshal(part)
		return "image-build-part-permit", raw, err
	}
	if !call.Request.Valid() {
		return "", nil, mydcp.ErrAdmission
	}
	raw, err := json.Marshal(call)
	return "image-build-io-permit", raw, err
}

// The User service passes its own just-authorized quorum view in-process.
// This is never a wire field or an owner effect permit: the owner rechecks
// current authority after acquiring the native gate and after the actual I/O.
func (r *Runtime) imageBuildTransfer(ctx context.Context, view cluster.View, call control.ImageBuildIOCall) (control.ImageBuildIOResult, error) {
	if view.Local || view.RaftIndex == 0 || ctx.Err() != nil || r.ctx.Err() != nil {
		return control.ImageBuildIOResult{}, mydcp.ErrAdmission
	}
	b, err := r.controlPolicy.ImageBuilds(view.State)
	if err != nil {
		return control.ImageBuildIOResult{}, err
	}
	u, ok := b.Upload(call.Tenant, call.Request.Upload)
	if !ok {
		return control.ImageBuildIOResult{}, mydcp.ErrAdmission
	}
	call.At = time.Now().Unix()
	if _, err := r.controlPolicy.ImageBuildIOPermit(view.State, u.Scope.Root.Key, call); err != nil {
		return control.ImageBuildIOResult{}, err
	}
	if u.Scope.Root.Key == r.Identity.Public {
		return r.imageBuildTransferOwner(ctx, call)
	}
	peer, ok := r.Mesh.Peer(mydcp.Identity(u.Scope.Root.Key))
	if !ok || !peer.Member || peer.ID != u.Scope.Root.Node {
		return control.ImageBuildIOResult{}, mydcp.ErrAdmission
	}
	raw, _ := json.Marshal(call)
	reply, err := cluster.CallManagement(ctx, r.Mesh, r.Identity, r.controlPolicy.Cluster, peer, cluster.ManagementRequest{Method: "image-build-owner", Input: raw})
	if err != nil || reply.Code != "ok" {
		return control.ImageBuildIOResult{}, mydcp.ErrAdmission
	}
	result, err := schema.Decode[control.ImageBuildIOResult](reply.Data)
	if err != nil || !result.Valid(u.Scope, call.Request) {
		return control.ImageBuildIOResult{}, mydcp.ErrAdmission
	}
	return result, nil
}

// Serialize owner file mutations and join shutdown via the existing lifetime
// lock. A root dependency survives RPC/daemon interruption until actual GC;
// closing this call's directory descriptor does not return that durable pin.
func (r *Runtime) imageBuildTransferOwner(ctx context.Context, call control.ImageBuildIOCall) (control.ImageBuildIOResult, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	// Reject malformed/full-body SHA mismatches before waiting or touching a
	// native root. The first full current permit belongs AFTER the native gate;
	// a permit obtained before a queued wait cannot authorize its later effect.
	if !call.Request.Valid() {
		return control.ImageBuildIOResult{}, imagebuild.ErrInvalid
	}
	r.life.RLock()
	defer r.life.RUnlock()
	if r.closed || r.nodeRoots == nil || r.reports == nil || r.ctx.Err() != nil {
		return control.ImageBuildIOResult{}, mydcp.ErrAdmission
	}
	r.imageBuildMu.Lock()
	defer r.imageBuildMu.Unlock()
	if err := ctx.Err(); err != nil {
		return control.ImageBuildIOResult{}, err
	}
	// Revalidate after waiting for the native gate; no stale queued call can
	// start writing because its previous grant once succeeded.
	work, err := r.imageBuildIOPermit(ctx, call)
	if err != nil {
		return control.ImageBuildIOResult{}, mydcp.ErrAdmission
	}
	var pin nodestorage.RootPin
	if work.Recorded {
		pin, err = r.nodeRoots.OpenRecordedPin(work.Scope.Root, buildArtifactConsumer(work.Scope))
	} else {
		pin, err = r.retainBuildRoot(ctx, work.Scope.Root, work.Root, buildArtifactConsumer(work.Scope))
	}
	if pin.Directory != nil {
		defer func() {
			if pin.Directory != nil {
				_ = pin.Directory.Close()
			}
		}()
	}
	if err != nil || pin.Directory == nil {
		return control.ImageBuildIOResult{}, errors.Join(imagebuild.ErrStorage, err)
	}
	openSpool := imagebuild.OpenSpool
	if work.Recorded {
		openSpool = imagebuild.OpenExistingSpool
	}
	spool, err := openSpool(pin.Directory.FD(), work.Scope.Root, r.reports)
	if err != nil {
		return control.ImageBuildIOResult{}, err
	}
	defer spool.Close()
	result := control.ImageBuildIOResult{Schema: 1, Scope: work.Scope.Hash(), Code: "OK"}
	if work.Recorded {
		part, cause := spool.RecoverPart(ctx, work.Scope, call.Request.Index, call.Request.Proof.Digest, r.Identity.Private)
		err = cause
		if err == nil {
			result.Part = &part
		}
	} else if err = spool.Begin(ctx, work.Scope); err == nil {
		if call.Request.Kind == "part" {
			part, cause := spool.Put(ctx, work.Scope, call.Request.Index, call.Request.Data, r.Identity.Private)
			err = cause
			if err == nil {
				result.Part = &part
			}
		} else {
			seal, _, cause := spool.Seal(ctx, work.Scope, r.Identity.Private)
			err = cause
			if err == nil {
				result.Seal = &seal
			}
		}
	}
	if err != nil {
		result.Code = "STORAGE_UNAVAILABLE"
		if errors.Is(err, imagebuild.ErrDigest) {
			result.Code = "DIGEST_MISMATCH"
		}
		if errors.Is(err, imagebuild.ErrInvalid) {
			result.Code = "INVALID_ZIP"
		}
		if errors.Is(err, imagebuild.ErrConflict) {
			result.Code = "CONFLICT"
		}
	}
	if err := spool.Close(); err != nil {
		return control.ImageBuildIOResult{}, err
	}
	if err := pin.Directory.Close(); err != nil {
		return control.ImageBuildIOResult{}, err
	}
	pin.Directory = nil
	// Callback errors and revoked authority never release the durable original
	// dependency. The creator may abort; only native reclamation can return it.
	latest, err := r.imageBuildIOPermit(ctx, call)
	if err != nil || latest.Scope != work.Scope {
		return control.ImageBuildIOResult{}, mydcp.ErrAdmission
	}
	if result.Code == "OK" && result.Part != nil && call.Request.Record {
		if !latest.Recorded {
			if latest.Expected != call.Request.Expected {
				return control.ImageBuildIOResult{}, imagebuild.ErrConflict
			}
			artifact := control.ImageBuildArtifactWork{Schema: 1, Cluster: latest.Cluster, Upload: control.ImageBuildUploadRecord{Scope: latest.Scope, Revision: latest.Expected}, Root: latest.Root, Epoch: latest.Epoch, RootRevision: latest.RootRevision, Index: latest.Index}
			fact := control.ImageBuildPartProgress{Session: call.Session, Proof: *call.Request.Proof, Receipt: *result.Part, At: time.Now().Unix()}
			reportErr := r.publishImageBuildOwner(ctx, artifact, control.ImageBuildOwnerReport{Action: "part", Part: &fact})
			revision, err := confirmedBuildPartRevision(latest, reportErr, func() (control.ImageBuildIOWork, error) { return r.imageBuildIOPermit(ctx, call) })
			if err != nil {
				return control.ImageBuildIOResult{}, err
			}
			result.Recorded, result.UploadRevision = true, revision
			return result, nil
		}
		result.Recorded, result.UploadRevision = true, latest.Expected
	}
	return result, nil
}

// A nil publish error is the exact signed report's Applied ACK: the reducer
// advances this upload CAS once. Only an uncertain/error ACK needs another
// current permit, fixed to the same original call and exact confirmed slot.
func confirmedBuildPartRevision(latest control.ImageBuildIOWork, reportErr error, recover func() (control.ImageBuildIOWork, error)) (uint64, error) {
	if reportErr == nil {
		return latest.Expected + 1, nil
	}
	confirmed, err := recover()
	if err != nil || confirmed.Scope != latest.Scope || !confirmed.Recorded || confirmed.Expected < latest.Expected {
		return 0, reportErr
	}
	return confirmed.Expected, nil
}

// retainBuildRoot shares the existing original-pin behavior for uploaded and
// locally generated immutable archives. Closing FD never returns this lease.
func (r *Runtime) retainBuildRoot(ctx context.Context, ref nodestorage.Reference, root nodestorage.Root, consumer string) (nodestorage.RootPin, error) {
	if root.Reference(r.controlPolicy.Cluster) != ref {
		return nodestorage.RootPin{}, imagebuild.ErrConflict
	}
	_, recorded, err := r.nodeRoots.RecordedPin(ref, consumer)
	if err != nil {
		return nodestorage.RootPin{}, err
	}
	if recorded {
		return r.nodeRoots.OpenRecordedPin(ref, consumer)
	}
	if err = r.nodeRoots.Desired(root); err != nil {
		return nodestorage.RootPin{}, err
	}
	return r.nodeRoots.Pin(ctx, root, consumer)
}
