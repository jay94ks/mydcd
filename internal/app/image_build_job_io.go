// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/registryclient"
	"github.com/jay94ks/mydcd/internal/schema"
)

// The real member/latest-quorum authority used by NativeJobs. A local state
// cache can deny work but cannot grant new Create/Copy/Start/publication.
// recover changes no permission: NativeJobs separately permits original cleanup.
func (r *Runtime) imageBuildAuthority(ctx context.Context, spec imagebuild.JobSpec, _ bool) (imagebuild.NativeGrant, error) {
	work, err := r.imageBuildJobWork(ctx, spec)
	if err != nil {
		return imagebuild.NativeGrant{}, err
	}
	return imagebuild.NativeGrant{Run: work.Run, Index: work.Index, Epoch: work.Epoch, Allowed: work.Allowed}, nil
}

// Both native modes settle the same original publication. Revocation can
// close only an untouched suffix; unknown sent roots remain read-only recovery.
func (r *Runtime) resumeImageBuildPublication(ctx context.Context, spec imagebuild.JobSpec, work control.ImageBuildJobWork) error {
	native := r.imageBuildNative
	result, cause := r.publishImageBuildOutput(ctx, spec, native)
	if cause == nil {
		return r.finishImageBuild(ctx, spec, result)
	}
	if !work.Allowed {
		code := "DENIED"
		if work.Run.Cancel {
			code = "CANCELLED"
		} else if work.Blocked == "TIMEOUT" {
			code = "TIMEOUT"
		}
		if result, cause = native.CloseUnsentPublication(spec, code); cause == nil {
			if work.Run.Cancel && result.Code != "OK" {
				result = imagebuild.JobResult{Code: "CANCELLED"}
			}
			return r.finishImageBuild(ctx, spec, result)
		}
	}
	return errors.Join(cause, r.markImageBuildUncertain(ctx, spec))
}

func (r *Runtime) imageBuildJobWork(ctx context.Context, spec imagebuild.JobSpec) (control.ImageBuildJobWork, error) {
	if spec.Cluster != r.controlPolicy.Cluster || spec.Scope.Root.Key != r.Identity.Public || r.ctx.Err() != nil {
		return control.ImageBuildJobWork{}, mydcp.ErrAdmission
	}
	q := control.ImageBuildJobWorkQuery{Tenant: spec.Tenant, ID: spec.ID, At: time.Now().Unix()}
	raw, _ := json.Marshal(q)
	reply, err := r.appCall(ctx, "image-build-job-work", raw)
	if err != nil || reply.Local {
		return control.ImageBuildJobWork{}, mydcp.ErrAdmission
	}
	work, err := schema.Decode[control.ImageBuildJobWork](reply.Data)
	if err != nil || work.Schema != 1 || work.Run.Shape() != nil || work.Run.Spec.Digest() != spec.Digest() || work.Index == 0 || work.RootRevision == 0 || work.Epoch == 0 {
		return control.ImageBuildJobWork{}, mydcp.ErrAdmission
	}
	// The permit above is quorum-backed; ReadAtLeast consumes its durable
	// local prefix. Local=true is expected here, not a fresh authority grant.
	view, err := r.Engine().ReadAtLeast(ctx, work.Index)
	if err != nil || view.State.ModuleEpoch() != work.Epoch {
		return control.ImageBuildJobWork{}, mydcp.ErrAdmission
	}
	q.At = time.Now().Unix()
	current, err := r.controlPolicy.ImageBuildJobWork(view.State, r.Identity.Public, q)
	if err != nil || current.Run.Spec.Digest() != spec.Digest() || current.Run.Revision < work.Run.Revision {
		return control.ImageBuildJobWork{}, mydcp.ErrAdmission
	}
	return current, nil
}

// This finite consumer owns its SDK client/output until their real I/O has
// joined. Recovery observes via the original registry owner's MYDCP Store
// read, even when the accepted job can no longer obtain a new push login.
// Shared report/Secret usage and original root-pin return belong to the worker.
func (r *Runtime) publishImageBuildOutput(ctx context.Context, spec imagebuild.JobSpec, native *imagebuild.NativeJobs) (result imagebuild.JobResult, failure error) {
	if native == nil {
		return imagebuild.JobResult{}, imagebuild.ErrInvalid
	}
	if result, err := native.PublicationResult(spec); err == nil {
		return result, nil
	} else if !errors.Is(err, reconcile.ErrPending) {
		return imagebuild.JobResult{}, err
	}
	record, err := native.Record(spec)
	if err != nil {
		return imagebuild.JobResult{}, err
	}
	observe := func(ctx context.Context, target string) (registryclient.Resolution, error) {
		return r.observeImageBuildPublication(ctx, spec, target)
	}
	if record.Publication != nil {
		result, err := native.RecoverPublication(ctx, spec, observe)
		if err == nil {
			return result, nil
		}
		if !errors.Is(err, reconcile.ErrPending) {
			return imagebuild.JobResult{}, err
		}
		record, err = native.Record(spec)
		if err != nil {
			return imagebuild.JobResult{}, err
		}
		for _, tag := range record.Publication.Tags {
			if tag.Code == "OK" {
				continue
			}
			if tag.Started || tag.Sent {
				return imagebuild.JobResult{}, reconcile.ErrPending
			}
			break // only an untouched original suffix may enter the SDK
		}
	}
	built, err := native.OpenBuiltImage(ctx, spec)
	if err != nil {
		return imagebuild.JobResult{}, err
	}
	defer func() { failure = errors.Join(failure, built.Close()) }()
	client, err := r.imageBuildRegistryClient(ctx, spec)
	if err != nil {
		return imagebuild.JobResult{}, err
	}
	defer client.Close()
	result, err = native.PublishOutput(ctx, spec, built, client)
	if errors.Is(err, reconcile.ErrPending) {
		return native.RecoverPublication(ctx, spec, observe)
	}
	return result, err
}
