// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/secrets"
)

// The worker must join its context/Secret/log and publication consumers before
// calling this. Positive native removal and output-reader join gate workspace
// deletion; only then can the original root and Secret usages be returned.
func (r *Runtime) completeImageBuild(ctx context.Context, native *imagebuild.NativeJobs, spec imagebuild.JobSpec, result imagebuild.JobResult) error {
	if native == nil || !result.Valid(spec) {
		return imagebuild.ErrInvalid
	}
	record, err := native.Record(spec)
	if err != nil {
		return err
	}
	if record.Workspace != nil {
		if _, err := native.FinishWorkspace(ctx, spec); err != nil {
			return err
		}
	}
	if err := r.returnImageBuildRoot(native, spec); err != nil {
		return err
	}
	work, err := r.imageBuildJobWork(ctx, spec)
	if err != nil {
		return err
	}
	closure, err := native.SealCompletion(imagebuild.NativeGrant{Run: work.Run, Index: work.Index, Epoch: work.Epoch, Allowed: work.Allowed}, result, uint64(time.Now().Unix()), r.Identity.Private)
	if err != nil {
		return err
	}
	if work.Run.Terminal() {
		if work.Run.Closure == nil || work.Run.Closure.Native != closure.Native || work.Run.Closure.Result != closure.Result || work.Run.Closure.At != closure.At {
			return imagebuild.ErrConflict
		}
		return nil // recover a lost acknowledgement of this original completion
	}
	view, err := r.Engine().ReadAtLeast(ctx, work.Index)
	if err != nil || view.State.ModuleEpoch() != work.Epoch {
		return imagebuild.ErrConflict
	}
	book, err := r.controlPolicy.ImageBuilds(view.State)
	if err != nil {
		return err
	}
	row, exists := book.Job(spec.Tenant, spec.ID)
	if !exists || row.Deleted || row.Run.Spec.Digest() != spec.Digest() {
		return imagebuild.ErrConflict
	}
	proofs := make([]secrets.UseGone, 0, len(row.Grants))
	for _, grant := range row.Grants {
		proof := secrets.UseGone{
			Purpose: secrets.PurposeImageBuild, Cluster: spec.Cluster,
			Realm: grant.Realm, Tenant: spec.Tenant, App: grant.Use.App,
			Deployment: grant.Use.Deployment, Consumer: grant.Consumer,
			Generation: grant.Generation, NodeKey: spec.Scope.Root.Key,
			Selection: grant.Selection, Lifetime: grant.Lifetime,
			Stopped: true, MountsGone: true,
		}
		proof.Signature = ed25519.Sign(r.Identity.Private, secrets.UseGoneBytes(proof))
		proofs = append(proofs, proof)
	}
	return r.publishImageBuildJob(ctx, work, control.ImageBuildJobReport{Action: "complete", Closure: &closure, Secrets: proofs})
}

func (r *Runtime) publishImageBuildJob(ctx context.Context, work control.ImageBuildJobWork, report control.ImageBuildJobReport) error {
	spec := work.Run.Spec
	report.Schema, report.Kind, report.Cluster, report.Owner = 1, "job", spec.Cluster, r.Identity.Public
	report.Tenant, report.Job = spec.Tenant, spec.ID
	report.Expected, report.RootRevision, report.Epoch = work.Run.Revision, work.RootRevision, work.Epoch
	// The report is a fresh quorum/CAS envelope around the immutable saved
	// closure. Downtime does not change when native cleanup actually completed.
	report.At = uint64(time.Now().Unix())
	report.Signature = ed25519.Sign(r.commandIdentity().Private, control.ImageBuildJobReportBytes(report))
	if !report.Valid(spec) {
		return imagebuild.ErrInvalid
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}
	reply, err := r.appCall(ctx, "image-build-job-report", raw)
	if err != nil {
		return err
	}
	if reply.Committed == nil || reply.Committed.Result.Code != state.Applied {
		return imagebuild.ErrConflict
	}
	return nil
}
