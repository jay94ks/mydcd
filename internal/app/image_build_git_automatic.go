// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/storage"
)

type imageBuildAutomaticGitLocal struct {
	Schema     uint8
	Definition [32]byte
	Plan       imagebuild.GitSavePlan
	StartedAt  uint64    `json:",omitempty"`
	Snapshot   *[32]byte `json:",omitempty"`
}

func imageBuildAutomaticGitLocalKey(plan imagebuild.GitSavePlan) string {
	return "image-build/automatic-git/" + plan.Tenant + "/" + plan.ID
}

func (r *Runtime) saveImageBuildAutomaticGitLocal(local imageBuildAutomaticGitLocal) error {
	raw, err := json.Marshal(local)
	if err != nil || len(raw) > 16<<10 {
		return imagebuild.ErrStorage
	}
	return r.reports.Write(map[string][]byte{imageBuildAutomaticGitLocalKey(local.Plan): raw})
}

// Runs inside the same finite Git observation worker. Native Git preparation,
// archive adoption and the ordinary builder loop retain their existing owners.
func (r *Runtime) submitImageBuildAutomaticGit(ctx context.Context, tenant, id string) error {
	ctx, cancel := context.WithTimeout(ctx, 300*time.Second)
	defer cancel()
	view, err := r.currentView(ctx)
	if err != nil || view.Local {
		return errors.Join(sfcp.ErrAdmission, err)
	}
	book, err := r.controlPolicy.ImageBuilds(view.State)
	if err != nil {
		return err
	}
	context, exists := book.Context(tenant, id)
	if !exists || context.GitObservation == nil || context.GitObservation.Report.Result.Code != "OK" {
		return nil
	}
	work, err := r.controlPolicy.ImageBuildGitWatchWork(view.State, r.Identity.Public, tenant, id, time.Now().Unix())
	if err != nil {
		return err
	}
	jobID := control.ImageBuildAutomaticGitID(work.Definition, work.Read.PolicyRevision, context.GitObservation.Report.Result.Commit)
	if job, exists := book.Job(tenant, jobID); exists {
		if job.Automatic == nil || job.Automatic.Definition != work.Definition || job.Automatic.Saved.Plan.Commit != context.GitObservation.Report.Result.Commit {
			return imagebuild.ErrConflict
		}
		return nil // Any original phase, including failed/deleted, prevents replay.
	}
	for _, job := range book.Jobs {
		if job.Automatic != nil && job.Run.Spec.Tenant == tenant && job.Run.Spec.Context.ID == id && !job.Run.Terminal() {
			return nil // Keep the newly observed commit; submit after prior closure.
		}
	}
	plan, err := r.controlPolicy.ImageBuildAutomaticGitSavePlan(view.State, r.Identity.Public, tenant, id, time.Now().Unix(), nil)
	if err != nil {
		return err
	}
	if r.reports == nil || r.nodeRoots == nil {
		return sfcp.ErrAdmission
	}
	var local imageBuildAutomaticGitLocal
	raw, err := r.reports.GetBounded(imageBuildAutomaticGitLocalKey(plan), 16<<10)
	if errors.Is(err, storage.ErrMissing) {
		// Fix archive ID/commit/tree/times before borrowing or writing files.
		local = imageBuildAutomaticGitLocal{Schema: 1, Definition: work.Definition, Plan: plan}
		if err := r.saveImageBuildAutomaticGitLocal(local); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else {
		local, err = schema.Decode[imageBuildAutomaticGitLocal](raw)
		if err != nil || local.Schema != 1 || local.Definition != work.Definition || local.Plan.Validate() != nil || local.Plan.ID != jobID || (local.StartedAt == 0) != (local.Snapshot == nil) || local.Snapshot != nil && *local.Snapshot == ([32]byte{}) {
			return imagebuild.ErrStorage
		}
	}
	plan, err = r.controlPolicy.ImageBuildAutomaticGitSavePlan(view.State, r.Identity.Public, tenant, id, time.Now().Unix(), &local.Plan)
	if err != nil {
		return err
	}
	current := func() (control.ImageBuildGitWork, error) {
		fresh, err := r.currentView(ctx)
		if err != nil || fresh.Local {
			return control.ImageBuildGitWork{}, errors.Join(sfcp.ErrAdmission, err)
		}
		return r.controlPolicy.ImageBuildAutomaticGitSaveWork(fresh.State, r.Identity.Public, plan, time.Now().Unix())
	}
	// No user proof/session is invented here. The shared native implementation
	// receives the authority callback for the exact committed Automatic grant.
	saved, err := r.saveImageBuildGitOwnerWork(ctx, control.ImageBuildGitCall{Tenant: tenant, Request: imagebuild.GitSaveRequest{Plan: plan}}, current)
	if err != nil {
		return err
	}
	if saved.Code == "PENDING" {
		return reconcile.ErrPending
	}
	if saved.Code != "SAVED" || saved.Saved == nil {
		return fmt.Errorf("automatic Git context %s: %s", id, saved.Code)
	}
	view, err = r.currentView(ctx)
	if err != nil || view.Local {
		return errors.Join(sfcp.ErrAdmission, err)
	}
	if local.StartedAt == 0 {
		local.StartedAt = uint64(time.Now().Unix())
	}
	jobPlan, err := r.controlPolicy.ImageBuildAutomaticGitPlan(view.State, r.Identity.Public, *saved.Saved, int64(local.StartedAt), time.Now().Unix())
	if err != nil {
		return err
	}
	snapshot := control.ImageBuildAutomaticGitSnapshot(jobPlan.Spec)
	if local.Snapshot != nil && *local.Snapshot != snapshot {
		return imagebuild.ErrConflict
	}
	report := control.ImageBuildAutomaticGitReport{Schema: 1, Kind: "automatic-git", Cluster: r.controlPolicy.Cluster, Owner: r.Identity.Public, Definition: local.Definition, Tenant: tenant, Context: id, RootRevision: jobPlan.RootRevision, Epoch: jobPlan.Epoch, At: uint64(time.Now().Unix()), StartedAt: local.StartedAt, Saved: *saved.Saved, Snapshot: snapshot}
	report.Signature = ed25519.Sign(r.commandIdentity().Private, control.ImageBuildAutomaticGitReportBytes(report))
	if local.Snapshot == nil {
		// An unapproved Group is not a submitted build. Check the same pure
		// reducer before fixing the first start time; no files, usage or shared
		// job are mutated by this check. After submission the time stays fixed.
		if err := r.controlPolicy.CheckImageBuildAutomaticGit(view.State, r.Identity.Public, report); err != nil {
			return err
		}
		local.Snapshot = &snapshot
		if err := r.saveImageBuildAutomaticGitLocal(local); err != nil {
			return err
		}
	}
	raw, _ = json.Marshal(report)
	reply, err := r.appCall(ctx, "image-build-automatic-git-report", raw)
	if err != nil {
		return err
	}
	if reply.Committed == nil || reply.Committed.Result.Code != state.Applied {
		return imagebuild.ErrConflict
	}
	return nil
}
