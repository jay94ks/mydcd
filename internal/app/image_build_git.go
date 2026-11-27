// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
)

func gitSaveConsumer(plan imagebuild.GitSavePlan) string {
	return imagebuild.GitRootConsumer(plan)
}
func (r *Runtime) saveImageBuildGit(ctx context.Context, call control.ImageBuildGitCall) (imagebuild.GitSaveResponse, error) {
	call.At = time.Now().Unix()
	view, err := r.currentView(ctx)
	if err != nil || view.Local {
		return imagebuild.GitSaveResponse{}, sfcp.ErrAdmission
	}
	work, err := r.controlPolicy.ImageBuildGitWork(view.State, call)
	if err != nil {
		return imagebuild.GitSaveResponse{}, err
	}
	if work.Read.Spec.Root.Key == r.Identity.Public {
		return r.saveImageBuildGitOwner(ctx, call)
	}
	peer, ok := r.Mesh.Peer(sfcp.Identity(work.Read.Spec.Root.Key))
	if !ok || !peer.Member || peer.ID != work.Read.Spec.Root.Node {
		return imagebuild.GitSaveResponse{}, sfcp.ErrAdmission
	}
	raw, _ := json.Marshal(call)
	reply, err := cluster.CallManagement(ctx, r.Mesh, r.Identity, r.controlPolicy.Cluster, peer, cluster.ManagementRequest{Method: "image-build-git-owner", Input: raw})
	if err != nil || reply.Code != "ok" {
		return imagebuild.GitSaveResponse{}, sfcp.ErrAdmission
	}
	out, err := schema.Decode[imagebuild.GitSaveResponse](reply.Data)
	if err != nil || !out.Valid(call.Request) {
		return imagebuild.GitSaveResponse{}, sfcp.ErrAdmission
	}
	return out, nil
}
func (r *Runtime) saveImageBuildGitOwner(ctx context.Context, call control.ImageBuildGitCall) (imagebuild.GitSaveResponse, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	current := func() (control.ImageBuildGitWork, error) {
		view, err := r.currentView(ctx)
		if err != nil || view.Local {
			return control.ImageBuildGitWork{}, sfcp.ErrAdmission
		}
		call.At = time.Now().Unix()
		work, err := r.controlPolicy.ImageBuildGitWork(view.State, call)
		if err != nil || work.Read.Spec.Root.Key != r.Identity.Public {
			return control.ImageBuildGitWork{}, sfcp.ErrAdmission
		}
		return work, nil
	}
	return r.saveImageBuildGitOwnerWork(ctx, call, current)
}

// Both callers establish current authority before entering this shared native
// implementation: user proof for manual saves, accepted definition for auto.
func (r *Runtime) saveImageBuildGitOwnerWork(ctx context.Context, call control.ImageBuildGitCall, current func() (control.ImageBuildGitWork, error)) (imagebuild.GitSaveResponse, error) {
	work, err := current()
	if err != nil {
		return imagebuild.GitSaveResponse{}, err
	}
	r.life.RLock()
	defer r.life.RUnlock()
	if r.closed || r.ctx.Err() != nil || !call.Request.Result && (r.gitFetcher == nil || r.nodeRoots == nil) || r.reports == nil {
		return imagebuild.GitSaveResponse{}, sfcp.ErrAdmission
	}
	if call.Request.Result {
		r.imageBuildMu.Lock()
		defer r.imageBuildMu.Unlock()
		fresh, err := current()
		if err != nil || fresh.Read.Epoch != work.Read.Epoch {
			return imagebuild.GitSaveResponse{}, sfcp.ErrAdmission
		}
		out, err := imagebuild.StoredGitSaveResult(r.reports, call.Request.Plan, r.Identity.Private)
		if err != nil {
			return imagebuild.GitSaveResponse{}, err
		}
		fresh, err = current()
		if err != nil || fresh.Read.Epoch != work.Read.Epoch || !out.Valid(call.Request) {
			return imagebuild.GitSaveResponse{}, sfcp.ErrAdmission
		}
		return out, nil
	}
	out, needsSource, err := r.writeImageBuildGit(ctx, call, current, nil)
	if err != nil || !needsSource {
		return out, err
	}
	// Only a genuinely unstarted plan fetches. No network access holds the
	// editor mutex; retained original intents/archives never regenerate here.
	var access deployment.GitAccess
	source := work.Read.Spec.Git
	if source.CredentialProfile != "" {
		p, ok := r.gitCredentials[call.Tenant+"/"+source.CredentialProfile]
		if !ok || p.Tenant != call.Tenant || p.Repository != source.Repository {
			out.Code = "SOURCE_FETCH"
			return out, nil
		}
		access, err = installedGitAccess(p)
		if err != nil {
			out.Code = "SOURCE_FETCH"
			return out, nil
		}
		defer clear(access.Username)
		defer clear(access.Password)
	}
	var nativeErr error
	_, fetchErr := r.gitFetcher.VisitRepository(ctx, call.Tenant, deployment.GitRepositoryRequest{Repository: source.Repository, Ref: source.Ref, Credential: source.CredentialProfile, Commit: call.Request.Plan.Commit, Seconds: min(work.Read.Policy.Seconds, 300)}, access, func(ctx context.Context, repo *git.Repository, commit string) error {
		if commit != call.Request.Plan.Commit {
			return imagebuild.ErrSourceFetch
		}
		out, _, nativeErr = r.writeImageBuildGit(ctx, call, current, func(w io.Writer) (imagebuild.Tree, error) {
			return imagebuild.WriteGitZIP(ctx, repo, commit, source.Path, call.Request.Plan.Dockerfile, w, call.Request.Plan.ExpandedLimit)
		})
		return nativeErr
	})
	if nativeErr != nil {
		return imagebuild.GitSaveResponse{}, nativeErr
	}
	if fetchErr != nil {
		if _, err := current(); err != nil {
			return imagebuild.GitSaveResponse{}, err
		}
		out.Code = "SOURCE_FETCH"
	}
	return out, nil
}

// Caller holds Runtime life. Both source kinds use the same owner gate and
// original RootManager pin; fetching is outside this critical section.
func (r *Runtime) writeImageBuildGit(ctx context.Context, call control.ImageBuildGitCall, current func() (control.ImageBuildGitWork, error), write func(io.Writer) (imagebuild.Tree, error)) (imagebuild.GitSaveResponse, bool, error) {
	r.imageBuildMu.Lock()
	defer r.imageBuildMu.Unlock()
	out := imagebuild.GitSaveResponse{Schema: 1, Plan: call.Request.Plan.Digest(), Code: "SOURCE_FETCH"}
	work, err := current()
	if err != nil {
		return out, false, err
	}
	plan := call.Request.Plan
	archive, retirement, recorded, err := imagebuild.GitStageState(r.reports, plan)
	if err != nil {
		return out, false, err
	}
	if retirement != nil {
		if !retirement.Transferred || archive == nil {
			return out, false, imagebuild.ErrUsed
		}
		// Stage Return is final. Re-read only the original independent archive
		// through its existing pin; never borrow/fetch a replacement stage.
		pin, err := r.nodeRoots.OpenRecordedPin(plan.Root, buildArtifactConsumer(*archive))
		if err != nil || pin.Directory == nil {
			if pin.Directory != nil {
				err = errors.Join(err, pin.Directory.Close())
			}
			return out, false, errors.Join(imagebuild.ErrStorage, err)
		}
		spool, err := imagebuild.OpenExistingSpool(pin.Directory.FD(), plan.Root, r.reports)
		if err != nil {
			return out, false, errors.Join(err, pin.Directory.Close())
		}
		saved, err := spool.AdoptGit(ctx, plan, r.Identity.Private)
		err = errors.Join(err, spool.Close(), pin.Directory.Close())
		if err != nil {
			return out, false, err
		}
		fresh, err := current()
		if err != nil || fresh.Read.Epoch != work.Read.Epoch {
			return out, false, sfcp.ErrAdmission
		}
		out.Code, out.Saved = "SAVED", &saved
		if !out.Valid(call.Request) {
			return out, false, sfcp.ErrAdmission
		}
		return out, false, nil
	}
	_, held, err := r.nodeRoots.RecordedPin(plan.Root, gitSaveConsumer(plan))
	if err != nil {
		return out, false, err
	}
	if recorded && !held {
		return out, false, imagebuild.ErrStorage
	}
	// A failed fetch must not allocate native staging or a durable root pin.
	if !recorded && write == nil {
		return out, true, nil
	}
	pin, err := r.retainBuildRoot(ctx, plan.Root, work.Root, gitSaveConsumer(plan))
	if pin.Directory != nil {
		defer pin.Directory.Close()
	}
	if err != nil || pin.Directory == nil {
		return out, false, errors.Join(imagebuild.ErrStorage, err)
	}
	var spool *imagebuild.Spool
	if recorded {
		spool, err = imagebuild.OpenExistingSpool(pin.Directory.FD(), plan.Root, r.reports)
	} else {
		spool, err = imagebuild.OpenSpool(pin.Directory.FD(), plan.Root, r.reports)
	}
	if err != nil {
		return out, false, err
	}
	defer spool.Close()
	found, err := spool.GitSaveExists(plan)
	if err != nil {
		return out, false, err
	}
	if recorded && !found {
		return out, false, imagebuild.ErrStorage
	}
	scope, err := spool.PrepareGit(ctx, plan, write)
	if errors.Is(err, reconcile.ErrPending) {
		out.Code = "PENDING"
		return out, false, nil
	}
	if errors.Is(err, imagebuild.ErrInvalid) || errors.Is(err, imagebuild.ErrDigest) {
		out.Code = "INVALID_CONTEXT"
		return out, false, nil
	}
	if errors.Is(err, imagebuild.ErrSourceFetch) {
		out.Code = "SOURCE_FETCH"
		return out, false, nil
	}
	if err != nil {
		return out, false, err
	}
	fresh, err := current()
	if err != nil || fresh.Read.Epoch != work.Read.Epoch {
		return out, false, sfcp.ErrAdmission
	}
	archivePin, err := r.retainBuildRoot(ctx, scope.Root, fresh.Root, buildArtifactConsumer(scope))
	if archivePin.Directory != nil {
		defer archivePin.Directory.Close()
	}
	if err != nil || archivePin.Directory == nil {
		return out, false, errors.Join(imagebuild.ErrStorage, err)
	}
	saved, err := spool.AdoptGit(ctx, plan, r.Identity.Private)
	if err != nil {
		return out, false, err
	}
	if err := spool.Close(); err != nil {
		return out, false, err
	}
	fresh, err = current()
	if err != nil || fresh.Read.Epoch != work.Read.Epoch {
		return out, false, sfcp.ErrAdmission
	}
	out.Code, out.Saved = "SAVED", &saved
	if !out.Valid(call.Request) {
		return out, false, sfcp.ErrAdmission
	}
	return out, false, nil
}
