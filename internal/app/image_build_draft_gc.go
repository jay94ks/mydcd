// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"slices"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

// The existing module loop collects unused editor bodies, including fenced
// partial edits, and closes obsolete data lifetimes. Adopted/unaccepted
// archives retain their separate consumers and closure.
func (r *Runtime) reconcileImageBuildDraftFiles(ctx context.Context, view cluster.View) error {
	b, err := r.controlPolicy.ImageBuilds(view.State)
	ownedDraft := func(c control.ImageBuildContextRecord) bool {
		return (c.Spec.Kind == "draft" || c.Spec.Kind == "git") && c.Spec.Root.Key == r.Identity.Public
	}
	if err != nil || !slices.ContainsFunc(b.Contexts, ownedDraft) {
		return err
	}
	r.life.RLock()
	defer r.life.RUnlock()
	if r.closed || r.ctx.Err() != nil || r.nodeRoots == nil || r.reports == nil {
		return mydcp.ErrAdmission
	}
	r.imageBuildMu.Lock()
	defer r.imageBuildMu.Unlock()
	view, err = r.currentView(ctx)
	if err != nil || view.Local {
		return errors.Join(mydcp.ErrAdmission, err)
	}
	currentPolicy, err := r.controlPolicy.Current(view.State)
	if err != nil {
		return err
	}
	b, err = currentPolicy.ImageBuilds(view.State)
	if err != nil || !slices.ContainsFunc(b.Contexts, ownedDraft) {
		return err
	}
	start := slices.IndexFunc(b.Contexts, func(c control.ImageBuildContextRecord) bool {
		return c.Spec.Tenant+"/"+c.Spec.ID > r.imageBuildDraftAfter
	})
	if start < 0 {
		start = 0
	}
	visited := 0
	var failed error
	for offset := 0; offset < len(b.Contexts) && visited < 4; offset++ {
		c := b.Contexts[(start+offset)%len(b.Contexts)]
		r.imageBuildDraftAfter = c.Spec.Tenant + "/" + c.Spec.ID
		if !ownedDraft(c) {
			continue
		}
		policy, configured := b.Policy(c.Spec.Tenant)
		if !configured {
			continue
		}
		visited++
		failed = errors.Join(failed, r.collectImageBuildGenerated(ctx, b, c, view.State.Index(), view.State.ModuleEpoch()))
		if c.Spec.Kind == "git" {
			failed = errors.Join(failed, r.collectImageBuildGitStages(ctx, b, c, view.State.Index(), view.State.ModuleEpoch()))
			continue
		}
		failed = errors.Join(failed, r.collectImageBuildDraftLifetimes(ctx, b, c, view.State.Index(), view.State.ModuleEpoch()))
		if c.Deleted {
			continue
		}
		scope := imagebuild.DraftScope{Schema: 1, Tenant: c.Spec.Tenant, Context: c.Spec.ID, Root: c.Spec.Root, ContextRevision: c.Revision, PolicyRevision: policy.Revision, Dockerfile: c.Spec.Dockerfile, ExpandedLimit: policy.Spec.WorkspaceBytes, Generation: c.DraftGeneration()}
		failed = errors.Join(failed, r.collectImageBuildDraftFiles(ctx, scope, func(plan imagebuild.DraftFreezePlan) (bool, error) {
			return b.DraftFreezeObsolete(currentPolicy.Cluster, r.Identity.Public, plan)
		}))
	}
	return failed
}

// Caller holds Runtime life/imageBuildMu. No cleanup invents a new root pin,
// Spool, namespace or editor state when original evidence is missing.
func (r *Runtime) collectImageBuildDraftFiles(ctx context.Context, scope imagebuild.DraftScope, obsolete func(imagebuild.DraftFreezePlan) (bool, error)) error {
	anchor, found, err := imagebuild.DraftStoredScope(r.reports, scope)
	if err != nil || !found {
		return err
	}
	pin, err := r.nodeRoots.OpenRecordedPin(scope.Root, draftConsumer(anchor))
	if err != nil || pin.Directory == nil {
		return errors.Join(imagebuild.ErrStorage, err)
	}
	defer pin.Directory.Close()
	spool, err := imagebuild.OpenExistingSpool(pin.Directory.FD(), scope.Root, r.reports)
	if err != nil {
		return err
	}
	defer spool.Close()
	store, err := imagebuild.OpenDraftStore(spool, scope, false)
	if err != nil {
		return err
	}
	defer store.Close()
	if _, err := store.CollectUnpreparedFreezes(ctx, obsolete, 16); err != nil {
		return err
	}
	_, err = store.CollectUnused(ctx, 16)
	return errors.Join(err, store.Close(), spool.Close(), pin.Directory.Close())
}
