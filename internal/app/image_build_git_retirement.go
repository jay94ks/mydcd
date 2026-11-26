// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagebuild"
)

// Caller holds life/imageBuildMu and a fresh quorum snapshot. Current partial
// sources do not consume the finite batch ahead of obsolete/transferred ones.
func (r *Runtime) collectImageBuildGitStages(ctx context.Context, book control.ImageBuildCatalog, context control.ImageBuildContextRecord, index, epoch uint64) error {
	grantFor := func(plan imagebuild.GitSavePlan) (imagebuild.GitStageGrant, error) {
		return book.GitStageGrant(r.controlPolicy.Cluster, r.Identity.Public, plan, index, epoch)
	}
	plans, err := imagebuild.StoredGitStages(r.reports, context.Spec.Root, context.Spec.Tenant, context.Spec.ID, func(plan imagebuild.GitSavePlan) (bool, error) {
		g, err := grantFor(plan)
		return g.Obsolete(), err
	}, 4)
	if err != nil {
		return err
	}
	var failed error
	for _, plan := range plans {
		g, err := grantFor(plan)
		if err == nil {
			err = r.retireImageBuildGitStage(ctx, g)
		}
		failed = errors.Join(failed, err)
	}
	return failed
}

func (r *Runtime) retireImageBuildGitStage(ctx context.Context, g imagebuild.GitStageGrant) error {
	if !g.Valid() || r.nodeRoots == nil || r.reports == nil {
		return imagebuild.ErrInvalid
	}
	_, original, found, err := imagebuild.GitStageState(r.reports, g.Plan)
	if err != nil || !found {
		return errors.Join(imagebuild.ErrStorage, err)
	}
	pin, held, err := r.nodeRoots.RecordedPin(g.Plan.Root, gitSaveConsumer(g.Plan))
	if err != nil {
		return err
	}
	if original == nil && !held || original != nil && (held && (original.Root.Returned || original.Root.Lease != pin.Lease) || !held && !original.Root.Returning) {
		return imagebuild.ErrStorage
	}
	if original != nil && (g.Index < original.Grant.Index || g.Epoch < original.Grant.Epoch || g.ContextRevision < original.Grant.ContextRevision || g.PolicyRevision < original.Grant.PolicyRevision) {
		return imagebuild.ErrConflict
	}
	if original != nil && original.Root.Returned {
		return nil
	}
	lease := pin.Lease
	if original != nil {
		lease = original.Root.Lease
	}
	if original == nil || !original.Removed {
		opened, err := r.nodeRoots.OpenRecordedPin(g.Plan.Root, gitSaveConsumer(g.Plan))
		if err != nil || opened.Directory == nil {
			if opened.Directory != nil {
				err = errors.Join(err, opened.Directory.Close())
			}
			return errors.Join(imagebuild.ErrStorage, err)
		}
		spool, err := imagebuild.OpenExistingSpool(opened.Directory.FD(), g.Plan.Root, r.reports)
		if err != nil {
			return errors.Join(err, opened.Directory.Close())
		}
		err = spool.RetireGitStage(ctx, g, lease)
		err = errors.Join(err, spool.Close(), opened.Directory.Close())
		if err != nil {
			return err
		}
	}
	if held {
		if err := r.nodeRoots.Return(pin); err != nil {
			return err
		}
	}
	return imagebuild.FinishGitStageRetirement(r.reports, g.Plan, lease)
}
