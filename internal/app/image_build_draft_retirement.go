// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/reconcile"
)

// Called under the existing Runtime life/imageBuildMu gate. Discovery uses
// original data anchors, including lifetimes before context recreation.
func (r *Runtime) collectImageBuildDraftLifetimes(ctx context.Context, book control.ImageBuildCatalog, context control.ImageBuildContextRecord, index, epoch uint64) error {
	grantFor := func(scope imagebuild.DraftScope) (imagebuild.DraftRetirementGrant, error) {
		return book.DraftRetirementGrant(r.controlPolicy.Cluster, r.Identity.Public, scope, index, epoch)
	}
	scopes, err := imagebuild.StoredDraftLifetimes(r.reports, context.Spec.Root, context.Spec.Tenant, context.Spec.ID, func(scope imagebuild.DraftScope, original *imagebuild.DraftRetirement) (bool, error) {
		if original != nil && original.Removed {
			if index < original.Grant.Index || epoch < original.Grant.Epoch {
				return false, imagebuild.ErrConflict
			}
			return true, nil // actual unlink; only original Return settlement remains
		}
		_, err := grantFor(scope)
		if errors.Is(err, reconcile.ErrPending) {
			return false, nil
		}
		return err == nil, err
	}, 4)
	if err != nil {
		return err
	}
	var failed error
	for _, scope := range scopes {
		original, found, cause := imagebuild.DraftRetirementState(r.reports, scope)
		grant := original.Grant
		if cause == nil && (!found || !original.Removed) {
			grant, cause = grantFor(scope)
		}
		if cause == nil {
			cause = r.retireImageBuildDraft(ctx, grant)
		}
		failed = errors.Join(failed, cause)
	}
	return failed
}

func (r *Runtime) retireImageBuildDraft(ctx context.Context, grant imagebuild.DraftRetirementGrant) error {
	if !grant.Valid() || r.nodeRoots == nil || r.reports == nil {
		return imagebuild.ErrInvalid
	}
	scope := grant.Scope
	original, started, err := imagebuild.DraftRetirementState(r.reports, scope)
	if err != nil {
		return err
	}
	consumer := draftConsumer(scope)
	pin, held, err := r.nodeRoots.RecordedPin(scope.Root, consumer)
	if err != nil {
		return err
	}
	if !started && !held || started && (held && (original.Root.Returned || original.Root.Lease != pin.Lease) || !held && !original.Root.Returning) {
		return imagebuild.ErrStorage
	}
	if started && original.Root.Returned {
		return nil
	}
	lease := pin.Lease
	if started {
		lease = original.Root.Lease
	}
	if !started || !original.Removed {
		opened, err := r.nodeRoots.OpenRecordedPin(scope.Root, consumer)
		if err != nil || opened.Directory == nil {
			if opened.Directory != nil {
				err = errors.Join(err, opened.Directory.Close())
			}
			return errors.Join(imagebuild.ErrStorage, err)
		}
		spool, err := imagebuild.OpenExistingSpool(opened.Directory.FD(), scope.Root, r.reports)
		if err != nil {
			return errors.Join(err, opened.Directory.Close())
		}
		err = spool.RetireDraft(ctx, grant, lease)
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
	return imagebuild.FinishDraftRetirement(r.reports, scope, lease)
}
