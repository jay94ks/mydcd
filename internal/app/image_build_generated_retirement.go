// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/reconcile"
)

// Called under life/imageBuildMu with the same fresh quorum catalog as draft
// and Git stage cleanup. Shared uploads use the existing shared reclaim path.
func (r *Runtime) collectImageBuildGenerated(ctx context.Context, book control.ImageBuildCatalog, context control.ImageBuildContextRecord, index, epoch uint64) error {
	grantFor := func(a imagebuild.GeneratedArtifact) (imagebuild.GeneratedArchiveGrant, error) {
		return book.GeneratedArchiveGrant(r.controlPolicy.Cluster, r.Identity.Public, a, index, epoch)
	}
	key := context.Spec.Tenant + "/" + context.Spec.ID
	if r.imageBuildGeneratedAfter == nil {
		r.imageBuildGeneratedAfter = map[string]string{}
	}
	artifacts, next, err := imagebuild.StoredGeneratedArtifacts(r.reports, context.Spec.Root, context.Spec.Tenant, context.Spec.ID, r.imageBuildGeneratedAfter[key], func(a imagebuild.GeneratedArtifact) (bool, error) {
		_, err := grantFor(a)
		if errors.Is(err, imagebuild.ErrUsed) || errors.Is(err, reconcile.ErrPending) {
			return false, nil
		}
		return err == nil, err
	}, 4)
	if err != nil {
		return err
	}
	r.imageBuildGeneratedAfter[key] = next
	var failed error
	for _, a := range artifacts {
		grant, err := grantFor(a)
		if err == nil {
			err = r.reclaimImageBuildGenerated(ctx, grant)
		}
		failed = errors.Join(failed, err)
	}
	return failed
}

func (r *Runtime) reclaimImageBuildGenerated(ctx context.Context, g imagebuild.GeneratedArchiveGrant) error {
	if !g.Valid() || r.nodeRoots == nil || r.reports == nil {
		return imagebuild.ErrInvalid
	}
	a := g.Artifact
	original, err := imagebuild.GeneratedArchiveState(r.reports, a)
	if err != nil {
		return err
	}
	pin, held, err := r.nodeRoots.RecordedPin(a.Scope.Root, buildArtifactConsumer(a.Scope))
	if err != nil {
		return err
	}
	lease := pin.Lease
	if original != nil {
		if held && (!original.Borrowed || original.Returned || original.Lease != lease) || !held && original.Borrowed && !original.Returning {
			return imagebuild.ErrStorage
		}
		if g.Index < original.Index || g.Epoch < original.Epoch || g.ContextRevision < original.ContextRevision || g.PolicyRevision < original.PolicyRevision {
			return imagebuild.ErrConflict
		}
		if original.Returned {
			return nil
		}
		lease = original.Lease
	}
	if original == nil || !original.Returning {
		consumer := buildArtifactConsumer(a.Scope)
		if !held {
			if a.Git != nil {
				consumer = gitSaveConsumer(*a.Git)
			} else {
				anchor, found, err := imagebuild.DraftStoredScope(r.reports, a.Draft.Scope)
				if err != nil || !found {
					return errors.Join(imagebuild.ErrStorage, err)
				}
				consumer = draftConsumer(anchor)
			}
		}
		opened, err := r.nodeRoots.OpenRecordedPin(a.Scope.Root, consumer)
		if err != nil || opened.Directory == nil {
			if opened.Directory != nil {
				err = errors.Join(err, opened.Directory.Close())
			}
			return errors.Join(imagebuild.ErrStorage, err)
		}
		spool, err := imagebuild.OpenExistingSpool(opened.Directory.FD(), a.Scope.Root, r.reports)
		if err != nil {
			return errors.Join(err, opened.Directory.Close())
		}
		if r.imageBuildTree != nil && r.imageBuildTree.scope == a.Scope.Hash() {
			if cause := r.imageBuildTree.Close(); cause != nil {
				return errors.Join(cause, spool.Close(), opened.Directory.Close())
			}
			r.imageBuildTree = nil
		}
		err = spool.ReclaimGenerated(ctx, g, lease)
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
	return imagebuild.FinishGeneratedRetirement(r.reports, a, lease)
}
