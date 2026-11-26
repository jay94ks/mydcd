// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"

	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/nodestorage"
)

// The native intent precedes Borrow. A lost acknowledgement is recovered from
// this same RootManager consumer; a known missing lease is never borrowed anew.
// Callers join the worker before closing NativeJobs or RootManager.
func (r *Runtime) openImageBuildRoot(ctx context.Context, native *imagebuild.NativeJobs, spec imagebuild.JobSpec, use imagebuild.RootUse) (nodestorage.RootPin, error) {
	if native == nil || r.nodeRoots == nil {
		return nodestorage.RootPin{}, imagebuild.ErrStorage
	}
	consumer, err := native.RootConsumer(spec, use)
	if err != nil {
		return nodestorage.RootPin{}, err
	}
	hold, exists, err := native.RootHold(spec, use)
	if err != nil {
		return nodestorage.RootPin{}, err
	}
	if !exists {
		if err := native.PlanRootHold(ctx, spec, use); err != nil {
			return nodestorage.RootPin{}, err
		}
		hold, exists, err = native.RootHold(spec, use)
		if err != nil || !exists {
			return nodestorage.RootPin{}, errors.Join(imagebuild.ErrStorage, err)
		}
	}
	if hold.Returning || hold.Returned {
		return nodestorage.RootPin{}, imagebuild.ErrUsed
	}
	ref := spec.Scope.Root
	pin, held, err := r.nodeRoots.RecordedPin(ref, consumer)
	if err != nil {
		return nodestorage.RootPin{}, err
	}
	if hold.Lease.Token != 0 && (!held || hold.Lease != pin.Lease) {
		return nodestorage.RootPin{}, imagebuild.ErrStorage
	}
	if held {
		if err := native.BindRootHold(spec, use, pin.Lease); err != nil {
			return nodestorage.RootPin{}, err
		}
		return r.nodeRoots.OpenRecordedPin(ref, consumer)
	}
	grant, err := r.imageBuildAuthority(ctx, spec, false)
	if err != nil || !grant.Allowed || grant.Run.Cancel || grant.Run.Phase != "queued" {
		return nodestorage.RootPin{}, errors.Join(imagebuild.ErrConflict, err)
	}
	view, err := r.Engine().ReadAtLeast(ctx, grant.Index)
	if err != nil || view.State.ModuleEpoch() != grant.Epoch {
		return nodestorage.RootPin{}, errors.Join(imagebuild.ErrConflict, err)
	}
	roots, err := r.controlPolicy.NodeStorage(view.State)
	if err != nil {
		return nodestorage.RootPin{}, err
	}
	root, exists := roots.Root(ref.Node, ref.ID)
	if !exists || root.Draining || root.Reference(spec.Cluster) != ref {
		return nodestorage.RootPin{}, imagebuild.ErrConflict
	}
	pin, err = r.retainBuildRoot(ctx, ref, root, consumer)
	// Pin may return a durable lease even when opening the directory failed.
	// Keep that exact acknowledgement for cleanup instead of leaking/replacing it.
	if pin.Lease.Token != 0 {
		if bindErr := native.BindRootHold(spec, use, pin.Lease); bindErr != nil {
			if pin.Directory != nil {
				bindErr = errors.Join(bindErr, pin.Directory.Close())
				pin.Directory = nil
			}
			return pin, errors.Join(err, bindErr)
		}
	}
	return pin, err
}

func (r *Runtime) prepareImageBuildWorkspace(ctx context.Context, native *imagebuild.NativeJobs, spec imagebuild.JobSpec) (failure error) {
	job, err := r.openImageBuildRoot(ctx, native, spec, imagebuild.JobRoot)
	if job.Directory != nil {
		defer func() { failure = errors.Join(failure, job.Directory.Close()) }()
	}
	if err != nil || job.Directory == nil {
		return errors.Join(imagebuild.ErrStorage, err)
	}
	cache, err := r.openImageBuildRoot(ctx, native, spec, imagebuild.CacheRoot)
	if cache.Directory != nil {
		defer func() { failure = errors.Join(failure, cache.Directory.Close()) }()
	}
	if err != nil || cache.Directory == nil {
		return errors.Join(imagebuild.ErrStorage, err)
	}
	return native.PrepareWorkspace(ctx, spec, job.Directory.FD())
}

// Workspace removal and all output/Secret/log I/O must have joined first.
// Returning is saved BEFORE Return, so lost Return/DB acknowledgements can be
// settled without a replacement lease or reopening the retired directory.
// The shared cache consumer is intentionally retained beyond job completion.
func (r *Runtime) returnImageBuildRoot(native *imagebuild.NativeJobs, spec imagebuild.JobSpec) error {
	if native == nil || r.nodeRoots == nil {
		return imagebuild.ErrStorage
	}
	hold, exists, err := native.RootHold(spec, imagebuild.JobRoot)
	if err != nil || !exists {
		return err // an undispatched cancelled job may never have borrowed a root
	}
	consumer, err := native.RootConsumer(spec, imagebuild.JobRoot)
	if err != nil {
		return err
	}
	pin, held, err := r.nodeRoots.RecordedPin(spec.Scope.Root, consumer)
	if err != nil {
		return err
	}
	if held {
		if hold.Returned || hold.Lease.Token != 0 && hold.Lease != pin.Lease {
			return imagebuild.ErrStorage
		}
		if hold.Lease.Token == 0 {
			if hold.Returning {
				return imagebuild.ErrStorage
			}
			if err := native.BindRootHold(spec, imagebuild.JobRoot, pin.Lease); err != nil {
				return err
			}
		}
	} else if hold.Lease.Token != 0 && !hold.Returning {
		return imagebuild.ErrStorage
	}
	if hold.Returned {
		return nil
	}
	if err := native.BeginRootReturn(spec, imagebuild.JobRoot); err != nil {
		return err
	}
	if held {
		if err := r.nodeRoots.Return(pin); err != nil {
			return err
		}
	}
	return native.FinishRootReturn(spec, imagebuild.JobRoot)
}
