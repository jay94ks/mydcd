// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"errors"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/nodestorage"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/storage"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

func (r *Runtime) fixedRootAuthority(ctx context.Context, ref nodestorage.Reference) (nodestorage.Root, error) {
	work, err := r.nodeStorageReferencePermit(ctx, ref)
	return work.Root, err
}

func (r *Runtime) prepareFixedCreation(ctx context.Context, work control.VolumeCreateWork) error {
	if r.fixedVolumes == nil || work.Fixed == nil {
		return volumes.ErrNativeVolume
	}
	permit, err := r.volumeCreatePermit(ctx, work)
	if err != nil {
		return err
	}
	key := volumes.NativeKey(work.Spec)
	if _, err = r.fixedVolumes.View(key); err == nil {
		if err = r.fixedVolumes.ValidateIntent(work.Spec, *work.Fixed, false); err != nil {
			return err
		}
	} else if !errors.Is(err, storage.ErrMissing) {
		return err
	}
	if _, err = r.fixedVolumes.Desired(work.Spec, *work.Fixed, 1, permit.Capacity); err != nil {
		return err
	}
	return r.fixedVolumes.ValidateIntent(work.Spec, *work.Fixed, false)
}

func (r *Runtime) createFixedVolume(ctx context.Context, work control.VolumeCreateWork) (volumes.NativeReady, error) {
	if r.fixedVolumes == nil || work.Fixed == nil || !work.Prepared {
		return volumes.NativeReady{}, volumes.ErrNativeVolume
	}
	permit, err := r.volumeCreatePermit(ctx, work)
	if err != nil {
		return volumes.NativeReady{}, err
	}
	if err = r.fixedVolumes.ValidateIntent(work.Spec, *work.Fixed, true); err != nil {
		return volumes.NativeReady{}, err
	}
	key, err := r.fixedVolumes.Desired(work.Spec, *work.Fixed, 1, permit.Capacity)
	if err != nil {
		return volumes.NativeReady{}, err
	}
	if err = r.fixedVolumes.Step(ctx, key); err != nil {
		return volumes.NativeReady{}, err
	}
	return r.fixedVolumes.Ready(ctx, key)
}

func (r *Runtime) cancelFixedCreation(ctx context.Context, work control.VolumeCreateWork) (volumes.NativeRemoved, error) {
	var proof volumes.NativeRemoved
	if r.fixedVolumes == nil || work.Fixed == nil {
		return proof, volumes.ErrNativeVolume
	}
	if _, err := r.volumeCreatePermit(ctx, work); err != nil {
		return proof, err
	}
	key := volumes.NativeKey(work.Spec)
	row, err := r.fixedVolumes.View(key)
	if errors.Is(err, storage.ErrMissing) {
		if work.Prepared {
			return proof, err
		}
		// This worker only dispatches after the shared Prepared report. Its
		// absence is therefore joined to producer proof, not guessed from
		// an arbitrary missing local journal or native path.
		if err = r.fixedVolumes.CancelUndispatched(ctx, work.Spec, *work.Fixed); err != nil {
			return proof, err
		}
	} else if err != nil {
		return proof, err
	} else {
		if err = r.fixedVolumes.CheckSelection(work.Spec, *work.Fixed); err != nil {
			return proof, err
		}
		revision := row.State.Desired.Revision
		if row.State.Desired.Present {
			if revision == ^uint64(0) {
				return proof, volumes.ErrNativeVolume
			}
			revision++
			if err = r.fixedVolumes.DeleteDesired(key, revision, work.Spec.Scope.Generation); err != nil {
				return proof, err
			}
		}
		if err = r.fixedVolumes.Step(ctx, key); err != nil {
			return proof, err
		}
		closed, err := r.fixedVolumes.Closed(ctx, work.Spec, *work.Fixed, revision)
		if err != nil || !closed {
			return proof, errors.Join(reconcile.ErrPending, err)
		}
	}
	proof = volumes.NativeRemoved{Schema: 1, Scope: work.Spec.Scope, Owner: volumes.Owner{Node: work.Spec.Node, Key: work.Spec.NodeKey, Native: volumes.FixedNativeName(work.Spec.Scope)}, Key: key, Generation: work.Spec.Scope.Generation, DeleteRevision: work.Revision, DataRetained: true}
	proof.Signature = ed25519.Sign(r.Identity.Private, volumes.NativeRemovedBytes(proof))
	return proof, proof.Verify()
}

func (r *Runtime) unregisterFixedVolume(ctx context.Context, work control.VolumeDeleteWork) error {
	if r.fixedVolumes == nil || work.Native.Fixed == nil {
		return volumes.ErrNativeVolume
	}
	if err := r.volumeDeletePermit(ctx, work); err != nil {
		return err
	}
	if err := r.fixedVolumes.CheckOriginal(work.Native); err != nil {
		return err
	}
	key := volumes.NativeKey(work.Native.Spec)
	row, err := r.fixedVolumes.View(key)
	if err != nil {
		return err
	}
	revision := row.State.Desired.Revision
	if row.State.Desired.Present {
		if revision == ^uint64(0) {
			return volumes.ErrNativeVolume
		}
		revision++
		if err = r.fixedVolumes.DeleteDesired(key, revision, work.Native.Generation); err != nil {
			return err
		}
	}
	if err = r.fixedVolumes.Step(ctx, key); err != nil {
		return err
	}
	closed, err := r.fixedVolumes.Gone(ctx, work.Native, revision)
	if err != nil || !closed {
		return errors.Join(reconcile.ErrPending, err)
	}
	return nil
}
