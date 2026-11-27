// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

func (r *Runtime) volumeDeletePermit(ctx context.Context, work control.VolumeDeleteWork) error {
	raw, _ := json.Marshal(work.Native.Spec.Scope)
	method := "volume-delete-permit"
	if work.Retained != "" {
		method = "volume-retained-delete-permit"
		raw, _ = json.Marshal(control.VolumeMoveSelection{Scope: work.Native.Spec.Scope, ID: work.Retained})
	}
	reply, err := r.appCall(ctx, method, raw)
	if err != nil {
		return err
	}
	permit, err := schema.Decode[control.VolumeDeleteWork](reply.Data)
	want, _ := json.Marshal(work)
	got, _ := json.Marshal(permit)
	if err != nil || reply.Local || reply.RaftIndex == 0 || !bytes.Equal(want, got) {
		return volumes.ErrNativeVolume
	}
	return nil
}

func (r *Runtime) removeOriginalVolume(ctx context.Context, work control.VolumeDeleteWork) error {
	if work.Native.Fixed != nil {
		return r.unregisterFixedVolume(ctx, work)
	}
	if err := r.volumeDeletePermit(ctx, work); err != nil {
		return err
	}
	key := volumes.NativeKey(work.Native.Spec)
	row, err := r.nativeVolumes.View(key)
	if err != nil {
		// A missing journal cannot prove which original Create may be in flight.
		return err
	}
	raw, _ := json.Marshal(work.Native.Spec)
	target := reconcile.Resource{Present: true, Generation: work.Native.Generation, Spec: string(raw)}
	if row.State.GenerationFloor != work.Native.Generation || row.State.Applied.Present && row.State.Applied != target || row.State.Desired.Present && row.State.Desired.Resource != target || row.State.Pending != nil && row.State.Pending.Target != target {
		return volumes.ErrNativeVolume
	}
	revision := row.State.Desired.Revision
	if row.State.Desired.Present {
		if revision == ^uint64(0) {
			return volumes.ErrNativeVolume
		}
		revision++
		if err = r.nativeVolumes.DeleteDesired(key, revision, work.Native.Generation); err != nil {
			return err
		}
	}
	// A2 settles the exact original Apply/Remove. Never replace its operation
	// ID or synthesize success from a missing Engine object.
	if err = r.nativeVolumes.Step(ctx, key); err != nil {
		return err
	}
	if gone, err := r.nativeVolumes.Gone(ctx, key, revision, work.Native.Generation); err != nil || !gone {
		return errors.Join(reconcile.ErrPending, err)
	}
	return nil
}

func (r *Runtime) reconcileVolumeDeletions(ctx context.Context, v control.Volumes) error {
	var failed error
	for _, work := range v.Deletions() {
		if work.Native.Owner.Key != r.Identity.Public {
			continue
		}
		err := r.removeOriginalVolume(ctx, work)
		if err == nil {
			err = r.publishVolumeDeleted(ctx, work)
		}
		failed = errors.Join(failed, err)
		if ctx.Err() != nil {
			break
		}
	}
	return failed
}

func (r *Runtime) publishVolumeDeleted(ctx context.Context, work control.VolumeDeleteWork) error {
	if err := r.volumeDeletePermit(ctx, work); err != nil {
		return err
	}
	view, err := r.Engine().Read(ctx, false)
	if err != nil {
		return err
	}
	proof := volumes.NativeRemoved{Schema: 1, Scope: work.Native.Spec.Scope, Owner: work.Native.Owner, Key: volumes.NativeKey(work.Native.Spec), Generation: work.Native.Generation, DeleteRevision: work.Revision, DataRetained: work.Native.Fixed != nil}
	proof.Signature = ed25519.Sign(r.Identity.Private, volumes.NativeRemovedBytes(proof))
	report := control.VolumeDeleteReport{Schema: 1, Operation: "delete", Epoch: view.State.ModuleEpoch(), RootRevision: view.State.Object(control.VolumesKey).Revision, At: time.Now().Unix(), Proof: proof, Retained: work.Retained}
	raw, _ := json.Marshal(report)
	reply, err := r.appCall(ctx, "volume-delete-report", raw)
	if err != nil {
		return err
	}
	if reply.Committed == nil || reply.Committed.Result.Code != state.Applied {
		return volumes.ErrNativeVolume
	}
	return nil
}
