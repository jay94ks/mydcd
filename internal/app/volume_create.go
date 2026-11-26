// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/storage"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

func (r *Runtime) volumeCreatePermit(ctx context.Context, work control.VolumeCreateWork) (control.VolumeCreateWork, error) {
	raw, _ := json.Marshal(work.Spec.Scope)
	reply, err := r.appCall(ctx, "volume-create-permit", raw)
	if err != nil {
		return work, err
	}
	permit, err := schema.Decode[control.VolumeCreateWork](reply.Data)
	if err != nil || reply.Local || reply.RaftIndex == 0 || permit.Spec != work.Spec || permit.Phase != work.Phase || permit.Prepared != work.Prepared || permit.Revision != work.Revision || permit.Capacity < 1 || permit.Capacity > work.Capacity {
		return work, mydcp.ErrAdmission
	}
	if (permit.Fixed == nil) != (work.Fixed == nil) || permit.Fixed != nil && (permit.Fixed.Validate() != nil || permit.Fixed.Digest() != work.Fixed.Digest()) {
		return work, mydcp.ErrAdmission
	}
	return permit, nil
}

// Creation's only native Apply is ID1. A confirmed failed first attempt does
// not silently become a new successful operation on the next reconcile tick.
func validateCreationIntent(row reconcile.Record, spec volumes.NativeSpec, prepared bool) error {
	raw, _ := json.Marshal(spec)
	target := reconcile.Resource{Present: true, Generation: 1, Spec: string(raw)}
	s := row.State
	if row.Schema != 1 || reconcile.Validate(s) != nil || !s.Desired.Present || s.Desired.Revision != 1 || s.Desired.Resource != target || s.GenerationFloor != 1 || s.LastID > 1 || s.Applied.Present && s.Applied != target || s.Pending != nil && (s.Pending.Kind != reconcile.Apply || s.Pending.ID != 1 || s.Pending.Target != target) {
		return volumes.ErrNativeVolume
	}
	if !prepared && (s.LastID != 0 || s.Pending != nil || s.Applied.Present) || prepared && s.LastID == 1 && s.Pending == nil && !s.Applied.Present {
		return volumes.ErrNativeVolume
	}
	return nil
}

func (r *Runtime) prepareOriginalCreation(ctx context.Context, work control.VolumeCreateWork) error {
	if work.Fixed != nil {
		return r.prepareFixedCreation(ctx, work)
	}
	permit, err := r.volumeCreatePermit(ctx, work)
	if err != nil {
		return err
	}
	key := volumes.NativeKey(work.Spec)
	row, err := r.nativeVolumes.View(key)
	if err != nil && !errors.Is(err, storage.ErrMissing) {
		return err
	}
	if err == nil {
		if err := validateCreationIntent(row, work.Spec, false); err != nil {
			return err
		}
	}
	if _, err = r.nativeVolumes.Desired(work.Spec, 1, 1, permit.Capacity); err != nil {
		return err
	}
	row, err = r.nativeVolumes.View(key)
	if err != nil {
		return err
	}
	return validateCreationIntent(row, work.Spec, false)
}

func (r *Runtime) createOriginalVolume(ctx context.Context, work control.VolumeCreateWork) (volumes.NativeReady, error) {
	if work.Fixed != nil {
		return r.createFixedVolume(ctx, work)
	}
	permit, err := r.volumeCreatePermit(ctx, work)
	if err != nil {
		return volumes.NativeReady{}, err
	}
	if !work.Prepared {
		return volumes.NativeReady{}, volumes.ErrNativeVolume
	}
	key := volumes.NativeKey(work.Spec)
	row, err := r.nativeVolumes.View(key)
	if err != nil {
		return volumes.NativeReady{}, err
	}
	if err = validateCreationIntent(row, work.Spec, true); err != nil {
		return volumes.NativeReady{}, err
	}
	if _, err = r.nativeVolumes.Desired(work.Spec, 1, 1, permit.Capacity); err != nil {
		return volumes.NativeReady{}, err
	}
	if err = r.nativeVolumes.Step(ctx, key); err != nil {
		return volumes.NativeReady{}, err
	}
	return r.nativeVolumes.Ready(ctx, key, r.Identity.Private)
}

func (r *Runtime) cancelOriginalCreation(ctx context.Context, work control.VolumeCreateWork) (volumes.NativeRemoved, error) {
	if work.Fixed != nil {
		return r.cancelFixedCreation(ctx, work)
	}
	var proof volumes.NativeRemoved
	if _, err := r.volumeCreatePermit(ctx, work); err != nil {
		return proof, err
	}
	key := volumes.NativeKey(work.Spec)
	row, err := r.nativeVolumes.View(key)
	if errors.Is(err, storage.ErrMissing) {
		if work.Prepared {
			return proof, err
		}
		// The only producer is this serial worker. A missing synced intent is
		// positive no-dispatch evidence here; it is not inferred from absence.
		if gone, err := r.docker.Gone(ctx, "volume", key); err != nil || !gone {
			return proof, errors.Join(reconcile.ErrPending, err)
		}
	} else if err != nil {
		return proof, err
	} else {
		raw, _ := json.Marshal(work.Spec)
		target := reconcile.Resource{Present: true, Generation: 1, Spec: string(raw)}
		if row.State.GenerationFloor != 1 || row.State.Desired.Present && row.State.Desired.Resource != target || row.State.Applied.Present && row.State.Applied != target || row.State.Pending != nil && row.State.Pending.Target != target {
			return proof, volumes.ErrNativeVolume
		}
		if err = r.nativeVolumes.DeleteDesired(key, 2, 1); err != nil {
			return proof, err
		}
		if err = r.nativeVolumes.Step(ctx, key); err != nil {
			return proof, err
		}
		if gone, err := r.nativeVolumes.Gone(ctx, key, 2, 1); err != nil || !gone {
			return proof, errors.Join(reconcile.ErrPending, err)
		}
	}
	owner := r.Identity.Public
	raw, _ := json.Marshal(work.Spec)
	clientOwner, err := r.docker.Identity("volume", key, reconcile.Resource{Present: true, Generation: 1, Spec: string(raw)})
	if err != nil {
		return proof, err
	}
	proof = volumes.NativeRemoved{Schema: 1, Scope: work.Spec.Scope, Owner: volumes.Owner{Node: work.Spec.Node, Key: owner, Native: clientOwner.Name}, Key: key, Generation: 1, DeleteRevision: work.Revision}
	proof.Signature = ed25519.Sign(r.Identity.Private, volumes.NativeRemovedBytes(proof))
	return proof, nil
}

func (r *Runtime) reconcileVolumeCreations(ctx context.Context, v control.Volumes) error {
	var failed error
	for _, j := range v.Creations() {
		if j.Spec.NodeKey != r.Identity.Public || j.Phase != "Reserved" && j.Phase != "Creating" && j.Phase != "Cancelling" {
			continue
		}
		var err error
		work := control.VolumeCreateWork{Spec: j.Spec, Revision: j.Revision, Phase: j.Phase, Capacity: j.Capacity, Prepared: j.Preparation != nil, Fixed: j.Fixed}
		report := control.VolumeCreateReport{Operation: "create", Schema: 1, Scope: j.Spec.Scope, Revision: j.Revision}
		if j.Phase == "Reserved" {
			err = r.prepareOriginalCreation(ctx, work)
			report.Prepared = true
		} else if j.Phase == "Creating" {
			ready, e := r.createOriginalVolume(ctx, work)
			err = e
			report.Ready = &ready
		} else {
			gone, e := r.cancelOriginalCreation(ctx, work)
			err = e
			report.Gone = &gone
		}
		if err == nil {
			_, err = r.volumeCreatePermit(ctx, work)
		}
		if err == nil {
			current, e := r.Engine().Read(ctx, false)
			err = e
			if err == nil {
				report.Epoch, report.RootRevision, report.At = current.State.ModuleEpoch(), current.State.Object(control.VolumesKey).Revision, time.Now().Unix()
				report.Signature = ed25519.Sign(r.Identity.Private, control.VolumeCreateReportBytes(report))
				raw, _ := json.Marshal(report)
				reply, e := r.appCall(ctx, "volume-create-report", raw)
				err = e
				if err == nil && (reply.Committed == nil || reply.Committed.Result.Code != state.Applied) {
					err = volumes.ErrNativeVolume
				}
			}
		}
		if err != nil {
			failed = errors.Join(failed, fmt.Errorf("volume create %s: %w", j.Phase, err))
		}
		if ctx.Err() != nil {
			break
		}
	}
	return failed
}
