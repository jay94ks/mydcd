// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/workload/volumes"
	"time"
)

func init() {
	defineNodeRead((*Runtime).nodeReadVolumeUsageObserve, false, "volume-usage-observe", "volume-backup-source-observe", "volume-move-recipe-observe", "volume-move-inputs-observe")
	defineNodeRead((*Runtime).nodeReadVolumeCreatePermit, true, "volume-create-permit")
	defineNodeRead((*Runtime).nodeReadVolumeDeletePermit, true, "volume-delete-permit")
	defineNodeRead((*Runtime).nodeReadVolumeRetainedDeletePermit, true, "volume-retained-delete-permit")
	defineNodeRead((*Runtime).nodeReadVolumeRestorePermit, true, "volume-restore-permit")
	defineNodeRead((*Runtime).nodeReadVolumeBackupPermit, true, "volume-backup-permit")
	defineNodeRead((*Runtime).nodeReadVolumeMovePermit, true, "volume-move-permit")
	defineNodeRead((*Runtime).nodeReadVolumeFileWork, true, "volume-file-work")
	defineNodeRead((*Runtime).nodeReadVolumeUsagePermit, true, "volume-usage-permit")
	defineNodeRead((*Runtime).nodeReadVolumePermit, true, "volume-permit")
}

func (r *Runtime) nodeReadVolumeUsageObserve(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	peer, known := r.Mesh.Peer(sfcp.Identity(caller))
	if err != nil || !known || !peer.Member {
		return nil, sfcp.ErrAdmission
	}
	if method == "volume-move-inputs-observe" {
		request, err := schema.Decode[control.VolumeMoveInputProbe](input)
		if err != nil {
			return nil, err
		}
		proof, err := r.observeVolumeMoveInputs(ctx, caller, request)
		if err != nil {
			return nil, err
		}
		return json.Marshal(proof)
	}
	ready, err := schema.Decode[volumes.NativeReady](input)
	if err != nil {
		return nil, err
	}
	owner, local := r.nativeOwner(ready.Owner.Key)
	if !local {
		return nil, sfcp.ErrAdmission
	}
	if method == "volume-move-recipe-observe" {
		value, err := owner.observeVolumeMoveRecipe(ctx, ready)
		if err != nil {
			return nil, err
		}
		return json.Marshal(value)
	}
	if method == "volume-backup-source-observe" {
		value, err := owner.observeVolumeBackupSource(ctx, ready)
		if err != nil {
			return nil, err
		}
		return json.Marshal(value)
	}
	value, err := owner.observeVolumeUsage(ctx, ready)
	if err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

func (r *Runtime) nodeReadVolumeCreatePermit(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	if v.Local {
		return nil, sfcp.ErrAdmission
	}
	caller, err := identity.ParseKey(key)
	if err != nil {
		return nil, err
	}
	scope, err := schema.Decode[volumes.Scope](input)
	if err != nil {
		return nil, err
	}
	work, err := r.controlPolicy.VolumeCreatePermit(v.State, caller, scope)
	if err != nil {
		return nil, err
	}
	return json.Marshal(work)
}

func (r *Runtime) nodeReadVolumeDeletePermit(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	if v.Local {
		return nil, sfcp.ErrAdmission
	}
	caller, err := identity.ParseKey(key)
	if err != nil {
		return nil, err
	}
	scope, err := schema.Decode[volumes.Scope](input)
	if err != nil {
		return nil, err
	}
	work, err := r.controlPolicy.VolumeDeletePermit(v.State, caller, scope)
	if err != nil {
		return nil, err
	}
	return json.Marshal(work)
}

func (r *Runtime) nodeReadVolumeRetainedDeletePermit(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	if v.Local {
		return nil, sfcp.ErrAdmission
	}
	caller, err := identity.ParseKey(key)
	if err != nil {
		return nil, err
	}
	selection, err := schema.Decode[control.VolumeMoveSelection](input)
	if err != nil {
		return nil, err
	}
	work, err := r.controlPolicy.VolumeRetainedDeletePermit(v.State, caller, selection)
	if err != nil {
		return nil, err
	}
	return json.Marshal(work)
}

func (r *Runtime) nodeReadVolumeRestorePermit(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	if v.Local {
		return nil, sfcp.ErrAdmission
	}
	caller, err := identity.ParseKey(key)
	if err != nil {
		return nil, err
	}
	request, err := schema.Decode[control.VolumeRestorePermitRequest](input)
	if err != nil {
		return nil, err
	}
	job, err := r.controlPolicy.VolumeRestorePermit(v.State, caller, request.Selection, request.Cleanup)
	if err != nil {
		return nil, err
	}
	return json.Marshal(job)
}

func (r *Runtime) nodeReadVolumeBackupPermit(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	if v.Local {
		return nil, sfcp.ErrAdmission
	}
	caller, err := identity.ParseKey(key)
	if err != nil {
		return nil, err
	}
	request, err := schema.Decode[control.VolumeBackupPermitRequest](input)
	if err != nil {
		return nil, err
	}
	job, err := r.controlPolicy.VolumeBackupPermit(v.State, caller, request.Selection, request.Cleanup)
	if err != nil {
		return nil, err
	}
	return json.Marshal(job)
}

func (r *Runtime) nodeReadVolumeMovePermit(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	if v.Local {
		return nil, sfcp.ErrAdmission
	}
	caller, err := identity.ParseKey(key)
	if err != nil {
		return nil, err
	}
	request, err := schema.Decode[control.VolumeMovePermitRequest](input)
	if err != nil {
		return nil, err
	}
	permit, err := r.controlPolicy.VolumeMovePermit(v.State, caller, request, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	return json.Marshal(permit)
}

func (r *Runtime) nodeReadVolumeFileWork(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	if v.Local {
		return nil, sfcp.ErrAdmission
	}
	caller, err := identity.ParseKey(key)
	if err != nil {
		return nil, err
	}
	q, err := schema.Decode[volumeFileWorkRequest](input)
	now := time.Now().Unix()
	if err != nil || !access.Recent(q.At, now, 30) {
		return nil, sfcp.ErrAdmission
	}
	job, err := r.controlPolicy.VolumeFileWork(v.State, caller, q.Session, q.ID, now)
	if err != nil {
		return nil, err
	}
	return json.Marshal(job)
}

func (r *Runtime) nodeReadVolumeUsagePermit(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	if v.Local {
		return nil, sfcp.ErrAdmission
	}
	caller, err := identity.ParseKey(key)
	if err != nil {
		return nil, err
	}
	ready, err := schema.Decode[volumes.NativeReady](input)
	if err != nil {
		return nil, err
	}
	index, err := r.controlPolicy.VolumeUsagePermit(v.State, caller, ready)
	if err != nil {
		return nil, err
	}
	return json.Marshal(index)
}

func (r *Runtime) nodeReadVolumePermit(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	if v.Local {
		return nil, errors.New("managed quorum volume read required")
	}
	caller, err := identity.ParseKey(key)
	if err != nil {
		return nil, err
	}
	request, err := schema.Decode[volumes.StartRequest](input)
	if err != nil {
		return nil, err
	}
	policy := r.controlPolicy
	permit, err := policy.VolumePermit(v.State, caller, request)
	if err != nil {
		return nil, err
	}
	return json.Marshal(permit)
}
