// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

func (r *Runtime) observeVolumeMoveRecipe(ctx context.Context, ready volumes.NativeReady) (control.VolumeMoveRecipe, error) {
	var out control.VolumeMoveRecipe
	if ready.Verify() != nil || ready.Owner.Key != r.Identity.Public || !r.volumeSourceMu.TryLock() {
		return out, sfcp.ErrAdmission
	}
	defer r.volumeSourceMu.Unlock()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	if err := r.volumeUsagePermit(ctx, ready); err != nil {
		return out, err
	}
	r.life.RLock()
	if r.closed || r.activations == nil {
		r.life.RUnlock()
		return out, sfcp.ErrAdmission
	}
	writer, err := r.activations.PlanningWriter(ready)
	r.life.RUnlock()
	if err != nil {
		return out, err
	}
	out = control.VolumeMoveRecipe{Schema: 1, NativeBinding: control.VolumeNativeDigest(ready), Compatibility: sha256.Sum256(append([]byte("sfc-volume-cold-recipe-1\x00"), []byte(writer.Task.Spec)...)), Consumer: writer.Consumer}
	if err = r.volumeUsagePermit(ctx, ready); err != nil {
		return control.VolumeMoveRecipe{}, err
	}
	return out, nil
}
func (r *Runtime) volumeMoveRecipe(ctx context.Context, ready volumes.NativeReady) (control.VolumeMoveRecipe, error) {
	if owner, local := r.nativeOwner(ready.Owner.Key); local {
		return owner.observeVolumeMoveRecipe(ctx, ready)
	}
	peer, ok := r.resourcePeer(ctx, ready.Owner.Node, ready.Owner.Key)
	if !ok || !peer.Member || peer.ID != ready.Owner.Node {
		return control.VolumeMoveRecipe{}, sfcp.ErrAdmission
	}
	raw, err := json.Marshal(ready)
	if err != nil {
		return control.VolumeMoveRecipe{}, err
	}
	reply, err := cluster.CallManagement(ctx, r.Mesh, r.commandIdentity(), ready.Spec.Scope.Cluster, peer, cluster.ManagementRequest{Method: "volume-move-recipe-observe", Input: raw})
	if err != nil {
		return control.VolumeMoveRecipe{}, err
	}
	value, err := schema.Decode[control.VolumeMoveRecipe](reply.Data)
	if err != nil || value.Schema != 1 || value.NativeBinding != control.VolumeNativeDigest(ready) || value.Consumer.Owner != ready.Owner || !value.Consumer.Writable {
		return control.VolumeMoveRecipe{}, sfcp.ErrAdmission
	}
	return value, nil
}
