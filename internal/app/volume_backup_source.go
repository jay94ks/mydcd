// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/workload"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

func (r *Runtime) observeVolumeBackupSource(ctx context.Context, ready volumes.NativeReady) (control.VolumeBackupSource, error) {
	var out control.VolumeBackupSource
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
	source, err := r.activations.ColdSource(ctx, ready)
	r.life.RUnlock()
	if err != nil {
		return out, err
	}
	digest := backupCompatibility(source)
	if !backupSourceMatches(source, control.VolumeBackupBinding{Scope: ready.Spec.Scope, Source: ready, Compatibility: digest}) {
		return out, sfcp.ErrAdmission
	}
	spec, err := workload.DecodeContainer(source.Writer.Task.Spec)
	if err != nil {
		return out, err
	}
	out = control.VolumeBackupSource{Schema: 1, Scope: ready.Spec.Scope, Node: ready.Owner.Node, Owner: ready.Owner.Key, NativeBinding: control.VolumeNativeDigest(ready), Compatibility: digest, Image: spec.Process.ImageID, WriterGeneration: source.Writer.Task.Generation, Exit: source.Exit}
	if err = r.volumeUsagePermit(ctx, ready); err != nil {
		return control.VolumeBackupSource{}, err
	}
	return out, nil
}
func (r *Runtime) volumeBackupSource(ctx context.Context, ready volumes.NativeReady) (control.VolumeBackupSource, error) {
	if owner, local := r.nativeOwner(ready.Owner.Key); local {
		return owner.observeVolumeBackupSource(ctx, ready)
	}
	peer, ok := r.resourcePeer(ctx, ready.Owner.Node, ready.Owner.Key)
	if !ok || !peer.Member || peer.ID != ready.Owner.Node {
		return control.VolumeBackupSource{}, sfcp.ErrAdmission
	}
	body, _ := json.Marshal(ready)
	reply, err := cluster.CallManagement(ctx, r.Mesh, r.commandIdentity(), ready.Spec.Scope.Cluster, peer, cluster.ManagementRequest{Method: "volume-backup-source-observe", Input: body})
	if err != nil {
		return control.VolumeBackupSource{}, err
	}
	value, err := schema.Decode[control.VolumeBackupSource](reply.Data)
	if err != nil || !value.Matches(ready) {
		return control.VolumeBackupSource{}, sfcp.ErrAdmission
	}
	return value, nil
}
