// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

func (r *Runtime) volumeUsagePermit(ctx context.Context, ready volumes.NativeReady) error {
	body, err := json.Marshal(ready)
	if err != nil {
		return err
	}
	reply, err := r.appCall(ctx, "volume-usage-permit", body)
	if err != nil {
		return err
	}
	index, err := schema.Decode[uint64](reply.Data)
	if err != nil || index == 0 || reply.Local || reply.RaftIndex == 0 || reply.CommandIndex < index {
		return sfcp.ErrAdmission
	}
	return nil
}

func (r *Runtime) observeVolumeUsage(ctx context.Context, ready volumes.NativeReady) (volumes.Usage, error) {
	if ready.Verify() != nil || ready.Owner.Key != r.Identity.Public || !r.volumeUsageMu.TryLock() {
		return volumes.Usage{}, sfcp.ErrAdmission
	}
	defer r.volumeUsageMu.Unlock()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	if err := r.volumeUsagePermit(ctx, ready); err != nil {
		return volumes.Usage{}, err
	}
	r.life.RLock()
	if r.closed || r.nativeVolumes == nil {
		r.life.RUnlock()
		return volumes.Usage{}, sfcp.ErrAdmission
	}
	// Node work ceiling, not a caller-controlled disk quota. One scan at a
	// time with finite entries/depth bounds directory memory and native work.
	value, err := r.nativeVolumes.Usage(ctx, volumes.NativeKey(ready.Spec), volumes.UsageLimits{Entries: 100_000, Depth: 64})
	r.life.RUnlock()
	if err != nil || !value.Matches(ready) {
		return volumes.Usage{}, sfcp.ErrAdmission
	}
	if err = r.volumeUsagePermit(ctx, ready); err != nil {
		return volumes.Usage{}, err
	}
	return value, nil
}

func (r *Runtime) volumeUsage(ctx context.Context, ready volumes.NativeReady) (volumes.Usage, error) {
	if owner, local := r.nativeOwner(ready.Owner.Key); local {
		return owner.observeVolumeUsage(ctx, ready)
	}
	peer, ok := r.resourcePeer(ctx, ready.Owner.Node, ready.Owner.Key)
	if !ok || !peer.Member || peer.ID != ready.Owner.Node {
		return volumes.Usage{}, sfcp.ErrAdmission
	}
	body, err := json.Marshal(ready)
	if err != nil {
		return volumes.Usage{}, err
	}
	reply, err := cluster.CallManagement(ctx, r.Mesh, r.commandIdentity(), ready.Spec.Scope.Cluster, peer, cluster.ManagementRequest{Method: "volume-usage-observe", Input: body})
	if err != nil {
		return volumes.Usage{}, err
	}
	value, err := schema.Decode[volumes.Usage](reply.Data)
	if err != nil || !value.Matches(ready) {
		return volumes.Usage{}, sfcp.ErrAdmission
	}
	return value, nil
}
