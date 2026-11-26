// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/schema"
)

func (r *Runtime) currentImageBuildCacheRead(ctx context.Context, read control.ImageBuildCacheRead) (control.ImageBuildCacheRead, error) {
	v, err := r.currentView(ctx)
	if err != nil || v.Local {
		return control.ImageBuildCacheRead{}, mydcp.ErrAdmission
	}
	return r.controlPolicy.CurrentImageBuildCacheRead(v.State, read, time.Now().Unix())
}
func (r *Runtime) imageBuildCache(ctx context.Context, read control.ImageBuildCacheRead) (control.ImageBuildCachePage, error) {
	current, err := r.currentImageBuildCacheRead(ctx, read)
	if err != nil {
		return control.ImageBuildCachePage{}, err
	}
	if current.Spec.Scope.Root.Key == r.Identity.Public {
		return r.imageBuildCacheOwner(ctx, current)
	}
	peer, ok := r.Mesh.Peer(mydcp.Identity(current.Spec.Scope.Root.Key))
	if !ok || !peer.Member || peer.ID != current.Spec.Scope.Root.Node {
		return control.ImageBuildCachePage{}, mydcp.ErrAdmission
	}
	raw, _ := json.Marshal(current)
	reply, err := cluster.CallManagement(ctx, r.Mesh, r.Identity, r.controlPolicy.Cluster, peer, cluster.ManagementRequest{Method: "image-build-cache-owner", Input: raw})
	if err != nil || reply.Code != "ok" {
		return control.ImageBuildCachePage{}, mydcp.ErrAdmission
	}
	out, err := schema.Decode[control.ImageBuildCachePage](reply.Data)
	if err != nil || !out.Valid(current) {
		return control.ImageBuildCachePage{}, mydcp.ErrAdmission
	}
	if _, err := r.currentImageBuildCacheRead(ctx, read); err != nil {
		return control.ImageBuildCachePage{}, err
	}
	return out, nil
}
func (r *Runtime) imageBuildCacheOwner(ctx context.Context, read control.ImageBuildCacheRead) (control.ImageBuildCachePage, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	current, err := r.currentImageBuildCacheRead(ctx, read)
	if err != nil {
		return control.ImageBuildCachePage{}, err
	}
	if current.Spec.Scope.Root.Key != r.Identity.Public {
		return control.ImageBuildCachePage{}, mydcp.ErrAdmission
	}
	r.life.RLock()
	defer r.life.RUnlock()
	if r.closed || r.ctx.Err() != nil || r.imageBuildNative == nil {
		return control.ImageBuildCachePage{}, mydcp.ErrAdmission
	}
	snapshot, offset, err := current.Offset()
	if err != nil {
		return control.ImageBuildCachePage{}, err
	}
	var page imagebuild.CachePage
	if current.Query.Cache != nil {
		page, err = r.imageBuildNative.ReadCacheScope(current.Spec, offset, snapshot)
	} else {
		page, err = r.imageBuildNative.ReadCacheUsage(current.Spec, offset, snapshot)
	}
	if errors.Is(err, imagebuild.ErrNativeMissing) && offset == 0 && snapshot == ([32]byte{}) {
		// Explicitly unobserved, never a claim of zero actual usage.
		page, err = imagebuild.CachePage{Schema: 1, Cache: imagebuild.CacheIdentity(current.Spec)}, nil
	}
	if err != nil {
		return control.ImageBuildCachePage{}, err
	}
	current, err = r.currentImageBuildCacheRead(ctx, read)
	if err != nil {
		return control.ImageBuildCachePage{}, err
	}
	return current.Page(page)
}
