// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
)

func (r *Runtime) imageBuildCacheInventory(ctx context.Context, session access.Session, tenant string, q control.ImageBuildQuery, after string) (control.ImageBuildPage, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	current := func() (control.ImageBuildPage, error) {
		view, err := r.currentView(ctx)
		if err != nil || view.Local {
			return control.ImageBuildPage{}, sfcp.ErrAdmission
		}
		return r.controlPolicy.ImageBuildPage(view.State, session, time.Now().Unix(), tenant, q, after)
	}
	page, err := current()
	if err != nil {
		return control.ImageBuildPage{}, err
	}
	if !control.ValidImageBuildCacheInventoryPage(page, q, after, false) {
		return control.ImageBuildPage{}, sfcp.ErrAdmission
	}
	for i := range page.Caches {
		row := &page.Caches[i]
		read := control.ImageBuildCacheInventoryRead{Session: session, Tenant: tenant, Query: q, After: after, Root: *page.InventoryRoot, Cache: row.Cache, Epoch: page.Epoch}
		var usage imagebuild.CacheSummary
		var cause error
		if row.Owner == r.Identity.Public {
			call, done := context.WithTimeout(ctx, 5*time.Second)
			usage, cause = r.imageBuildCacheInventoryOwner(call, read)
			done()
		} else {
			peer, known := r.Mesh.Peer(sfcp.Identity(row.Owner))
			if !known || !peer.Member || peer.ID != row.Node {
				row.Code = "UNAVAILABLE"
				continue
			}
			raw, _ := json.Marshal(read)
			call, done := context.WithTimeout(ctx, 5*time.Second)
			reply, err := cluster.CallManagement(call, r.Mesh, r.Identity, r.controlPolicy.Cluster, peer, cluster.ManagementRequest{Method: "image-build-caches-owner", Input: raw})
			done()
			if err != nil || reply.Code != "ok" {
				row.Code = "UNAVAILABLE"
				continue
			}
			usage, cause = schema.Decode[imagebuild.CacheSummary](reply.Data)
		}
		if cause != nil || !usage.Valid(row.Cache) {
			row.Code = "UNAVAILABLE"
			continue
		}
		row.Code, row.Usage = "OK", &usage
	}
	fresh, err := current()
	if err != nil {
		return control.ImageBuildPage{}, err
	}
	if fresh.InventoryRoot == nil || *fresh.InventoryRoot != *page.InventoryRoot || fresh.Epoch != page.Epoch || !control.ValidImageBuildCacheInventoryPage(page, q, after, true) {
		return control.ImageBuildPage{}, access.ErrConflict
	}
	return page, nil
}

func (r *Runtime) imageBuildCacheInventoryOwner(ctx context.Context, read control.ImageBuildCacheInventoryRead) (imagebuild.CacheSummary, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	current := func() (imagebuild.JobSpec, error) {
		view, err := r.currentView(ctx)
		if err != nil || view.Local {
			return imagebuild.JobSpec{}, sfcp.ErrAdmission
		}
		spec, err := r.controlPolicy.CurrentImageBuildCacheInventory(view.State, read, time.Now().Unix())
		if err != nil || spec.Scope.Root.Key != r.Identity.Public {
			return imagebuild.JobSpec{}, sfcp.ErrAdmission
		}
		return spec, nil
	}
	spec, err := current()
	if err != nil {
		return imagebuild.CacheSummary{}, err
	}
	r.life.RLock()
	defer r.life.RUnlock()
	if r.closed || r.ctx.Err() != nil || r.imageBuildNative == nil {
		return imagebuild.CacheSummary{}, sfcp.ErrAdmission
	}
	usage, err := r.imageBuildNative.ReadCacheSummary(spec)
	if err != nil {
		return imagebuild.CacheSummary{}, err
	}
	if _, err := current(); err != nil {
		return imagebuild.CacheSummary{}, err
	}
	return usage, nil
}
