// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
)

func (r *Runtime) currentImageBuildLogRead(ctx context.Context, read control.ImageBuildLogRead) (control.ImageBuildLogRead, error) {
	view, err := r.currentView(ctx)
	if err != nil || view.Local {
		return control.ImageBuildLogRead{}, sfcp.ErrAdmission
	}
	return r.controlPolicy.CurrentImageBuildLogRead(view.State, read, time.Now().Unix())
}
func (r *Runtime) imageBuildLogs(ctx context.Context, read control.ImageBuildLogRead) (control.ImageBuildLogPage, error) {
	current, err := r.currentImageBuildLogRead(ctx, read)
	if err != nil {
		return control.ImageBuildLogPage{}, err
	}
	if current.Spec.Scope.Root.Key == r.Identity.Public {
		return r.imageBuildLogsOwner(ctx, current)
	}
	peer, exists := r.Mesh.Peer(sfcp.Identity(current.Spec.Scope.Root.Key))
	if !exists || !peer.Member || peer.ID != current.Spec.Scope.Root.Node {
		return control.ImageBuildLogPage{}, sfcp.ErrAdmission
	}
	raw, _ := json.Marshal(current)
	reply, err := cluster.CallManagement(ctx, r.Mesh, r.Identity, r.controlPolicy.Cluster, peer, cluster.ManagementRequest{Method: "image-build-logs-owner", Input: raw})
	if err != nil || reply.Code != "ok" {
		return control.ImageBuildLogPage{}, sfcp.ErrAdmission
	}
	out, err := schema.Decode[control.ImageBuildLogPage](reply.Data)
	if err != nil || !out.Valid(current) {
		return control.ImageBuildLogPage{}, sfcp.ErrAdmission
	}
	if _, err := r.currentImageBuildLogRead(ctx, read); err != nil {
		return control.ImageBuildLogPage{}, err
	}
	return out, nil
}
func (r *Runtime) imageBuildLogsOwner(ctx context.Context, read control.ImageBuildLogRead) (control.ImageBuildLogPage, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	current, err := r.currentImageBuildLogRead(ctx, read)
	if err != nil {
		return control.ImageBuildLogPage{}, err
	}
	if current.Spec.Scope.Root.Key != r.Identity.Public {
		return control.ImageBuildLogPage{}, sfcp.ErrAdmission
	}
	r.life.RLock()
	defer r.life.RUnlock()
	if r.closed || r.ctx.Err() != nil || r.reports == nil {
		return control.ImageBuildLogPage{}, sfcp.ErrAdmission
	}
	offset, err := current.Offset()
	if err != nil {
		return control.ImageBuildLogPage{}, err
	}
	var page imagebuild.LogPage
	if current.Query.Tail {
		page, err = imagebuild.ReadNativeLogsTail(r.reports, current.Spec, current.Query.MaxBytes)
	} else {
		page, err = imagebuild.ReadNativeLogs(r.reports, current.Spec, offset, current.Query.MaxBytes)
	}
	if errors.Is(err, imagebuild.ErrNativeMissing) && current.Phase == "queued" && offset == 0 {
		page, err = imagebuild.LogPage{Schema: 1, Job: current.Spec.Digest()}, nil
	}
	if err != nil {
		return control.ImageBuildLogPage{}, err
	}
	current, err = r.currentImageBuildLogRead(ctx, read)
	if err != nil {
		return control.ImageBuildLogPage{}, err
	}
	return current.Page(page)
}

func (r *Runtime) pruneImageBuildLogs(ctx context.Context, native *imagebuild.NativeJobs, spec imagebuild.JobSpec) error {
	if native == nil {
		return imagebuild.ErrInvalid
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	r.life.RLock()
	defer r.life.RUnlock()
	if r.closed || r.ctx.Err() != nil {
		return sfcp.ErrAdmission
	}
	view, err := r.currentView(ctx)
	if err != nil || view.Local {
		return sfcp.ErrAdmission
	}
	closure, err := r.controlPolicy.ImageBuildLogReclaim(view.State, r.Identity.Public, spec)
	if err != nil {
		return err
	}
	return native.PruneLogs(spec, closure)
}
