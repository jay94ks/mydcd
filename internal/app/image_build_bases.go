// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/registryclient"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
)

func (r *Runtime) imageBuildBaseWork(ctx context.Context, spec imagebuild.JobSpec, source imagebuild.Source) (control.ImageBuildBaseRead, error) {
	if spec.Validate() != nil || spec.Cluster != r.controlPolicy.Cluster || spec.Scope.Root.Key != r.Identity.Public || !source.Valid() {
		return control.ImageBuildBaseRead{}, sfcp.ErrAdmission
	}
	q := control.ImageBuildBaseQuery{Tenant: spec.Tenant, Job: spec.ID, Snapshot: spec.Digest(), Source: source, At: time.Now().Unix()}
	raw, _ := json.Marshal(q)
	reply, err := r.appCall(ctx, "image-build-base-work", raw)
	if err != nil || reply.Local {
		return control.ImageBuildBaseRead{}, sfcp.ErrAdmission
	}
	read, err := schema.Decode[control.ImageBuildBaseRead](reply.Data)
	if err != nil || read.Cluster != spec.Cluster || read.Builder != r.Identity.Public || read.Query.Tenant != q.Tenant || read.Query.Job != q.Job || read.Query.Snapshot != q.Snapshot || read.Query.Source != source || read.Index == 0 || read.Epoch == 0 {
		return control.ImageBuildBaseRead{}, sfcp.ErrAdmission
	}
	view, err := r.Engine().ReadAtLeast(ctx, read.Index)
	if err != nil {
		return control.ImageBuildBaseRead{}, sfcp.ErrAdmission
	}
	return r.controlPolicy.CurrentImageBuildBaseRead(view.State, read, time.Now().Unix())
}
func (r *Runtime) currentImageBuildBase(ctx context.Context, read control.ImageBuildBaseRead) (control.ImageBuildBaseRead, error) {
	view, err := r.currentView(ctx)
	if err != nil || view.Local {
		return control.ImageBuildBaseRead{}, sfcp.ErrAdmission
	}
	return r.controlPolicy.CurrentImageBuildBaseRead(view.State, read, time.Now().Unix())
}

func (r *Runtime) resolveImageBuildBaseOwner(ctx context.Context, read control.ImageBuildBaseRead) (control.ImageBuildBaseResult, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	current, err := r.currentImageBuildBase(ctx, read)
	if err != nil || current.Target.Code != "" || current.Target.Owner != r.Identity.Public {
		return control.ImageBuildBaseResult{}, sfcp.ErrAdmission
	}
	image, err := r.readImageResolveTarget(ctx, read.Query.Tenant, current.Target)
	result := current.Result(current.Target.Result("OK", &image))
	if err != nil {
		result = current.Result(current.Target.Result(registryclient.Sanitize(err).Error(), nil))
	}
	view, err := r.currentView(ctx)
	if err != nil || view.Local {
		return control.ImageBuildBaseResult{}, sfcp.ErrAdmission
	}
	if err := r.controlPolicy.ValidateImageBuildBaseResult(view.State, read, result, time.Now().Unix()); err != nil {
		return control.ImageBuildBaseResult{}, err
	}
	return result, nil
}

func (r *Runtime) resolveImageBuildBase(ctx context.Context, spec imagebuild.JobSpec, source imagebuild.Source) (string, error) {
	pinned, _, err := r.resolveImageBuildSource(ctx, spec, source)
	return pinned, err
}

// unreachableOwner is the code for a source owner this node cannot reach.
const unreachableOwner = "OWNER_UNREACHABLE"

// resolveImageBuildSource also reports why a resolution failed: the
// target's or the registry's code, or unreachableOwner. The code is a
// diagnosis only; the error stays the authority.
func (r *Runtime) resolveImageBuildSource(ctx context.Context, spec imagebuild.JobSpec, source imagebuild.Source) (string, string, error) {
	read, err := r.imageBuildBaseWork(ctx, spec, source)
	if err != nil {
		return "", "", err
	}
	if read.Target.Code != "" {
		if read.Target.Code == "UNTRUSTED" {
			return "", read.Target.Code, imagebuild.ErrUntrustedBase
		}
		return "", read.Target.Code, imagebuild.ErrSourceFetch
	}
	var result control.ImageBuildBaseResult
	if read.Target.Owner == r.Identity.Public {
		result, err = r.resolveImageBuildBaseOwner(ctx, read)
	} else {
		peer, known := r.Mesh.Peer(sfcp.Identity(read.Target.Owner))
		if !known || !peer.Member {
			return "", unreachableOwner, sfcp.ErrAdmission
		}
		raw, _ := json.Marshal(read)
		reply, cause := cluster.CallManagement(ctx, r.Mesh, r.Identity, r.controlPolicy.Cluster, peer, cluster.ManagementRequest{Method: "image-build-base-owner", Input: raw})
		if cause != nil {
			return "", unreachableOwner, sfcp.ErrAdmission
		}
		if reply.Code != "ok" {
			return "", "", sfcp.ErrAdmission
		}
		result, err = schema.Decode[control.ImageBuildBaseResult](reply.Data)
	}
	if err != nil || !result.Valid(read) {
		return "", "", sfcp.ErrAdmission
	}
	view, err := r.currentView(ctx)
	if err != nil || view.Local {
		return "", "", sfcp.ErrAdmission
	}
	if err := r.controlPolicy.ValidateImageBuildBaseResult(view.State, read, result, time.Now().Unix()); err != nil {
		return "", "", err
	}
	if result.Result.Code != "OK" || result.Result.Image == nil {
		return "", result.Result.Code, imagebuild.ErrSourceFetch
	}
	return result.Result.Image.Pinned, "", nil
}
