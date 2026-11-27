// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/distribution/reference"
	oci "github.com/google/go-containerregistry/pkg/registry"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/registryclient"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
)

func (r *Runtime) resolveManagedImage(ctx context.Context, read control.ImageResolveRead) (registryclient.Resolution, error) {
	run := read.Target.Managed
	if run == nil || run.Owner != r.Identity.Public {
		return registryclient.Resolution{}, sfcp.ErrAdmission
	}
	if _, _, err := r.registryCurrent(ctx, *run); err != nil {
		return registryclient.Resolution{}, err
	}
	named, err := reference.ParseNormalizedNamed(read.Target.Normalized)
	if err != nil {
		return registryclient.Resolution{}, &registryclient.Error{Code: "INVALID_IMAGE"}
	}
	var target string
	if digested, ok := named.(reference.Digested); ok {
		target = digested.Digest().String()
	} else if tagged, ok := named.(reference.Tagged); ok {
		target = tagged.Tag()
	}
	if target == "" {
		return registryclient.Resolution{}, &registryclient.Error{Code: "INVALID_IMAGE"}
	}
	data, err := r.readRegistryManifest(ctx, *run, reference.Path(named), target, true)
	if err != nil {
		if errors.Is(err, oci.ErrNameUnknown) || errors.Is(err, oci.ErrNotFound) {
			return registryclient.Resolution{}, &registryclient.Error{Code: "NOT_FOUND"}
		}
		return registryclient.Resolution{}, err
	}
	return registryclient.ResolveManifest(read.Target.Normalized, data.ContentType, data.Body)
}

func (r *Runtime) resolveImageOwner(ctx context.Context, read control.ImageResolveRead) (control.ImageResolveResult, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	view, err := r.currentView(ctx)
	if err != nil {
		return control.ImageResolveResult{}, sfcp.ErrAdmission
	}
	current, err := r.controlPolicy.CurrentImageResolve(view.State, read, time.Now().Unix())
	if err != nil || current.Target.Code != "" || current.Target.Owner != r.Identity.Public {
		return control.ImageResolveResult{}, sfcp.ErrAdmission
	}
	image, err := r.readImageResolveTarget(ctx, read.Tenant, current.Target)
	result := current.Target.Result("OK", &image)
	if err != nil {
		result = current.Target.Result(registryclient.Sanitize(err).Error(), nil)
	}
	latest, cause := r.currentView(ctx)
	if cause != nil {
		return control.ImageResolveResult{}, sfcp.ErrAdmission
	}
	current, cause = r.controlPolicy.CurrentImageResolve(latest.State, read, time.Now().Unix())
	if cause != nil {
		return control.ImageResolveResult{}, sfcp.ErrAdmission
	}
	if current.Target.External != nil {
		if _, cause = r.externalRegistryWork(ctx, *current.Target.External); cause != nil {
			return control.ImageResolveResult{}, sfcp.ErrAdmission
		}
	}
	if result.Image != nil {
		catalog, cause := r.controlPolicy.Catalog(latest.State)
		if cause != nil {
			return control.ImageResolveResult{}, cause
		}
		if _, cause = catalog.CheckImageTrust(read.Tenant, result.Image.Pinned); cause != nil {
			return control.ImageResolveResult{}, sfcp.ErrAdmission
		}
	}
	if !result.Valid(current) {
		return control.ImageResolveResult{}, sfcp.ErrAdmission
	}
	return result, nil
}

// This function returns public resolution metadata only. External credential
// reads and the SDK client remain on their approved reader owner; the caller
// checks its user/job grant before and after this finite consumer.
func (r *Runtime) readImageResolveTarget(ctx context.Context, tenant string, target control.ImageResolveTarget) (registryclient.Resolution, error) {
	if target.Owner != r.Identity.Public || target.Code != "" || !target.Trust.Trusted {
		return registryclient.Resolution{}, sfcp.ErrAdmission
	}
	if target.Managed != nil {
		return r.resolveManagedImage(ctx, control.ImageResolveRead{Tenant: tenant, Target: target})
	}
	var client *registryclient.Access
	var err error
	if target.External != nil {
		work, cause := r.externalRegistryWork(ctx, *target.External)
		if cause != nil {
			return registryclient.Resolution{}, cause
		}
		if work.Inputs.ReadSet != target.ExternalReadSet {
			return registryclient.Resolution{}, sfcp.ErrAdmission
		}
		release, cause := r.acquireExternalReader(work)
		if cause != nil {
			return registryclient.Resolution{}, cause
		}
		defer release()
		client, err = r.sourceRegistryClient(ctx, work)
	} else {
		_, authority, _, cause := registryclient.Normalize(target.Normalized)
		if cause != nil {
			return registryclient.Resolution{}, sfcp.ErrAdmission
		}
		client, err = registryclient.New(authority, nil, nil, nil)
	}
	if err != nil {
		return registryclient.Resolution{}, err
	}
	defer client.Close()
	return client.Resolve(ctx, target.Normalized)
}

func (r *Runtime) resolveImage(ctx context.Context, read control.ImageResolveRead) (control.ImageResolveResult, error) {
	view, err := r.currentView(ctx)
	if err != nil {
		return control.ImageResolveResult{}, sfcp.ErrAdmission
	}
	current, err := r.controlPolicy.CurrentImageResolve(view.State, read, time.Now().Unix())
	if err != nil {
		return control.ImageResolveResult{}, err
	}
	if current.Target.Code != "" {
		return current.Target.Result(current.Target.Code, nil), nil
	}
	owner := current.Target.Owner
	if owner == r.Identity.Public {
		return r.resolveImageOwner(ctx, current)
	}
	peer, ok := r.Mesh.Peer(sfcp.Identity(owner))
	if !ok || !peer.Member {
		return control.ImageResolveResult{}, sfcp.ErrAdmission
	}
	body, _ := json.Marshal(current)
	reply, err := cluster.CallManagement(ctx, r.Mesh, r.Identity, r.controlPolicy.Cluster, peer, cluster.ManagementRequest{Method: "image-resolve-owner", Input: body})
	if err != nil || reply.Code != "ok" {
		return control.ImageResolveResult{}, sfcp.ErrAdmission
	}
	result, err := schema.Decode[control.ImageResolveResult](reply.Data)
	if err != nil || !result.Valid(current) {
		return control.ImageResolveResult{}, sfcp.ErrAdmission
	}
	return result, nil
}
