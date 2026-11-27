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
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/registryclient"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// This original-job read remains separate from new push/login authority. The
// remote owner returns only public resolution metadata on authenticated SFCP.
func (r *Runtime) observeImageBuildPublication(ctx context.Context, spec imagebuild.JobSpec, target string) (registryclient.Resolution, error) {
	if spec.Cluster != r.controlPolicy.Cluster || spec.Scope.Root.Key != r.Identity.Public {
		return registryclient.Resolution{}, sfcp.ErrAdmission
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	q := control.ImageBuildPublicationQuery{Tenant: spec.Tenant, Job: spec.ID, Snapshot: spec.Digest(), Target: target}
	view, err := r.currentView(ctx)
	if err != nil || view.Local {
		return registryclient.Resolution{}, sfcp.ErrAdmission
	}
	read, err := r.controlPolicy.ImageBuildPublicationRead(view.State, r.Identity.Public, q)
	if err != nil {
		return registryclient.Resolution{}, err
	}
	var observation control.ImageBuildPublicationObservation
	if read.Run.Owner == r.Identity.Public {
		observation, err = r.imageBuildPublicationOwner(ctx, r.Identity.Public, q)
	} else {
		peer, ok := r.Mesh.Peer(sfcp.Identity(read.Run.Owner))
		if !ok || !peer.Member || peer.ID != read.Run.Spec.Node {
			return registryclient.Resolution{}, sfcp.ErrAdmission
		}
		raw, _ := json.Marshal(q)
		reply, cause := cluster.CallManagement(ctx, r.Mesh, r.Identity, r.controlPolicy.Cluster, peer, cluster.ManagementRequest{Method: "image-build-publication-owner", Input: raw})
		if cause != nil || reply.Code != "ok" {
			return registryclient.Resolution{}, sfcp.ErrAdmission
		}
		observation, err = schema.Decode[control.ImageBuildPublicationObservation](reply.Data)
	}
	if err != nil || !observation.Valid(q) || !control.SameRegistryReadRun(read.Run, observation.Read.Run) {
		return registryclient.Resolution{}, sfcp.ErrAdmission
	}
	latest, err := r.Engine().ReadAtLeast(ctx, observation.Read.Index)
	if err != nil || latest.State.ModuleEpoch() != observation.Read.Epoch {
		return registryclient.Resolution{}, sfcp.ErrAdmission
	}
	current, err := r.controlPolicy.ImageBuildPublicationRead(latest.State, r.Identity.Public, q)
	if err != nil || !control.SameRegistryReadRun(current.Run, observation.Read.Run) {
		return registryclient.Resolution{}, sfcp.ErrAdmission
	}
	if observation.Code != "OK" {
		return registryclient.Resolution{}, &registryclient.Error{Code: observation.Code}
	}
	return *observation.Result, nil
}

func (r *Runtime) imageBuildPublicationOwner(ctx context.Context, caller [32]byte, q control.ImageBuildPublicationQuery) (control.ImageBuildPublicationObservation, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	r.life.RLock()
	defer r.life.RUnlock()
	if r.closed || r.ctx.Err() != nil {
		return control.ImageBuildPublicationObservation{}, sfcp.ErrAdmission
	}
	view, err := r.currentView(ctx)
	if err != nil || view.Local {
		return control.ImageBuildPublicationObservation{}, sfcp.ErrAdmission
	}
	read, err := r.controlPolicy.ImageBuildPublicationRead(view.State, caller, q)
	if err != nil || read.Run.Owner != r.Identity.Public {
		return control.ImageBuildPublicationObservation{}, sfcp.ErrAdmission
	}
	named, err := reference.ParseNormalizedNamed(q.Target)
	if err != nil {
		return control.ImageBuildPublicationObservation{}, sfcp.ErrAdmission
	}
	tag, ok := named.(reference.Tagged)
	if !ok {
		return control.ImageBuildPublicationObservation{}, sfcp.ErrAdmission
	}
	data, cause := r.readRegistryManifest(ctx, read.Run, reference.Path(named), tag.Tag(), false)
	result := control.ImageBuildPublicationObservation{Schema: 1, Read: read, Code: "OK"}
	if cause != nil {
		result.Code = "UNAVAILABLE"
		if errors.Is(cause, oci.ErrNameUnknown) || errors.Is(cause, oci.ErrNotFound) {
			result.Code = "NOT_FOUND"
		}
	} else {
		resolved, err := registryclient.ResolveManifest(q.Target, data.ContentType, data.Body)
		if err != nil {
			result.Code = "UNAVAILABLE"
		} else {
			result.Result = &resolved
		}
	}
	// Do not hold registryMu across quorum. Revalidate the original run after
	// I/O so a replacement owner/namespace cannot be returned as original data.
	latest, err := r.currentView(ctx)
	if err != nil || latest.Local {
		return control.ImageBuildPublicationObservation{}, sfcp.ErrAdmission
	}
	current, err := r.controlPolicy.ImageBuildPublicationRead(latest.State, caller, q)
	if err != nil || !control.SameRegistryReadRun(read.Run, current.Run) {
		return control.ImageBuildPublicationObservation{}, sfcp.ErrAdmission
	}
	result.Read = current
	return result, nil
}
