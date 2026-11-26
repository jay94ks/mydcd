// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"io"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/registryclient"
	"github.com/jay94ks/mydcd/internal/userauth"
)

func (r *Runtime) currentImageBuildBaseContent(ctx context.Context, q control.ImageBuildBaseContentRead) error {
	view, err := r.currentView(ctx)
	if err != nil || view.Local {
		return mydcp.ErrAdmission
	}
	read, err := r.controlPolicy.CurrentImageBuildBaseContent(view.State, q, time.Now().Unix())
	if err != nil || read.Target.Owner != r.Identity.Public {
		return mydcp.ErrAdmission
	}
	if run := read.Target.Managed; run != nil {
		_, _, err = r.registryCurrent(ctx, *run)
		return err
	}
	if source := read.Target.External; source != nil {
		work, err := r.externalRegistryWork(ctx, *source)
		if err != nil || work.Inputs.ReadSet != read.Target.ExternalReadSet {
			return mydcp.ErrAdmission
		}
	}
	return nil
}

// Every SDK store remains attached to one original FrozenSource. Repository
// credentials are consumed by that source's owner, even for a local owner.
func (r *Runtime) readImageBuildBaseContent(ctx context.Context, spec imagebuild.JobSpec, source imagebuild.Source, query registryclient.GraphContentQuery, to io.Writer) (registryclient.ContentInfo, error) {
	view, err := r.currentView(ctx)
	if err != nil || view.Local || spec.Scope.Root.Key != r.Identity.Public || spec.Cluster != r.controlPolicy.Cluster {
		return registryclient.ContentInfo{}, mydcp.ErrAdmission
	}
	read, err := r.controlPolicy.ImageBuildBaseRead(view.State, r.Identity.Public, control.ImageBuildBaseQuery{Tenant: spec.Tenant, Job: spec.ID, Snapshot: spec.Digest(), Source: source, At: time.Now().Unix()})
	if err != nil {
		return registryclient.ContentInfo{}, err
	}
	q := control.ImageBuildBaseContentRead{Read: read, Query: query}
	if _, err := r.controlPolicy.CurrentImageBuildBaseContent(view.State, q, time.Now().Unix()); err != nil {
		return registryclient.ContentInfo{}, err
	}
	var info registryclient.ContentInfo
	if read.Target.Owner == r.Identity.Public {
		body, cause := r.openImageBuildBaseContent(ctx, q)
		if cause != nil {
			return info, cause
		}
		info, err = userauth.ReadImageContentSource(ctx, query.Selected(), body, to)
	} else {
		peer, ok := r.Mesh.Peer(mydcp.Identity(read.Target.Owner))
		if !ok || !peer.Member {
			return info, mydcp.ErrAdmission
		}
		client := userauth.Client{Mesh: r.Mesh, Self: r.Identity, Cluster: spec.Cluster}
		info, err = client.ReadImageBuildBaseContent(ctx, peer, q, to)
	}
	if err != nil {
		return info, err
	}
	view, err = r.currentView(ctx)
	if err != nil || view.Local {
		return info, mydcp.ErrAdmission
	}
	if _, err := r.controlPolicy.CurrentImageBuildBaseContent(view.State, q, time.Now().Unix()); err != nil {
		return info, err
	}
	return info, nil
}

func (r *Runtime) openImageBuildBaseContent(ctx context.Context, q control.ImageBuildBaseContentRead) (userauth.ImageContentSource, error) {
	if err := r.currentImageBuildBaseContent(ctx, q); err != nil {
		return userauth.ImageContentSource{}, err
	}
	return r.openImageContentTarget(ctx, q.Read.Target, q.Query, func(call context.Context) error { return r.currentImageBuildBaseContent(call, q) })
}
