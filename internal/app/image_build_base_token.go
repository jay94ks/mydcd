// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/registry"
	"github.com/jay94ks/mydcd/internal/registryclient"
	"github.com/jay94ks/mydcd/internal/schema"
)

func (r *Runtime) currentImageBuildBaseToken(ctx context.Context, q control.ImageBuildBaseTokenRequest) (control.ImageBuildBaseRead, error) {
	view, err := r.currentView(ctx)
	if err != nil || view.Local {
		return control.ImageBuildBaseRead{}, mydcp.ErrAdmission
	}
	return r.controlPolicy.CurrentImageBuildBaseToken(view.State, q, time.Now().Unix())
}

func (r *Runtime) imageBuildBaseTokenOwner(ctx context.Context, q control.ImageBuildBaseTokenRequest) (registryclient.PullToken, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	read, err := r.currentImageBuildBaseToken(ctx, q)
	if err != nil || read.Target.Owner != r.Identity.Public || read.Target.Managed != nil {
		return registryclient.PullToken{}, mydcp.ErrAdmission
	}
	var client *registryclient.Access
	if read.Target.External != nil {
		work, err := r.externalRegistryWork(ctx, *read.Target.External)
		if err != nil || work.Inputs.ReadSet != read.Target.ExternalReadSet {
			return registryclient.PullToken{}, mydcp.ErrAdmission
		}
		release, err := r.acquireExternalReader(work)
		if err != nil {
			return registryclient.PullToken{}, err
		}
		defer release()
		client, err = r.sourceRegistryClient(ctx, work)
		if err != nil {
			return registryclient.PullToken{}, registryclient.Sanitize(err)
		}
	} else {
		_, authority, _, err := registryclient.Normalize(read.Target.Normalized)
		if err != nil {
			return registryclient.PullToken{}, mydcp.ErrAdmission
		}
		client, err = registryclient.New(authority, nil, nil, nil)
		if err != nil {
			return registryclient.PullToken{}, err
		}
	}
	defer client.Close()
	token, err := client.FetchPullTokenForImages(ctx, q.References(), q.Challenge)
	if err != nil {
		return registryclient.PullToken{}, registryclient.Sanitize(err)
	}
	if _, err := r.currentImageBuildBaseToken(ctx, q); err != nil {
		return registryclient.PullToken{}, mydcp.ErrAdmission
	}
	return token, nil
}

// The session consumes exact original sources, never a host-wide credential
// lookup. One fresh state barrier supplies this bounded set of work grants.
func (r *Runtime) imageBuildBasePullToken(ctx context.Context, spec imagebuild.JobSpec, sources []imagebuild.Source, challenge registryclient.PullTokenChallenge) (registryclient.PullToken, error) {
	if spec.Validate() != nil || spec.Cluster != r.controlPolicy.Cluster || spec.Scope.Root.Key != r.Identity.Public || len(sources) == 0 || len(sources) > 8 {
		return registryclient.PullToken{}, mydcp.ErrAdmission
	}
	view, err := r.currentView(ctx)
	if err != nil || view.Local {
		return registryclient.PullToken{}, mydcp.ErrAdmission
	}
	var reads []control.ImageBuildBaseRead
	for _, source := range sources {
		read, err := r.controlPolicy.ImageBuildBaseRead(view.State, r.Identity.Public, control.ImageBuildBaseQuery{Tenant: spec.Tenant, Job: spec.ID, Snapshot: spec.Digest(), Source: source, At: time.Now().Unix()})
		if err != nil {
			return registryclient.PullToken{}, err
		}
		reads = append(reads, read)
	}
	read := reads[0]
	q := control.ImageBuildBaseTokenRequest{Read: read, Challenge: challenge, Additional: reads[1:]}
	if _, err := r.currentImageBuildBaseToken(ctx, q); err != nil {
		return registryclient.PullToken{}, err
	}
	var token registryclient.PullToken
	if read.Target.Managed != nil {
		permit, credential, err := r.imageBuildRegistryLogin(ctx, spec, "pull", read.Target.Normalized)
		if err != nil {
			return registryclient.PullToken{}, err
		}
		defer clear(credential)
		trust, err := r.imageBuildRegistryTrust(ctx, permit)
		if err != nil {
			return registryclient.PullToken{}, err
		}
		ca, err := trust.PEM()
		if err != nil {
			return registryclient.PullToken{}, err
		}
		client, err := registryclient.New(permit.Run.Spec.Authority, []byte(registry.BuildUsername), credential, ca)
		if err != nil {
			return registryclient.PullToken{}, err
		}
		defer client.Close()
		token, err = client.FetchPullToken(ctx, read.Target.Normalized, challenge)
		if err != nil {
			return registryclient.PullToken{}, err
		}
	} else if read.Target.Owner == r.Identity.Public {
		token, err = r.imageBuildBaseTokenOwner(ctx, q)
	} else {
		peer, known := r.Mesh.Peer(mydcp.Identity(read.Target.Owner))
		if !known || !peer.Member {
			return registryclient.PullToken{}, mydcp.ErrAdmission
		}
		raw, _ := json.Marshal(q)
		reply, cause := cluster.CallManagement(ctx, r.Mesh, r.Identity, spec.Cluster, peer, cluster.ManagementRequest{Method: "image-build-base-token-owner", Input: raw})
		if cause != nil || reply.Code != "ok" {
			return registryclient.PullToken{}, mydcp.ErrAdmission
		}
		token, err = schema.Decode[registryclient.PullToken](reply.Data)
	}
	if err != nil || !token.Valid() {
		return registryclient.PullToken{}, mydcp.ErrAdmission
	}
	if _, err := r.currentImageBuildBaseToken(ctx, q); err != nil {
		return registryclient.PullToken{}, mydcp.ErrAdmission
	}
	remaining := int64(spec.CreatedAt+spec.Policy.Seconds) - token.IssuedAt
	token.ExpiresIn = min(token.ExpiresIn, remaining)
	if !token.Valid() || time.Now().Unix() >= token.IssuedAt+token.ExpiresIn {
		return registryclient.PullToken{}, mydcp.ErrAdmission
	}
	return token, nil
}

func (r *Runtime) imageBuildSessionAuth(ctx context.Context, spec imagebuild.JobSpec) (*imagebuild.BuildKitPullAuth, error) {
	work, err := r.imageBuildJobWork(ctx, spec)
	if err != nil || !work.Allowed || work.Run.Phase != "running" && work.Run.Phase != "unknown" {
		return nil, mydcp.ErrAdmission
	}
	authorize := func(ctx context.Context) error {
		current, err := r.imageBuildJobWork(ctx, spec)
		if err != nil || !current.Allowed || current.Run.Phase != "running" && current.Run.Phase != "unknown" {
			return mydcp.ErrAdmission
		}
		return nil
	}
	fetch := func(ctx context.Context, sources []imagebuild.Source, challenge registryclient.PullTokenChallenge) (registryclient.PullToken, error) {
		return r.imageBuildBasePullToken(ctx, spec, sources, challenge)
	}
	read := func(ctx context.Context, source imagebuild.Source, query registryclient.GraphContentQuery, to io.Writer) (registryclient.ContentInfo, error) {
		return r.readImageBuildBaseContent(ctx, spec, source, query, to)
	}
	return imagebuild.NewBuildKitSourceAuth(spec, work.Run.Inputs, authorize, fetch, read)
}
