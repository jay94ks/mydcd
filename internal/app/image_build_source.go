// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"runtime"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/schema"
)

func (r *Runtime) checkImageBuildSource(ctx context.Context, read control.ImageBuildSourceRead) (control.ImageBuildSourceResult, error) {
	view, err := r.currentView(ctx)
	if err != nil || view.Local {
		return control.ImageBuildSourceResult{}, mydcp.ErrAdmission
	}
	current, err := r.controlPolicy.CurrentImageBuildSourceRead(view.State, read, time.Now().Unix())
	if err != nil {
		return control.ImageBuildSourceResult{}, err
	}
	if current.Spec.Root.Key == r.Identity.Public {
		return r.checkImageBuildSourceOwner(ctx, current)
	}
	peer, ok := r.Mesh.Peer(mydcp.Identity(current.Spec.Root.Key))
	if !ok || !peer.Member || peer.ID != current.Spec.Root.Node {
		return control.ImageBuildSourceResult{}, mydcp.ErrAdmission
	}
	raw, _ := json.Marshal(current)
	reply, err := cluster.CallManagement(ctx, r.Mesh, r.Identity, r.controlPolicy.Cluster, peer, cluster.ManagementRequest{Method: "image-build-source-owner", Input: raw})
	if err != nil || reply.Code != "ok" {
		return control.ImageBuildSourceResult{}, mydcp.ErrAdmission
	}
	out, err := schema.Decode[control.ImageBuildSourceResult](reply.Data)
	if err != nil || !out.Valid(current) {
		return control.ImageBuildSourceResult{}, mydcp.ErrAdmission
	}
	return out, nil
}
func (r *Runtime) checkImageBuildSourceOwner(ctx context.Context, read control.ImageBuildSourceRead) (control.ImageBuildSourceResult, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	current := func() (control.ImageBuildSourceRead, error) {
		view, err := r.currentView(ctx)
		if err != nil || view.Local {
			return control.ImageBuildSourceRead{}, mydcp.ErrAdmission
		}
		now, err := r.controlPolicy.CurrentImageBuildSourceRead(view.State, read, time.Now().Unix())
		if err != nil || now.Spec.Root.Key != r.Identity.Public {
			return control.ImageBuildSourceRead{}, mydcp.ErrAdmission
		}
		return now, nil
	}
	return r.inspectImageBuildSourceOwner(ctx, read, current)
}

// Manual source reads and accepted automatic contexts share the exact Git,
// Dockerfile and trust checker. Only the origin authorization differs.
func (r *Runtime) inspectImageBuildSourceOwner(ctx context.Context, read control.ImageBuildSourceRead, current func() (control.ImageBuildSourceRead, error)) (control.ImageBuildSourceResult, error) {
	read, err := current()
	if err != nil {
		return control.ImageBuildSourceResult{}, err
	}
	r.life.RLock()
	defer r.life.RUnlock()
	if r.closed || r.gitFetcher == nil || r.ctx.Err() != nil {
		return control.ImageBuildSourceResult{}, mydcp.ErrAdmission
	}
	out := control.ImageBuildSourceResult{Schema: 1, Context: read.Spec.ID, ContextRevision: read.ContextRevision, PolicyRevision: read.PolicyRevision, Epoch: read.Epoch, Code: "SOURCE_FETCH"}
	var access deployment.GitAccess
	source := read.Spec.Git
	if source.CredentialProfile != "" {
		p, ok := r.gitCredentials[read.Tenant+"/"+source.CredentialProfile]
		if !ok || p.Tenant != read.Tenant || p.Repository != source.Repository {
			return out, nil
		}
		access, err = installedGitAccess(p)
		if err != nil {
			return out, nil
		}
		defer clear(access.Password)
		defer clear(access.Username)
	}
	var tree imagebuild.Tree
	var bases []imagebuild.Source
	var contextErr error
	commit, err := r.gitFetcher.VisitRepository(ctx, read.Tenant, deployment.GitRepositoryRequest{Repository: source.Repository, Ref: source.Ref, Credential: source.CredentialProfile, Seconds: min(read.Policy.Seconds, 300)}, access, func(ctx context.Context, repo *git.Repository, commit string) error {
		var err error
		tree, err = imagebuild.WriteGitZIP(ctx, repo, commit, source.Path, read.Spec.Dockerfile, io.Discard, read.Policy.WorkspaceBytes)
		if err != nil {
			contextErr = err
			return err
		}
		for _, platform := range read.Spec.Platforms {
			plan, cause := imagebuild.AnalyzeDockerfile(tree.Dockerfile, imagebuild.DockerfileOptions{Platform: platform, BuildPlatform: runtime.GOOS + "/" + runtime.GOARCH, Arguments: read.Spec.Arguments})
			if cause != nil {
				contextErr = cause
				return cause
			}
			if len(bases)+len(plan.Sources) > imagebuild.MaxTreeEntries {
				contextErr = imagebuild.ErrInvalid
				return contextErr
			}
			bases = append(bases, plan.Sources...)
		}
		return nil
	})
	if err != nil {
		if errors.Is(contextErr, imagebuild.ErrInvalid) {
			out.Code = "INVALID_CONTEXT"
		}
	} else {
		view, cause := r.currentView(ctx)
		if cause != nil || view.Local {
			return control.ImageBuildSourceResult{}, mydcp.ErrAdmission
		}
		users, cause := r.controlPolicy.Catalog(view.State)
		if cause != nil {
			return control.ImageBuildSourceResult{}, cause
		}
		out.Code = "OK"
		for _, base := range bases {
			if _, cause := users.CheckImageTrust(read.Tenant, base.Reference); cause != nil {
				out.Code = "UNTRUSTED_BASE"
				break
			}
		}
		if out.Code == "OK" {
			out.Commit, out.Tree, out.Entries, out.ExpandedBytes, out.BaseSources = commit, tree.Digest(), uint32(len(tree.Entries)), tree.Bytes, uint32(len(bases))
		}
	}
	if _, err := current(); err != nil {
		return control.ImageBuildSourceResult{}, err
	}
	return out, nil
}
