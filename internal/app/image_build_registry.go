// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/registry"
	"github.com/jay94ks/seafield/internal/registryclient"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
)

func (r *Runtime) imageBuildRegistryPermit(ctx context.Context, spec imagebuild.JobSpec, action, image string) (control.ImageBuildRegistryPermit, error) {
	if spec.Validate() != nil || spec.Cluster != r.controlPolicy.Cluster || spec.Scope.Root.Key != r.Identity.Public {
		return control.ImageBuildRegistryPermit{}, sfcp.ErrAdmission
	}
	q := control.ImageBuildRegistryRequest{Tenant: spec.Tenant, Job: spec.ID, Snapshot: spec.Digest(), Action: action, Image: image, At: time.Now().Unix()}
	raw, _ := json.Marshal(q)
	reply, err := r.appCall(ctx, "image-build-registry-permit", raw)
	if err != nil || reply.Local {
		return control.ImageBuildRegistryPermit{}, sfcp.ErrAdmission
	}
	permit, err := schema.Decode[control.ImageBuildRegistryPermit](reply.Data)
	want := registry.BuildSubject{Tenant: q.Tenant, Job: q.Job, Snapshot: q.Snapshot, Node: r.Identity.Public, Image: q.Image}
	if err != nil || permit.Subject != want || permit.Index == 0 || permit.Epoch == 0 || permit.Run.Spec.Tenant != spec.Tenant || permit.Run.Spec.Validate(spec.Cluster) != nil {
		return control.ImageBuildRegistryPermit{}, sfcp.ErrAdmission
	}
	view, err := r.Engine().ReadAtLeast(ctx, permit.Index)
	if err != nil || view.State.ModuleEpoch() != permit.Epoch {
		return control.ImageBuildRegistryPermit{}, sfcp.ErrAdmission
	}
	q.At = time.Now().Unix()
	current, err := r.controlPolicy.ImageBuildRegistryPermit(view.State, r.Identity.Public, q)
	if err != nil || current.Subject != permit.Subject || current.Run.Spec != permit.Run.Spec || current.Run.Generation != permit.Run.Generation || current.Run.Owner != permit.Run.Owner || current.Repository != permit.Repository {
		return control.ImageBuildRegistryPermit{}, sfcp.ErrAdmission
	}
	return current, nil
}

// The result is transient authority-scoped input, never a logged/stringified
// job field. The real native caller still owns closure and token expiry.
func (r *Runtime) managedImageBuildAuth(ctx context.Context, spec imagebuild.JobSpec, action, image string) (engine.RegistryAuth, error) {
	authority, secret, err := r.imageBuildRegistryCredential(ctx, spec, action, image)
	if err != nil {
		return engine.RegistryAuth{}, err
	}
	defer clear(secret)
	return engine.NewRegistryAuth(authority, registry.BuildUsername, secret)
}

// The daemon's OCI publisher uses the same current BuildSubject login grant,
// on its own explicit HTTPS client. It never borrows Docker's ambient auth or
// changes OS/Engine trust. Its explicit public serving chain is verified against the accepted run.
func (r *Runtime) imageBuildRegistryClient(ctx context.Context, spec imagebuild.JobSpec) (*registryclient.Access, error) {
	permit, secret, err := r.imageBuildRegistryLogin(ctx, spec, "push", "")
	if err != nil {
		return nil, err
	}
	defer clear(secret)
	trust, err := r.imageBuildRegistryTrust(ctx, permit)
	if err != nil {
		return nil, err
	}
	ca, err := trust.PEM()
	if err != nil {
		return nil, err
	}
	return registryclient.New(permit.Run.Spec.Authority, []byte(registry.BuildUsername), secret, ca)
}

func (r *Runtime) imageBuildRegistryCredential(ctx context.Context, spec imagebuild.JobSpec, action, image string) (string, []byte, error) {
	permit, secret, err := r.imageBuildRegistryLogin(ctx, spec, action, image)
	return permit.Run.Spec.Authority, secret, err
}

func (r *Runtime) imageBuildRegistryLogin(ctx context.Context, spec imagebuild.JobSpec, action, image string) (control.ImageBuildRegistryPermit, []byte, error) {
	permit, err := r.imageBuildRegistryPermit(ctx, spec, action, image)
	if err != nil {
		return control.ImageBuildRegistryPermit{}, nil, err
	}
	repository := permit.Repository
	actions := []string{"pull", "push"}
	if action == "pull" {
		pin, err := access.PinImage(image)
		if err != nil {
			return control.ImageBuildRegistryPermit{}, nil, err
		}
		if pin.Repository != repository {
			return control.ImageBuildRegistryPermit{}, nil, sfcp.ErrAdmission
		}
		actions = []string{"pull"}
	}
	now := time.Now().Unix()
	grant := registry.Grant{Cluster: spec.Cluster, Tenant: spec.Tenant, Registry: permit.Run.Spec.ID, Authority: permit.Run.Spec.Authority, Repository: repository, Actions: actions, Subject: registry.Subject{Build: &permit.Subject}, IssuedAt: now, ExpiresAt: min(now+int64(permit.Run.Spec.TokenSeconds), int64(spec.CreatedAt+spec.Policy.Seconds))}
	credential, err := registry.IssueLogin(grant, r.Identity.Private)
	if err != nil {
		return control.ImageBuildRegistryPermit{}, nil, err
	}
	return permit, credential.Bytes(), nil
}
