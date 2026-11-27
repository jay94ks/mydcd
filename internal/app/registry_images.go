// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/imagesource"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/registry"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/workload"
)

// This path is used both while resolving the frozen image configuration and at
// the actual native image edge. No user session is refreshed or impersonated.
func (r *Runtime) appRegistryImagePermit(ctx context.Context, task deployment.ObjectRef, binding [32]byte, image string, configID ...string) (control.RegistryImagePermit, error) {
	q := control.RegistryImageRequest{AppBindingRequest: control.AppBindingRequest{Task: task, Digest: binding, At: time.Now().Unix()}, Image: image}
	if len(configID) > 1 {
		return control.RegistryImagePermit{}, deployment.ErrInputs
	}
	if len(configID) == 1 {
		q.ConfigID = configID[0]
	}
	raw, err := json.Marshal(q)
	if err != nil {
		return control.RegistryImagePermit{}, err
	}
	reply, err := r.appCall(ctx, "registry-image-permit", raw)
	if err != nil {
		return control.RegistryImagePermit{}, err
	}
	permit, err := schema.Decode[control.RegistryImagePermit](reply.Data)
	pinned, pinErr := access.PinImage(image)
	if err != nil || pinErr != nil || reply.Local || permit.Index == 0 || permit.Epoch == 0 || permit.Subject != (registry.TaskSubject{Task: task, Binding: binding, Node: r.Identity.Public, Image: pinned.Reference}) {
		return control.RegistryImagePermit{}, deployment.ErrInputs
	}
	view, err := r.Engine().ReadAtLeast(ctx, permit.Index)
	if err != nil || view.State.Index() < permit.Index || view.State.ModuleEpoch() != permit.Epoch {
		return control.RegistryImagePermit{}, deployment.ErrInputs
	}
	// Recheck against the same local immutable state after its quorum barrier.
	current, err := r.controlPolicy.RegistryImagePermit(view.State, r.Identity.Public, q)
	if err != nil || !sameRegistryImageAuthority(current, permit) {
		return control.RegistryImagePermit{}, deployment.ErrInputs
	}
	return permit, nil
}

func sameRegistryImageAuthority(a, b control.RegistryImagePermit) bool {
	if a.Subject != b.Subject || a.Epoch != b.Epoch || (a.Registry == nil) != (b.Registry == nil) || a.Registry != nil && *a.Registry != *b.Registry || (a.External == nil) != (b.External == nil) || a.External != nil && !imagesource.Equal(*a.External, *b.External) {
		return false
	}
	x, xe := json.Marshal(a.ExternalInputs)
	y, ye := json.Marshal(b.ExternalInputs)
	return xe == nil && ye == nil && bytes.Equal(x, y)
}

func (r *Runtime) appRegistryImageAuth(ctx context.Context, task deployment.ObjectRef, binding [32]byte, image string, configID ...string) (engine.RegistryAuth, error) {
	permit, err := r.appRegistryImagePermit(ctx, task, binding, image, configID...)
	if err != nil {
		return engine.RegistryAuth{}, err
	}
	pinned, err := access.PinImage(image)
	if err != nil {
		return engine.RegistryAuth{}, err
	}
	if permit.Registry == nil {
		return r.appExternalRegistryAuth(ctx, task, binding, image, permit)
	}
	spec := *permit.Registry
	if spec.Validate(r.controlPolicy.Cluster) != nil || spec.Authority != pinned.Registry {
		return engine.RegistryAuth{}, deployment.ErrInputs
	}
	now := time.Now().Unix()
	grant := registry.Grant{Cluster: r.controlPolicy.Cluster, Tenant: spec.Tenant, Registry: spec.ID, Authority: spec.Authority, Repository: pinned.Repository, Actions: []string{"pull"}, Subject: registry.Subject{Task: &permit.Subject}, IssuedAt: now, ExpiresAt: now + int64(spec.TokenSeconds)}
	credential, err := registry.IssueLogin(grant, r.Identity.Private)
	if err != nil {
		return engine.RegistryAuth{}, err
	}
	secret := credential.Bytes()
	defer clear(secret)
	return engine.NewRegistryAuth(spec.Authority, registry.TaskUsername, secret)
}

func (r *Runtime) appTaskImageAuthority(ctx context.Context, key string, op reconcile.Operation) (engine.RegistryAuth, error) {
	// The native edge additionally checks activation, exact resolved recipe,
	// original input projection, compiled checkers and restored writer readiness.
	if err := r.appTaskAuthority(ctx, key, op); err != nil {
		return engine.RegistryAuth{}, err
	}
	view, err := r.Engine().Read(ctx, false)
	if err != nil {
		return engine.RegistryAuth{}, err
	}
	apps, err := r.controlPolicy.Apps(view.State)
	if err != nil {
		return engine.RegistryAuth{}, err
	}
	spec, err := workload.DecodeContainer(op.Target.Spec)
	if err != nil {
		return engine.RegistryAuth{}, err
	}
	for _, b := range apps.Bindings().Live() {
		source, ok := apps.BindingSource(b.Digest())
		if ok && source.Task.Key == key && source.Task.Generation == op.Target.Generation {
			if spec.Process != nil {
				return r.appRegistryImageAuth(ctx, source.Task, b.Digest(), spec.Image, spec.Process.ImageID)
			}
			return r.appRegistryImageAuth(ctx, source.Task, b.Digest(), spec.Image)
		}
	}
	return engine.RegistryAuth{}, deployment.ErrInputs
}

func appTaskImage(s state.State, task deployment.ObjectRef) (string, error) {
	object := s.Object(task.Key)
	goal, err := schema.Decode[deployment.GoalCommand]([]byte(object.Value))
	if err != nil || !object.Present || object.Revision != task.Revision || object.Generation != task.Generation || goal.Kind != "task" {
		return "", deployment.ErrInputs
	}
	service, err := schema.Decode[deployment.ComposeService](goal.Config)
	if err != nil {
		return "", deployment.ErrInputs
	}
	return service.Image, nil
}
