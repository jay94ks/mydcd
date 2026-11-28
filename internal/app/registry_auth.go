// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"slices"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/registry"
	"github.com/jay94ks/seafield/internal/schema"
)

// The quorum work read fixes the server run, then the local immutable state
// must have caught up to that exact barrier before it supplies account policy.
func registryWorkMatchesRun(work control.RegistryWork, run control.RegistryRunRef, owner [32]byte) bool {
	active := work.Entry.Active
	return work.MayStart && active != nil && run.Owner == owner && active.Generation == run.Generation && active.SpecRevision == run.SpecRevision && active.Spec == run.Spec && active.Owner == owner && active.Consumer == run.Consumer && active.Budget.Generation == run.Budget.Generation && active.DefinitionDigest == run.DefinitionDigest && active.OriginDigest == run.OriginDigest
}

// registryWorkMismatch says which part of registryWorkMatchesRun failed.
func registryWorkMismatch(work control.RegistryWork, run control.RegistryRunRef, owner [32]byte, err error) string {
	active := work.Entry.Active
	switch {
	case err != nil:
		return "reply: " + err.Error()
	case !work.MayStart && work.Blocked != "":
		return work.Blocked
	case !work.MayStart:
		return "the leader does not allow it to start"
	case active == nil:
		return "no active run"
	case run.Owner != owner || active.Owner != owner:
		return "run owned by another node key"
	case active.Generation != run.Generation || active.SpecRevision != run.SpecRevision || active.Spec != run.Spec:
		return fmt.Sprintf("run generation/definition changed (active %d/%d, local %d/%d)", active.Generation, active.SpecRevision, run.Generation, run.SpecRevision)
	case active.Consumer != run.Consumer:
		return "volume consumer changed"
	case active.Budget.Generation != run.Budget.Generation:
		return "quota reservation changed"
	}
	return "definition or origin digest changed"
}

func (r *Runtime) registryCurrent(ctx context.Context, run control.RegistryRunRef) (state.State, control.Policy, error) {
	request := control.RegistryWorkRequest{RegistrySelection: control.RegistrySelection{Tenant: run.Spec.Tenant, ID: run.Spec.ID}, At: time.Now().Unix()}
	raw, _ := json.Marshal(request)
	reply, err := r.appCall(ctx, "registry-work", raw)
	if err != nil || reply.Local {
		log.Printf("registry %s/%s: registry-work not answered by the leader: %v", run.Spec.Tenant, run.Spec.ID, err)
		return state.State{}, control.Policy{}, registry.ErrUnavailable
	}
	work, err := schema.Decode[control.RegistryWork](reply.Data)
	if err != nil || !registryWorkMatchesRun(work, run, r.Identity.Public) {
		log.Printf("registry %s/%s: current registry work does not allow this run: %s", run.Spec.Tenant, run.Spec.ID, registryWorkMismatch(work, run, r.Identity.Public, err))
		return state.State{}, control.Policy{}, registry.ErrUnavailable
	}
	view, err := r.Engine().ReadAtLeast(ctx, work.Index)
	if err != nil || view.State.Index() < work.Index || view.State.ModuleEpoch() != work.Epoch {
		return state.State{}, control.Policy{}, registry.ErrUnavailable
	}
	p, err := r.controlPolicy.Current(view.State)
	if err != nil {
		return state.State{}, control.Policy{}, registry.ErrUnavailable
	}
	// A newer committed heartbeat may advance the registry root while the
	// same run/authority remains valid. Re-evaluate its actual current permit
	// at this at-least barrier; exact root equality is a mutation CAS contract.
	current, err := p.RegistryWork(view.State, r.Identity.Public, request)
	if err != nil || !registryWorkMatchesRun(current, run, r.Identity.Public) {
		log.Printf("registry %s/%s: local registry work does not allow this run: %s", run.Spec.Tenant, run.Spec.ID, registryWorkMismatch(current, run, r.Identity.Public, err))
		return state.State{}, control.Policy{}, registry.ErrUnavailable
	}
	return view.State, p, nil
}

func registrySubjectUser(subject registry.Subject) string {
	if subject.Session != nil {
		return subject.Session.User
	}
	return ""
}

// Current sessions authenticate HTTP clients. Accepted app grants are handled
// by their separate Task-bound Engine adapter, never accepted on this path.
func registrySubjectPermission(p control.Policy, c access.Catalog, subject registry.Subject, tenant, node string, permission registry.Permission, now int64) error {
	if subject.Session == nil {
		return registry.ErrUnauthorized
	}
	session := *subject.Session
	allowed := func(action access.Action, node string) bool {
		return c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), now, tenant, action, node) == nil
	}
	switch permission.Action {
	case "login", "pull":
		if allowed(access.Deploy, "") || allowed(access.ManageRegistry, node) {
			return nil
		}
	case "push":
		if c.OperationAllowed(session, "registry-push") == nil && allowed(access.ManageRegistry, node) {
			return nil
		}
	case "catalog":
		if allowed(access.ManageRegistry, node) {
			return nil
		}
	}
	return registry.ErrForbidden
}

func registryGrantCurrent(p control.Policy, s state.State, run control.RegistryRunRef, g registry.Grant, permission registry.Permission, now int64) error {
	if now < g.IssuedAt || now >= g.ExpiresAt {
		return registry.ErrUnauthorized
	}
	if !g.Matches(p.Cluster, run.Spec) || !g.Allows(permission.Repository, permission.Action) {
		return registry.ErrForbidden
	}
	members, err := p.Members(s)
	if err != nil || !members.MemberKey(g.Issuer) {
		return registry.ErrUnauthorized
	}
	catalog, err := p.Catalog(s)
	if err != nil {
		return registry.ErrUnavailable
	}
	if task := g.Subject.Task; task != nil {
		if permission.Action != "login" && permission.Action != "pull" {
			return registry.ErrForbidden
		}
		permit, err := p.RegistryImagePermit(s, task.Node, control.RegistryImageRequest{AppBindingRequest: control.AppBindingRequest{Task: task.Task, Digest: task.Binding, At: now}, Image: task.Image})
		if err != nil || permit.Subject != *task || permit.Registry == nil || *permit.Registry != run.Spec {
			return registry.ErrForbidden
		}
		return nil
	}
	if build := g.Subject.Build; build != nil {
		action := "pull"
		if build.Image == "" {
			action = "push"
		}
		permit, err := p.ImageBuildRegistryPermit(s, build.Node, control.ImageBuildRegistryRequest{Tenant: build.Tenant, Job: build.Job, Snapshot: build.Snapshot, Action: action, Image: build.Image, At: now})
		if err != nil || permit.Subject != *build || permit.Run.Spec != run.Spec || permit.Run.Generation != run.Generation || permission.Action != "login" && permission.Repository != permit.Repository {
			return registry.ErrForbidden
		}
		return nil
	}
	return registrySubjectPermission(p, catalog, g.Subject, run.Spec.Tenant, run.Spec.Node, permission, now)
}

func (r *Runtime) registryAuthorization(run control.RegistryRunRef, store *registry.Store) registry.Authorization {
	return registry.Authorization{
		Check: func(ctx context.Context, token string, permission registry.Permission) error {
			if r.registryFailed.Load() {
				return registry.ErrUnavailable
			}
			now := time.Now().Unix()
			grant, err := registry.ParseAccess(token, now)
			if err != nil {
				return err
			}
			current, p, err := r.registryCurrent(ctx, run)
			if err != nil {
				return err
			}
			if (grant.Subject.Task != nil || grant.Subject.Build != nil) && grant.Issuer != run.Owner {
				return registry.ErrUnauthorized
			}
			if err = registryGrantCurrent(p, current, run, grant, permission, time.Now().Unix()); err != nil {
				return err
			}
			if err = recordRegistryPushLease(ctx, store, grant, false, time.Now().Unix()); err != nil {
				return err
			}
			return nil
		},
		Token: func(ctx context.Context, q registry.TokenRequest) (registry.TokenResponse, error) {
			if r.registryFailed.Load() {
				return registry.TokenResponse{}, registry.ErrUnavailable
			}
			now := time.Now().Unix()
			grant, err := registry.ParseLogin(string(q.Secret), now)
			if err != nil || q.Service != run.Spec.Authority {
				return registry.TokenResponse{}, registry.ErrUnauthorized
			}
			repo, actions, err := registry.RequestedScope(q.Scope)
			if err != nil {
				return registry.TokenResponse{}, err
			}
			current, p, err := r.registryCurrent(ctx, run)
			if err != nil {
				return registry.TokenResponse{}, err
			}
			catalog, err := p.Catalog(current)
			if err != nil {
				return registry.TokenResponse{}, registry.ErrUnavailable
			}
			if build := grant.Subject.Build; build != nil {
				if q.Username != registry.BuildUsername || grant.Issuer != build.Node {
					return registry.TokenResponse{}, registry.ErrUnauthorized
				}
			} else if grant.Subject.Task != nil {
				if q.Username != registry.TaskUsername || grant.Issuer != grant.Subject.Task.Node {
					return registry.TokenResponse{}, registry.ErrUnauthorized
				}
			} else {
				user, known := catalog.User(registrySubjectUser(grant.Subject))
				if !known || user.Username != q.Username {
					return registry.TokenResponse{}, registry.ErrUnauthorized
				}
			}
			for _, action := range actions {
				if err = registryGrantCurrent(p, current, run, grant, registry.Permission{Repository: repo, Action: action}, time.Now().Unix()); err != nil {
					return registry.TokenResponse{}, err
				}
			}
			if slices.Contains(actions, "push") && p.RegistryPushAvailable(current, run.Spec) != nil {
				return registry.TokenResponse{}, registry.ErrUnavailable
			}
			grant.Repository, grant.Actions = repo, slices.Clone(actions)
			grant.IssuedAt = time.Now().Unix()
			grant.ExpiresAt = min(grant.ExpiresAt, grant.IssuedAt+int64(run.Spec.TokenSeconds))
			if err = recordRegistryPushLease(ctx, store, grant, true, time.Now().Unix()); err != nil {
				return registry.TokenResponse{}, err
			}
			response, err := registry.IssueAccess(grant, r.Identity.Private)
			if err != nil {
				return registry.TokenResponse{}, errors.Join(registry.ErrUnauthorized, err)
			}
			response.IssuedAt = time.Unix(grant.IssuedAt, 0).UTC().Format(time.RFC3339)
			return response, nil
		},
	}
}

// Current user/run/grant checks precede this adapter. The captured original
// Store is joined by Server.Close, avoiding registryMu inside an HTTP callback
// while quiesce holds that mutex and waits for the same request to finish.
func recordRegistryPushLease(ctx context.Context, store *registry.Store, grant registry.Grant, issuing bool, now int64) error {
	if !slices.Contains(grant.Actions, "push") {
		return nil
	}
	if store == nil {
		return registry.ErrUnavailable
	}
	if err := store.RegisterPushLease(ctx, grant.Repository, grant.IssuedAt, grant.ExpiresAt, now, issuing); err != nil {
		return registry.ErrUnavailable
	}
	return nil
}
