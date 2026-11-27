// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/workload"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

func appCheckServices(p checker.TaskProgram, check checker.ResolvedCheck) []string {
	return p.AppCheckServices(check)
}

func (r *Runtime) appCheckTargets(v cluster.View, b deployment.Binding, task deployment.ObjectRef, p checker.TaskProgram, check checker.ResolvedCheck, status workload.ContainerStatus) ([]contract.Target, error) {
	if p.Service != p.Coordinator || len(r.Identity.Certificate.Certificate) == 0 {
		return nil, checker.ErrReference
	}
	apps, err := r.controlPolicy.Apps(v.State)
	if err != nil {
		return nil, err
	}
	u := b.Needs().Use
	e, ok := apps.Execution(u.Tenant, u.App)
	if !ok {
		return nil, checker.ErrReference
	}
	boot := sha256.Sum256(r.Identity.Certificate.Certificate[0])
	var targets []contract.Target
	now := uint64(time.Now().Unix())
	for _, service := range appCheckServices(p, check) {
		if !slices.Contains(p.Services, service) {
			return nil, checker.ErrReference
		}
		instances, err := e.Blueprint().ServiceInstances(service)
		if err != nil || len(instances) == 0 {
			return nil, checker.ErrReference
		}
		// The app-scope contract names logical services once. Bind each role
		// to its first explicitly declared instance; Task-scoped health still
		// inspects every instance independently.
		key := deployment.ResourceKey("task", u.Tenant, u.App, instances[0].ResourceID())
		s, ok := e.Stage(key)
		if !ok || s.Result == nil || s.Result.Code != state.Applied {
			return nil, checker.ErrReference
		}
		o := v.State.Object(key)
		goal, err := schema.Decode[deployment.GoalCommand]([]byte(o.Value))
		if err != nil || !o.Present || o.Generation != s.Result.Generation || o.Revision != s.Result.Revision || goal.Kind != "task" {
			return nil, checker.ErrReference
		}
		declaration, err := schema.Decode[deployment.ComposeService](goal.Config)
		if err != nil || declaration.LifecycleProgram == nil || declaration.LifecycleProgram.Program != p.Program || declaration.LifecycleProgram.Service != service {
			return nil, checker.ErrReference
		}
		instance, err := deployment.TaskInstanceForKey(u.Tenant, u.App, key, declaration)
		if err != nil || instance.Service != service || instance.Node != goal.Node {
			return nil, checker.ErrReference
		}
		target := contract.Target{Service: service, TaskKey: key, Generation: o.Generation, Revision: o.Revision, Owner: hex.EncodeToString(goal.Owner[:])}
		if service == p.Coordinator {
			if key != task.Key || o.Generation != task.Generation || o.Revision != task.Revision || goal.Owner != r.Identity.Public {
				return nil, checker.ErrReference
			}
			target.NativeID, target.StartedAt, target.OwnerBoot = status.NativeID, status.StartedAt, hex.EncodeToString(boot[:])
		} else {
			observed := s.Observation
			if !liveTargetObservation(observed, goal.Owner, o.Generation, o.Revision, now) {
				return nil, checker.ErrReference
			}
			target.NativeID, target.OwnerBoot = observed.Native, observed.OwnerBoot
			target.StartedAt = time.Unix(0, observed.StartedAt).UTC().Format(time.RFC3339Nano)
		}
		if _, err := parseAppInstance(target.StartedAt); err != nil {
			return nil, checker.ErrReference
		}
		targets = append(targets, target)
	}
	return targets, nil
}

func (r *Runtime) appCheckDefinition(v cluster.View, b deployment.Binding, task deployment.ObjectRef, p checker.TaskProgram, check checker.ResolvedCheck, status workload.ContainerStatus) (checker.Definition, error) {
	d, err := r.checkerDefinition(b, task, p, check, status)
	if err != nil {
		return d, err
	}
	d.Scope = ""
	d.Request.Targets, err = r.appCheckTargets(v, b, task, p, check, status)
	if err != nil {
		return d, err
	}
	return d, d.Validate()
}

func (r *Runtime) validateAppCheckTargets(ctx context.Context, b deployment.Binding, task deployment.ObjectRef, p checker.TaskProgram, check checker.ResolvedCheck, request contract.Request) error {
	v, err := r.Engine().Read(ctx, false)
	if err != nil {
		return err
	}
	local, err := r.workload.ProbeTarget(ctx, task.Key, task.Generation, task.Revision)
	if err != nil {
		return err
	}
	targets, err := r.appCheckTargets(v, b, task, p, check, local.Status)
	if err != nil {
		return err
	}
	if !slices.Equal(targets, request.Targets) {
		return checker.ErrStale
	}
	return nil
}

type appCheckProbe struct {
	*workload.ServiceProbe
	request    contract.Request
	localOwner string
	remote     checker.ProbeDispatch
	dependency func(context.Context, contract.DependencyProbe) (contract.DependencyResult, error)
}

func (p *appCheckProbe) Dependency(ctx context.Context, q contract.DependencyProbe) (contract.DependencyResult, error) {
	return p.dependency(ctx, q)
}

func appTargetDependency(target contract.Target, s deployment.StageRecord, condition string, now uint64) contract.DependencyResult {
	result := contract.DependencyResult{Status: contract.Unknown, Generation: target.Generation, Revision: target.Revision}
	o := s.Observation
	stamp, err := parseAppInstance(target.StartedAt)
	if err != nil || o == nil || o.Released || o.Native != target.NativeID || o.Generation != target.Generation || o.Revision != target.Revision || hex.EncodeToString(o.Owner[:]) != target.Owner || o.OwnerBoot != target.OwnerBoot || o.StartedAt != stamp || !o.Live(now) {
		return result
	}
	pass := false
	switch condition {
	case "service_started":
		pass = o.Applied
	case "service_healthy":
		pass = o.Healthy
	case "service_completed_successfully":
		pass = o.Applied && o.Exit != nil && o.Exit.Valid() && o.Exit.Code == 0
	default:
		return result
	}
	result.Status = contract.Fail
	if pass {
		result.Status = contract.Pass
	}
	return result
}

func (r *Runtime) appProbeDependency(ctx context.Context, b deployment.Binding, request contract.Request, q contract.DependencyProbe, authorize func(context.Context, string) error) (contract.DependencyResult, error) {
	if err := authorize(ctx, "dependency"); err != nil {
		return contract.DependencyResult{}, err
	}
	var target contract.Target
	for _, t := range request.Targets {
		if t.Service == q.Service {
			target = t
			break
		}
	}
	if target.TaskKey == "" {
		return contract.DependencyResult{}, checker.ErrContract
	}
	v, err := r.Engine().Read(ctx, false)
	if err != nil {
		return contract.DependencyResult{}, err
	}
	apps, err := r.controlPolicy.Apps(v.State)
	if err != nil {
		return contract.DependencyResult{}, err
	}
	u := b.Needs().Use
	e, ok := apps.Execution(u.Tenant, u.App)
	if !ok {
		return contract.DependencyResult{}, checker.ErrReference
	}
	s, ok := e.Stage(target.TaskKey)
	if !ok {
		return contract.DependencyResult{Status: contract.Unknown, Generation: target.Generation, Revision: target.Revision}, nil
	}
	return appTargetDependency(target, s, q.Condition, uint64(time.Now().Unix())), nil
}

// liveTargetObservation accepts a peer task's stored observation as a checker
// target. Liveness is the reducer's Expired mark, not the stored At: an
// unchanged task keeps its last fact time while renewals go over SFCP.
func liveTargetObservation(observed *deployment.Observation, owner [32]byte, generation, revision, now uint64) bool {
	return observed != nil && !observed.Released && observed.Owner == owner && observed.Generation == generation && observed.Revision == revision && observed.OwnerBoot != "" && observed.Live(now)
}
