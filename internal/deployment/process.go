// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"context"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/desired"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/workload"
	"slices"
	"strconv"
)

// ResolveProcess is the image adapter for the single-file service model.
// Native mounts require their own admitted/pinned adapter. Unsupported inputs
// are rejected here before inspecting/pulling, never silently dropped.
func (s ComposeService) ResolveProcess(ctx context.Context, docker *engine.Client, catalog access.Catalog, actor, tenant, node string, pull bool) (workload.Process, error) {
	return s.resolveProcess(ctx, docker, catalog, actor, tenant, node, pull, nil, 0, nil, nil)
}

// ResolveTaskProcess joins the exact single-file recipe to its public input
// reference. It resolves image configuration only; native Acquire still checks
// current authority and a synced local projection before create/start.
func (b Blueprint) ResolveTaskProcess(ctx context.Context, service string, bound Binding, ref workload.InputRef, catalog access.Catalog, docker *engine.Client, pull bool) (workload.Process, error) {
	s, ok := b.d.Input.Services[service]
	if !ok || !validBinding(bound) || bound.d.Cluster != b.d.Cluster || projectionReference(bound) != ref || docker == nil || docker.Owner != desired.Owner(b.d.Cluster, bound.d.Needs.Use.NodeKey) {
		return workload.Process{}, ErrInputs
	}
	want, err := b.Inputs(service, bound.d.Needs.Consumer, ref.Generation, bound.d.Needs.Use.RequesterKey)
	if err != nil || !sameNeeds(want, bound.d.Needs) {
		return workload.Process{}, ErrInputs
	}
	if s.Memory == "" {
		s.Memory = strconv.FormatUint(b.d.Nodes[s.Sfc.Node].DefaultMemory, 10)
	}
	var targets []string
	for _, f := range bound.d.Needs.Files {
		if f.Kind != "env" {
			targets = append(targets, f.Target)
		}
	}
	return s.resolveProcess(ctx, docker, catalog, b.d.Actor, b.d.Tenant, s.Sfc.Node, pull, targets, len(s.Sfc.SecretEnv), nil, nil)
}

func (s ComposeService) resolveProcess(ctx context.Context, docker *engine.Client, catalog access.Catalog, actor, tenant, node string, pull bool, secretTargets []string, secretEnvs int, mounts []workload.VolumeMount, resolver *workload.Resolver, credentials ...engine.RegistryAuth) (workload.Process, error) {
	if len(credentials) > 1 {
		return workload.Process{}, ErrInputs
	}
	var auth engine.RegistryAuth
	if len(credentials) == 1 {
		auth = credentials[0]
	}
	image, err := catalog.CheckImage(actor, tenant, node, s.Image)
	if err != nil {
		return workload.Process{}, err
	}
	if s.ReadOnly != nil && !*s.ReadOnly && !s.Standalone || len(s.CapDrop) > 0 && !slices.Equal(s.CapDrop, []string{"ALL"}) || len(s.SecurityOpt) > 0 && !slices.Equal(s.SecurityOpt, []string{"no-new-privileges:true"}) {
		return workload.Process{}, workload.ErrProcess
	}
	expected, err := s.resolverSpec()
	if err != nil || (expected == nil) != (resolver == nil) || expected != nil && (!slices.Equal(expected.Servers, resolver.Servers) || !slices.Equal(expected.Search, resolver.Search)) {
		return workload.Process{}, inputError("FEATURE_UNAVAILABLE", "unbound resolver inputs")
	}
	if docker == nil || len(s.Volumes) != len(mounts) || len(s.Secrets) != len(secretTargets) || len(s.Sfc.SecretEnv) != secretEnvs {
		return workload.Process{}, inputError("FEATURE_UNAVAILABLE", "service process inputs")
	}
	stop, err := engine.ParseStopPolicy(s.StopGracePeriod, s.StopSignal)
	if err != nil {
		return workload.Process{}, err
	}
	overrides := workload.ProcessOverrides{WorkingDir: s.WorkingDir, User: s.User, Environment: s.Environment}
	if stop != nil {
		overrides.StopSignal = stop.Signal
	}
	overrides.MountTargets = slices.Clone(secretTargets)
	for i, m := range mounts {
		if m.Target != s.Volumes[i].Target || m.Consumer.Writable == s.Volumes[i].ReadOnly {
			return workload.Process{}, ErrInputs
		}
		overrides.MountTargets = append(overrides.MountTargets, m.Target)
	}

	if len(s.Tmpfs) > 0 {
		memory, err := byteSize(s.Memory)
		if err != nil || memory == 0 {
			return workload.Process{}, workload.ErrTmpfs
		}
		mounts, err := s.TmpfsMounts(int64(memory))
		if err != nil {
			return workload.Process{}, err
		}
		for _, m := range mounts {
			overrides.MountTargets = append(overrides.MountTargets, m.Target)
		}
	}
	if s.Command != nil {
		v := slices.Clone([]string(*s.Command))
		overrides.Command = &v
	}
	if s.Entrypoint != nil {
		v := slices.Clone([]string(*s.Entrypoint))
		overrides.Entrypoint = &v
	}
	if h := s.Healthcheck; h != nil {
		converted, err := h.dockerConfig()
		if err != nil {
			return workload.Process{}, err
		}
		overrides.Healthcheck = converted
	}
	got, err := docker.ImageWithAuth(ctx, image.Reference, pull, auth)
	if err != nil {
		return workload.Process{}, err
	}
	if got.Config == nil || workload.CheckSecretImageMounts(got.Config.Volumes, secretTargets) != nil {
		return workload.Process{}, workload.ErrInputMount
	}
	return workload.ResolveImageProcess(got, overrides)
}
