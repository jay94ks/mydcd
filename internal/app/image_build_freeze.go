// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"runtime"
	"slices"

	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// Only the immutable, sealed original is inspected. No missing archive/root
// journal is repaired, and closing these descriptors never returns its pin.
func (r *Runtime) imageBuildDockerfile(ctx context.Context, spec imagebuild.JobSpec) (body []byte, failure error) {
	r.life.RLock()
	defer r.life.RUnlock()
	if r.closed || r.ctx.Err() != nil || r.nodeRoots == nil || r.reports == nil {
		return nil, sfcp.ErrAdmission
	}
	r.imageBuildMu.Lock()
	defer r.imageBuildMu.Unlock()
	grant, err := r.imageBuildAuthority(ctx, spec, true)
	if err != nil || !grant.Allowed {
		return nil, sfcp.ErrAdmission
	}
	pin, err := r.nodeRoots.OpenRecordedPin(spec.Scope.Root, buildArtifactConsumer(spec.Scope))
	if pin.Directory != nil {
		defer func() { failure = errors.Join(failure, pin.Directory.Close()) }()
	}
	if err != nil || pin.Directory == nil {
		return nil, errors.Join(imagebuild.ErrStorage, err)
	}
	spool, err := imagebuild.OpenExistingSpool(pin.Directory.FD(), spec.Scope.Root, r.reports)
	if err != nil {
		return nil, err
	}
	defer func() { failure = errors.Join(failure, spool.Close()) }()
	tree, err := spool.Inspect(ctx, spec.Scope, spec.Seal)
	if err != nil {
		return nil, err
	}
	return tree.Dockerfile, nil
}

// Every executable image dependency uses the reusable Dockerfile/FreezeSources
// core. Once begin fixes Inputs, recovery reuses those pins rather than asking
// a mutable tag for a different digest. No native BuildKit work starts here.
func (r *Runtime) freezeImageBuildInputs(ctx context.Context, spec imagebuild.JobSpec) ([]imagebuild.FrozenSource, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	grant, err := r.imageBuildAuthority(ctx, spec, true)
	if err != nil || !grant.Allowed {
		return nil, sfcp.ErrAdmission
	}
	if grant.Run.Phase != "queued" {
		return slices.Clone(grant.Run.Inputs), nil
	}
	body, err := r.imageBuildDockerfile(ctx, spec)
	if err != nil {
		return nil, err
	}
	var plans []imagebuild.DockerfilePlan
	count := 0
	for _, platform := range spec.Context.Platforms {
		plan, err := imagebuild.AnalyzeDockerfile(body, imagebuild.DockerfileOptions{Platform: platform, BuildPlatform: runtime.GOOS + "/" + runtime.GOARCH, Arguments: spec.Context.Arguments})
		if err != nil {
			return nil, err
		}
		count += len(plan.Sources)
		if count > 128 {
			return nil, imagebuild.ErrInvalid
		}
		plans = append(plans, plan)
	}
	resolved := map[string]string{}
	var inputs []imagebuild.FrozenSource
	for _, plan := range plans {
		frozen, err := imagebuild.FreezeSources(plan, func(source imagebuild.Source) (string, error) {
			// The resolver returns the root manifest/index, not a selected
			// platform child. Freeze a mutable tag once across target platforms.
			key := source.Reference
			if pinned, exists := resolved[key]; exists {
				return pinned, nil
			}
			pinned, err := r.resolveImageBuildBase(ctx, spec, source)
			if err == nil {
				resolved[key] = pinned
			}
			return pinned, err
		})
		if err != nil {
			return nil, err
		}
		inputs = append(inputs, frozen...)
	}
	if err := imagebuild.ValidateJobInputs(spec, inputs); err != nil {
		return nil, err
	}
	grant, err = r.imageBuildAuthority(ctx, spec, true)
	if err != nil || !grant.Allowed {
		return nil, sfcp.ErrAdmission
	}
	if grant.Run.Phase != "queued" {
		return slices.Clone(grant.Run.Inputs), nil
	}
	return inputs, nil
}
