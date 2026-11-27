// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"slices"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

// Only the already admitted run's same-node, service-scoped reads may use a
// local current view. The runner still checks quorum before source resolution
// and before accepting its result; its pre-execution check stays current. Exec, remote/app probes and
// shutdown keep their existing fresh authority edges.
func checkerProbeAuthorizer(request contract.Request, appScope bool, owner string, fresh, local func(context.Context, string) error) func(context.Context, string, contract.Target) error {
	targets := slices.Clone(request.Targets)
	return func(ctx context.Context, kind string, target contract.Target) error {
		if ctx == nil || ctx.Err() != nil || fresh == nil || local == nil || !slices.Contains(targets, target) || !appScope && len(targets) != 1 {
			return checker.ErrContract
		}
		if !appScope && request.Phase != contract.Shutdown && target.Owner == owner && (kind == "healthz" || kind == "connect" || kind == "file") {
			return local(ctx, kind)
		}
		return fresh(ctx, kind)
	}
}

// This revalidates current local policy; it cannot mint a provider/activation
// grant and its derived permit is never sent, cached or used for an effect.
func (r *Runtime) checkerLocalReadAuthority(ctx context.Context, binding deployment.Binding, task deployment.ObjectRef, program checker.TaskProgram, kind string) (checker.TenantPolicy, error) {
	if ctx == nil || ctx.Err() != nil || r.Engine() == nil {
		return checker.TenantPolicy{}, checker.ErrPreparation
	}
	view, err := r.Engine().Read(ctx, false)
	if err != nil {
		return checker.TenantPolicy{}, err
	}
	_, err = r.controlPolicy.AppBindingPermit(view.State, r.commandIdentity().Public, control.AppBindingRequest{Task: task, Digest: binding.Digest(), At: time.Now().Unix()})
	if err != nil {
		return checker.TenantPolicy{}, err
	}
	policy, err := r.checkerAuthorityView(view, binding, task, program, kind)
	if err == nil {
		err = ctx.Err()
	}
	return policy, err
}

// The source runner invokes this at source entry and result acceptance. No
// permission is retained between calls; resolve is private source validation
// under the SAME fresh authority/context, never a native effect or grant.
func checkerSourceAuthorizer(fresh, resolve func(context.Context) error) func(context.Context) error {
	return func(ctx context.Context) error {
		if ctx == nil || fresh == nil {
			return checker.ErrContract
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := fresh(ctx); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if resolve != nil {
			if err := resolve(ctx); err != nil {
				return err
			}
		}
		return ctx.Err()
	}
}
