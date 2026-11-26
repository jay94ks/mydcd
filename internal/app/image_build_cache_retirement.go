// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagebuild"
)

// collectTenantImageBuildCaches runs inside the existing tenant owner pass.
// No queue, new job, root borrow or user session is created. Ordinary policy,
// job and context deletion continues to retain reusable cache namespaces.
func (r *Runtime) collectTenantImageBuildCaches(ctx context.Context, s state.State, tenant string) error {
	native := r.imageBuildNative
	if native == nil {
		return nil // readonly stored census still protects a disabled adapter
	}
	activity, err := native.TenantActivity(tenant)
	if err != nil {
		return err
	}
	if activity.Resources != 0 || activity.Writers != 0 || activity.Flows != 0 {
		return nil // original finite workers must finish first
	}
	records, err := native.Records()
	if err != nil {
		return err
	}
	seen := map[[32]byte]bool{}
	for _, record := range records {
		spec := record.Spec
		cache := imagebuild.CacheIdentity(spec)
		if spec.Tenant != tenant || seen[cache] {
			continue
		}
		seen[cache] = true
		grant, err := r.controlPolicy.ImageBuildCacheRetirementGrant(s, r.Identity.Public, spec)
		if err != nil {
			return err
		}
		if err := r.retireImageBuildCache(ctx, native, grant); err != nil {
			return err
		}
	}
	return nil
}

// One original cache/root settlement, shared by the Runtime pass and actual
// RootManager adapter tests. No authority or replacement lease is manufactured.
func (r *Runtime) retireImageBuildCache(ctx context.Context, native *imagebuild.NativeJobs, grant imagebuild.NativeCacheRetirementGrant) error {
	spec := grant.Source
	hold, found, err := native.RootHold(spec, imagebuild.CacheRoot)
	if err != nil {
		return err
	}
	if !found {
		return nil // this source never planned or borrowed a cache root
	}
	if r.nodeRoots == nil {
		return imagebuild.ErrStorage
	}
	consumer, err := native.RootConsumer(spec, imagebuild.CacheRoot)
	if err != nil {
		return err
	}
	pin, held, err := r.nodeRoots.RecordedPin(spec.Scope.Root, consumer)
	if err != nil {
		return err
	}
	if held && (hold.Returned || hold.Lease.Token != 0 && hold.Lease != pin.Lease) || !held && hold.Lease.Token != 0 && !hold.Returning {
		return imagebuild.ErrStorage
	}
	if hold.Returned {
		return nil
	}
	fd := -1
	if held && !hold.Returning {
		pin, err = r.nodeRoots.OpenRecordedPin(spec.Scope.Root, consumer)
		if err != nil || pin.Directory == nil {
			if pin.Directory != nil {
				err = errors.Join(err, pin.Directory.Close())
			}
			return errors.Join(imagebuild.ErrStorage, err)
		}
		fd = pin.Directory.FD()
	}
	lease := hold.Lease
	if held {
		lease = pin.Lease
	}
	err = native.RetireTenantCache(ctx, grant, lease, fd)
	if pin.Directory != nil {
		err = errors.Join(err, pin.Directory.Close())
	}
	if err != nil {
		return err
	}
	if held {
		if err := r.nodeRoots.Return(pin); err != nil {
			return err
		}
	}
	if err := native.FinishCacheRetirement(grant); err != nil {
		return err
	}
	return nil
}
