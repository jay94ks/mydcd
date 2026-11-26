// SPDX-License-Identifier: Apache-2.0

package app

import (
	"strings"

	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/nodestorage"
	"github.com/jay94ks/mydcd/internal/schema"
)

func buildInputRootConsumer(consumer string) bool {
	return strings.HasPrefix(consumer, "imagebuild-draft/") || strings.HasPrefix(consumer, "imagebuild-git/") || strings.HasPrefix(consumer, "imagebuild/") && !strings.HasPrefix(consumer, "imagebuild/job/") && !strings.HasPrefix(consumer, "imagebuild/cache/")
}

// Counts actual original input leases. Missing metadata is Unknown, not a
// lease attributed to every tenant or silently treated as already returned.
func (r *Runtime) tenantImageBuildInputActivity(tenant string) (lifecycle.Activity, error) {
	var activity lifecycle.Activity
	if r.nodeRoots == nil {
		return activity, nil // managed production nodes always open this owner
	}
	if r.reports == nil {
		return activity, imagebuild.ErrStorage
	}
	counted := map[string]bool{}
	count := func(root nodestorage.Reference, consumer string) error {
		digest := root.Digest()
		key := string(digest[:]) + consumer
		if counted[key] {
			return nil
		}
		var err error
		activity, err = activity.Add(lifecycle.Activity{Leases: 1})
		counted[key] = err == nil
		return err
	}
	for _, key := range r.nodeRoots.Keys() {
		record, err := r.nodeRoots.View(key)
		if err != nil {
			return activity, err
		}
		var inputs []string
		for consumer := range record.Consumers {
			if buildInputRootConsumer(consumer) {
				inputs = append(inputs, consumer)
			}
		}
		if len(inputs) == 0 {
			continue
		}
		if record.Checkpoint == nil {
			return activity, imagebuild.ErrStorage
		}
		root, err := schema.Decode[nodestorage.Reference]([]byte(record.Checkpoint.Target.Spec))
		if err != nil || root.Validate() != nil || nodestorage.RootNativeKey(root) != key {
			return activity, imagebuild.ErrStorage
		}
		owners, err := imagebuild.StoredInputRootOwners(r.reports, root)
		if err != nil {
			return activity, err
		}
		for _, consumer := range inputs {
			pin, held, err := r.nodeRoots.RecordedPin(root, consumer)
			if err != nil {
				return activity, err
			}
			if !held {
				continue
			}
			owner, known := owners[consumer]
			if !known || pin.Lease != record.Consumers[consumer] {
				return activity, imagebuild.ErrStorage
			}
			if owner.Tenant == tenant {
				if err := count(root, consumer); err != nil {
					return activity, err
				}
			}
		}
	}
	// Also inspect original allocations whose lease disappeared. Iterating only
	// current RootManager consumers would silently omit a lost known dependency.
	roots, err := imagebuild.StoredInputRoots(r.reports)
	if err != nil {
		return activity, err
	}
	for _, root := range roots {
		owners, err := imagebuild.StoredInputRootOwners(r.reports, root)
		if err != nil {
			return activity, err
		}
		for consumer, owner := range owners {
			if owner.Tenant != tenant || !owner.Required && !owner.Pending {
				continue
			}
			_, held, err := r.nodeRoots.RecordedPin(root, consumer)
			if err != nil || !held && owner.Required {
				return activity, imagebuild.ErrStorage
			}
			if err := count(root, consumer); err != nil {
				return activity, err
			}
		}
	}
	return activity, nil
}
