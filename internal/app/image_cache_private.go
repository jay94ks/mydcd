// SPDX-License-Identifier: Apache-2.0

package app

import (
	"errors"

	"github.com/jay94ks/mydcd/internal/imagecache"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/workload"
)

// Private resolved Process IDs are authoritative even for untagged SDK loads.
// Callers serialize recipe resolution+Desired publication with imageUseMu;
// neither an absent RepoDigest nor a withdrawn public goal settles that recipe.
func (r *Runtime) privateImageReferences(id string) (uint64, error) {
	if !imagecache.ValidID(id) {
		return 0, imagecache.ErrPlan
	}
	if r.workload == nil {
		return 0, nil
	}
	var count uint64
	for _, key := range r.workload.Keys() {
		record, err := r.workload.View(key)
		if err != nil {
			return 0, errors.New("image cache private recipe unavailable")
		}
		uses, err := journalImageReferences(record, id)
		if err != nil {
			return 0, err
		}
		if uses {
			count++
		}
	}
	return count, nil
}

func journalImageReferences(record reconcile.Record, id string) (bool, error) {
	resources := []reconcile.Resource{record.State.Desired.Resource, record.State.Applied}
	if pending := record.State.Pending; pending != nil {
		resources = append(resources, pending.Target)
	}
	for _, resource := range resources {
		if !resource.Present {
			continue
		}
		spec, err := workload.DecodeContainer(resource.Spec)
		if err != nil {
			return false, errors.New("image cache private recipe invalid")
		}
		if spec.Process != nil && spec.Process.ImageID == id {
			return true, nil
		}
		if imagecache.ValidID(spec.Image) && spec.Image == id {
			return true, nil
		}
	}
	return false, nil
}
