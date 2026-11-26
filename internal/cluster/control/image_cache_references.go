// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/json"
	"slices"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/imagecache"
)

// Submitted mutations contain GoalCommand; Blueprint.Step.Goal contains only
// its Config. Keep these actual input envelopes distinct at their adapters.
func cacheGoalImage(raw []byte) (string, error) {
	var goal deployment.GoalCommand
	var service deployment.ComposeService
	if json.Unmarshal(raw, &goal) != nil || goal.Schema != 1 || goal.Kind != "task" || json.Unmarshal(goal.Config, &service) != nil {
		return "", ErrCatalog
	}
	return imagecache.CanonicalReference(service.Image)
}

// Include accepted but not yet materialized tasks and unremoved older claims.
// A Docker-only list would otherwise delete images needed by pending Create.
func (p Policy) imageCacheReferences(s state.State, node string) ([]string, error) {
	rows, err := p.ImageReferences(s, "", node)
	if err != nil {
		return nil, err
	}
	refs := map[string]string{}
	for _, row := range rows {
		if row.Unknown {
			return nil, ErrAppSourceUnavailable
		}
		key := row.Task
		if key == "" {
			key = row.ID
		}
		refs[key+"\x00"+row.Image] = row.Image
	}
	keys := make([]string, 0, len(refs))
	for key := range refs {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, refs[key])
	}
	return result, nil
}
func cacheReferenceCount(image imagecache.Image, refs []string) uint64 {
	var count uint64
	for _, ref := range refs {
		if image.Matches(ref) {
			count++
		}
	}
	return count
}

// Pending exact aliases are a temporary admission fence. Existing consumers
// cannot enter the delete plan; new app/CD/build intents cannot race its IO.
func (p Policy) imageCacheAvailable(s state.State, node, ref string) error {
	if err := p.registryMaintenanceImageAvailable(s, ref); err != nil {
		return err
	}
	jobs, err := p.ImageCacheJobs(s)
	if err != nil {
		return err
	}
	for _, row := range jobs.Records {
		if row.Plan.Node != node || row.State != "queued" && row.State != "running" {
			continue
		}
		for _, image := range row.Plan.Images {
			if image.Matches(ref) {
				return access.ErrConflict
			}
		}
	}
	return nil
}
func (p Policy) imageCacheBlueprintAvailable(s state.State, plan deployment.Blueprint) error {
	for _, step := range plan.Steps() {
		if step.Kind != "task" {
			continue
		}
		var service deployment.ComposeService
		if json.Unmarshal(step.Goal, &service) != nil {
			return ErrCatalog
		}
		ref, err := imagecache.CanonicalReference(service.Image)
		if err != nil {
			return err
		}
		if err = p.imageCacheAvailable(s, step.Node, ref); err != nil {
			return err
		}
		if program := service.LifecycleProgram; program != nil {
			compiled := false
			for _, script := range program.Scripts {
				compiled = compiled || script.Compile
			}
			if compiled {
				for _, node := range program.Policy.Build.Nodes {
					if err := p.imageCacheAvailable(s, node, program.Policy.Build.Image); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}
