// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"encoding/json"
	"reflect"
	"slices"
)

// validPlanTaskMetadata joins borrowed Volume and lifecycle metadata to the
// same decoded Task goal, including plans without fixed Volume registrations.
func validPlanTaskMetadata(d blueprintRecord) bool {
	if !validRegistrySources(d) {
		return false
	}
	var envServices []string
	for _, name := range mapKeys(d.Input.Services) {
		if len(d.Input.Services[name].Sfc.SecretEnv) != 0 {
			envServices = append(envServices, name)
		}
	}
	if !slices.Equal(envServices, d.SecretEnvRequiresNewGeneration) {
		return false
	}
	if len(d.FixedVolumes) > len(d.Input.Volumes) || !validCompletionSteps(d.Steps) {
		return false
	}
	seen := map[string]VolumeReference{}
	for alias, ref := range d.FixedVolumes {
		v, ok := d.Input.Volumes[alias]
		name := v.Name
		if name == "" {
			name = alias
		}
		node, present := d.Nodes[v.Sfc.Node]
		if !ok || !identifier(alias) || !fixedVolumePolicy(v) || !ref.Valid() || ref.Scope.Cluster != d.Cluster || ref.Scope.Tenant != d.Tenant || ref.Scope.ID != name || !present || node.Key != ref.Owner.Key || ref.Owner.Node != v.Sfc.Node {
			return false
		}
		if old, exists := seen[ref.Scope.Key()]; exists && old != ref {
			return false
		}
		seen[ref.Scope.Key()] = ref
	}
	for _, service := range d.Input.Services {
		if len(service.FixedVolumes) != 0 {
			return false
		}
	}
	expected, placementErr := planServicePlacements(d.Input, "")
	if placementErr != nil {
		return false
	}
	pending := map[string]TaskInstance{}
	for _, instances := range expected {
		for _, instance := range instances {
			pending[instance.ResourceID()] = instance
		}
	}
	for _, step := range d.Steps {
		if step.Kind != "task" {
			continue
		}
		var frozen ComposeService
		if json.Unmarshal(step.Goal, &frozen) != nil {
			return false
		}
		instance, identityErr := TaskInstanceForKey(d.Tenant, d.App, step.Key, frozen)
		if identityErr != nil || pending[instance.ResourceID()] != instance || frozen.Sfc.Node != step.Node || d.Nodes[step.Node].Key != step.Owner {
			return false
		}
		delete(pending, instance.ResourceID())
		service, ok := d.Input.Services[instance.Service]
		if !ok || !reflect.DeepEqual(frozen.FixedVolumes, taskVolumeReferences(service, d.FixedVolumes)) || !validTaskCheckers(d, instance.Service, service, frozen) {
			return false
		}
	}
	return len(pending) == 0
}
