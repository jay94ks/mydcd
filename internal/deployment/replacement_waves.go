// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"encoding/json"
	"slices"
)

// ReplacementWave is a read-only stop-set from the SAME lifetime closure as
// Inventory.Retire. Targets identify original claims, not native closure or a
// grant to start the next wave. A replacement needs positive retirement and
// fresh health before another node can be changed.
type ReplacementWave struct {
	Node    string
	Tasks   []string
	Targets []ObjectRef
}

type ReplacementPlan struct {
	Required    bool
	BlockedCode string `json:",omitempty"`
	Blocker     string `json:",omitempty"`
	Waves       []ReplacementWave
}

func (p ReplacementPlan) Valid(tenant, app string) bool {
	if !p.Required || !identifier(tenant) || !identifier(app) || len(p.Waves) > 128 {
		return false
	}
	if p.BlockedCode != "" {
		if len(p.Waves) != 0 {
			return false
		}
		switch p.BlockedCode {
		case "ORIGINAL_OPERATION_PENDING":
			return p.Blocker == "" || identifier(p.Blocker)
		case "ROLLING_DEPENDENCY_CONFLICT":
			_, err := ResourceIDFromKey("task", tenant, app, p.Blocker)
			return err == nil
		default:
			return false
		}
	}
	if p.Blocker != "" || len(p.Waves) == 0 {
		return false
	}
	nodes, sources := map[string]bool{}, map[string]bool{}
	for _, wave := range p.Waves {
		if !identifier(wave.Node) || nodes[wave.Node] || len(wave.Targets) == 0 || len(wave.Targets) > 1024 || len(wave.Tasks) > 128 || !slices.IsSorted(wave.Tasks) {
			return false
		}
		nodes[wave.Node] = true
		inWave := map[string]bool{}
		for index, ref := range wave.Targets {
			if ref.Generation == 0 || ref.Revision < ref.Generation || sources[ref.Key] || index > 0 && wave.Targets[index-1].Key >= ref.Key {
				return false
			}
			scoped := false
			for _, kind := range []string{"task", "inputs", "bridge", "tunnel", "network-ref", "dns", "route", "volume", "namespace", "registry", "delivery", "ingress"} {
				if _, err := ResourceIDFromKey(kind, tenant, app, ref.Key); err == nil {
					scoped = true
					break
				}
			}
			if !scoped || len(sources) >= 1024 {
				return false
			}
			sources[ref.Key], inWave[ref.Key] = true, true
		}
		for index, key := range wave.Tasks {
			if !inWave[key] || index > 0 && wave.Tasks[index-1] == key {
				return false
			}
			if _, err := ResourceIDFromKey("task", tenant, app, key); err != nil {
				return false
			}
		}
	}
	return true
}

// ReplacementPlan projects node-at-a-time replacement from accepted ownership
// and the target graph. It neither edits source nor fabricates an intermediate
// all-new app, allocation, stopped writer, or successful Task observation.
func (a Inventory) ReplacementPlan(b Blueprint, prune bool) (*ReplacementPlan, error) {
	return a.replacementPlan(b, prune, false)
}

// DeployReplacementPlan is ReplacementPlan for an explicit app deploy: an
// edited Task kept alone on its node (its command, image or environment
// changed) is replaced in one wave on that node too. Without this, Begin had
// no stop set for it and refused every such edit as TRANSITION_REQUIRED.
// CD and drain keep ReplacementPlan; their own transitions cover that case.
func (a Inventory) DeployReplacementPlan(b Blueprint, prune bool) (*ReplacementPlan, error) {
	return a.replacementPlan(b, prune, true)
}

func (a Inventory) replacementPlan(b Blueprint, prune, edits bool) (*ReplacementPlan, error) {
	changes, err := a.Changes(b, prune)
	if err != nil {
		return nil, err
	}
	steps := map[string]Step{}
	counts := map[string]int{}
	for _, step := range b.d.Steps {
		steps[step.Key] = step
		if step.Kind == "task" {
			var service ComposeService
			if json.Unmarshal(step.Goal, &service) != nil {
				return nil, ErrInputs
			}
			instance, err := TaskInstanceForKey(a.d.Tenant, a.d.App, step.Key, service)
			if err != nil {
				return nil, err
			}
			counts[instance.Service]++
		}
	}
	oldCounts := map[string]int{}
	for _, claim := range a.d.Claims {
		if claim.Removed || claim.Step.Kind != "task" {
			continue
		}
		var service ComposeService
		if json.Unmarshal(claim.Step.Goal, &service) != nil {
			return nil, ErrInputs
		}
		instance, err := TaskInstanceForKey(a.d.Tenant, a.d.App, claim.Step.Key, service)
		if err != nil {
			return nil, err
		}
		oldCounts[instance.Service]++
	}
	replacements := map[string]bool{}
	required := false
	for _, change := range changes {
		if change.Action != "Replace" && change.Action != "Remove" {
			continue
		}
		at := a.claim(change.Key)
		if at < 0 || a.d.Claims[at].Removed {
			return nil, ErrInputs
		}
		replacements[change.Key] = true
		claim := a.d.Claims[at]
		if claim.Step.Kind == "task" {
			var service ComposeService
			if json.Unmarshal(claim.Step.Goal, &service) != nil {
				return nil, ErrInputs
			}
			instance, err := TaskInstanceForKey(a.d.Tenant, a.d.App, change.Key, service)
			if err != nil {
				return nil, err
			}
			target, present := steps[change.Key]
			relocated := present && (target.Node != claim.Step.Node || target.Owner != claim.Step.Owner)
			edited := edits && present && change.Action == "Replace"
			required = required || b.StandaloneName() != "" || counts[instance.Service] > 1 || oldCounts[instance.Service] > 1 || relocated || edited
		}
	}
	if !required {
		return nil, nil
	}
	result := &ReplacementPlan{Required: true, Waves: []ReplacementWave{}}
	if a.d.Retirement != nil || a.pendingSubmission() {
		result.BlockedCode = "ORIGINAL_OPERATION_PENDING"
		return result, nil
	}
	if execution, exists := a.Execution(); exists && execution.Status() != "Succeeded" && execution.Status() != "Closed" {
		result.BlockedCode = "ORIGINAL_OPERATION_PENDING"
		result.Blocker = execution.ActiveOperation()
		return result, nil
	}
	// Declaration order is the wave order. Key sorting within a wave makes
	// its exact stop set stable independently of map or claim insertion order.
	var nodes []string
	for _, name := range mapKeys(b.d.Input.Services) {
		instances, err := b.ServiceInstances(name)
		if err != nil {
			return nil, err
		}
		changing := false
		for _, instance := range instances {
			changing = changing || replacements[ResourceKey("task", a.d.Tenant, a.d.App, instance.ResourceID())]
		}
		if !changing {
			continue
		}
		for _, instance := range instances {
			if !slices.Contains(nodes, instance.Node) {
				nodes = append(nodes, instance.Node)
			}
		}
	}
	groups := map[string][]string{}
	for _, key := range mapKeys(replacements) {
		claim := a.d.Claims[a.claim(key)]
		if claim.Step.Kind != "task" {
			continue
		}
		node := claim.Step.Node
		if target, exists := steps[key]; exists {
			node = target.Node
		}
		if !slices.Contains(nodes, node) {
			nodes = append(nodes, node)
		}
		groups[node] = append(groups[node], key)
	}
	// Task stop sets already include private inputs and listeners that bind
	// them. Add other explicitly changed roots only when no Task closure owns
	// that replacement. This avoids turning a listener's host into the owner
	// of every remote Task wave.
	covered := map[string]bool{}
	for _, node := range nodes {
		if len(groups[node]) == 0 {
			continue
		}
		closure, err := a.retirementSelection(groups[node], false)
		if err != nil {
			return nil, err
		}
		for key := range closure {
			covered[key] = true
		}
	}
	for _, key := range mapKeys(replacements) {
		if covered[key] {
			continue
		}
		claim := a.d.Claims[a.claim(key)]
		node := claim.Step.Node
		if target, exists := steps[key]; exists {
			node = target.Node
		}
		if node == "" {
			node = nodes[0]
		}
		if !slices.Contains(nodes, node) {
			nodes = append(nodes, node)
		}
		groups[node] = append(groups[node], key)
	}
	seen := map[string]bool{}
	for _, node := range nodes {
		if len(groups[node]) == 0 {
			continue
		}
		closure, err := a.retirementSelection(groups[node], false)
		if err != nil {
			return nil, err
		}
		wave := ReplacementWave{Node: node, Tasks: []string{}, Targets: []ObjectRef{}}
		for _, key := range mapKeys(closure) {
			if seen[key] {
				continue
			}
			claim := a.d.Claims[a.claim(key)]
			if claim.Step.Kind == "task" {
				ownerNode := claim.Step.Node
				if target, exists := steps[key]; exists {
					ownerNode = target.Node
				}
				if ownerNode != node {
					// A shared producer/depends_on edit requires several nodes to
					// stop at once. Do not label that unsafe closure a rolling update.
					result.BlockedCode, result.Blocker = "ROLLING_DEPENDENCY_CONFLICT", key
					result.Waves = nil
					return result, nil
				}
				wave.Tasks = append(wave.Tasks, key)
			}
			seen[key] = true
			wave.Targets = append(wave.Targets, ObjectRef{Key: key, Generation: claim.Result.Generation, Revision: claim.Result.Revision})
		}
		if len(wave.Targets) != 0 {
			result.Waves = append(result.Waves, wave)
		}
	}
	// A newly introduced startup edge must not deadlock the selected order
	// or consume an old replica's health as readiness for its new target.
	positions := map[string]int{}
	for index, wave := range result.Waves {
		positions[wave.Node] = index
	}
	for _, step := range b.d.Steps {
		at, ordered := positions[step.Node]
		if step.Kind != "task" || !ordered {
			continue
		}
		for _, dependency := range step.Dependencies {
			producer := steps[dependency.Key]
			later, scheduled := positions[producer.Node]
			if producer.Kind == "task" && scheduled && later > at && (replacements[producer.Key] || !producer.BasePresent) {
				result.BlockedCode, result.Blocker, result.Waves = "ROLLING_DEPENDENCY_CONFLICT", producer.Key, nil
				return result, nil
			}
		}
	}
	return result, nil
}
