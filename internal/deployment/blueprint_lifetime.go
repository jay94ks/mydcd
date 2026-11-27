// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"encoding/json"
	"slices"
)

// A task declaration must commit before private inputs can name its real
// generation. That identity edge is not a runtime ownership edge: the task
// consumes those inputs, so closure runs task -> inputs -> volume/namespace.
func validateLifetimes(steps []Step) error {
	byKey := map[string]Step{}
	for _, s := range steps {
		byKey[s.Key] = s
	}
	for _, s := range steps {
		if len(s.Identity) != 0 && s.Kind != "inputs" && s.Kind != "ingress" || len(s.Activation) != 0 && s.Kind != "task" {
			return inputError("INVALID_LIFETIME", s.Key)
		}
		if s.Kind == "ingress" && len(s.Identity) != 0 {
			var declaration IngressDeclaration
			if json.Unmarshal(s.Goal, &declaration) != nil || len(s.Identity) > 1024 || !slices.IsSorted(s.Identity) {
				return inputError("INVALID_INGRESS_IDENTITY", s.Key)
			}
			for at, key := range s.Identity {
				task, exists := byKey[key]
				var service ComposeService
				if !exists || task.Kind != "task" || at > 0 && s.Identity[at-1] == key || !slices.Contains(s.Dependencies, Dependency{key, Healthy}) || json.Unmarshal(task.Goal, &service) != nil || service.Sfc.Instance == nil || !ingressHasService(declaration, service.Sfc.Instance.Service) {
					return inputError("INVALID_INGRESS_IDENTITY", s.Key)
				}
			}
			for _, task := range steps {
				if task.Kind != "task" {
					continue
				}
				var service ComposeService
				if json.Unmarshal(task.Goal, &service) != nil || service.Sfc.Instance != nil && ingressHasService(declaration, service.Sfc.Instance.Service) && !slices.Contains(s.Identity, task.Key) {
					return inputError("INVALID_INGRESS_IDENTITY", s.Key)
				}
			}
		}
		if s.Kind == "inputs" {
			if len(s.Identity) != 1 || !slices.Contains(s.Dependencies, Dependency{s.Identity[0], Committed}) {
				return inputError("INVALID_INPUT_IDENTITY", s.Key)
			}
			task, ok := byKey[s.Identity[0]]
			if !ok || task.Kind != "task" || task.Node != s.Node || task.Owner != s.Owner || !slices.Contains(task.Activation, Dependency{s.Key, Applied}) {
				return inputError("INVALID_INPUT_ACTIVATION", s.Key)
			}
		}
		seen := map[string]bool{}
		for _, d := range s.Activation {
			input, ok := byKey[d.Key]
			if !ok || seen[d.Key] || d.Condition != Applied || input.Owner != s.Owner && input.Kind != "dns" || input.Node != s.Node {
				return inputError("INVALID_INPUT_ACTIVATION", s.Key)
			}
			seen[d.Key] = true
			if input.Kind == "dns" {
				var cfg DNSDeclaration
				if json.Unmarshal(input.Goal, &cfg) != nil || !cfg.Enabled || !slices.Contains(s.Dependencies, Dependency{input.Key, Committed}) {
					return inputError("INVALID_DNS_ACTIVATION", s.Key)
				}
			} else if input.Kind != "inputs" || len(input.Identity) != 1 || input.Identity[0] != s.Key {
				return inputError("INVALID_INPUT_ACTIVATION", s.Key)
			}
		}
	}
	lifetimes := map[string]Step{}
	for _, s := range steps {
		s.Dependencies = lifetimeDependencies(s)
		lifetimes[s.Key] = s
	}
	_, err := orderSteps(lifetimes)
	return err
}

func ingressIdentity(step Step, key string) bool {
	return step.Kind == "ingress" && slices.Contains(step.Identity, key)
}
