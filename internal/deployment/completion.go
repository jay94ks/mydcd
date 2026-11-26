// SPDX-License-Identifier: Apache-2.0

package deployment

func dependencyCondition(name string) (Condition, error) {
	switch name {
	case "service_started":
		return Applied, nil
	case "service_healthy":
		return Healthy, nil
	case "service_completed_successfully":
		return Completed, nil
	default:
		return "", ErrInputs
	}
}

// Started is implied by either health or positive completion. Health and
// completion are different lifecycle phases, not a ranking of one condition.
func mergeDependencyCondition(a, b Condition) (Condition, error) {
	if a == b {
		return a, nil
	}
	if a == Applied && (b == Healthy || b == Completed) {
		return b, nil
	}
	if b == Applied && (a == Healthy || a == Completed) {
		return a, nil
	}
	return "", inputError("INCOMPATIBLE_DEPENDENCY", "lifecycle.depends_on")
}

// A provider used as a successful one-shot job completes with its exit fact,
// rather than requiring it to remain simultaneously alive and healthy.
func requireJobCompletion(steps map[string]Step) error {
	for _, s := range steps {
		for _, d := range s.Dependencies {
			if d.Condition != Completed {
				continue
			}
			provider, ok := steps[d.Key]
			if !ok || provider.Kind != "task" {
				return inputError("INVALID_DEPENDENCY", s.Key)
			}
			provider.Completion = Completed
			steps[d.Key] = provider
		}
	}
	return nil
}

func validCompletionSteps(steps []Step) bool {
	byKey := make(map[string]Step, len(steps))
	for _, s := range steps {
		if s.Completion == Completed && s.Kind != "task" {
			return false
		}
		byKey[s.Key] = s
	}
	for _, s := range steps {
		for _, d := range s.Dependencies {
			if d.Condition == Completed && (byKey[d.Key].Kind != "task" || byKey[d.Key].Completion != Completed) {
				return false
			}
		}
	}
	return true
}
