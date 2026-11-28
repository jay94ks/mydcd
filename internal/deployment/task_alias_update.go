// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/json"
	"slices"

	"github.com/jay94ks/seafield/internal/cluster/state"
)

// TaskAliasRuntimeUpdate reports whether a Task's next goal differs from its
// committed original only in network aliases. Aliases never reach the engine:
// they are managed DNS names projected from the Task goal (control
// managedDNSRegistrations), and the container recipe has no alias field. So
// such a change needs no new generation, no native replacement and no engine
// network connect/disconnect. Any other difference, including the network
// set, fixed addresses, dependencies, identity or activation, returns false.
//
// It is a judgment input for Inventory.Changes, not a mutation grant.
func TaskAliasRuntimeUpdate(claim Claim, step Step) bool {
	if claim.Removed || claim.Retained || claim.Result.Code != state.Applied || claim.Step.Kind != "task" || step.Kind != "task" || claim.Step.Key != step.Key || claim.Step.Node != step.Node || claim.Step.Owner != step.Owner || !bytes.Equal(goal(claim.Step.Dependencies), goal(step.Dependencies)) || !slices.Equal(claim.Step.Identity, step.Identity) || !bytes.Equal(goal(claim.Step.Activation), goal(step.Activation)) {
		return false
	}
	var original GoalCommand
	var before, after ComposeService
	if json.Unmarshal([]byte(claim.Command.Value), &original) != nil || original.Kind != "task" || original.Node != step.Node || original.Owner != step.Owner || original.Lifecycle != nil || json.Unmarshal(original.Config, &before) != nil || json.Unmarshal(step.Goal, &after) != nil {
		return false
	}
	if bytes.Equal(goal(before), goal(after)) {
		return false // nothing changed: Keep, not an update
	}
	return bytes.Equal(goal(withoutAliases(before)), goal(withoutAliases(after)))
}

func withoutAliases(s ComposeService) ComposeService {
	if s.Networks == nil {
		return s
	}
	networks := make(map[string]Attachment, len(s.Networks))
	for name, a := range s.Networks {
		a.Aliases = nil
		networks[name] = a
	}
	s.Networks = networks
	return s
}
