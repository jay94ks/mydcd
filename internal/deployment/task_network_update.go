// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/json"
	"maps"
	"slices"

	"github.com/jay94ks/seafield/internal/cluster/state"
)

// TaskNetworkRuntimeUpdate reports whether a Task's next goal differs from
// its committed original only by attaching or detaching networks other than
// its first (primary) one. The container driver applies that in place with
// engine network connect/disconnect, under the same generation and native
// container (workload.DockerDriver.InPlace).
//
// Kept networks must be unchanged apart from aliases (same fixed addresses).
// The primary network, the rest of the service, its identity and its
// non-network dependencies must be equal. Dependencies and activations may
// differ only by the Bridge, reference, TUN and DNS steps of the networks
// that were attached or detached. Tasks with volumes are excluded, like the
// driver: their activation is granted per operation.
//
// It is a judgment input for Inventory.Changes, not a mutation grant.
func TaskNetworkRuntimeUpdate(claim Claim, step Step) bool {
	if claim.Removed || claim.Retained || claim.Result.Code != state.Applied || claim.Step.Kind != "task" || step.Kind != "task" || claim.Step.Key != step.Key || claim.Step.Node != step.Node || claim.Step.Owner != step.Owner || !slices.Equal(claim.Step.Identity, step.Identity) {
		return false
	}
	var original GoalCommand
	var before, after ComposeService
	if json.Unmarshal([]byte(claim.Command.Value), &original) != nil || original.Kind != "task" || original.Node != step.Node || original.Owner != step.Owner || original.Lifecycle != nil || json.Unmarshal(original.Config, &before) != nil || json.Unmarshal(step.Goal, &after) != nil {
		return false
	}
	if len(before.Networks) == 0 || len(after.Networks) == 0 || len(before.Volumes) != 0 || len(after.Volumes) != 0 {
		return false
	}
	primary := slices.Min(slices.Collect(maps.Keys(before.Networks)))
	if slices.Min(slices.Collect(maps.Keys(after.Networks))) != primary {
		return false
	}
	changed := map[string]bool{}
	for name, a := range before.Networks {
		b, kept := after.Networks[name]
		if !kept {
			changed[name] = true
			continue
		}
		if a.IPv4 != b.IPv4 || a.IPv6 != b.IPv6 {
			return false
		}
	}
	for name := range after.Networks {
		if _, kept := before.Networks[name]; !kept {
			changed[name] = true
		}
	}
	if len(changed) == 0 {
		return false // alias-only or no change: TaskAliasRuntimeUpdate or Keep
	}
	b, a := before, after
	b.Networks, a.Networks = nil, nil
	if !bytes.Equal(goal(b), goal(a)) {
		return false
	}
	networkStep := func(d Dependency) bool {
		for name := range changed {
			for _, kind := range []string{"bridge", "network-ref", "tunnel", "dns"} {
				if d.Key == ResourceKey(kind, original.Tenant, original.App, name+"/"+step.Node) {
					return true
				}
			}
		}
		return false
	}
	others := func(deps []Dependency) []byte {
		rest := slices.DeleteFunc(slices.Clone(deps), networkStep)
		if len(rest) == 0 {
			rest = nil
		}
		return goal(rest)
	}
	return bytes.Equal(others(claim.Step.Dependencies), others(step.Dependencies)) && bytes.Equal(others(claim.Step.Activation), others(step.Activation))
}
