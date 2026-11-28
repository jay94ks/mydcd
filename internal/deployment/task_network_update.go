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
	_, ok := taskNetworkChange(claim, step)
	return ok
}

// TaskNetworkAttach is TaskNetworkRuntimeUpdate that only attaches networks:
// every original network stays. Detaching in place waits for the address
// release of the detached attachment (AttachmentClosed), so it is replaced.
func TaskNetworkAttach(claim Claim, step Step) bool {
	c, ok := taskNetworkChange(claim, step)
	return ok && !c.detaches
}

// taskNetworkChanges is what an in-place network update changes.
type taskNetworkChanges struct {
	tenant, app, node string
	changed           map[string]bool // attached or detached network names
	detaches          bool
}

// step reports whether dependency key is a Bridge, reference, TUN or DNS step
// of a network the update attaches or detaches.
func (c taskNetworkChanges) step(key string) bool {
	for name := range c.changed {
		for _, kind := range []string{"bridge", "network-ref", "tunnel", "dns"} {
			if key == ResourceKey(kind, c.tenant, c.app, name+"/"+c.node) {
				return true
			}
		}
	}
	return false
}

func taskNetworkChange(claim Claim, step Step) (taskNetworkChanges, bool) {
	fail := taskNetworkChanges{}
	if claim.Removed || claim.Retained || claim.Result.Code != state.Applied || claim.Step.Kind != "task" || step.Kind != "task" || claim.Step.Key != step.Key || claim.Step.Node != step.Node || claim.Step.Owner != step.Owner || !slices.Equal(claim.Step.Identity, step.Identity) {
		return fail, false
	}
	var original GoalCommand
	if json.Unmarshal([]byte(claim.Command.Value), &original) != nil {
		return fail, false
	}
	c, ok := taskNetworkGoalChange(original, step)
	if !ok {
		return fail, false
	}
	networkStep := func(d Dependency) bool { return c.step(d.Key) }
	others := func(deps []Dependency) []byte {
		rest := slices.DeleteFunc(slices.Clone(deps), networkStep)
		if len(rest) == 0 {
			rest = nil
		}
		return goal(rest)
	}
	if !bytes.Equal(others(claim.Step.Dependencies), others(step.Dependencies)) || !bytes.Equal(others(claim.Step.Activation), others(step.Activation)) {
		return fail, false
	}
	return c, true
}

// taskNetworkGoalChange is taskNetworkChange over the committed goal alone
// (no dependency check): the planner uses it like taskAliasOnly.
func taskNetworkGoalChange(original GoalCommand, step Step) (taskNetworkChanges, bool) {
	fail := taskNetworkChanges{}
	var before, after ComposeService
	if step.Kind != "task" || original.Kind != "task" || original.Node != step.Node || original.Owner != step.Owner || original.Lifecycle != nil || json.Unmarshal(original.Config, &before) != nil || json.Unmarshal(step.Goal, &after) != nil {
		return fail, false
	}
	if len(before.Networks) == 0 || len(after.Networks) == 0 || len(before.Volumes) != 0 || len(after.Volumes) != 0 {
		return fail, false
	}
	primary := slices.Min(slices.Collect(maps.Keys(before.Networks)))
	if slices.Min(slices.Collect(maps.Keys(after.Networks))) != primary {
		return fail, false
	}
	changed := map[string]bool{}
	for name, a := range before.Networks {
		b, kept := after.Networks[name]
		if !kept {
			changed[name] = true
			continue
		}
		if a.IPv4 != b.IPv4 || a.IPv6 != b.IPv6 {
			return fail, false
		}
	}
	for name := range after.Networks {
		if _, kept := before.Networks[name]; !kept {
			changed[name] = true
		}
	}
	if len(changed) == 0 {
		return fail, false // alias-only or no change: TaskAliasRuntimeUpdate or Keep
	}
	b, a := before, after
	b.Networks, a.Networks = nil, nil
	if !bytes.Equal(goal(b), goal(a)) {
		return fail, false
	}
	c := taskNetworkChanges{tenant: original.Tenant, app: original.App, node: step.Node, changed: changed}
	for name := range changed {
		if _, kept := after.Networks[name]; !kept {
			c.detaches = true
		}
	}
	return c, true
}
