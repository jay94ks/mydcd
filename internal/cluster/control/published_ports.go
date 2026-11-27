// SPDX-License-Identifier: Apache-2.0

package control

import (
	"slices"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/desired"
)

// projectPublishedPorts borrows the existing committed objects, claims and
// accepted plans. It retains original ports through drain/unknown, and holds
// an accepted replacement before its new native exists. No independent port
// authority, allocator, quota or native publication receipt is introduced.
func (p Policy) projectPublishedPorts(s state.State, result *ResourceProjection, apps Apps) error {
	var uses []deployment.HostPortUse
	admit := func(use deployment.HostPortUse) error {
		if len(use.Ports) == 0 {
			return nil
		}
		if err := deployment.CheckHostPortUses(uses, use); err != nil {
			return err
		}
		uses = append(uses, use)
		return nil
	}
	step := func(value deployment.Step) error {
		use, err := deployment.StepHostPortUse(value)
		if err != nil {
			return err
		}
		return admit(use)
	}
	plan := func(value deployment.Blueprint) error {
		for _, s := range value.Steps() {
			if err := step(s); err != nil {
				return err
			}
		}
		return nil
	}
	// The managed node's shared listener and direct app/standalone publishes
	// occupy the same host namespace. Shared app mappings add no extra use.
	gateways, err := p.nodeGatewayHostPortUses(s)
	if err != nil {
		return err
	}
	for _, use := range gateways {
		if err = admit(use); err != nil {
			return err
		}
	}
	for _, key := range desired.Sorted(result.Goals) {
		goal := result.Goals[key].Goal
		if goal.Lifecycle != nil && goal.Lifecycle.Released() {
			continue
		}
		if err := step(deployment.Step{Key: key, Kind: goal.Kind, Node: goal.Node, Owner: goal.Owner, Goal: goal.Config}); err != nil {
			return err
		}
	}
	keys := make([]string, 0, len(apps.entries))
	for key := range apps.entries {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		entry := apps.entries[key]
		for _, claim := range entry.Inventory.Claims() {
			if !claim.Removed {
				if err := step(claim.Step); err != nil {
					return err
				}
			}
		}
		if entry.Down != nil || entry.Standalone != nil && entry.Standalone.Cleanup != nil {
			continue
		}
		if execution, ok := entry.Inventory.Execution(); ok && execution.Status() != "Closed" {
			if err := plan(execution.Blueprint()); err != nil {
				return err
			}
		}
		if entry.PendingSync != nil && entry.PendingSync.Recreate != nil {
			b, err := deployment.DecodeBlueprint(entry.PendingSync.Recreate.Blueprint)
			if err != nil {
				return err
			}
			if err = plan(b); err != nil {
				return err
			}
		}
		if entry.Delivery != nil {
			if b, ok := entry.Delivery.TransitionPlan(); ok {
				if err := plan(b); err != nil {
					return err
				}
			}
		}
	}
	for _, hold := range result.MoveHolds {
		use := deployment.HostPortUse{Key: hold.Demand.Key, Node: hold.Demand.Node, Owner: hold.Demand.Owner, Ports: hold.Demand.Ports}
		if hold.Demand.Ingress != nil {
			raw, err := deployment.IngressHostPortUse(hold.Demand.Key, hold.Demand.Node, hold.Demand.Owner, *hold.Demand.Ingress)
			if err != nil {
				return err
			}
			use = raw
		}
		if err := admit(use); err != nil {
			return err
		}
	}
	result.HostPorts = uses
	return nil
}
