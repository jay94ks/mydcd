// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/json"

	"github.com/jay94ks/mydcd/internal/workload"
)

// unchangedReservation credits only a current, exact owned goal whose explicit
// desired reservation is already in the node total. An update, stale dependency
// binding or unaccounted/unknown object must pay the full new reservation until
// a separately verified Drain/transition has actually released the old one.
func unchangedReservation(b Blueprint, ctx PlanningContext, s Step, need workload.Resources, steps map[string]Step) bool {
	o := ctx.Current[s.Key]
	if !o.Present || o.Revision == 0 || o.Generation == 0 || o.Generation > o.Revision || ctx.Reserved[s.Key] != need {
		return false
	}
	var g GoalCommand
	if json.Unmarshal([]byte(o.Value), &g) != nil || g.Schema != 1 || g.Cluster != b.d.Cluster || g.Tenant != b.d.Tenant || g.App != b.d.App || g.Deployment != b.d.Deployment || g.Kind != s.Kind || g.Node != s.Node || g.Owner != s.Owner || g.Lifecycle != nil || !bytes.Equal(goal(g.Activation), goal(s.Activation)) || !bytes.Equal(g.Config, s.Goal) || len(g.Dependencies) != len(s.Dependencies) {
		return false
	}
	for i, d := range s.Dependencies {
		ref := g.Dependencies[i]
		current := ctx.Current[d.Key]
		producer, ok := steps[d.Key]
		if !ok || ref.Key != d.Key || !current.Present || ref.Revision != current.Revision || ref.Generation != current.Generation {
			return false
		}
		var parent GoalCommand
		if json.Unmarshal([]byte(current.Value), &parent) != nil || parent.Schema != 1 || parent.Cluster != b.d.Cluster || parent.Tenant != b.d.Tenant || parent.App != b.d.App || parent.Deployment != b.d.Deployment || parent.Kind != producer.Kind || parent.Node != producer.Node || parent.Owner != producer.Owner || !bytes.Equal(parent.Config, producer.Goal) {
			return false
		}
	}
	return true
}
func validatePlanBudget(b Blueprint, ctx PlanningContext) error {
	steps := map[string]Step{}
	for _, s := range b.d.Steps {
		steps[s.Key] = s
	}
	additional := map[string]workload.Resources{}
	credited := map[string]workload.Resources{}
	for _, s := range b.d.Steps {
		if s.Kind != "task" && s.Kind != "registry" {
			continue
		}
		need, err := stepNeed(s)
		if err != nil {
			return err
		}
		n := ctx.Nodes[s.Node]
		if need.CPU == 0 || need.Memory == 0 || n.Used.CPU > n.Capacity.CPU || n.Used.Memory > n.Capacity.Memory {
			return inputError("RESOURCE_BUDGET_REQUIRED", s.Key)
		}
		if unchangedReservation(b, ctx, s, need, steps) || plannedCredit(b, ctx, s, need) {
			credit := credited[s.Node]
			if credit.CPU > n.Used.CPU || credit.Memory > n.Used.Memory || need.CPU > n.Used.CPU-credit.CPU || need.Memory > n.Used.Memory-credit.Memory {
				return inputError("RESERVATION_VIEW_CONFLICT", s.Key)
			}
			credit.CPU += need.CPU
			credit.Memory += need.Memory
			credited[s.Node] = credit
			continue
		}
		a := additional[s.Node]
		if a.CPU > n.Capacity.CPU-n.Used.CPU || a.Memory > n.Capacity.Memory-n.Used.Memory || need.CPU > n.Capacity.CPU-n.Used.CPU-a.CPU || need.Memory > n.Capacity.Memory-n.Used.Memory-a.Memory {
			return inputError("NODE_CAPACITY", s.Key)
		}
		a.CPU += need.CPU
		a.Memory += need.Memory
		additional[s.Node] = a
	}
	return nil
}
