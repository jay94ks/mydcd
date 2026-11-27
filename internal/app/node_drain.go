// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"slices"
)

func (r *Runtime) nodeDrainPlan(ctx context.Context, view cluster.View, session access.Session, at int64, q control.NodeDrainQuery) (control.NodeDrainPlan, error) {
	plan, err := r.controlPolicy.PlanNodeDrain(view.State, session, at, q)
	if err != nil {
		return plan, err
	}
	recipes := []control.VolumeMoveRecipe{}
	for _, ready := range plan.Needs {
		recipe, e := r.volumeMoveRecipe(ctx, ready)
		if e == nil {
			recipes = append(recipes, recipe)
		}
	}
	return r.controlPolicy.PlanNodeDrainWithRecipes(view.State, session, at, q, recipes)
}
func (r *Runtime) advanceNodeDrains(ctx context.Context) {
	view, d, err := r.members(ctx, false)
	if err != nil {
		return
	}
	registry, err := r.controlPolicy.Volumes(view.State)
	if err != nil {
		return
	}
	for _, row := range d.Drains {
		if row.Pending == 0 {
			continue
		}
		var plan control.NodeDrainPlan
		if json.Unmarshal(row.Plan, &plan) != nil {
			return
		}
		for _, job := range plan.Jobs {
			if job.Move == nil {
				continue
			}
			children := append([]control.NodeDrainVolumeMove{*job.Move}, job.AdditionalMoves...)
			for _, child := range children {
				if slices.Contains(row.Started, child.Begin.ID) {
					continue
				}
				busy := false
				for _, prior := range registry.Moves() {
					_, move, found := registry.Move(prior.Selection())
					sameGroup := prior.Origin.Change.Action == "drain-node" && bytes.Equal(prior.Origin.Signature, originalDrainSignature(row.Origin)) && prior.Binding.Scope.Tenant == job.Tenant && prior.Binding.Scope.App == job.App
					if found && move.Phase != "Completed" && move.Phase != "Cancelled" && !sameGroup && (prior.Binding.Source.Node == row.Node || prior.Binding.Target.Node == row.Node || prior.Binding.Source.Node == job.Target || prior.Binding.Target.Node == job.Target) {
						busy = true
						break
					}
				}
				if busy {
					continue
				}
				_ = r.memberReport(ctx, view, control.MemberReport{Action: "drain-move-start", Node: row.Node, Operation: row.Operation, DrainJob: child.Begin.ID, Expected: d.Revision})
				return
			}
		}

	}
}

func originalDrainSignature(raw json.RawMessage) []byte {
	var op control.UserOperation
	if json.Unmarshal(raw, &op) != nil {
		return nil
	}
	return op.Signature
}
