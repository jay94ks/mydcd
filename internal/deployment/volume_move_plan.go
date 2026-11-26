// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
	"strings"
)

func armedMove(current volumes.State, binding volumes.Binding) bool {
	owner, revision := current.Owner()
	m, ok := current.Move(binding.ID)
	return ok && current.Scope() == binding.Scope && m.Binding == binding && m.Irreversible && m.CommitRevision == revision && owner == binding.Target && m.Fence != nil && m.Verified != nil && (m.Phase == volumes.Activating || m.Phase == volumes.Active || m.Phase == volumes.Completed)
}

func committedVolumeGoal(old GoalCommand, next Step, current map[string]volumes.State) bool {
	if old.Kind != "volume" || next.Kind != "volume" {
		return false
	}
	key := old.Tenant + "/" + old.App + "/" + next.Key[strings.LastIndexByte(next.Key, '/')+1:]
	v, ok := current[key]
	if !ok || ResourceKey("volume", old.Tenant, old.App, v.Scope().ID) != next.Key {
		return false
	}
	for _, move := range v.Moves() {
		b := move.Binding
		if armedMove(v, b) && old.Node == b.Source.Node && old.Owner == b.Source.Key && next.Node == b.Target.Node && next.Owner == b.Target.Key {
			return true
		}
	}
	return false
}

func (a Inventory) retainedVolumeHandoff(old Claim, next Step, current map[string]volumes.State, binding volumes.Binding) bool {
	key := binding.Scope.Tenant + "/" + binding.Scope.App + "/" + binding.Scope.ID
	v, ok := current[key]
	proof := old.RetainProof
	return ok && armedMove(v, binding) && old.Step.Kind == "volume" && next.Kind == "volume" && old.Step.Key == next.Key && next.Key == ResourceKey("volume", binding.Scope.Tenant, binding.Scope.App, binding.Scope.ID) && !old.Removed && old.Retained && proof != nil && a.validRetain(old, *proof, proof.Retirement, proof.StopRevision) && proof.Native == binding.Source.Native && old.Step.Node == binding.Source.Node && old.Step.Owner == binding.Source.Key && next.Node == binding.Target.Node && next.Owner == binding.Target.Key
}

// Rebase changes only current CAS/readiness/usage metadata after positive
// retirement. The accepted declaration and node identities stay immutable.
func (b Blueprint) Rebase(policy access.Catalog, ctx PlanningContext) (Blueprint, error) {
	current, err := compile(b.d.Input, policy, ctx, nil, b.d.InputKind)
	if err != nil {
		return Blueprint{}, err
	}
	current.d.Document = b.OriginalDocument()
	if !validBlueprintDocument(current) || !sameDeliveryIntent(b, current) {
		return Blueprint{}, inputError("PLAN_CONFLICT", "rebase")
	}
	return current, nil
}

func (a Inventory) BeginMoved(expected uint64, c access.Catalog, ctx PlanningContext, b Blueprint, binding volumes.Binding, id, submitter string, epoch uint64) (Inventory, error) {
	if _, active := a.Execution(); active {
		return a, ErrInputs
	}
	found := false
	for _, step := range b.Steps() {
		if i := a.claim(step.Key); i >= 0 && a.retainedVolumeHandoff(a.d.Claims[i], step, ctx.Volumes, binding) {
			found = true
		}
	}
	if !found {
		return a, inputError("VOLUME_MOVE_CLOSURE_REQUIRED", binding.Scope.ID)
	}
	return a.begin(expected, c, ctx, b, id, submitter, epoch, false, []volumes.Binding{binding})
}

// VolumeMovePlacement describes a proposed placement, not an ownership grant.
// Only the preview compiler accepts it. NewExecution still uses Compile through
// ValidateCurrent and cannot dispatch this plan before the real owner changes.
type VolumeMovePlacement struct {
	Others              []VolumeMovePlacement `json:",omitempty"`
	Scope               volumes.Scope
	Source, Target      volumes.Owner
	SourceOwnerRevision uint64
}

func CompileVolumeMove(c Compose, policy access.Catalog, ctx PlanningContext, move VolumeMovePlacement) (Blueprint, error) {
	return compileVolumeMove(c, policy, ctx, move, "")
}

func CompileAppVolumeMove(c Compose, policy access.Catalog, ctx PlanningContext, move VolumeMovePlacement) (Blueprint, error) {
	return compileVolumeMove(c, policy, ctx, move, "app")
}

func compileVolumeMove(c Compose, policy access.Catalog, ctx PlanningContext, move VolumeMovePlacement, inputKind string) (Blueprint, error) {
	rows := volumeMovePlacements(move)
	if len(rows) == 0 || len(rows) > 128 {
		return Blueprint{}, ErrInputs
	}
	seen := map[string]bool{}
	for _, row := range rows {
		key := row.Scope.Tenant + "/" + row.Scope.App + "/" + row.Scope.ID
		original, ok := ctx.Volumes[key]
		owner, revision := original.Owner()
		if !ok || seen[key] || original.Scope() != row.Scope || row.Scope.Cluster != ctx.Cluster || row.Scope.Tenant != move.Scope.Tenant || row.Scope.App != move.Scope.App || owner != row.Source || revision != row.SourceOwnerRevision || row.Target.Node == "" || row.Target.Key == ([32]byte{}) || row.Target.Node == row.Source.Node || row.Target.Native == "" {
			return Blueprint{}, inputError("VOLUME_MOVE_SOURCE_CONFLICT", key)
		}
		seen[key] = true
	}

	b, err := compile(c, policy, ctx, &move, inputKind)
	if err != nil {
		return b, err
	}
	if b.d.Tenant != move.Scope.Tenant || b.d.App != move.Scope.App {
		return Blueprint{}, inputError("PLAN_SCOPE_CONFLICT", "move")
	}
	for _, row := range rows {
		found := false
		for _, step := range b.Steps() {
			if step.Key == ResourceKey("volume", row.Scope.Tenant, row.Scope.App, row.Scope.ID) && step.Node == row.Target.Node && step.Owner == row.Target.Key {
				found = true
				break
			}
		}
		if !found {
			return Blueprint{}, inputError("VOLUME_MOVE_TARGET_CONFLICT", row.Scope.ID)
		}
	}
	return b, nil

}

func (b Blueprint) ValidateVolumeMove(policy access.Catalog, ctx PlanningContext, move VolumeMovePlacement) error {
	if ctx.Cluster != b.d.Cluster || ctx.Actor != b.d.Actor || ctx.Tenant != "" && ctx.Tenant != b.d.Tenant || ctx.Project != "" && ctx.Project != b.d.App || ctx.Deployment != "" && ctx.Deployment != b.d.Deployment {
		return inputError("PLAN_SCOPE_CONFLICT", "move")
	}
	current, err := compileVolumeMove(b.d.Input, policy, ctx, move, b.d.InputKind)
	if err != nil {
		return err
	}
	current.d.Document = b.OriginalDocument()
	if !validBlueprintDocument(current) || !sameDeliveryIntent(b, current) {
		return inputError("PLAN_CONFLICT", "move")
	}
	return nil
}

func volumeMovePlacements(move VolumeMovePlacement) []VolumeMovePlacement {
	rows := []VolumeMovePlacement{move}
	for _, row := range move.Others {
		if len(row.Others) != 0 {
			return nil
		}
		rows = append(rows, row)
	}
	return rows
}
func selectedVolumeMove(move *VolumeMovePlacement, scope volumes.Scope) (VolumeMovePlacement, bool) {
	if move == nil {
		return VolumeMovePlacement{}, false
	}
	for _, row := range volumeMovePlacements(*move) {
		if row.Scope == scope {
			return row, true
		}
	}
	return VolumeMovePlacement{}, false
}
func (a Inventory) BeginMovedGroup(expected uint64, c access.Catalog, ctx PlanningContext, b Blueprint, bindings []volumes.Binding, id, submitter string, epoch uint64) (Inventory, error) {
	if len(bindings) == 0 || len(bindings) > 128 {
		return a, ErrInputs
	}
	if _, active := a.Execution(); active {
		return a, ErrInputs
	}
	for _, binding := range bindings {
		found := false
		for _, step := range b.Steps() {
			if i := a.claim(step.Key); i >= 0 && a.retainedVolumeHandoff(a.d.Claims[i], step, ctx.Volumes, binding) {
				found = true
				break
			}
		}
		if !found {
			return a, inputError("VOLUME_MOVE_CLOSURE_REQUIRED", binding.Scope.ID)
		}
	}
	return a.begin(expected, c, ctx, b, id, submitter, epoch, false, bindings)
}
