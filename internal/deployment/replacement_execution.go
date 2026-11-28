// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
)

// The one accepted Execution owns every wave. Previous is an original native
// claim, never an Applied result for the new target or a second executor.
type replacementExecution struct {
	Previous *executionRecord `json:",omitempty"` // immutable recipe/authority input, never scheduled as another rollout
	Plan     ReplacementPlan
	Wave     int
	Phase    string // retiring -> applying -> next wave, then complete
}

type ReplacementProgress struct {
	Wave, Waves int
	Node, Phase string
}

func (e Execution) Replacement() (ReplacementProgress, bool) {
	r := e.d.Replacement
	if r == nil {
		return ReplacementProgress{}, false
	}
	return ReplacementProgress{Wave: r.Wave + 1, Waves: len(r.Plan.Waves), Node: r.Plan.Waves[r.Wave].Node, Phase: r.Phase}, true
}

func (e Execution) replacementRetirementID() string {
	if e.d.Replacement == nil {
		return ""
	}
	return e.replacementRetirementIDAt(e.d.Replacement.Wave)
}

func (e Execution) replacementRetirementIDAt(wave int) string {
	raw := goal(struct {
		Cluster                           [32]byte
		Tenant, App, Operation, Submitter string
		Epoch                             uint64
		Wave                              int
	}{e.d.Plan.Cluster, e.d.Plan.Tenant, e.d.Plan.App, e.d.Operation, e.d.Submitter, e.d.Epoch, wave})
	digest := sha256.Sum256(append([]byte("sfc-replacement-retire-1\x00"), raw...))
	return "roll-" + hex.EncodeToString(digest[:24])
}

func (e Execution) ReplacementAllows(key string) bool {
	i := e.index(key)
	return i >= 0 && e.replacementAllows(i)
}

func (e Execution) validReplacement() bool {
	r := e.d.Replacement
	if r != nil && (!r.Plan.Valid(e.d.Plan.Tenant, e.d.Plan.App) || r.Plan.BlockedCode != "" || r.Wave < 0 || r.Wave >= len(r.Plan.Waves) || r.Phase != "retiring" && r.Phase != "applying" && r.Phase != "complete" && r.Phase != phaseSurging || r.Phase == "complete" && r.Wave+1 != len(r.Plan.Waves) || r.Phase == phaseSurging && !r.Plan.Waves[r.Wave].Surge) {
		return false
	}
	if r != nil && r.Previous != nil {
		old := Execution{*r.Previous}
		previous, target := old.Scope(), e.Scope()
		if old.d.Replacement != nil && old.d.Replacement.Previous != nil || old.d.CompletedAt == 0 || old.d.Paused || old.d.Stopping || old.d.Closed || old.d.Operation == e.d.Operation || previous.Cluster != target.Cluster || previous.Tenant != target.Tenant || previous.App != target.App || previous.Deployment != target.Deployment || old.validate() != nil {
			return false
		}
	} else if r != nil && r.Phase != "complete" {
		return false
	}
	validator := Inventory{inventoryRecord{Schema: 1, Cluster: e.d.Plan.Cluster, Tenant: e.d.Plan.Tenant, App: e.d.Plan.App, Deployment: e.d.Plan.Deployment}}
	for index, stage := range e.d.Stages {
		previous := stage.Previous
		if previous == nil {
			continue
		}
		step := e.d.Plan.Steps[index]
		if r == nil || !validator.validClaim(*previous) || previous.Step.Retain || previous.Retained || previous.Step.Key != stage.Key || !step.BasePresent || step.Base.Revision != previous.Result.Revision || step.Base.Generation != previous.Result.Generation {
			return false
		}
		if !previous.Removed {
			old, ok := e.originalExecution(stage.Key)
			if !ok {
				return false
			}
			at := old.index(stage.Key)
			actual := old.d.Stages[at]
			original := old.d.Plan.Steps[at]
			if actual.Command == nil || actual.Result == nil || actual.Result.Code != state.Applied || actual.Command.Value != previous.Command.Value || actual.Result.Revision != previous.Result.Revision || actual.Result.Generation != previous.Result.Generation || original.Kind != previous.Step.Kind || original.Node != previous.Step.Node || original.Owner != previous.Step.Owner || !bytes.Equal(original.Goal, previous.Step.Goal) {
				return false
			}
		}
		found := -1
		for wave, plan := range r.Plan.Waves {
			for _, ref := range plan.Targets {
				if ref.Key == stage.Key && ref.Revision == previous.Result.Revision && ref.Generation == previous.Result.Generation {
					found = wave
				}
			}
		}
		surging := found == r.Wave && r.Plan.Waves[found].Surge && (r.Phase == phaseSurging || r.Phase == "retiring")
		if found < 0 || found < r.Wave && !previous.Removed || found > r.Wave && previous.Removed || !previous.Removed && stage.Command != nil && !surging || stage.Result != nil && stage.Result.Code == state.Applied && stage.Result.Generation <= previous.Result.Generation || previous.Removed && (previous.Removal == nil || previous.Removal.ID != e.replacementRetirementIDAt(found) || !previous.Removal.Superseded && (previous.Removal.Delete.Command.Actor != e.d.Submitter || previous.Removal.Delete.Command.Epoch != e.d.Epoch) || previous.Removal.Superseded && !r.Plan.Waves[found].Surge) {
			return false
		}
	}
	if r != nil {
		for wave, plan := range r.Plan.Waves {
			for _, ref := range plan.Targets {
				if index := e.index(ref.Key); index >= 0 {
					previous := e.d.Stages[index].Previous
					if previous == nil || (wave < r.Wave || wave == r.Wave && r.Phase != "retiring" && r.Phase != phaseSurging) && !previous.Removed {
						return false
					}
				}
			}
		}
	}
	return true
}

// originalExecution is the original execution of a Task whose original
// native still runs: held, or running next to its new generation (surge).
func (e Execution) originalExecution(key string) (Execution, bool) {
	i := e.index(key)
	if i < 0 || e.d.Stages[i].Previous == nil || e.d.Stages[i].Previous.Removed || e.d.Replacement == nil || e.d.Replacement.Previous == nil {
		return Execution{}, false
	}
	old := Execution{*e.d.Replacement.Previous}
	return old, old.index(key) >= 0
}

func (e Execution) heldExecution(key string) (Execution, bool) {
	i := e.index(key)
	if i < 0 || !e.d.Stages[i].Held() || e.d.Replacement == nil || e.d.Replacement.Previous == nil {
		return Execution{}, false
	}
	old := Execution{*e.d.Replacement.Previous}
	return old, old.index(key) >= 0
}

// HeldExecution returns an owned, read-only source of the unchanged native
// recipe/activation evidence. Its old command IDs are never submitted again.
func (e Execution) HeldExecution(key string) (Execution, bool) {
	old, ok := e.heldExecution(key)
	if !ok {
		return Execution{}, false
	}
	raw, err := json.Marshal(old.d)
	if err != nil {
		return Execution{}, false
	}
	owned, err := DecodeExecution(raw)
	return owned, err == nil
}

func (a Inventory) validReplacementInventory() bool {
	e, active := a.Execution()
	if !active || e.d.Replacement == nil {
		return a.d.Retirement == nil || !a.d.Retirement.KeepExecution
	}
	r := e.d.Replacement
	if a.d.Retirement != nil && a.d.Retirement.Down && !a.d.Retirement.KeepExecution && e.d.Stopping {
		return true
	}
	if r.Phase == "retiring" {
		retirement := a.d.Retirement
		if retirement == nil || !retirement.KeepExecution || retirement.ID != e.replacementRetirementID() || len(retirement.Targets) != len(r.Plan.Waves[r.Wave].Targets) {
			return false
		}
		for _, target := range retirement.Targets {
			original := target.Original
			if !slices.Contains(r.Plan.Waves[r.Wave].Targets, ObjectRef{Key: original.Step.Key, Generation: original.Result.Generation, Revision: original.Result.Revision}) {
				return false
			}
		}
	} else if retirement := a.d.Retirement; retirement != nil {
		// A completed rollout remains its immutable source proof. A later
		// explicit partial retirement (for example log recreation) owns a new
		// closure journal; it must not be mistaken for an unfinished wave.
		if r.Phase != "complete" || e.d.CompletedAt == 0 || e.Status() != "Succeeded" || retirement.KeepExecution {
			return false
		}
	}
	for wave, plan := range r.Plan.Waves {
		for _, ref := range plan.Targets {
			if e.index(ref.Key) >= 0 || wave > r.Wave || wave == r.Wave && (r.Phase == "retiring" || r.Phase == phaseSurging) {
				continue
			}
			index := a.claim(ref.Key)
			if index < 0 || !a.d.Claims[index].Removed || a.d.Claims[index].Result.Generation != ref.Generation || a.d.Claims[index].Result.Revision != ref.Revision || a.d.Claims[index].Removal.ID != e.replacementRetirementIDAt(wave) {
				return false
			}
		}
	}
	return true
}

func (s StageRecord) Held() bool {
	return s.Previous != nil && !s.Previous.Removed && s.Command == nil
}

// HeldSource owns a view of the actual old native identity. It does not fill
// the pending target's Command/Result or authorize a target Prepare/Start.
func (s StageRecord) HeldSource() (StageRecord, bool) {
	if !s.Held() {
		return StageRecord{}, false
	}
	raw, _ := json.Marshal(s.Previous)
	var previous Claim
	_ = json.Unmarshal(raw, &previous)
	return StageRecord{Key: s.Key, Command: &previous.Command, Result: &previous.Result, Observation: s.Observation}, true
}

func (e Execution) observationStep(i int) Step {
	if e.d.Stages[i].Held() {
		return e.d.Stages[i].Previous.Step
	}
	return e.d.Plan.Steps[i]
}

func (e Execution) preparationBase(i int) (ObjectRef, bool) {
	step, stage := e.d.Plan.Steps[i], e.d.Stages[i]
	if previous := stage.Previous; previous != nil && previous.Removed && previous.Removal != nil && previous.Removal.Delete != nil && previous.Removal.Delete.Result != nil {
		return ObjectRef{Key: step.Key, Generation: previous.Result.Generation, Revision: previous.Removal.Delete.Result.Revision}, false
	}
	return step.Base, step.BasePresent
}

// PreparationBase is the exact CAS source used by Prepare and checkpoint
// validation. A positively removed original contributes its tombstone revision,
// while the frozen blueprint still describes the old, present native.
func (e Execution) PreparationBase(key string) (ObjectRef, bool, bool) {
	i := e.index(key)
	if i < 0 {
		return ObjectRef{}, false, false
	}
	base, present := e.preparationBase(i)
	return base, present, true
}

func (e Execution) replacementAllows(i int) bool {
	r := e.d.Replacement
	if r == nil {
		return true
	}
	step := e.d.Plan.Steps[i]
	if r.Phase == phaseSurging && e.surgeTask(i) {
		// The new generation starts next to the original.
		return true
	}
	if e.d.Stages[i].Held() {
		return false
	}
	if r.Phase == "retiring" || r.Phase == phaseSurging {
		// Publish the unchanged listener's drain acknowledgement before any
		// Task stop. Its unchanged producers also need their original results.
		// Prepare separately requires the exact existing noop value; selected
		// replacement sources remain Held and cannot enter this branch.
		return step.BasePresent
	}
	// A listener binds all replicas and can be prepared only after every
	// original Task has closed. Its single original request ID is not reused
	// for one new listener generation per wave.
	if step.Kind == "ingress" && len(step.Identity) == 0 && r.Wave+1 != len(r.Plan.Waves) {
		return false
	}
	for wave, plan := range r.Plan.Waves {
		if step.Node != "" && step.Node == plan.Node && wave > r.Wave && (e.d.Stages[i].Previous != nil || !step.BasePresent) {
			return false
		}
		for _, ref := range plan.Targets {
			if ref.Key == step.Key && wave > r.Wave {
				return false
			}
		}
	}
	return true
}

func (e Execution) replacementFutureNode(i int) bool {
	r := e.d.Replacement
	if r != nil {
		for wave, plan := range r.Plan.Waves {
			if wave > r.Wave && plan.Node == e.d.Plan.Steps[i].Node {
				return true
			}
		}
	}
	return false
}

func (a Inventory) beginReplacement(c access.Catalog, ctx PlanningContext, b Blueprint, id, submitter string, epoch uint64, plan ReplacementPlan) (Inventory, error) {
	if !plan.Valid(a.d.Tenant, a.d.App) || plan.BlockedCode != "" {
		return a, inputError(plan.BlockedCode, plan.Blocker)
	}
	e, err := NewExecution(b, c, ctx, id, submitter, epoch)
	if err != nil {
		return a, err
	}
	old, active := a.Execution()
	if !active || old.d.CompletedAt == 0 || old.Status() != "Succeeded" {
		return a, inputError("ORIGINAL_OPERATION_PENDING", "replacement")
	}
	old, err = old.cloneAt(old.d.Revision)
	if err != nil {
		return a, err
	}
	if old.d.Replacement != nil {
		// A completed rollout has no held source. Retain its validated plan
		// and receipts, without accumulating previous rollouts recursively.
		old.d.Replacement.Previous = nil
	}
	e.d.Replacement = &replacementExecution{Plan: plan, Phase: "retiring", Previous: &old.d}
	for _, wave := range plan.Waves {
		for _, ref := range wave.Targets {
			at := a.claim(ref.Key)
			if at < 0 || a.d.Claims[at].Removed || a.d.Claims[at].Result.Generation != ref.Generation || a.d.Claims[at].Result.Revision != ref.Revision {
				return a, ErrInputs
			}
			if index := e.index(ref.Key); index >= 0 {
				previous := a.d.Claims[at]
				if previous.Step.Retain {
					return a, inputError("ROLLING_RETAINED_PRODUCER", ref.Key)
				}
				e.d.Stages[index].Previous = &previous
			}
		}
	}
	n, err := a.clone()
	if err != nil {
		return a, err
	}
	if old, active := n.Execution(); active {
		n.d.History = append(n.d.History, summarize(old, old.Status()))
	}
	n.d.Active = &e.d
	if plan.Waves[0].Surge {
		e.d.Replacement.Phase = phaseSurging
		return n, nil
	}
	return n.startReplacementRetirement(c)
}

func (a Inventory) startReplacementRetirement(c access.Catalog) (Inventory, error) {
	e, ok := a.Execution()
	if !ok || e.d.Replacement == nil || e.d.Replacement.Phase != "retiring" || a.pendingSubmission() {
		return a, ErrInputs
	}
	wave := e.d.Replacement.Plan.Waves[e.d.Replacement.Wave]
	var keys []string
	for _, ref := range wave.Targets {
		at := a.claim(ref.Key)
		if at < 0 || a.d.Claims[at].Removed || a.d.Claims[at].Result.Generation != ref.Generation || a.d.Claims[at].Result.Revision != ref.Revision {
			return a, inputError("ORIGINAL_REPLACEMENT_SOURCE_CHANGED", ref.Key)
		}
		keys = append(keys, ref.Key)
	}
	selected, err := a.retirementSelection(keys, false)
	if err != nil || len(selected) != len(keys) {
		return a, inputError("ROLLING_DEPENDENCY_CONFLICT", wave.Node)
	}
	for key := range selected {
		if !slices.Contains(keys, key) {
			return a, inputError("ROLLING_DEPENDENCY_CONFLICT", key)
		}
	}
	return a.retire(a.Revision(), c, e.d.Plan.Actor, e.replacementRetirementID(), e.d.Submitter, e.d.Epoch, keys, false, true)
}

func (a Inventory) finishReplacementRetirement(e Execution) (Execution, error) {
	r := a.d.Retirement
	if r == nil || !r.KeepExecution || e.d.Replacement == nil || e.d.Replacement.Phase != "retiring" || r.ID != e.replacementRetirementID() {
		return e, ErrInputs
	}
	n, err := e.clone()
	if err != nil {
		return e, err
	}
	for _, target := range r.Targets {
		if !target.Closed {
			return e, ErrInputs
		}
		if index := n.index(target.Original.Step.Key); index >= 0 {
			stage := &n.d.Stages[index]
			at := a.claim(stage.Key)
			surged := n.surgeTask(index) && stage.Command != nil
			if stage.Command != nil && !surged || stage.Previous == nil || !bytes.Equal(goal(stage.Previous), goal(target.Original)) || at < 0 || !a.d.Claims[at].Removed {
				return e, ErrInputs
			}
			closed := a.d.Claims[at]
			stage.Previous = &closed
			if !surged {
				// A held stage's observation was the original's; a surged
				// one already observes the new generation.
				stage.Observation = nil
			}
		}
	}
	n.d.Replacement.Phase = "applying"
	return n, nil
}

func (a Inventory) ReplacementReady(now uint64) bool {
	e, ok := a.Execution()
	if ok && e.d.Replacement != nil && e.d.Replacement.Phase == phaseSurging {
		if a.d.Retirement != nil || e.d.Paused || e.d.Stopping || e.d.CompletedAt != 0 || a.pendingSubmission() || now == 0 {
			return false
		}
		for _, stage := range e.d.Stages {
			if stage.Result != nil && stage.Result.Code != state.Applied {
				return false
			}
		}
		return a.surgeReady(e, now)
	}
	if !ok || e.d.Replacement == nil || e.d.Replacement.Phase != "applying" || a.d.Retirement != nil || e.d.Paused || e.d.Stopping || e.d.CompletedAt != 0 || a.pendingSubmission() || now == 0 {
		return false
	}
	for _, stage := range e.d.Stages {
		if stage.Result != nil && stage.Result.Code != state.Applied {
			return false
		}
	}
	wave := e.d.Replacement.Plan.Waves[e.d.Replacement.Wave]
	keys := slices.Clone(wave.Tasks)
	for _, step := range e.d.Plan.Steps {
		if step.Kind != "task" || step.Node != wave.Node || slices.Contains(keys, step.Key) {
			continue
		}
		var service ComposeService
		if json.Unmarshal(step.Goal, &service) != nil {
			return false
		}
		if service.Sfc.Instance != nil {
			keys = append(keys, step.Key)
		}
	}
	for _, key := range keys {
		if index := e.index(key); index >= 0 {
			stage := e.d.Stages[index]
			if previous := stage.Previous; previous != nil && (!previous.Removed || stage.Command == nil || stage.Result == nil || stage.Result.Generation <= previous.Result.Generation) {
				return false
			}
			if !e.satisfies(index, Healthy, now) {
				return false
			}
		} else if at := a.claim(key); at < 0 || !a.d.Claims[at].Removed {
			return false
		}
	}
	for index, step := range e.d.Plan.Steps {
		if step.Kind != "ingress" || len(step.Identity) == 0 {
			continue
		}
		stage := e.d.Stages[index]
		for _, key := range keys {
			if !slices.Contains(step.Identity, key) {
				continue
			}
			task := e.index(key)
			if task < 0 {
				continue
			}
			result := e.d.Stages[task].Result
			if result == nil || stage.Observation == nil || !stage.Observation.AvailableAt(now) || !slices.Contains(stage.Observation.IngressBackends, ObjectRef{Key: key, Revision: result.Revision, Generation: result.Generation}) {
				return false
			}
		}
	}
	return true
}

func (e Execution) validIngressBackends(index int, o Observation) bool {
	step := e.d.Plan.Steps[index]
	if len(o.IngressDrained) != 0 {
		if step.Kind != "ingress" || len(step.Identity) == 0 || len(o.IngressDrained) > 1024 || !o.Applied {
			return false
		}
		for at, ref := range o.IngressDrained {
			if at > 0 && o.IngressDrained[at-1].Key >= ref.Key || !slices.Contains(step.Identity, ref.Key) || slices.Contains(o.IngressBackends, ref) {
				return false
			}
			task := e.index(ref.Key)
			if task < 0 {
				return false
			}
			stage := e.d.Stages[task]
			result := stage.Result
			if stage.Previous != nil && ref.Generation == stage.Previous.Result.Generation {
				result = &stage.Previous.Result
			}
			if result == nil || result.Code != state.Applied || ref.Generation != result.Generation || ref.Revision != result.Revision {
				return false
			}
		}
	}
	if len(o.IngressBackends) == 0 {
		return true
	}
	if step.Kind != "ingress" || len(step.Identity) == 0 || len(o.IngressBackends) > 1024 || !o.Applied || !o.Healthy {
		return false
	}
	for at, ref := range o.IngressBackends {
		if at > 0 && o.IngressBackends[at-1].Key >= ref.Key || !slices.Contains(step.Identity, ref.Key) {
			return false
		}
		task := e.index(ref.Key)
		if task < 0 {
			return false
		}
		stage := e.d.Stages[task]
		if stage.Held() {
			stage, _ = stage.HeldSource()
		}
		if previous := stage.Previous; e.surgeTask(task) && ref.Generation == previous.Result.Generation && ref.Revision == previous.Result.Revision {
			continue // the original still serves next to its new generation
		}
		if stage.Result == nil || stage.Result.Code != state.Applied || ref.Generation != stage.Result.Generation || ref.Revision != stage.Result.Revision {
			return false
		}
	}
	return true
}

func (e Execution) ingressAllReady(index int, o Observation) bool {
	step := e.d.Plan.Steps[index]
	if step.Kind != "ingress" || len(step.Identity) == 0 {
		return true
	}
	for _, key := range step.Identity {
		task := e.index(key)
		if task < 0 {
			return false
		}
		stage := e.d.Stages[task]
		if stage.Held() {
			stage, _ = stage.HeldSource()
		}
		if stage.Result == nil || stage.Result.Code != state.Applied || !slices.Contains(o.IngressBackends, ObjectRef{Key: key, Generation: stage.Result.Generation, Revision: stage.Result.Revision}) {
			return false
		}
	}
	return true
}

// AdvanceReplacement uses fresh facts for this original operation. It never
// resubmits an unknown request, restarts the rollout, or promotes old health.
func (a Inventory) AdvanceReplacement(expected uint64, c access.Catalog, now uint64) (Inventory, error) {
	if expected != a.Revision() || !a.ReplacementReady(now) {
		return a, inputError("REPLACEMENT_HEALTH_PENDING", "wave")
	}
	e, _ := a.Execution()
	if c.AuthorizeCleanup(e.d.Plan.Actor, a.d.Tenant, access.Deploy) != nil {
		return a, access.ErrDenied
	}
	n, err := a.clone()
	if err != nil {
		return a, err
	}
	updated, err := e.clone()
	if err != nil {
		return a, err
	}
	if updated.d.Replacement.Phase == phaseSurging {
		// Every new Task serves: stop the originals of this wave.
		updated.d.Replacement.Phase = "retiring"
		n.d.Active = &updated.d
		return n.startReplacementRetirement(c)
	}
	if updated.d.Replacement.Wave+1 == len(updated.d.Replacement.Plan.Waves) {
		updated.d.Replacement.Phase = "complete"
		updated.d.Replacement.Previous = nil // all held originals positively closed
		n.d.Active = &updated.d
		return n, nil
	}
	updated.d.Replacement.Wave++
	if updated.d.Replacement.Plan.Waves[updated.d.Replacement.Wave].Surge {
		updated.d.Replacement.Phase = phaseSurging
		n.d.Active = &updated.d
		return n, nil
	}
	updated.d.Replacement.Phase = "retiring"
	n.d.Active = &updated.d
	return n.startReplacementRetirement(c)
}
