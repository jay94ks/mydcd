// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/json"
	"slices"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

// The candidate is only the original current Task/binding/consumer metadata.
// Actual Running, native recipe and activation-pin checks stay on its owner.
// A zero candidate is only the validated, explicitly unused target Volume;
// the caller must request a distinct native Idle fact, never fake a Task.
type VolumeMoveActiveTask struct {
	Task     deployment.ObjectRef
	Binding  [32]byte
	Consumer volumes.Consumer
}

func (p Policy) moveActiveTask(s state.State, j VolumeMove) (VolumeMoveActiveTask, error) {
	var out VolumeMoveActiveTask
	v, err := p.Volumes(s)
	if err != nil {
		return out, err
	}
	_, move, ok := v.Move(j.Selection())
	core, found := v.Volume(j.Binding.Scope)
	if !ok || !found || move.Phase != volumes.Activating || !move.Irreversible || move.CommitRevision == 0 || j.App == nil || j.App.Target == nil {
		return out, ErrCatalog
	}
	a, err := p.Apps(s)
	if err != nil {
		return out, err
	}
	entry, found := a.entries[appKey(j.Binding.Scope.Tenant, j.Binding.Scope.App)]
	if !found || entry.Down != nil || !sameMoveExecution(entry, j.Origin) {
		return out, ErrCatalog
	}
	execution, found := entry.Inventory.Execution()
	if !found || execution.ActiveOperation() != j.App.Target.Operation || execution.Status() != "Succeeded" {
		return out, ErrCatalog
	}
	owner, revision := core.Owner()
	if owner != j.Binding.Target || revision != move.CommitRevision {
		return out, ErrCatalog
	}
	volumeKey := deployment.ResourceKey("volume", j.Binding.Scope.Tenant, j.Binding.Scope.App, j.Binding.Scope.ID)
	volumeStage, found := execution.Stage(volumeKey)
	volumeObject := s.Object(volumeKey)
	if !found || volumeStage.Command == nil || volumeStage.Result == nil || volumeStage.Result.Code != state.Applied || !volumeObject.Present || volumeStage.Result.Generation != volumeObject.Generation || volumeStage.Result.Revision != volumeObject.Revision || volumeObject.Value != volumeStage.Command.Value || volumeStage.Observation == nil || !volumeStage.Observation.Applied || volumeStage.Observation.Released || volumeStage.Observation.Native != j.Binding.Target.Native {
		return out, ErrCatalog
	}
	var volumeGoal deployment.GoalCommand
	if canonical([]byte(volumeObject.Value), &volumeGoal) != nil || volumeGoal.Kind != "volume" || volumeGoal.Owner != j.Binding.Target.Key || volumeGoal.Node != j.Binding.Target.Node || volumeGoal.Lifecycle != nil && volumeGoal.Lifecycle.Drain {
		return out, ErrCatalog
	}
	// The accepted execution, not the accidental absence of current bindings,
	// determines whether a Volume has consumers. Every declared mount must have
	// its original current binding before either Running or Idle can be reported.
	expected := map[string]bool{}
	for _, step := range execution.Steps() {
		if step.Kind != "task" {
			continue
		}
		var service deployment.ComposeService
		if json.Unmarshal(step.Goal, &service) != nil {
			return out, ErrCatalog
		}
		for _, mount := range service.Volumes {
			if mount.Source == j.Binding.Scope.ID {
				if step.Node != j.Binding.Target.Node || step.Owner != j.Binding.Target.Key {
					return out, ErrCatalog
				}
				if _, duplicate := expected[step.Key]; duplicate {
					return out, ErrCatalog
				}
				expected[step.Key] = !mount.ReadOnly
			}
		}
	}
	seen := map[string]bool{}
	for _, b := range a.bindings.Live() {
		source, found := a.BindingSource(b.Digest())
		if !found || b.Needs().Use.Tenant != j.Binding.Scope.Tenant || b.Needs().Use.App != j.Binding.Scope.App || b.Needs().Use.NodeKey != j.Binding.Target.Key || !sameMoveBinding(source, j.Origin) {
			continue
		}
		for _, pin := range b.Pins() {
			if pin.Scope != j.Binding.Scope {
				continue
			}
			writable, declared := expected[source.Task.Key]
			if !declared || seen[source.Task.Key] || pin.Consumer.Writable != writable || pin.Consumer.Owner != j.Binding.Target || pin.Consumer.OwnerRevision != move.CommitRevision || core.CheckActivation(pin.Consumer) != nil {
				return out, ErrCatalog
			}
			stage, found := execution.Stage(source.Task.Key)
			o := s.Object(source.Task.Key)
			if !found || stage.Command == nil || stage.Result == nil || stage.Result.Code != state.Applied || stage.Result.Generation != source.Task.Generation || stage.Result.Revision != source.Task.Revision || !o.Present || o.Generation != source.Task.Generation || o.Revision != source.Task.Revision || o.Value != stage.Command.Value || stage.Observation == nil || !stage.Observation.Applied || stage.Observation.Released {
				return out, ErrCatalog
			}
			var goal deployment.GoalCommand
			if canonical([]byte(o.Value), &goal) != nil || goal.Kind != "task" || goal.Owner != j.Binding.Target.Key || goal.Node != j.Binding.Target.Node || goal.Lifecycle != nil && goal.Lifecycle.Drain {
				return out, ErrCatalog
			}
			if !slices.Contains(core.Consumers(), pin.Consumer) {
				return out, ErrCatalog
			}
			seen[source.Task.Key] = true
			if out.Task.Key == "" || source.Task.Key < out.Task.Key {
				out = VolumeMoveActiveTask{Task: source.Task, Binding: b.Digest(), Consumer: pin.Consumer}
			}
		}
	}
	if len(seen) != len(expected) || len(core.Consumers()) != len(expected) {
		return VolumeMoveActiveTask{}, ErrCatalog
	}
	return out, nil
}
