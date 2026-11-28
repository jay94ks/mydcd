// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/json"
	"slices"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/schema"
)

// FeatureTaskSurge is the PlanningContext feature saying that every server
// can run two generations of one Task side by side. Without it no wave is
// planned as a surge.
const FeatureTaskSurge = "task-surge"

// Surge phase: a Surge wave starts in "surging", where the new generation of
// each of its Tasks is prepared and started while the original keeps
// running. It moves to "retiring" (stop the originals) once every new Task
// is healthy and every listener serving it has drained the original, then to
// "applying" and the next wave as before.
const phaseSurging = "surging"

// surgeWave reports whether wave may run its Tasks twice for a while: each
// target is a replaced Task, or a Task's private inputs, that stays on its
// server and owner; a Task has no interruption other than SINGLE_INSTANCE
// (which surge lifts) and mounts no Volume (a second consumer is not
// provided for yet).
func (a Inventory) surgeWave(wave ReplacementWave, steps map[string]Step, changes map[string]Change) bool {
	if len(wave.Tasks) == 0 {
		return false
	}
	for _, ref := range wave.Targets {
		step, present := steps[ref.Key]
		at := a.claim(ref.Key)
		if !present || at < 0 || step.Kind != "task" && step.Kind != "inputs" {
			return false
		}
		claim := a.d.Claims[at]
		if claim.Step.Node != step.Node || claim.Step.Owner != step.Owner || claim.Step.Retain {
			return false
		}
		if step.Kind == "inputs" {
			continue
		}
		if change := changes[ref.Key]; change.Action != "Replace" || change.Interruption != "" && change.Interruption != InterruptSingleInstance {
			return false
		}
		var service, original ComposeService
		if json.Unmarshal(step.Goal, &service) != nil || json.Unmarshal(claim.Step.Goal, &original) != nil || len(service.Volumes) != 0 {
			return false
		}
		// Both generations are attached at once, so the new one needs
		// addresses of its own.
		for alias, attachment := range service.Networks {
			old := original.Networks[alias]
			if attachment.IPv4 != "" && attachment.IPv4 == old.IPv4 || attachment.IPv6 != "" && attachment.IPv6 == old.IPv6 {
				return false
			}
		}
	}
	return true
}

// surgeTarget reports whether stage i is a target of a Surge wave of this
// rollout (its command renews the object's generation).
func (e Execution) surgeTarget(i int) bool {
	r := e.d.Replacement
	if r == nil {
		return false
	}
	key := e.d.Stages[i].Key
	for _, wave := range r.Plan.Waves {
		if wave.Surge && slices.ContainsFunc(wave.Targets, func(ref ObjectRef) bool { return ref.Key == key }) {
			return true
		}
	}
	return false
}

func (r *replacementExecution) surgeWave() bool {
	return r != nil && r.Wave >= 0 && r.Wave < len(r.Plan.Waves) && r.Plan.Waves[r.Wave].Surge
}

// surgeTask reports whether stage i is a target (a Task or its private
// inputs) of the current Surge wave whose original still runs.
func (e Execution) surgeTask(i int) bool {
	r := e.d.Replacement
	if !r.surgeWave() || r.Phase != phaseSurging && r.Phase != "retiring" {
		return false
	}
	stage := e.d.Stages[i]
	previous := stage.Previous
	return previous != nil && !previous.Removed && slices.ContainsFunc(r.Plan.Waves[r.Wave].Targets, func(ref ObjectRef) bool { return ref.Key == stage.Key })
}

// SurgeWindow reports the original generation of a Task while its new
// generation runs next to it: the Task is in the current Surge wave, the
// original has not been stopped yet, and the new generation is Applied and
// last observed healthy. Listeners serve both while it holds and drain the
// original (IngressDrained) before the wave stops it.
func (e Execution) SurgeWindow(key string) (ObjectRef, bool) {
	i := e.index(key)
	if i < 0 || !e.surgeTask(i) {
		return ObjectRef{}, false
	}
	stage := e.d.Stages[i]
	previous := stage.Previous
	if stage.Command == nil || stage.Result == nil || stage.Result.Code != state.Applied || stage.Result.Generation <= previous.Result.Generation {
		return ObjectRef{}, false
	}
	if o := stage.Observation; o == nil || !o.Applied || !o.Healthy || o.Expired || o.Released || o.Stopped || o.Gone || o.Generation != stage.Result.Generation {
		return ObjectRef{}, false
	}
	return ObjectRef{Key: key, Generation: previous.Result.Generation, Revision: previous.Result.Revision}, true
}

// HeldExecutionAt is HeldExecution for one exact generation: it returns the
// original execution while the original native of that generation still
// runs, including during a surge after the new generation was sent.
func (e Execution) HeldExecutionAt(key string, generation uint64) (Execution, bool) {
	i := e.index(key)
	if i < 0 || e.d.Replacement == nil || e.d.Replacement.Previous == nil {
		return Execution{}, false
	}
	previous := e.d.Stages[i].Previous
	if previous == nil || previous.Removed || previous.Result.Generation != generation {
		return Execution{}, false
	}
	if !e.d.Stages[i].Held() && !e.surgeTask(i) {
		return Execution{}, false
	}
	old := Execution{*e.d.Replacement.Previous}
	if old.index(key) < 0 {
		return Execution{}, false
	}
	raw, err := json.Marshal(old.d)
	if err != nil {
		return Execution{}, false
	}
	owned, err := DecodeExecution(raw)
	return owned, err == nil
}

// surgeReady reports whether a surging wave may stop its originals: every
// new Task is healthy now and every listener that serves it already sends
// to the new generation and has drained the original.
func (a Inventory) surgeReady(e Execution, now uint64) bool {
	wave := e.d.Replacement.Plan.Waves[e.d.Replacement.Wave]
	for _, key := range wave.Tasks {
		i := e.index(key)
		if i < 0 {
			return false
		}
		previous, ok := e.SurgeWindow(key)
		if !ok || !e.satisfies(i, Healthy, now) {
			return false
		}
		result := e.d.Stages[i].Result
		current := ObjectRef{Key: key, Generation: result.Generation, Revision: result.Revision}
		for index, step := range e.d.Plan.Steps {
			if step.Kind != "ingress" || len(step.Identity) == 0 || !slices.Contains(step.Identity, key) {
				continue
			}
			o := e.d.Stages[index].Observation
			if o == nil || !o.AvailableAt(now) || !slices.Contains(o.IngressBackends, current) || !slices.Contains(o.IngressDrained, previous) {
				return false
			}
		}
	}
	return true
}

// supersededTarget reports whether claim c is the original of a target of
// the current Surge wave whose new generation already holds the object:
// stopping it touches only its native, never the object.
func (a Inventory) supersededTarget(c Claim) bool {
	e, ok := a.Execution()
	if !ok || a.d.Retirement == nil || !a.d.Retirement.KeepExecution {
		return false
	}
	i := e.index(c.Step.Key)
	if i < 0 || !e.surgeTask(i) {
		return false
	}
	stage := e.d.Stages[i]
	return stage.Command != nil && stage.Command.Renew && stage.Result != nil && stage.Result.Code == state.Applied && stage.Result.Generation > c.Result.Generation && stage.Previous.Result == c.Result
}

// supersededDrain is what the owner's Gone signature covers for a
// superseded original: the drain value an ordinary retirement would have
// written, so the proof shape stays schema.GoneBytes over it.
func supersededDrain(cluster [32]byte, id string, revision uint64, c Claim) []byte {
	var g GoalCommand
	_ = json.Unmarshal([]byte(c.Command.Value), &g)
	g.Lifecycle = &schema.Lifecycle{Drain: true, Nonce: retirementNonce(cluster, id+"/"+string(goal(revision)), c.Step.Key, c.Result.Generation)}
	return goal(g)
}

// SupersededDrain is the value a node signs (schema.GoneBytes) once the
// superseded original of key has stopped and gone; false when key is not
// such a target.
func (a Inventory) SupersededDrain(key string) ([]byte, bool) {
	j := a.target(key)
	if j < 0 || !a.d.Retirement.Targets[j].Superseded {
		return nil, false
	}
	return supersededDrain(a.d.Cluster, a.d.Retirement.ID, a.d.Retirement.Revision, a.d.Retirement.Targets[j].Original), true
}

// SupersededGone closes a superseded original on its owner's signature
// that the native of that generation is gone.
func (a Inventory) SupersededGone(expected uint64, key string, signature []byte) (Inventory, error) {
	j := a.target(key)
	if expected != a.d.Revision || j < 0 || !a.canRetire(key) {
		return a, ErrInputs
	}
	t := a.d.Retirement.Targets[j]
	c := t.Original
	if !t.Superseded || t.Closed || schema.VerifyGone(c.Step.Owner, a.d.Cluster, key, c.Result.Generation, supersededDrain(a.d.Cluster, a.d.Retirement.ID, a.d.Retirement.Revision, c), signature) != nil {
		return a, ErrInputs
	}
	n, err := a.clone()
	if err != nil {
		return a, err
	}
	target := &n.d.Retirement.Targets[j]
	target.Gone, target.Closed = bytes.Clone(signature), true
	i := n.claim(key)
	n.d.Claims[i].Removed = true
	n.d.Claims[i].Removal = &RemovalProof{ID: n.d.Retirement.ID, Revision: n.d.Retirement.Revision, Gone: bytes.Clone(signature), Superseded: true}
	return n, nil
}
