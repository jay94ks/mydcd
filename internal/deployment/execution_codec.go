// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/reconcile"
	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

func (e Execution) validate() error {
	d := e.d
	if d.Schema != 1 || !identifier(d.Operation) || d.Submitter == "" || len(d.Submitter) > 256 || d.Epoch == 0 || d.Revision < 1 || d.Closed && !d.Stopping || len(d.Stages) != len(d.Plan.Steps) {
		return ErrInputs
	}
	if !e.validReplacement() {
		return ErrInputs
	}
	if d.Images != nil && !validImages(e.TagImages(), d.Images) {
		return ErrInputs
	}
	plan, e2 := json.Marshal(d.Plan)
	if e2 != nil {
		return e2
	}
	if _, e2 = DecodeBlueprint(plan); e2 != nil {
		return e2
	}
	// DecodeBlueprint has fully validated these canonical bytes, including
	// frozen lifecycle/source metadata. Hash once for this validation call;
	// each observation/witness must still match it and verify its own signature.
	planDigest := sha256.Sum256(plan)
	for i, s := range d.Stages {
		if s.Key != d.Plan.Steps[i].Key {
			return ErrInputs
		}
		if s.Command == nil {
			if s.Result != nil || s.Replay != nil || s.Observation != nil && (!s.Held() || !e.validObservationForPlan(i, *s.Observation, planDigest)) || s.Noop || !bytes.Equal(goal(s.Journal), goal(reconcile.State{})) {
				return ErrInputs
			}
			continue
		}
		cmd := *s.Command
		base, _ := e.preparationBase(i)
		if cmd.Actor != d.Submitter || cmd.Epoch != d.Epoch || cmd.RequestID != requestID(d.Operation, s.Key) || cmd.Key != s.Key || cmd.Kind != state.Mutate || cmd.Delete || cmd.Renew && !e.surgeTarget(i) || cmd.Target != "" || cmd.Rights != 0 || cmd.Expected != base.Revision {
			return ErrInputs
		}
		value, err := e.commandValue(i)
		if err != nil || cmd.Value != value {
			return ErrInputs
		}
		if s.Result != nil && !validResult(*s.Result) {
			return ErrInputs
		}
		if s.Noop {
			if s.Result == nil || s.Result.Code != state.Applied || cmd.Expected != s.Result.Revision || !bytes.Equal(goal(s.Journal), goal(reconcile.State{})) {
				return ErrInputs
			}
		} else {
			j := s.Journal
			if reconcile.Validate(j) != nil || j.LastID != 1 || !j.Desired.Present || j.Desired.Spec != string(goal(cmd)) || j.Desired.Generation != j.Desired.Revision || j.Desired.Generation > e.d.Revision || j.Stopped != d.Stopping {
				return ErrInputs
			}
			if j.Pending != nil {
				if s.Result != nil || j.Applied.Present || j.Pending.Target != j.Desired.Resource {
					return ErrInputs
				}
			} else {
				if s.Result == nil {
					if !d.Stopping || j.Applied.Present {
						return ErrInputs
					}
				} else if s.Result.Code == state.Applied {
					if j.Applied != j.Desired.Resource {
						return ErrInputs
					}
				} else if j.Applied.Present {
					return ErrInputs
				}
			}
		}
		if r := s.Replay; r != nil {
			j := s.Journal
			if s.Noop || r.Request == "" || len(r.Request) > 512 || r.Revision < j.Desired.Revision || r.Revision > d.Revision ||
				s.Result == nil && (j.Pending == nil || !r.Dispatched && j.Pending.Phase != reconcile.RecoveryRequired || r.Dispatched && j.Pending.Phase != reconcile.Dispatched && j.Pending.Phase != reconcile.RecoveryRequired) {
				return ErrInputs
			}
		}
		if s.Observation != nil && !e.validObservationForPlan(i, *s.Observation, planDigest) {
			return ErrInputs
		}
		if o := s.Observation; o != nil && (o.Applied && !e.activationReady(i) || o.Released && !e.CanRelease(s.Key)) {
			return ErrInputs
		}
	}
	if d.Closed {
		for i, s := range d.Stages {
			if s.Journal.Pending != nil || s.Result != nil && s.Result.Code == state.Applied && d.Plan.Steps[i].Node != "" && (s.Observation == nil || !s.Observation.Released) {
				return ErrInputs
			}
		}
	}
	if d.CompletedAt == 0 {
		if len(d.CompletionWitness) != 0 {
			return ErrInputs
		}
	} else {
		if d.Replacement != nil && d.Replacement.Phase != "complete" {
			return ErrInputs
		}
		witnessIndex := 0
		for i, s := range d.Stages {
			if s.Result == nil || s.Result.Code != state.Applied {
				return ErrInputs
			}
			if d.Plan.Steps[i].Completion == Committed {
				continue
			}
			if witnessIndex >= len(d.CompletionWitness) {
				return ErrInputs
			}
			o := d.CompletionWitness[witnessIndex]
			witnessIndex++
			// No age bound: an unchanged fact is renewed over SFCP, not in
			// Raft, so its stored At ages while it stays live. Liveness is the
			// leader's Expired marker, which satisfies already requires unset.
			if !e.validObservationForPlan(i, o, planDigest) || o.At > d.CompletedAt || o.Expired {
				return ErrInputs
			}
			if key, required, _, _ := e.appCheckCoordinator(); required && s.Key == key && e.appCheckOutcome(&o, d.CompletedAt) != contract.Pass {
				return ErrInputs
			}
			switch d.Plan.Steps[i].Completion {
			case Applied:
				if !appliedObservation(o) {
					return ErrInputs
				}
			case Healthy:
				if !o.Applied || !o.Healthy || !e.ingressAllReady(i, o) {
					return ErrInputs
				}
			case Completed:
				if !successfulCompletion(o) {
					return ErrInputs
				}
			case Released:
				if !o.Released {
					return ErrInputs
				}
			default:
				return ErrInputs
			}
		}
		if witnessIndex != len(d.CompletionWitness) {
			return ErrInputs
		}
	}

	return nil
}
func (e Execution) Encode() ([]byte, error) {
	if err := e.validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(e.d)
	if len(raw) > 16<<20 {
		return nil, ErrInputs
	}
	return raw, err
}
func DecodeExecution(raw []byte) (Execution, error) {
	if len(raw) > 16<<20 {
		return Execution{}, ErrInputs
	}
	var d executionRecord
	if json.Unmarshal(raw, &d) != nil {
		return Execution{}, ErrInputs
	}
	e := Execution{d}
	if err := e.validate(); err != nil {
		return Execution{}, err
	}
	canonical, _ := json.Marshal(d)
	if !bytes.Equal(raw, canonical) {
		return Execution{}, ErrInputs
	}
	return e, nil
}
