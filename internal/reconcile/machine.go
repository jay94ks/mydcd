// SPDX-License-Identifier: Apache-2.0

// Package reconcile contains single-owner, side-effect-free journal transitions.
package reconcile

import "errors"

var (
	ErrDesired   = errors.New("stale or inconsistent desired state")
	ErrPending   = errors.New("an operation must be settled first")
	ErrOperation = errors.New("invalid operation or completion")
	ErrStopped   = errors.New("new work is stopped")
)

type Resource struct {
	Generation uint64
	Spec       string
	Present    bool
}

type Desired struct {
	Revision uint64
	// Retiring records an absent generation even when its Apply was never
	// planned locally. It cannot erase an existing dispatched operation.
	Retiring uint64
	Resource
}

type Kind uint8

const (
	Apply Kind = iota + 1
	Remove
)

type Phase uint8

const (
	Prepared Phase = iota + 1
	Dispatched
	RecoveryRequired
	Retiring
)

type Operation struct {
	ID     uint64
	Kind   Kind
	Target Resource
	Phase  Phase
}

type State struct {
	Desired         Desired
	Applied         Resource
	Pending         *Operation
	LastID          uint64
	GenerationFloor uint64
	Stopped         bool
}

func copyState(s State) State {
	if s.Pending != nil {
		operation := *s.Pending
		s.Pending = &operation
	}
	return s
}

func validResource(r Resource) bool {
	return (r.Present && r.Generation != 0) || (!r.Present && r == (Resource{}))
}

// Validate is required before using a restored journal as an execution plan.
func Validate(s State) error {
	if !validResource(s.Applied) || !validResource(s.Desired.Resource) || s.Desired.Present && s.Desired.Retiring != 0 || (s.Desired.Revision == 0 && (s.Desired.Resource != (Resource{}) || s.Desired.Retiring != 0)) || s.GenerationFloor < s.Desired.Generation || s.GenerationFloor < s.Desired.Retiring || s.GenerationFloor < s.Applied.Generation {
		return ErrOperation
	}
	if op := s.Pending; op != nil {
		if op.ID == 0 || op.ID != s.LastID || !op.Target.Present || !validResource(op.Target) || op.Target.Generation > s.GenerationFloor || (op.Kind != Apply && op.Kind != Remove) || op.Phase < Prepared || op.Phase > Retiring || op.Phase == Retiring && (op.Kind != Apply || s.Desired.Present && s.Desired.Generation == op.Target.Generation) || (op.Kind == Remove && op.Target != s.Applied) || (op.Kind == Apply && s.Applied.Present && op.Target.Generation != s.Applied.Generation) {
			return ErrOperation
		}
	}
	return nil
}

func SetDesired(s State, d Desired) (State, error) {
	if err := Validate(s); err != nil {
		return s, err
	}
	if d.Revision == 0 || !validResource(d.Resource) || d.Present && d.Retiring != 0 || d.Retiring != 0 && d.Retiring < s.GenerationFloor || d.Revision < s.Desired.Revision || (d.Revision == s.Desired.Revision && d != s.Desired) {
		return s, ErrDesired
	}
	if d.Revision == s.Desired.Revision {
		return copyState(s), nil
	}
	if d.Present && (d.Generation < s.GenerationFloor || (!s.Desired.Present && d.Generation <= s.GenerationFloor)) {
		return s, ErrDesired
	}
	n := copyState(s)
	n.Desired = d
	if d.Generation > n.GenerationFloor {
		n.GenerationFloor = d.Generation
	}
	if d.Retiring > n.GenerationFloor {
		n.GenerationFloor = d.Retiring
	}
	return n, nil
}

// Plan creates a Prepared journal; persist it before progressing to Dispatch.
func Plan(s State) (State, *Operation, error) {
	if err := Validate(s); err != nil {
		return s, nil, err
	}
	if s.Stopped {
		return s, nil, ErrStopped
	}
	if s.Pending != nil {
		return s, nil, ErrPending
	}
	var kind Kind
	var target Resource
	if s.Applied.Present && (!s.Desired.Present || s.Applied.Generation != s.Desired.Generation) {
		kind, target = Remove, s.Applied
	} else if s.Desired.Present && s.Desired.Resource != s.Applied {
		kind, target = Apply, s.Desired.Resource
	} else {
		return s, nil, nil
	}
	if s.LastID == ^uint64(0) {
		return s, nil, ErrOperation
	}
	n := copyState(s)
	n.LastID++
	op := Operation{ID: n.LastID, Kind: kind, Target: target, Phase: Prepared}
	n.Pending = &op
	// Do not return an alias to the journal that an adapter can mutate.
	return n, &Operation{ID: op.ID, Kind: op.Kind, Target: op.Target, Phase: op.Phase}, nil
}

// PlanRestore prepares repair of a positively absent, already-confirmed local
// effect. The adapter must prove complete native absence under its owner lock.
// An unresolved operation is never replaced, and Applied/pins stay intact.
func PlanRestore(s State) (State, error) {
	if err := Validate(s); err != nil {
		return s, err
	}
	if s.Stopped {
		return s, ErrStopped
	}
	if s.Pending != nil {
		return s, ErrPending
	}
	if !s.Applied.Present || s.Desired.Resource != s.Applied || s.LastID == 0 || s.LastID == ^uint64(0) {
		return s, ErrOperation
	}
	n := copyState(s)
	n.LastID++
	n.Pending = &Operation{ID: n.LastID, Kind: Apply, Target: n.Applied, Phase: Prepared}
	return n, Validate(n)
}

// Dispatch must itself be persisted before invoking the external adapter. A crash
// after this record requires inspection even if the actual call had not started.
func Dispatch(s State, id uint64) (State, error) {
	if err := Validate(s); err != nil {
		return s, err
	}
	if s.Stopped {
		return s, ErrStopped
	}
	if s.Pending == nil || s.Pending.ID != id || s.Pending.Phase != Prepared {
		return s, ErrOperation
	}
	n := copyState(s)
	n.Pending.Phase = Dispatched
	return n, nil
}

type Outcome uint8

const (
	EffectApplied Outcome = iota + 1
	EffectNotApplied
	EffectUnknown
)

// Settle consumes evidence for the original operation, not the latest Desired.
// NotApplied requires positive evidence; a generic error is Unknown.
func Settle(s State, id uint64, outcome Outcome) (State, error) {
	if err := Validate(s); err != nil {
		return s, err
	}
	if s.Pending == nil || s.Pending.ID != id || (s.Pending.Phase != Dispatched && s.Pending.Phase != RecoveryRequired) || outcome < EffectApplied || outcome > EffectUnknown {
		return s, ErrOperation
	}
	n := copyState(s)
	if outcome == EffectUnknown {
		n.Pending.Phase = RecoveryRequired
		return n, nil
	}
	if outcome == EffectApplied {
		if n.Pending.Kind == Remove {
			n.Applied = Resource{}
		} else {
			n.Applied = n.Pending.Target
		}
	}
	n.Pending = nil
	return n, nil
}

func Stop(s State) State { n := copyState(s); n.Stopped = true; return n }

// AbortPrepared is safe only before the durable dispatch record. A dispatched
// call cannot be abandoned merely because a newer Desired or shutdown arrived.
func AbortPrepared(s State, id uint64) (State, error) {
	if Validate(s) != nil || s.Pending == nil || s.Pending.ID != id || s.Pending.Phase != Prepared {
		return s, ErrOperation
	}
	n := copyState(s)
	n.Pending = nil
	return n, nil
}
func Resume(s State) (State, error) {
	if Validate(s) != nil {
		return s, ErrOperation
	}
	n := copyState(s)
	n.Stopped = false
	return n, nil
}

func BeginRetirement(s State, id uint64) (State, error) {
	if Validate(s) != nil || s.Pending == nil || s.Pending.ID != id || s.Pending.Kind != Apply || s.Pending.Phase == Prepared || s.Desired.Present && s.Desired.Generation == s.Pending.Target.Generation {
		return s, ErrOperation
	}
	n := copyState(s)
	n.Pending.Phase = Retiring
	return n, nil
}

// FinishRetirement consumes positive original native closure. Historical Apply
// execution remains unspecified; it is neither Applied nor NotApplied evidence.
func FinishRetirement(s State, id uint64, closed bool) (State, error) {
	if Validate(s) != nil || s.Pending == nil || s.Pending.ID != id || s.Pending.Phase != Retiring {
		return s, ErrOperation
	}
	n := copyState(s)
	if !closed {
		return n, nil
	}
	if n.Applied.Generation == n.Pending.Target.Generation {
		n.Applied = Resource{}
	}
	n.Pending = nil
	return n, nil
}
