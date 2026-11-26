// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"time"

	contract "github.com/jay94ks/mydcd/lifecycle/v1"
)

type ControlPhase string

const (
	ControlPrepared  ControlPhase = "prepared"
	ControlStopSent  ControlPhase = "stop-sent"
	ControlStopped   ControlPhase = "stopped"
	ControlStartSent ControlPhase = "start-sent"
	ControlCompleted ControlPhase = "completed"
	ControlCanceled  ControlPhase = "canceled"
)

// ContainerControl is a receipt for one admitted control intent. Its native
// identity never changes and sent phases are never retransmitted. Callers keep
// it in the original checker observation or accepted user-operation row.
type ContainerControl struct {
	Schema        uint8
	RunID         string
	RequestDigest [32]byte
	Target        contract.Target
	Action        ContainerAction
	Phase         ControlPhase
}

type ControlView struct {
	NativeID, StartedAt string
	Running, Startable  bool
}

func validInstance(stamp string) bool {
	t, err := time.Parse(time.RFC3339Nano, stamp)
	return err == nil && !t.IsZero() && len(stamp) <= 64
}

func NewContainerControl(o Observation, policy ActionPolicy, published contract.Status, running bool) (*ContainerControl, error) {
	if ValidateRequest(o.Run.Request) != nil || o.Run.Phase != Dispatched || o.Run.RequestDigest != requestDigest(o.Run.Request) || ValidateResult(o.Result) != nil || o.Run.Request.Phase != contract.Liveness || len(o.Run.Request.Targets) != 1 || policy.Validate() != nil || !validStatus(published) {
		return nil, ErrContract
	}
	// Honor the existing Machine's grace/retry/freshness decision, without
	// treating an old published pass as this failed sample's new authority.
	if published != o.Result.Status {
		return nil, nil
	}
	action, err := policy.Decide(published, running)
	if err != nil || action == KeepContainer {
		return nil, err
	}
	c := &ContainerControl{Schema: 1, RunID: o.Run.Request.RunID, RequestDigest: o.Run.RequestDigest, Target: o.Run.Request.Targets[0], Action: action, Phase: ControlPrepared}
	return c, c.ValidateFor(o)
}

func (c ContainerControl) ValidateFor(o Observation) error {
	if c.Validate() != nil || ValidateRequest(o.Run.Request) != nil || o.Run.Phase != Dispatched || ValidateResult(o.Result) != nil {
		return ErrContract
	}
	if c.RunID != o.Run.Request.RunID || c.RequestDigest != o.Run.RequestDigest || c.RequestDigest != requestDigest(o.Run.Request) || len(o.Run.Request.Targets) != 1 || c.Target != o.Run.Request.Targets[0] || o.Run.Request.Phase != contract.Liveness || o.Result.Status != contract.Pass && o.Result.Status != contract.Fail {
		return ErrContract
	}
	return nil
}

// NewRequestedContainerControl does not manufacture a liveness observation.
// request/run identify the already accepted signed operation; this constructor
// is not authorization and dispatch still requires the caller's current gate.
func NewRequestedContainerControl(run string, request [32]byte, target contract.Target, action ContainerAction) (ContainerControl, error) {
	c := ContainerControl{Schema: 1, RunID: run, RequestDigest: request, Target: target, Action: action, Phase: ControlPrepared}
	return c, c.Validate()
}

func (c ContainerControl) Validate() error {
	t := c.Target
	if c.Schema != 1 || !digest(c.RunID) || c.RequestDigest == ([32]byte{}) || !name(t.Service) || !text(t.TaskKey, 512) || !text(t.NativeID, 128) || !digest(t.Owner) || !digest(t.OwnerBoot) || t.Generation == 0 || t.Revision < t.Generation || !validInstance(t.StartedAt) {
		return ErrContract
	}
	if c.Action != StartContainer && c.Action != StopContainer && c.Action != RestartContainer {
		return ErrContract
	}
	switch c.Phase {
	case ControlPrepared, ControlCompleted, ControlCanceled:
	case ControlStopSent, ControlStopped:
		if c.Action == StartContainer {
			return ErrContract
		}
	case ControlStartSent:
		if c.Action == StopContainer {
			return ErrContract
		}
	default:
		return ErrContract
	}
	return nil
}

func (c ContainerControl) Terminal() bool {
	return c.Phase == ControlCompleted || c.Phase == ControlCanceled
}

// Observe uses positive SDK identity/state only. Same-instance non-observation
// after a Start never proves non-execution; it leaves start-sent unresolved.
func (c ContainerControl) Observe(v ControlView) (ContainerControl, error) {
	if v.NativeID != c.Target.NativeID || !validInstance(v.StartedAt) {
		return c, ErrStale
	}
	if c.Terminal() {
		return c, nil
	}
	changed := v.StartedAt != c.Target.StartedAt
	switch c.Phase {
	case ControlPrepared:
		if changed {
			c.Phase = ControlCanceled
			break
		}
		if c.Action == StartContainer && v.Running {
			c.Phase = ControlCompleted
		}
		if c.Action != StartContainer && !v.Running {
			c.Phase = ControlStopped
		}
	case ControlStopSent:
		if changed {
			c.Phase = ControlCanceled
		} else if !v.Running && v.Startable {
			c.Phase = ControlStopped
		}
	case ControlStartSent:
		if changed {
			c.Phase = ControlCompleted
		}
	case ControlStopped:
	default:
		return c, ErrContract
	}
	if c.Phase == ControlStopped {
		if c.Action == StopContainer {
			c.Phase = ControlCompleted
		} else if changed || v.Running {
			c.Phase = ControlCanceled
		}
	}
	return c, nil
}

func (c ContainerControl) Next(v ControlView) ContainerAction {
	if c.Phase == ControlPrepared && v.Running && (c.Action == StopContainer || c.Action == RestartContainer) {
		return StopContainer
	}
	if !v.Running && v.Startable && (c.Phase == ControlPrepared && c.Action == StartContainer || c.Phase == ControlStopped && c.Action == RestartContainer) {
		return StartContainer
	}
	return KeepContainer
}

func (c ContainerControl) Dispatch(action ContainerAction) (ContainerControl, error) {
	if action == StopContainer && c.Phase == ControlPrepared && (c.Action == StopContainer || c.Action == RestartContainer) {
		c.Phase = ControlStopSent
		return c, nil
	}
	if action == StartContainer && (c.Phase == ControlPrepared && c.Action == StartContainer || c.Phase == ControlStopped && c.Action == RestartContainer) {
		c.Phase = ControlStartSent
		return c, nil
	}
	return c, ErrPending
}

// CanAdvanceTo compares progress mirrors of the same durable intent. An owner
// may publish several private phases at once; terminal receipts are immutable.
func (c ContainerControl) CanAdvanceTo(next ContainerControl) bool {
	if c.Validate() != nil || next.Validate() != nil {
		return false
	}
	a, b := c, next
	a.Phase = ""
	b.Phase = ""
	if a != b {
		return false
	}
	if c.Terminal() {
		return c == next
	}
	if next.Phase == ControlCanceled {
		return true
	}
	rank := map[ControlPhase]int{ControlPrepared: 0, ControlStopSent: 1, ControlStopped: 2, ControlStartSent: 3, ControlCompleted: 4}
	return rank[next.Phase] >= rank[c.Phase]
}
