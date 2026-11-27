// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"errors"
	"strings"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/reconcile"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
	"github.com/moby/moby/client"
)

// ControlContainer consumes one durable checker receipt. save must sync the
// same observation row before returning; a failed save prevents SDK dispatch.
// Recovery observes sent requests and never retransmits them.
func (m *Manager) ControlContainer(ctx context.Context, observation checker.Observation, control checker.ContainerControl, allowEffects bool, save func(checker.ContainerControl) error, authorize func(context.Context) error) error {
	if save == nil || control.ValidateFor(observation) != nil {
		return checker.ErrContract
	}
	return m.ControlContainerAction(ctx, control, allowEffects, func(next checker.ContainerControl) error {
		if next.ValidateFor(observation) != nil {
			return checker.ErrContract
		}
		return save(next)
	}, authorize)
}

// ControlContainerAction shares the exact Stop/Start/Volume-fence state machine
// between checker policy and explicit user intent. The caller owns the same
// original durable receipt, authorization and publication; no new supervisor or
// fabricated checker pass/fail is introduced. Recovery observes sent requests.
func (m *Manager) ControlContainerAction(ctx context.Context, control checker.ContainerControl, allowEffects bool, save func(checker.ContainerControl) error, authorize func(context.Context) error) error {
	if m == nil || m.driver == nil || m.driver.Engine == nil || m.driver.Engine.API == nil || ctx == nil || save == nil || control.Validate() != nil || allowEffects && authorize == nil {
		return checker.ErrContract
	}
	if !strings.HasSuffix(m.driver.Engine.Owner, "/"+control.Target.Owner) {
		return engine.ErrOwnership
	}
	m.controlMu.Lock()
	defer m.controlMu.Unlock()
	if control.Terminal() {
		return nil
	}
	persist := func(next checker.ContainerControl) error {
		if err := next.Validate(); err != nil {
			return err
		}
		if err := save(next); err != nil {
			return err
		}
		control = next
		return nil
	}
	for steps := 0; steps < 4; steps++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		record, err := m.journal.Read(control.Target.TaskKey)
		if err != nil {
			return err
		}
		if control.Phase == checker.ControlStopSent || control.Phase == checker.ControlStartSent {
			_, err := m.driver.Engine.API.ContainerInspect(ctx, control.Target.NativeID, client.ContainerInspectOptions{})
			if cerrdefs.IsNotFound(err) {
				next := control
				next.Phase = checker.ControlCanceled
				return persist(next)
			}
			if err != nil {
				return err
			}
		}
		if !record.State.Applied.Present || record.State.Applied.Generation != control.Target.Generation {
			// Retirement may have removed the original while its control reply
			// was unknown. Only positive absence of THAT native settles it.
			_, err := m.driver.Engine.API.ContainerInspect(ctx, control.Target.NativeID, client.ContainerInspectOptions{})
			if !cerrdefs.IsNotFound(err) {
				return errors.Join(reconcile.ErrPending, err)
			}
			next := control
			next.Phase = checker.ControlCanceled
			return persist(next)
		}
		op := reconcile.Operation{Kind: reconcile.Apply, ID: record.State.LastID, Target: record.State.Applied, Phase: reconcile.Dispatched}
		spec, _, err := m.driver.parameters(control.Target.TaskKey, op)
		if err != nil {
			return err
		}
		cancelUnsent := func() error {
			if len(spec.Volumes) == 0 || control.Phase != checker.ControlPrepared && control.Phase != checker.ControlStopped {
				return nil
			}
			lookup := op
			lookup.ID = 0
			refs, err := m.driver.originalVolumes(spec, control.Target.TaskKey, lookup)
			if err != nil {
				return err
			}
			return m.driver.Volumes.CancelExistingStart(refs)
		}
		status, err := m.statusRecord(ctx, control.Target.TaskKey, record, false, false, false)
		if cerrdefs.IsNotFound(err) {
			next := control
			next.Phase = checker.ControlCanceled
			return persist(next)
		}
		if err != nil {
			return err
		}
		if control.Phase == checker.ControlStartSent && len(spec.Volumes) > 0 {
			lookup := op
			lookup.ID = 0 // recovery retains the original activation operation
			refs, err := m.driver.originalVolumes(spec, control.Target.TaskKey, lookup)
			if err != nil {
				return err
			}
			if err = m.driver.Volumes.RecoverExistingStart(ctx, refs, control.Target.NativeID, control.Target.StartedAt); err != nil {
				if record.State.Pending != nil || record.State.Desired.Resource != record.State.Applied {
					return reconcile.ErrPending
				}
				return err
			}
		}
		view := checker.ControlView{NativeID: status.NativeID, StartedAt: status.StartedAt, Running: status.Running, Startable: status.Startable}
		next, err := control.Observe(view)
		if err != nil {
			return err
		}
		if next != control {
			if next.Phase == checker.ControlCanceled {
				if err = cancelUnsent(); err != nil {
					return err
				}
			}
			if err = persist(next); err != nil {
				return err
			}
		}
		if control.Terminal() {
			return nil
		}
		current := record.State.Pending == nil && !record.State.Stopped && record.State.Desired.Present && record.State.Desired.Resource == record.State.Applied && record.State.Desired.Revision == control.Target.Revision && !spec.Lifecycle.Drain
		if !current && (control.Phase == checker.ControlPrepared || control.Phase == checker.ControlStopped) {
			if err = cancelUnsent(); err != nil {
				return err
			}
			next := control
			next.Phase = checker.ControlCanceled
			return persist(next)
		}
		action := control.Next(view)
		if !allowEffects || !current || action == checker.KeepContainer {
			return reconcile.ErrPending
		}
		// The requested control owns Stop authorization. TaskAuthority admits
		// creation/activation and may correctly deny a stopped desired state;
		// applying it to Stop would cancel the very stop that set that state.
		// A restart still rechecks activation immediately before its Start.
		if err = authorize(ctx); err == nil && action == checker.StartContainer && m.driver.Authority != nil {
			err = m.driver.Authority(ctx, control.Target.TaskKey, op)
		}
		if err != nil {
			if cancelErr := cancelUnsent(); cancelErr != nil {
				return errors.Join(err, cancelErr)
			}
			next := control
			next.Phase = checker.ControlCanceled
			return errors.Join(err, persist(next))
		}
		fresh, err := m.statusRecord(ctx, control.Target.TaskKey, record, false, false, false)
		if err != nil {
			return err
		}
		if fresh.StartedAt != status.StartedAt || fresh.Running != status.Running {
			continue
		}
		if action == checker.StopContainer {
			policy, err := engine.StopPolicyFromSpec(op.Target.Spec)
			if err != nil {
				return err
			}
			if err = engine.CheckStopBudget(ctx, policy); err != nil {
				return err
			}
			next, err := control.Dispatch(action)
			if err != nil {
				return err
			}
			if err = persist(next); err != nil {
				return err
			}
			if err = m.driver.Engine.StopContainer(ctx, control.Target.NativeID, policy); err != nil {
				return err
			}
		} else if len(spec.Volumes) > 0 {
			refs, err := m.driver.originalVolumes(spec, control.Target.TaskKey, op)
			if err != nil {
				return err
			}
			err = m.driver.Volumes.StartExisting(ctx, refs, control.Target.NativeID, control.Target.StartedAt, func() error {
				next, err := control.Dispatch(checker.StartContainer)
				if err != nil {
					return err
				}
				return persist(next)
			})
			if errors.Is(err, engine.ErrBindBeforeRequest) {
				next := control
				next.Phase = checker.ControlCanceled
				return errors.Join(err, persist(next))
			}
			if err != nil {
				return err
			}
		} else {
			next, err := control.Dispatch(checker.StartContainer)
			if err != nil {
				return err
			}
			if err = persist(next); err != nil {
				return err
			}
			if _, err = m.driver.Engine.API.ContainerStart(ctx, control.Target.NativeID, client.ContainerStartOptions{}); err != nil {
				return err
			}
		}
	}
	return reconcile.ErrPending
}
