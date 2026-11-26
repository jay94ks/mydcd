// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"context"
	"crypto/rand"
	"errors"
	"time"

	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

// requestActivationStarts is shared by the initial and lifecycle Start. The
// caller holds every original volume's Fence lock through the native request.
func (s *Activations) requestActivationStarts(ctx context.Context, rows []activationBatchEntry) error {
	for i := range rows {
		row := &rows[i]
		owner, scope, err := row.e.store.native.Owner(ctx, row.r.NativeKey)
		if err != nil || owner != row.r.Consumer.Owner || scope != row.r.Scope {
			return errors.Join(ErrActivation, err)
		}
		var challenge [32]byte
		if _, err = rand.Read(challenge[:]); err != nil {
			return err
		}
		g, request, err := row.g.Request(row.r.Consumer, challenge)
		if err != nil {
			return err
		}
		row.e.gate, err = g.CancelRequest(request)
		if err != nil {
			return err
		}
		permit, err := s.authority(ctx, request)
		if err != nil {
			return err
		}
		row.g, err = g.Accept(permit)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Activations) existingStartState(ctx context.Context, refs []Activation, rows []activationBatchEntry, native string) (container.State, error) {
	var result container.State
	for i, row := range rows {
		b := row.d.Bindings[row.i]
		if b.Closed || b.Released || b.Unsent || b.CreatePrepared || b.StopSent || !b.Started || b.NativeID != native || row.d.Gate.Starting != nil && *row.d.Gate.Starting != row.r.Consumer {
			return result, ErrActivation
		}
		state, err := row.e.store.native.View(row.r.NativeKey)
		if err != nil || !state.State.Applied.Present || state.State.Applied.Generation != row.r.NativeGeneration || state.Consumers[b.Lease.Consumer] != b.Lease.Pin {
			return result, errors.Join(ErrActivation, err)
		}
		owner, scope, err := row.e.store.native.Owner(ctx, row.r.NativeKey)
		if err != nil || owner != row.r.Consumer.Owner || scope != row.r.Scope {
			return result, errors.Join(ErrActivation, err)
		}
		got, err := s.container(ctx, row.r, native)
		if err != nil || !s.completeVolumeMounts(got, refs) {
			return result, errors.Join(engine.ErrOwnership, err)
		}
		stamp, err := time.Parse(time.RFC3339Nano, got.State.StartedAt)
		if err != nil || stamp.IsZero() || i > 0 && (result.StartedAt != got.State.StartedAt || result.Running != got.State.Running) {
			return result, engine.ErrOwnership
		}
		if got.State.Running {
			if err = s.checkFixedProcess(ctx, rows, got); err != nil {
				return result, err
			}
		}
		result = *got.State
	}
	return result, nil
}

func (s *Activations) settleExistingStarts(rows []activationBatchEntry, outcome reconcile.Outcome) error {
	for i := range rows {
		row := &rows[i]
		if row.d.Gate.Starting == nil {
			continue
		}
		var err error
		row.g, err = row.g.SettleStart(row.r.Consumer, outcome)
		if err != nil {
			return err
		}
	}
	return s.saveBatch(rows)
}

// CancelExistingStart requires the caller's original receipt to be positively
// unsent. It cancels only that task's accepted grant, never a dispatched Start.
func (s *Activations) CancelExistingStart(refs []Activation) error {
	refs, err := activationBatch(refs)
	if err != nil {
		return err
	}
	s.life.RLock()
	defer s.life.RUnlock()
	rows, unlock, err := s.lockBatch(refs)
	if err != nil {
		return err
	}
	defer unlock()
	changed := false
	for _, row := range rows {
		if row.d.Gate.Starting == nil {
			continue
		}
		if *row.d.Gate.Starting != row.r.Consumer || !row.d.Bindings[row.i].Started {
			return ErrActivation
		}
		changed = true
	}
	if !changed {
		return nil
	}
	return s.settleExistingStarts(rows, reconcile.EffectNotApplied)
}

// StartExisting requires the caller's durable UNSENT lifecycle receipt.
// beforeStart syncs its start-sent marker after the accepted volume permits
// and before SDK dispatch. A response loss retains the original Starting.
func (s *Activations) StartExisting(ctx context.Context, refs []Activation, native, before string, beforeStart func() error) error {
	if ctx == nil || beforeStart == nil || !validNativeID(native) {
		return ErrActivation
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	refs, err := activationBatch(refs)
	if err != nil {
		return err
	}
	s.life.RLock()
	defer s.life.RUnlock()
	rows, unlock, err := s.lockBatch(refs)
	if err != nil {
		return err
	}
	defer unlock()
	state, err := s.existingStartState(ctx, refs, rows, native)
	if err != nil {
		return err
	}
	if state.Running || state.Paused || state.Restarting || state.Dead || state.Pid != 0 || state.StartedAt != before || state.Status != container.StateExited {
		return reconcile.ErrPending
	}
	// A retained grant with a positively unsent original receipt cannot have
	// dispatched a Start. Clear only that grant before a fresh current permit.
	if err = s.settleExistingStarts(rows, reconcile.EffectNotApplied); err != nil {
		return err
	}
	api, closeAPI, err := s.bindClient(ctx, rows)
	if err != nil {
		return err
	}
	defer closeAPI()
	if err = s.requestActivationStarts(ctx, rows); err != nil {
		return err
	}
	if err = s.saveBatch(rows); err != nil {
		return err
	}
	if err = beforeStart(); err != nil {
		return errors.Join(err, s.settleExistingStarts(rows, reconcile.EffectNotApplied))
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if _, err = api.ContainerStart(ctx, native, client.ContainerStartOptions{}); err != nil {
		if errors.Is(err, engine.ErrBindBeforeRequest) {
			return errors.Join(err, s.settleExistingStarts(rows, reconcile.EffectNotApplied))
		}
		return err
	}
	state, err = s.existingStartState(ctx, refs, rows, native)
	if err != nil {
		return err
	}
	if state.StartedAt == before {
		return reconcile.ErrPending
	}
	return s.settleExistingStarts(rows, reconcile.EffectApplied)
}

// RecoverExistingStart never requests a new permit or sends Start. The same
// native's changed StartedAt proves a new execution; the previous exit does not.
func (s *Activations) RecoverExistingStart(ctx context.Context, refs []Activation, native, before string) error {
	if ctx == nil || !validNativeID(native) {
		return ErrActivation
	}
	refs, err := activationBatch(refs)
	if err != nil {
		return err
	}
	s.life.RLock()
	defer s.life.RUnlock()
	rows, unlock, err := s.lockBatch(refs)
	if err != nil {
		return err
	}
	defer unlock()
	state, err := s.existingStartState(ctx, refs, rows, native)
	if err != nil {
		return err
	}
	if state.StartedAt == before {
		return reconcile.ErrPending
	}
	return s.settleExistingStarts(rows, reconcile.EffectApplied)
}
