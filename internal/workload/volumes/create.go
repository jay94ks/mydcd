// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"context"
	"errors"

	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/storage"
)

// UsesClient binds the native checks and the task SDK effects to one explicit
// local Engine, preventing a mount from being prepared on another endpoint.
func (s *Activations) UsesClient(c *engine.Client) bool { return s != nil && s.client == c }

func (r Activation) Validate() error {
	if !validActivation(r, r.Scope.Cluster, r.Consumer.Owner.Key) {
		return ErrActivation
	}
	return nil
}

// Original resolves only the exact local task binding. Operation must be zero
// because Remove/observation uses the original Apply ID, never its newer ID.
func (s *Activations) Original(r Activation) (Activation, error) {
	if r.Operation != 0 {
		return Activation{}, ErrActivation
	}
	r.Operation = 1
	s.life.RLock()
	defer s.life.RUnlock()
	if owner := s.ownerStore(r.Consumer.Owner.Key); owner != nil && owner != s {
		return owner.Original(originalRef(r))
	}
	if s.closed || !validActivation(r, s.cluster, s.node) {
		return Activation{}, ErrActivation
	}
	s.mu.Lock()
	e := s.entries[r.Consumer.Owner.Native]
	s.mu.Unlock()
	if e == nil {
		return Activation{}, storage.ErrMissing
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	i := bindingIndex(e.disk, r)
	if i < 0 {
		return Activation{}, storage.ErrMissing
	}
	original := e.disk.Bindings[i].Ref
	normalized := original
	normalized.Operation = 1
	if normalized != r {
		return Activation{}, ErrActivation
	}
	return original, nil
}

// CreateUnpreparedAll proves a newer task never crossed the whole-batch
// preparation barrier. Every mount must retain its older, positively closed
// binding for the same task/consumer. Missing history is never this proof.
// planAll only replaces that binding with a strictly newer generation, and
// CreateAll requires all replacements synced before dispatching the SDK call.
func (s *Activations) CreateUnpreparedAll(refs []Activation) (bool, error) {
	refs, err := activationBatch(refs)
	if err != nil {
		return false, err
	}
	s.life.RLock()
	defer s.life.RUnlock()
	var rows []activationBatchEntry
	defer func() {
		for i := len(rows) - 1; i >= 0; i-- {
			rows[i].e.mu.Unlock()
		}
	}()
	for _, r := range refs {
		e, err := s.entry(r, false)
		if errors.Is(err, storage.ErrMissing) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		e.mu.Lock()
		rows = append(rows, activationBatchEntry{r: r, e: e, d: e.disk, i: bindingIndex(e.disk, r)})
	}
	for _, row := range rows {
		if row.i < 0 {
			return false, nil
		}
		b := row.d.Bindings[row.i]
		old, next := b.Ref, row.r
		if !b.Closed || !b.Released || row.d.Gate.Starting != nil ||
			old.TaskKey != next.TaskKey || old.Scope != next.Scope ||
			old.NativeKey != next.NativeKey || old.NativeGeneration != next.NativeGeneration ||
			old.NativeBinding != next.NativeBinding || old.Consumer.ID != next.Consumer.ID ||
			old.Consumer.Owner != next.Consumer.Owner || old.Consumer.Generation >= next.Consumer.Generation ||
			old.Task.Generation >= next.Task.Generation || old.Operation >= next.Operation {
			return false, nil
		}
	}
	return true, nil
}

// PrepareCreateAll records the positive pre-dispatch state for ALL mounts
// before Borrow. Partial pin/receipt failure therefore keeps an original,
// recoverable no-Create intent instead of an unprovable absent container.
func (s *Activations) PrepareCreateAll(ctx context.Context, refs []Activation) error {
	return s.planAll(ctx, refs, true)
}

func (s *Activations) planAll(ctx context.Context, refs []Activation, create bool) error {
	refs, err := activationBatch(refs)
	if err != nil {
		return err
	}
	s.life.RLock()
	defer s.life.RUnlock()
	rows, unlock, err := s.lockBatchEntries(refs, false)
	if err != nil {
		return err
	}
	defer unlock()
	for i := range rows {
		row := &rows[i]
		r := row.r
		if row.i >= 0 && row.d.Bindings[row.i].Ref == r {
			b := row.d.Bindings[row.i]
			if b.Closed || create && !b.CreatePrepared {
				return ErrActivation
			}
			continue
		}
		if row.i >= 0 && (!row.d.Bindings[row.i].Closed || !row.d.Bindings[row.i].Released || row.d.Bindings[row.i].Ref.Consumer.Generation >= r.Consumer.Generation) || row.i < 0 && len(row.d.Bindings) >= 256 || r.Consumer.OwnerRevision <= row.d.Gate.FenceThrough {
			return ErrActivation
		}
		owner, scope, err := row.e.store.native.Owner(ctx, r.NativeKey)
		if err != nil || owner != r.Consumer.Owner || scope != r.Scope {
			return errors.Join(ErrActivation, err)
		}
		b := activationBinding{Ref: r, CreatePrepared: create, Lease: NativeLease{Key: r.NativeKey, Consumer: activationID(r), Owner: r.Consumer.Owner, Scope: r.Scope, Pin: reconcile.Lease{Generation: r.NativeGeneration}}}
		if row.i >= 0 {
			row.d.Bindings[row.i] = b
		} else {
			row.i = len(row.d.Bindings)
			row.d.Bindings = append(row.d.Bindings, b)
		}
	}
	if err = s.saveBatch(rows); err != nil {
		return err
	}
	for i := range rows {
		row := &rows[i]
		if row.d.Bindings[row.i].Lease.Pin.Token != 0 {
			continue
		}
		lease, err := row.e.store.native.Pin(ctx, row.r.NativeKey, activationID(row.r), row.r.NativeGeneration)
		if err != nil {
			return err
		}
		row.d.Bindings[row.i].Lease = lease
	}
	return s.saveBatch(rows)
}

func (s *Activations) CreatePreparedAll(refs []Activation) (bool, error) {
	refs, err := activationBatch(refs)
	if err != nil {
		return false, err
	}
	s.life.RLock()
	defer s.life.RUnlock()
	rows, unlock, err := s.lockBatch(refs)
	if err != nil {
		return false, err
	}
	defer unlock()
	prepared := rows[0].d.Bindings[rows[0].i].CreatePrepared
	for _, row := range rows {
		if row.d.Bindings[row.i].CreatePrepared != prepared {
			return false, ErrActivation
		}
	}
	return prepared, nil
}

// DispatchCreateAll consumes the no-Create fact atomically, BEFORE the actual
// SDK request. A lost response can never turn back into CreatePrepared.
func (s *Activations) DispatchCreateAll(refs []Activation) error {
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
	for i := range rows {
		b := &rows[i].d.Bindings[rows[i].i]
		// Fixed effects must keep source descriptors and inspect the actual
		// Docker peer through CreateAll, not a bare dispatch acknowledgement.
		if rows[i].r.Scope.TenantManaged() {
			return ErrActivation
		}
		if !b.CreatePrepared || b.Closed || b.Started || b.NativeID != "" || b.Lease.Pin.Token == 0 {
			return ErrActivation
		}
		b.CreatePrepared = false
	}
	return s.saveBatch(rows)
}

// InspectAll checks the original binding/pin/native ownership without obtaining
// a permit, borrowing a new reference or changing a stopped process.
func (s *Activations) InspectAll(ctx context.Context, refs []Activation, nativeID string) error {
	refs, err := activationBatch(refs)
	if err != nil || !validNativeID(nativeID) {
		return ErrActivation
	}
	s.life.RLock()
	defer s.life.RUnlock()
	rows, unlock, err := s.lockBatch(refs)
	if err != nil {
		return err
	}
	defer unlock()
	for _, row := range rows {
		b := row.d.Bindings[row.i]
		if b.Closed || b.CreatePrepared || !b.Started || b.NativeID != nativeID || row.d.Gate.Starting != nil && *row.d.Gate.Starting == row.r.Consumer {
			return reconcile.ErrPending
		}
		state, err := row.e.store.native.View(row.r.NativeKey)
		if err != nil || !state.State.Applied.Present || state.State.Applied.Generation != row.r.NativeGeneration || state.Consumers[b.Lease.Consumer] != b.Lease.Pin {
			return errors.Join(ErrActivation, err)
		}
		owner, scope, err := row.e.store.native.recordedOwner(row.r.NativeKey, state.State.Applied)
		if err == nil && !row.r.Scope.TenantManaged() {
			owner, scope, err = row.e.store.native.inspect(ctx, row.r.NativeKey, state.State.Applied)
		}
		if err != nil || owner != row.r.Consumer.Owner || scope != row.r.Scope {
			return errors.Join(ErrActivation, err)
		}
		got, err := s.container(ctx, row.r, nativeID)
		if err != nil || !s.completeVolumeMounts(got, refs) {
			return errors.Join(ErrActivation, err)
		}
		if got.State.Running {
			if err = s.checkFixedProcess(ctx, rows, got); err != nil {
				return err
			}
		}
	}
	return nil
}
