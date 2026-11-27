// SPDX-License-Identifier: Apache-2.0

package reconcile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jay94ks/seafield/internal/storage"
	"sort"
	"strings"
	"sync"
)

// Driver must recover the EXACT original operation. Absence after a timeout is
// not proof of non-execution: an accepted external call may still be running.
// Only a terminal, authoritative observation may return EffectNotApplied.
// EffectNotApplied may carry its failure cause: the journal persists this
// positive evidence before returning the error. Every other error is Unknown.
// Recover may complete idempotent substeps on a positively identified original
// object. It must not recreate an absent object or substitute a new operation.
type Driver interface {
	Execute(context.Context, string, Operation) (Outcome, error)
	Recover(context.Context, string, Operation) (Outcome, error)
}

// RetirementDriver may compensate an obsolete original Apply. It must persist
// any positively observed native identity through save BEFORE removing it.
// true requires original closure and all dependency returns, never just absence.
type RetirementDriver interface {
	Retire(context.Context, string, Operation, []byte, func([]byte) error) (bool, error)
}

// RemovalDriver keeps an original normal Remove's closure/dispatch receipt in
// this same journal. Recovery receives the original bytes and operation; it
// must never treat Unknown as permission to repeat an irreversible request.
type RemovalDriver interface {
	RemoveCheckpoint(context.Context, string, Operation, []byte, func([]byte) error) (Outcome, error)
}

// InPlaceDriver may update a live resource under its current consumers: a
// same-generation Apply whose change keeps the native identity the consumers
// hold (a TUN's route set). Any other Apply still waits for no consumers.
type InPlaceDriver interface {
	InPlace(applied, target Resource) bool
}

// CheckpointDriver may sync a positively observed immutable identity during
// the first dispatched Apply, BEFORE writing data into that original object.
// Recovery cannot invent a checkpoint. The callback is valid only for this
// call; a failed save prevents Applied even if the driver ignores the error.
type CheckpointDriver interface {
	ExecuteCheckpoint(context.Context, string, Operation, func([]byte) error) (Outcome, error)
}
type EffectCheckpoint struct {
	Operation uint64
	Target    Resource
	Data      []byte
}

// Record combines operation intent and its durable consumers in one sync write.
// Consumer IDs identify durable owners, not process IDs or inferred liveness.
type Record struct {
	Schema     uint8
	State      State
	Pins       *LeaseJournal
	Consumers  map[string]Lease
	Capacity   int
	Scope      ConsumerScope     `json:",omitzero"`
	Retirement []byte            `json:",omitempty"` // original closure receipt: Retiring or dispatched/recovering Remove
	Checkpoint *EffectCheckpoint `json:",omitempty"`
}

type journalEntry struct {
	mu     sync.Mutex
	r      Record
	failed bool // a DB write may have committed; reopen the same durable journal
}

var ErrJournalUncertain = errors.New("journal write uncertain; same database recovery required")

// Journal owns one local module DB. Independent resources can progress in
// parallel; each resource serializes intent, native work, inspection and pins.
// Close waits for admitted work and never removes external resources or pins.
type Journal struct {
	life    sync.RWMutex
	mu      sync.Mutex
	db      *storage.DB
	entries map[string]*journalEntry
	closed  bool
}

func OpenJournal(path string) (*Journal, error) {
	db, err := storage.Open(path)
	if err != nil {
		return nil, err
	}
	j := &Journal{db: db, entries: map[string]*journalEntry{}}
	rows, err := db.Scan("resource/")
	if err == nil {
		for k, b := range rows {
			var r Record
			key := strings.TrimPrefix(k, "resource/")
			if !journalKey(key) || json.Unmarshal(b, &r) != nil || validateRecord(r) != nil {
				err = ErrOperation
				break
			}
			j.entries[key] = &journalEntry{r: r}
		}
	}
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return j, nil
}

func journalKey(k string) bool { return k != "" && len(k) <= 512 && !strings.ContainsRune(k, 0) }

func validateRecord(r Record) error {
	if r.Schema != 1 || r.Capacity <= 0 || Validate(r.State) != nil {
		return ErrOperation
	}
	if r.Scope != (ConsumerScope{}) && !r.Scope.Valid() {
		return ErrLease
	}
	if len(r.Retirement) > 64<<10 || len(r.Retirement) > 0 && (r.State.Pending == nil || r.State.Pending.Phase != Retiring && !(r.State.Pending.Kind == Remove && (r.State.Pending.Phase == Dispatched || r.State.Pending.Phase == RecoveryRequired))) {
		return ErrOperation
	}
	if c := r.Checkpoint; c != nil {
		if c.Operation == 0 || c.Operation > r.State.LastID || len(c.Data) == 0 || len(c.Data) > 64<<10 || !c.Target.Present || !validResource(c.Target) || c.Target.Generation > r.State.GenerationFloor {
			return ErrOperation
		}
		applied := r.State.Applied == c.Target
		pending := r.State.Pending != nil && r.State.Pending.Kind == Apply && r.State.Pending.ID == c.Operation && r.State.Pending.Target == c.Target && r.State.Pending.Phase != Prepared
		if !applied && !pending {
			return ErrOperation
		}
	}
	if r.Pins == nil {
		if r.State.Applied.Present || len(r.Consumers) != 0 {
			return ErrLease
		}
		return nil
	}
	l, err := RestoreLeases(*r.Pins)
	if err != nil || r.Pins.Capacity != r.Capacity || l.Count() != len(r.Consumers) || r.Pins.Generation > r.State.GenerationFloor || r.State.Applied.Present && r.Pins.Generation != r.State.Applied.Generation {
		return ErrLease
	}
	seen := map[uint64]bool{}
	for consumer, pin := range r.Consumers {
		if !journalKey(consumer) || seen[pin.Token] || l.active[pin.Token] != pin {
			return ErrLease
		}
		seen[pin.Token] = true
	}
	return nil
}

func cloneRecord(r Record) Record {
	r.Retirement = append([]byte(nil), r.Retirement...)
	if r.Checkpoint != nil {
		own := *r.Checkpoint
		own.Data = append([]byte(nil), own.Data...)
		r.Checkpoint = &own
	}
	r.State = copyState(r.State)
	if r.Pins != nil {
		p := *r.Pins
		p.Active = append([]Lease(nil), p.Active...)
		r.Pins = &p
	}
	m := map[string]Lease{}
	for k, v := range r.Consumers {
		m[k] = v
	}
	r.Consumers = m
	return r
}

func (j *Journal) entry(key string, create bool) (*journalEntry, error) {
	if j.closed || !journalKey(key) {
		return nil, ErrOperation
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	e := j.entries[key]
	if e == nil && create {
		e = &journalEntry{}
		j.entries[key] = e
	}
	if e == nil {
		return nil, storage.ErrMissing
	}
	return e, nil
}

// save publishes a candidate only after the synchronous DB transaction succeeds.
func (j *Journal) save(key string, e *journalEntry, r Record) error {
	if e.failed {
		return ErrJournalUncertain
	}
	if err := validateRecord(r); err != nil {
		return err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if err = j.db.Write(map[string][]byte{"resource/" + key: b}); err != nil {
		e.failed = true
		return errors.Join(ErrJournalUncertain, err)
	}
	e.r = r
	return nil
}

// Desired accepts only committed Desired. An admission-budget change is synced
// with that Desired, preserving all existing consumers and operation evidence.
func (j *Journal) Desired(key string, d Desired, capacity int) error {
	j.life.RLock()
	defer j.life.RUnlock()
	e, err := j.entry(key, true)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.failed {
		return ErrJournalUncertain
	}
	if e.r.Schema == 1 && e.r.State.Desired == d && e.r.Capacity == capacity {
		return nil
	}
	r := cloneRecord(e.r)
	if r.Schema == 0 {
		r = Record{Schema: 1, Capacity: capacity, Consumers: map[string]Lease{}}
	} else if capacity != r.Capacity {
		if capacity <= 0 {
			return ErrLease
		}
		if r.Pins != nil {
			l, restoreErr := RestoreLeases(*r.Pins)
			if restoreErr != nil {
				return restoreErr
			}
			if err = l.Resize(capacity); err != nil {
				return err
			}
			p := l.Checkpoint()
			r.Pins = &p
		}
		r.Capacity = capacity
	}
	r.State, err = SetDesired(r.State, d)
	if err != nil {
		return fmt.Errorf("desired key=%s incoming_revision=%d current_revision=%d incoming_generation=%d applied_generation=%d incoming_retiring=%d current_retiring=%d spec_changed=%t: %w", key, d.Revision, e.r.State.Desired.Revision, d.Generation, e.r.State.Applied.Generation, d.Retiring, e.r.State.Desired.Retiring, d.Spec != e.r.State.Desired.Spec, err)
	}
	return j.save(key, e, r)
}

func (j *Journal) Read(key string) (Record, error) {
	j.life.RLock()
	defer j.life.RUnlock()
	e, err := j.entry(key, false)
	if err != nil {
		return Record{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.failed {
		return Record{}, ErrJournalUncertain
	}
	if e.r.Schema == 0 {
		return Record{}, storage.ErrMissing
	}
	return cloneRecord(e.r), nil
}

// AppliedAbsenceDriver is only for synchronous local effects whose previous
// execution has a durable terminal Applied receipt. It cannot settle Unknown.
type AppliedAbsenceDriver interface {
	Driver
	AppliedAbsent(context.Context, string, Resource) (bool, error)
}

// RestoreApplied persists a new local repair intent while retaining the same
// confirmed resource and all consumer tokens. Step owns dispatch/recovery.
func (j *Journal) RestoreApplied(ctx context.Context, key string, driver AppliedAbsenceDriver) error {
	if driver == nil {
		return ErrOperation
	}
	j.life.RLock()
	defer j.life.RUnlock()
	e, err := j.entry(key, false)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.failed {
		return ErrJournalUncertain
	}
	r := cloneRecord(e.r)
	if r.Schema == 0 {
		return storage.ErrMissing
	}
	if r.State.Pending != nil || !r.State.Applied.Present || r.State.Desired.Resource != r.State.Applied {
		return nil
	}
	if r.State.Stopped {
		return ErrStopped
	}
	if r.Checkpoint != nil || len(r.Retirement) != 0 {
		return ErrOperation
	}
	absent, err := driver.AppliedAbsent(ctx, key, r.State.Applied)
	if err != nil || !absent {
		return err
	}
	r.State, err = PlanRestore(r.State)
	if err != nil {
		return err
	}
	return j.save(key, e, r)
}

func inPlace(driver Driver, applied Resource, op *Operation) bool {
	d, ok := driver.(InPlaceDriver)
	return ok && op.Kind == Apply && applied.Present && op.Target.Generation == applied.Generation && d.InPlace(applied, op.Target)
}

// Step executes a newly persisted dispatch once. Restored/uncertain dispatches
// are inspected, never automatically resubmitted under a new operation ID.
func (j *Journal) Step(ctx context.Context, key string, driver Driver) error {
	if driver == nil {
		return ErrOperation
	}
	j.life.RLock()
	defer j.life.RUnlock()
	e, err := j.entry(key, false)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.failed {
		return ErrJournalUncertain
	}
	r := cloneRecord(e.r)
	if r.Schema == 0 {
		return storage.ErrMissing
	}
	if r.State.Pending != nil && r.State.Pending.Phase == Retiring {
		if _, ok := driver.(RetirementDriver); !ok {
			return ErrOperation
		}
	}
	if len(r.Retirement) != 0 && r.State.Pending != nil && r.State.Pending.Kind == Remove {
		if _, ok := driver.(RemovalDriver); !ok {
			return ErrOperation
		}
	}
	if retire, ok := driver.(RetirementDriver); ok && r.State.Pending != nil && r.State.Pending.Kind == Apply && (!r.State.Desired.Present || r.State.Desired.Generation != r.State.Pending.Target.Generation) {
		if r.State.Pending.Phase == Prepared {
			r.State, err = AbortPrepared(r.State, r.State.Pending.ID)
			if err != nil {
				return err
			}
			return j.save(key, e, r)
		}
		if r.Pins != nil {
			l, _ := RestoreLeases(*r.Pins)
			l.Drain()
			p := l.Checkpoint()
			r.Pins = &p
			if !l.CanRetire() {
				if err = j.save(key, e, r); err != nil {
					return err
				}
				return ErrPending
			}
		}
		r.State, err = BeginRetirement(r.State, r.State.Pending.ID)
		if err != nil {
			return err
		}
		if err = j.save(key, e, r); err != nil {
			return err
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		op := *r.State.Pending
		save := func(receipt []byte) error {
			candidate := cloneRecord(r)
			candidate.Retirement = append([]byte(nil), receipt...)
			if err := j.save(key, e, candidate); err != nil {
				return err
			}
			r = candidate
			return nil
		}
		closed, callErr := retire.Retire(ctx, key, op, append([]byte(nil), r.Retirement...), save)
		if callErr != nil {
			return callErr
		}
		r.State, err = FinishRetirement(r.State, op.ID, closed)
		if err != nil {
			return err
		}
		if closed {
			r.Retirement = nil
			r.Checkpoint = nil
		}
		if err = j.save(key, e, r); err != nil {
			return err
		}
		if !closed {
			return ErrPending
		}
		return nil
	}
	fresh := false
	if r.State.Pending == nil {
		var op *Operation
		r.State, op, err = Plan(r.State)
		if err != nil || op == nil {
			return err
		}
		if op.Kind == Remove && r.Pins != nil {
			l, _ := RestoreLeases(*r.Pins)
			l.Drain()
			p := l.Checkpoint()
			r.Pins = &p
			// Persist Drain without a dispatch, retaining all current users.
			if !l.CanRetire() {
				r.State = e.r.State
				if err = j.save(key, e, r); err != nil {
					return err
				}
				return ErrPending
			}
		} else if r.Pins != nil && len(r.Pins.Active) != 0 && !inPlace(driver, r.State.Applied, op) {
			return ErrLease
		}
		if err = j.save(key, e, r); err != nil {
			return err
		}
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if r.State.Pending.Phase == Prepared {
		r.State, err = Dispatch(r.State, r.State.Pending.ID)
		if err != nil {
			return err
		}
		if err = j.save(key, e, r); err != nil {
			return err
		}
		fresh = true
	}
	op := *r.State.Pending
	var outcome Outcome
	if removal, ok := driver.(RemovalDriver); ok && op.Kind == Remove {
		var saveErr error
		open := true
		save := func(data []byte) error {
			if !open {
				return ErrOperation
			}
			if len(data) == 0 || len(data) > 64<<10 {
				saveErr = ErrOperation
				return saveErr
			}
			candidate := cloneRecord(r)
			candidate.Retirement = bytes.Clone(data)
			if writeErr := j.save(key, e, candidate); writeErr != nil {
				saveErr = writeErr
				return writeErr
			}
			r = candidate
			return nil
		}
		outcome, err = removal.RemoveCheckpoint(ctx, key, op, bytes.Clone(r.Retirement), save)
		open = false
		if saveErr != nil {
			outcome, err = EffectUnknown, errors.Join(err, saveErr)
		}
	} else if fresh {
		if checkpoint, ok := driver.(CheckpointDriver); ok && op.Kind == Apply {
			var saveErr error
			open := true
			save := func(data []byte) error {
				if !open {
					return ErrOperation
				}
				if len(data) == 0 || len(data) > 64<<10 {
					saveErr = ErrOperation
					return saveErr
				}
				if r.Checkpoint != nil {
					if r.Checkpoint.Operation != op.ID || r.Checkpoint.Target != op.Target || !bytes.Equal(r.Checkpoint.Data, data) {
						saveErr = ErrOperation
						return saveErr
					}
					return nil
				}
				candidate := cloneRecord(r)
				candidate.Checkpoint = &EffectCheckpoint{Operation: op.ID, Target: op.Target, Data: append([]byte(nil), data...)}
				if writeErr := j.save(key, e, candidate); writeErr != nil {
					saveErr = writeErr
					return writeErr
				}
				r = candidate
				return nil
			}
			outcome, err = checkpoint.ExecuteCheckpoint(ctx, key, op, save)
			open = false
			if saveErr != nil {
				outcome = EffectUnknown
				err = errors.Join(err, saveErr)
			}
		} else {
			outcome, err = driver.Execute(ctx, key, op)
		}
	} else {
		outcome, err = driver.Recover(ctx, key, op)
	}
	if err != nil && outcome != EffectNotApplied || outcome < EffectApplied || outcome > EffectUnknown {
		outcome = EffectUnknown
	}
	r.State, _ = Settle(r.State, op.ID, outcome)
	if outcome == EffectApplied && op.Kind == Remove {
		r.Checkpoint = nil
		r.Retirement = nil
	}
	if outcome == EffectApplied && op.Kind == Apply {
		var l *Leases
		if r.Pins == nil {
			l, _ = NewLeases(op.Target.Generation, r.Capacity)
		} else {
			l, _ = RestoreLeases(*r.Pins)
			if l.generation != op.Target.Generation {
				if replaceErr := l.Replace(op.Target.Generation); replaceErr != nil {
					return replaceErr
				}
			}
		}
		p := l.Checkpoint()
		r.Pins = &p
	}
	if saveErr := j.save(key, e, r); saveErr != nil {
		return saveErr
	}
	if err != nil {
		return err
	}
	if outcome == EffectUnknown {
		return ErrPending
	}
	return nil
}

func (j *Journal) Borrow(key, consumer string, generation uint64) (Lease, error) {
	return j.borrow(key, consumer, generation, nil)
}

// BorrowLimited atomically records a currently authorized source's capacity
// with its new pin. A rejected shrink retains the new cap and every old pin.
// sourceRevision is the Desired used for the permission lookup, preventing a
// delayed answer from admitting into a replacement source. Exact existing pins
// remain recoverable without treating their lookup as a fresh admission.
func (j *Journal) BorrowLimited(key, consumer string, generation, sourceRevision uint64, capacity int) (Lease, error) {
	return j.borrow(key, consumer, generation, &consumerAdmission{revision: sourceRevision, capacity: capacity})
}

func (j *Journal) BorrowScoped(key, consumer string, generation, sourceRevision uint64, capacity int, scope ConsumerScope) (Lease, error) {
	if !scope.Valid() {
		return Lease{}, ErrLease
	}
	return j.borrow(key, consumer, generation, &consumerAdmission{revision: sourceRevision, capacity: capacity, scope: scope})
}

type consumerAdmission struct {
	revision uint64
	capacity int
	scope    ConsumerScope
}

func (j *Journal) borrow(key, consumer string, generation uint64, admission *consumerAdmission) (Lease, error) {
	j.life.RLock()
	defer j.life.RUnlock()
	e, err := j.entry(key, false)
	if err != nil {
		return Lease{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.failed {
		return Lease{}, ErrJournalUncertain
	}
	r := cloneRecord(e.r)
	if !journalKey(consumer) || r.Pins == nil || generation != r.Pins.Generation {
		return Lease{}, ErrLease
	}
	if pin, exists := r.Consumers[consumer]; exists {
		if admission != nil && admission.scope != (ConsumerScope{}) && r.Scope != (ConsumerScope{}) && admission.scope != r.Scope {
			return Lease{}, ErrLease
		}
		return pin, nil
	}
	if r.State.Stopped || r.State.Pending != nil || !r.State.Applied.Present || r.State.Applied != r.State.Desired.Resource {
		return Lease{}, ErrLease
	}
	if admission != nil && (admission.revision == 0 || admission.revision != r.State.Desired.Revision || admission.capacity < 1) {
		return Lease{}, ErrLease
	}
	if r.Scope != (ConsumerScope{}) && (admission == nil || admission.scope != r.Scope) {
		return Lease{}, ErrLease
	}
	l, err := RestoreLeases(*r.Pins)
	if err != nil {
		return Lease{}, err
	}
	resized := admission != nil && r.Capacity != admission.capacity
	if resized {
		if err := l.Resize(admission.capacity); err != nil {
			return Lease{}, err
		}
		r.Capacity = admission.capacity
	}
	pin, err := l.Acquire()
	if err != nil {
		if resized {
			p := l.Checkpoint()
			r.Pins = &p
			if saveErr := j.save(key, e, r); saveErr != nil {
				return Lease{}, saveErr
			}
		}
		return Lease{}, err
	}
	p := l.Checkpoint()
	r.Pins, r.Consumers[consumer] = &p, pin
	if admission != nil && admission.scope != (ConsumerScope{}) {
		r.Scope = admission.scope
	}
	if err = j.save(key, e, r); err != nil {
		return Lease{}, err
	}
	return pin, nil
}

func (j *Journal) Return(key, consumer string, pin Lease) error {
	j.life.RLock()
	defer j.life.RUnlock()
	e, err := j.entry(key, false)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.failed {
		return ErrJournalUncertain
	}
	r := cloneRecord(e.r)
	if r.Pins == nil || r.Consumers[consumer] != pin || pin == (Lease{}) {
		return ErrLease
	}
	l, _ := RestoreLeases(*r.Pins)
	if err = l.Release(pin); err != nil {
		return err
	}
	p := l.Checkpoint()
	r.Pins = &p
	delete(r.Consumers, consumer)
	return j.save(key, e, r)
}

func (j *Journal) Close() error {
	j.life.Lock()
	defer j.life.Unlock()
	if j.closed {
		return nil
	}
	j.closed = true
	return j.db.Close()
}

func (j *Journal) Keys() []string {
	j.life.RLock()
	defer j.life.RUnlock()
	j.mu.Lock()
	entries := make(map[string]*journalEntry, len(j.entries))
	for k, e := range j.entries {
		entries[k] = e
	}
	j.mu.Unlock()
	keys := make([]string, 0, len(entries))
	for k, e := range entries {
		e.mu.Lock()
		if e.r.Schema == 1 {
			keys = append(keys, k)
		}
		e.mu.Unlock()
	}
	sort.Strings(keys)
	return keys
}
