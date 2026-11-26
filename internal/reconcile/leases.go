// SPDX-License-Identifier: Apache-2.0

package reconcile

import (
	"errors"
	"sort"
)

var ErrLease = errors.New("invalid lease, capacity, or generation transition")

type Lease struct{ Token, Generation uint64 }

// Leases is single-owner bookkeeping. Persist Checkpoint before publishing a
// borrow/release/drain; Restore keeps all pins until their owners are reconciled.
type Leases struct {
	generation, next uint64
	capacity         int
	draining         bool
	active           map[uint64]Lease
}

func NewLeases(generation uint64, capacity int) (*Leases, error) {
	if generation == 0 || capacity <= 0 {
		return nil, ErrLease
	}
	return &Leases{generation: generation, capacity: capacity, active: make(map[uint64]Lease)}, nil
}

func (b *Leases) Acquire() (Lease, error) {
	if b.draining || len(b.active) >= b.capacity || b.next == ^uint64(0) {
		return Lease{}, ErrLease
	}
	b.next++
	l := Lease{Token: b.next, Generation: b.generation}
	b.active[l.Token] = l
	return l, nil
}

func (b *Leases) Release(l Lease) error {
	stored, ok := b.active[l.Token]
	if !ok || stored != l {
		return ErrLease
	}
	delete(b.active, l.Token)
	return nil
}

func (b *Leases) Drain()          { b.draining = true }
func (b *Leases) Count() int      { return len(b.active) }
func (b *Leases) CanRetire() bool { return b.draining && len(b.active) == 0 }

// Resize changes admission only. A reduction never revokes existing users;
// borrowing resumes only after enough exact receipts have been returned.
// Generation, token floor and Drain survive both resize and checkpoint.
func (b *Leases) Resize(capacity int) error {
	if capacity <= 0 {
		return ErrLease
	}
	b.capacity = capacity
	return nil
}

func (b *Leases) Replace(generation uint64) error {
	if !b.CanRetire() || generation <= b.generation {
		return ErrLease
	}
	b.generation, b.draining = generation, false
	return nil
}

type LeaseJournal struct {
	Schema           uint8
	Generation, Next uint64
	Capacity         int
	Draining         bool
	Active           []Lease
}

func (b *Leases) Checkpoint() LeaseJournal {
	j := LeaseJournal{Schema: 1, Generation: b.generation, Next: b.next, Capacity: b.capacity, Draining: b.draining}
	for _, l := range b.active {
		j.Active = append(j.Active, l)
	}
	sort.Slice(j.Active, func(i, k int) bool { return j.Active[i].Token < j.Active[k].Token })
	return j
}
func RestoreLeases(j LeaseJournal) (*Leases, error) {
	b, err := NewLeases(j.Generation, j.Capacity)
	if err != nil || j.Schema != 1 {
		return nil, ErrLease
	}
	b.next = j.Next
	b.draining = j.Draining
	var previous uint64
	for _, l := range j.Active {
		if l.Token <= previous || l.Token > j.Next || l.Generation != j.Generation {
			return nil, ErrLease
		}
		b.active[l.Token] = l
		previous = l.Token
	}
	return b, nil
}
