// SPDX-License-Identifier: Apache-2.0

package services

import (
	"encoding/hex"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/reconcile"
)

type localReferenceFence struct {
	ID     [32]byte
	Target ReferenceTarget
	Epoch  uint64
}

func (m DNSManager) scopeInUse(scope string) bool {
	if _, pending := m.pending[scope]; pending {
		return true
	}
	for _, v := range m.views {
		if dnsKey(v.Projection.Config.Tenant, v.Projection.Config.ID) == scope {
			return true
		}
	}
	return false
}
func (m DNSManager) referenceActive(a Authority, p dnsProjection) bool {
	if a.revision < m.referenceFloor || a.cluster != m.cluster {
		return false
	}
	c, ok := referenceForProjection(a, p)
	if !ok || m.closedConsumers[c.ID] >= c.Generation {
		return false
	}
	need, known := m.bindings[dnsKey(p.Config.Tenant, p.Config.ID)]
	return known && need.Consumer == c.ID && need.Generation == c.Generation && need.Lifetime == c.Lifetime && need.Owner == c.Local.Owner
}
func (m DNSManager) addressBlocked(a Authority, alloc network.Allocation) bool {
	if a.addressFenced(alloc) {
		return true
	}
	for _, f := range m.fenced {
		if f.Target.Allocation == alloc {
			return true
		}
	}
	return false
}

// SyncReferenceFence is persisted before producing any retirement receipt.
// It blocks the original allocation even if a caller passes an older shared
// snapshot later. It does not cancel work or infer native completion.
func (m DNSManager) SyncReferenceFence(a Authority, consumer, target [32]byte) (DNSManager, error) {
	c, ok := a.ReferenceConsumer(consumer)
	f, exists := a.ReferenceRetirement(target)
	if !ok || !exists || a.cluster != m.cluster || c.Local.Owner != m.owner || a.revision < m.referenceFloor {
		return m, ErrProtocol
	}
	required := false
	for _, need := range f.Required {
		if need.Consumer == c.ID && need.Generation == c.Generation && need.Lifetime == c.Lifetime {
			required = true
		}
	}
	if !required {
		return m, ErrProtocol
	}
	q := m.clone()
	q.referenceFloor = max(q.referenceFloor, a.revision)
	if old, known := q.fenced[target]; known && (old.Target != f.Target || old.Epoch != f.Epoch) {
		return m, ErrProtocol
	}
	q.fenced[target] = localReferenceFence{f.ID, f.Target, f.Epoch}
	return q, nil
}

// SyncReferenceState compacts a local fence only after observing a newer shared
// root where the exact allocation is no longer held. The floor survives local
// snapshots and prevents replay of a pre-compaction shared root.
func (m DNSManager) SyncReferenceState(a Authority) (DNSManager, error) {
	if a.cluster != m.cluster || a.revision < m.referenceFloor {
		return m, ErrProtocol
	}
	q := m.clone()
	q.referenceFloor = a.revision
	for id, f := range q.fenced {
		if _, exists := a.references.Fences[id]; exists {
			continue
		}
		alloc, held := a.book.Allocation(f.Target.Allocation.Endpoint)
		if (!held || alloc != f.Target.Allocation) && a.revision > f.Epoch {
			delete(q.fenced, id)
		}
	}
	for id := range q.closedConsumers {
		c, exists := a.references.Consumers[id]
		if !exists || c.Closed != nil {
			delete(q.closedConsumers, id)
		}
	}
	return q, nil
}
func (m DNSManager) MarkReferenceClosed(a Authority, consumer [32]byte) (DNSManager, error) {
	c, ok := a.ReferenceConsumer(consumer)
	if !ok || a.cluster != m.cluster || c.Local.Owner != m.owner || a.revision < m.referenceFloor {
		return m, ErrProtocol
	}
	for _, v := range m.views {
		if dnsReferenceScope(v.Projection) == c.Scope {
			return m, ErrProtocol
		}
	}
	for _, v := range m.pending {
		if dnsReferenceScope(v.Projection) == c.Scope {
			return m, ErrProtocol
		}
	}
	q := m.clone()
	q.referenceFloor = max(q.referenceFloor, a.revision)
	q.closedConsumers[c.ID] = c.Generation
	return q, nil
}

// ReferenceFacts is a template for the REAL native collector. Settled remains
// false: local query/view metadata cannot prove that socket workers, pending
// native operations or writes have stopped. Only the collector may fill/sign
// that fact after inspecting the original instance's durable native journal.
func (m DNSManager) ReferenceFacts(a Authority, consumer, target [32]byte, now Clock) (ReferenceClose, error) {
	c, ok := a.ReferenceConsumer(consumer)
	if !ok || !validClock(now) || a.cluster != m.cluster || c.Local.Owner != m.owner || a.revision < m.referenceFloor {
		return ReferenceClose{}, ErrProtocol
	}
	p := ReferenceClose{Cluster: m.cluster, Consumer: c.ID, Generation: c.Generation, Lifetime: c.Lifetime, Owner: m.owner, Boot: now.Boot, At: now.Wall, Native: "dns/" + hex.EncodeToString(c.ID[:]), Fenced: true, TTLExpired: true}
	if target == ([32]byte{}) {
		if m.closedConsumers[c.ID] != c.Generation {
			return ReferenceClose{}, ErrProtocol
		}
		for _, v := range m.views {
			if dnsReferenceScope(v.Projection) == c.Scope {
				return ReferenceClose{}, ErrProtocol
			}
		}
		for _, v := range m.pending {
			if dnsReferenceScope(v.Projection) == c.Scope {
				return ReferenceClose{}, ErrProtocol
			}
		}
		return p, nil
	}
	f, exists := a.ReferenceRetirement(target)
	local, known := m.fenced[target]
	if !exists || !known || local.Target != f.Target || local.Epoch != f.Epoch || !m.CanReleaseAddress(f.Target.Allocation) {
		return ReferenceClose{}, ErrProtocol
	}
	required := false
	for _, need := range f.Required {
		if need.Consumer == c.ID && need.Generation == c.Generation && need.Lifetime == c.Lifetime {
			required = true
		}
	}
	if !required {
		return ReferenceClose{}, ErrProtocol
	}
	p.Target = target
	p.Epoch = f.Epoch
	return p, nil
}

// RetireCurrent stops new admission while retaining all original query pins
// and the completion-based TTL hold. Native Stop/Wait is a separate step.
func (m DNSManager) RetireCurrent(tenant, id string, expected uint64, now Clock) (DNSManager, error) {
	k := dnsKey(tenant, id)
	h, ok := m.current[k]
	v := m.views[h]
	if !ok || v.Projection.Config.Source != expected {
		return m, ErrProtocol
	}
	pins, e := reconcile.RestoreLeases(v.Pins)
	if e != nil {
		return m, e
	}
	pins.Drain()
	v.Pins = pins.Checkpoint()
	v.Retired = true
	v.Hold = completionClock(v.Last, v.Completed, now)
	q := m.clone()
	q.views[h] = v
	delete(q.current, k)
	return q, nil
}
