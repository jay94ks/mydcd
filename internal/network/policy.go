// SPDX-License-Identifier: Apache-2.0

// Package network contains deterministic allocation and packet budget policy.
// It has no Docker, Netlink, TUN or socket side effects.
package network

import (
	"errors"
	"net/netip"
	"sort"
)

var ErrPolicy = errors.New("network ownership, allocation or capacity conflict")

type Pool struct {
	ID, Network, Owner string
	Prefix             netip.Prefix
	Gateway            netip.Addr
	MTU                int
	Draining           bool
	IPAM               PoolIPAM `json:",omitzero"`
}
type Allocation struct {
	Endpoint, Owner, Pool string
	Generation            uint64
	Address               netip.Addr
}

// Book holds at most one allocation per endpoint and generation, and at
// most two generations per endpoint: while a surged Task's new generation
// runs next to its original (devel/design/zero-downtime-apply.md), both hold
// an address under the same endpoint. allocations is the newest generation of
// each endpoint, previous an older one still held.
type Book struct {
	pools       map[string]Pool
	allocations map[string]Allocation
	previous    map[string]Allocation
	floors      map[string]uint64
	capacity    int
}

func NewBook(capacity int) (Book, error) {
	if capacity <= 0 {
		return Book{}, ErrPolicy
	}
	return Book{map[string]Pool{}, map[string]Allocation{}, map[string]Allocation{}, map[string]uint64{}, capacity}, nil
}
func (b Book) copy() Book {
	q := b
	q.pools = map[string]Pool{}
	q.allocations = map[string]Allocation{}
	q.previous = map[string]Allocation{}
	q.floors = map[string]uint64{}
	for k, v := range b.pools {
		q.pools[k] = v
	}
	for k, v := range b.allocations {
		q.allocations[k] = v
	}
	for k, v := range b.previous {
		q.previous[k] = v
	}
	for k, v := range b.floors {
		q.floors[k] = v
	}
	return q
}
func (b Book) Count() int { return len(b.allocations) + len(b.previous) }

// Allocation is the newest generation's allocation of endpoint.
func (b Book) Allocation(id string) (Allocation, bool) { a, ok := b.allocations[id]; return a, ok }

// AllocationOf is endpoint's allocation of exactly generation.
func (b Book) AllocationOf(endpoint string, generation uint64) (Allocation, bool) {
	if a, ok := b.allocations[endpoint]; ok && a.Generation == generation {
		return a, true
	}
	if a, ok := b.previous[endpoint]; ok && a.Generation == generation {
		return a, true
	}
	return Allocation{}, false
}
func (b Book) Pool(id string) (Pool, bool) { p, ok := b.pools[id]; return p, ok }

// each calls f for every allocation, newest generations first.
func (b Book) each(f func(Allocation) bool) {
	for _, a := range b.allocations {
		if !f(a) {
			return
		}
	}
	for _, a := range b.previous {
		if !f(a) {
			return
		}
	}
}

// AllocationAt reads the same authoritative Book without allocating/sorting a
// complete checkpoint for each native DNS packet. Pool CIDRs never overlap.
func (b Book) AllocationAt(address netip.Addr) (Allocation, bool) {
	if !address.IsValid() {
		return Allocation{}, false
	}
	var found Allocation
	ok := false
	b.each(func(a Allocation) bool {
		found, ok = a, a.Address == address
		return !ok
	})
	if !ok {
		return Allocation{}, false
	}
	return found, true
}
func validPool(p Pool) bool {
	return p.ID != "" && p.Network != "" && p.Owner != "" && p.Prefix.IsValid() && p.Prefix == p.Prefix.Masked() && !p.Prefix.Addr().Is4In6() && p.Prefix.Addr().Zone() == "" && p.Gateway.IsValid() && p.Gateway.Zone() == "" && p.Prefix.Contains(p.Gateway) && p.MTU >= 1280 && p.MTU <= 65535
}
func (b Book) AddPool(p Pool) (Book, error) {
	if b.capacity <= 0 || !validPool(p) || !p.validIPAM() || p.Gateway == p.Prefix.Addr() || p.Gateway.IsMulticast() || p.Gateway.Is4() && !p.Prefix.Contains(p.Gateway.Next()) {
		return b, ErrPolicy
	}
	if old, ok := b.pools[p.ID]; ok {
		if old == p {
			return b.copy(), nil
		}
		return b, ErrPolicy
	}
	for _, old := range b.pools {
		if old.Prefix.Overlaps(p.Prefix) {
			return b, ErrPolicy
		}
	}
	q := b.copy()
	q.pools[p.ID] = p
	return q, nil
}
func (b Book) DrainPool(id, owner string) (Book, error) {
	p, ok := b.pools[id]
	if !ok || p.Owner != owner {
		return b, ErrPolicy
	}
	q := b.copy()
	p.Draining = true
	q.pools[id] = p
	return q, nil
}
func (b Book) RemovePool(id, owner string) (Book, error) {
	p, ok := b.pools[id]
	if !ok || p.Owner != owner || !p.Draining {
		return b, ErrPolicy
	}
	used := false
	b.each(func(a Allocation) bool {
		used = a.Pool == id
		return !used
	})
	if used {
		return b, ErrPolicy
	}
	q := b.copy()
	delete(q.pools, id)
	return q, nil
}
func usable(p Pool, a netip.Addr) bool {
	if !a.IsValid() || a.Zone() != "" || !p.Prefix.Contains(a) || a == p.Prefix.Addr() || a == p.Gateway || a.IsMulticast() || a.IsUnspecified() {
		return false
	}
	if a.Is4() {
		next := a.Next()
		if !next.IsValid() || !p.Prefix.Contains(next) {
			return false
		}
	} // IPv4 broadcast
	return true
}

// Reserve is deterministic, all-or-nothing, and idempotent for the EXACT tuple.
// Prefer a specific pool/address, or use sorted eligible pool IDs/lowest address.
func (b Book) Reserve(endpoint, owner, network, pool string, generation uint64, want netip.Addr) (Book, Allocation, error) {
	return b.reserve(endpoint, owner, network, pool, generation, want, false)
}

// WithCommittedAllocation reconstructs only an already committed static hold
// in a read-only projection. Drain must retain old holds while Reserve rejects
// new admission. It is not an operational allocator reset or native receipt.
func (b Book) WithCommittedAllocation(endpoint, owner, network string, generation uint64, address netip.Addr) (Book, error) {
	if !address.IsValid() {
		return b, ErrPolicy
	}
	next, _, err := b.reserve(endpoint, owner, network, "", generation, address, true)
	return next, err
}

func (b Book) reserve(endpoint, owner, network, pool string, generation uint64, want netip.Addr, committed bool) (Book, Allocation, error) {
	if endpoint == "" || owner == "" || network == "" || generation == 0 || want.Is4In6() {
		return b, Allocation{}, ErrPolicy
	}
	if old, ok := b.AllocationOf(endpoint, generation); ok {
		p := b.pools[old.Pool]
		if old.Owner == owner && p.Network == network && (pool == "" || old.Pool == pool) && (!want.IsValid() || want == old.Address) {
			return b.copy(), old, nil
		}
		return b, Allocation{}, ErrPolicy
	}
	// A newer generation may join one still-held older one (surge); a third,
	// or an older one, is refused.
	_, held := b.allocations[endpoint]
	if _, two := b.previous[endpoint]; two || b.Count() >= b.capacity || generation <= b.floors[endpoint] {
		return b, Allocation{}, ErrPolicy
	}
	ids := []string{}
	for id := range b.pools {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		p := b.pools[id]
		if p.Draining && !committed || p.Owner != owner || p.Network != network || pool != "" && pool != id {
			continue
		}
		a := want
		if !a.IsValid() {
			a = p.Prefix.Addr().Next()
		}
		// With n allocations, at most n+3 candidates can be occupied/reserved.
		for steps := 0; steps <= len(b.allocations)+3; steps++ {
			if !a.IsValid() || !p.Prefix.Contains(a) {
				break
			}
			_, used := b.AllocationAt(a)
			if usable(p, a) && !used {
				q := b.copy()
				r := Allocation{endpoint, owner, id, generation, a}
				if held {
					q.previous[endpoint] = q.allocations[endpoint]
				}
				q.allocations[endpoint] = r
				q.floors[endpoint] = generation
				return q, r, nil
			}
			if want.IsValid() {
				break
			}
			a = a.Next()
		}
	}
	return b, Allocation{}, ErrPolicy
}

// Release requires the whole receipt; a stale completion cannot free a new owner.
func (b Book) Release(a Allocation) (Book, error) {
	q := b.copy()
	switch {
	case b.allocations[a.Endpoint] == a && a.Endpoint != "":
		// The older generation, if still held, is the newest again.
		delete(q.allocations, a.Endpoint)
		if older, ok := q.previous[a.Endpoint]; ok {
			q.allocations[a.Endpoint] = older
			delete(q.previous, a.Endpoint)
		}
	case b.previous[a.Endpoint] == a && a.Endpoint != "":
		delete(q.previous, a.Endpoint)
	default:
		return b, ErrPolicy
	}
	return q, nil
}
func (b Book) Resize(capacity int) (Book, error) {
	if capacity <= 0 || capacity < b.Count() {
		return b, ErrPolicy
	}
	q := b.copy()
	q.capacity = capacity
	return q, nil
}

type Listener struct {
	ID, Owner  string
	Generation uint64
	Address    netip.Addr
	Protocol   uint8
	Port       uint16
	DualStack  bool
}

// Overlap is scoped by the caller to one host/network namespace. Separate
// protocols do not collide. IPv6 wildcard dual-stack also occupies IPv4.
func ListenerConflict(a, b Listener) bool {
	if a.Protocol != b.Protocol || a.Port != b.Port {
		return false
	}
	if a.Address == b.Address {
		return true
	}
	if a.Address.Is4() == b.Address.Is4() {
		return a.Address.IsUnspecified() || b.Address.IsUnspecified()
	}
	return a.DualStack && a.Address == netip.IPv6Unspecified() || b.DualStack && b.Address == netip.IPv6Unspecified()
}
func ReserveListener(current []Listener, want Listener, limit int) ([]Listener, error) {
	if want.ID == "" || want.Owner == "" || want.Generation == 0 || !want.Address.IsValid() || want.Address.Is4In6() || want.Address.Zone() != "" || want.Address.IsMulticast() || want.Port == 0 || want.Protocol != 6 && want.Protocol != 17 || want.DualStack && want.Address != netip.IPv6Unspecified() || limit <= 0 {
		return nil, ErrPolicy
	}
	for _, old := range current {
		if old.ID == want.ID {
			if old == want {
				return append([]Listener(nil), current...), nil
			}
			return nil, ErrPolicy
		}
		if ListenerConflict(old, want) {
			return nil, ErrPolicy
		}
	}
	if len(current) >= limit {
		return nil, ErrPolicy
	}
	return append(append([]Listener(nil), current...), want), nil
}
func ReleaseListener(current []Listener, receipt Listener) ([]Listener, error) {
	for i, v := range current {
		if v.ID == receipt.ID {
			if v != receipt {
				return nil, ErrPolicy
			}
			q := append([]Listener(nil), current[:i]...)
			return append(q, current[i+1:]...), nil
		}
	}
	return nil, ErrPolicy
}

// PacketBudget subtracts the explicit, adapter-measured encapsulation budget.
// An insufficient path is unavailable; never silently violate the TUN minimum.
func PacketBudget(tunMTU, pathMTU, overhead int) (int, error) {
	if tunMTU < 1280 || tunMTU > 65535 || pathMTU < 0 || pathMTU > 65535 || overhead < 0 || overhead >= pathMTU {
		return 0, ErrPolicy
	}
	n := pathMTU - overhead
	if n > tunMTU {
		n = tunMTU
	}
	if n < 1280 {
		return 0, ErrPolicy
	}
	return n, nil
}
