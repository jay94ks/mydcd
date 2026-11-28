// SPDX-License-Identifier: Apache-2.0

package network

import "sort"

type Generation struct {
	Endpoint string
	Value    uint64
}
type Journal struct {
	Schema      uint8
	Capacity    int
	Pools       []Pool
	Allocations []Allocation
	Floors      []Generation
}

func (b Book) Checkpoint() Journal {
	j := Journal{Schema: 1, Capacity: b.capacity}
	for _, p := range b.pools {
		j.Pools = append(j.Pools, p)
	}
	b.each(func(a Allocation) bool {
		j.Allocations = append(j.Allocations, a)
		return true
	})
	for id, g := range b.floors {
		j.Floors = append(j.Floors, Generation{id, g})
	}
	sort.Slice(j.Pools, func(i, k int) bool { return j.Pools[i].ID < j.Pools[k].ID })
	// An endpoint's older generation first, so Restore rebuilds it the
	// same way it was reserved.
	sort.Slice(j.Allocations, func(i, k int) bool {
		x, y := j.Allocations[i], j.Allocations[k]
		return x.Endpoint < y.Endpoint || x.Endpoint == y.Endpoint && x.Generation < y.Generation
	})
	sort.Slice(j.Floors, func(i, k int) bool { return j.Floors[i].Endpoint < j.Floors[k].Endpoint })
	return j
}
func Restore(j Journal) (Book, error) {
	b, err := NewBook(j.Capacity)
	if err != nil || j.Schema != 1 {
		return Book{}, ErrPolicy
	}
	seen := map[string]bool{}
	for _, p := range j.Pools {
		if seen[p.ID] {
			return Book{}, ErrPolicy
		}
		seen[p.ID] = true
		p.Draining = false
		b, err = b.AddPool(p)
		if err != nil {
			return Book{}, err
		}
	}
	held := map[string]uint64{}
	for _, a := range j.Allocations {
		if last, ok := held[a.Endpoint]; ok && last >= a.Generation {
			return Book{}, ErrPolicy
		}
		held[a.Endpoint] = a.Generation
		p, ok := b.pools[a.Pool]
		if !ok {
			return Book{}, ErrPolicy
		}
		var actual Allocation
		b, actual, err = b.reserve(a.Endpoint, a.Owner, p.Network, a.Pool, a.Generation, a.Address, true)
		if err != nil || actual != a {
			return Book{}, ErrPolicy
		}
	}
	seen = map[string]bool{}
	for _, f := range j.Floors {
		if f.Endpoint == "" || f.Value == 0 || seen[f.Endpoint] || b.floors[f.Endpoint] != 0 && b.floors[f.Endpoint] != f.Value {
			return Book{}, ErrPolicy
		}
		seen[f.Endpoint] = true
		b.floors[f.Endpoint] = f.Value
	}
	for id := range b.allocations {
		if !seen[id] {
			return Book{}, ErrPolicy
		}
	}
	for _, p := range j.Pools {
		if p.Draining {
			b, err = b.DrainPool(p.ID, p.Owner)
			if err != nil {
				return Book{}, err
			}
		}
	}
	return b, nil
}
