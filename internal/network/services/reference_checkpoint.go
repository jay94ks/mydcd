// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bytes"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/reconcile"
)

type referenceScope struct {
	Scope    string
	Consumer [32]byte
	Floor    uint64
}
type referenceSnapshot struct {
	Schema    uint8
	Pins      reconcile.LeaseJournal
	Scopes    []referenceScope
	Consumers []ReferenceConsumer
	Fences    []ReferenceRetirement
}

func (a Authority) referencesSnapshot() (*referenceSnapshot, error) {
	s := a.references
	if s.Pins.Schema == 0 {
		return nil, ErrLease
	}
	pins, e := reconcile.RestoreLeases(s.Pins)
	if e != nil || s.Pins.Generation != 1 || s.Pins.Capacity != maxRecords || s.Pins.Draining || len(s.Consumers) > maxRecords || len(s.Floors) > maxRecords || len(s.Fences) > maxRecords {
		return nil, ErrLease
	}
	out := &referenceSnapshot{Schema: 1, Pins: s.Pins}
	out.Pins.Active = slices.Clone(s.Pins.Active)
	active := map[uint64]bool{}
	for scope, floor := range s.Floors {
		if len(scope) < 1 || len(scope) > 512 || strings.ContainsRune(scope, 0) || floor == 0 || floor > a.revision {
			return nil, ErrLease
		}
		latest := s.Scopes[scope]
		if latest != ([32]byte{}) {
			c, ok := s.Consumers[latest]
			if !ok || c.Scope != scope || c.Generation != floor {
				return nil, ErrLease
			}
		}
		out.Scopes = append(out.Scopes, referenceScope{scope, latest, floor})
	}
	for scope := range s.Scopes {
		if _, ok := s.Floors[scope]; !ok {
			return nil, ErrLease
		}
	}
	for id, c := range s.Consumers {
		if c.ID != id || id != referenceID(c.Scope, c.Generation) || c.Generation == 0 || c.Generation > a.revision || c.Generation > s.Floors[c.Scope] || c.Local.Cluster != a.cluster || !idValidReferenceConsumer(c) || c.Lifetime.Generation != 1 || c.Lifetime.Token == 0 || c.Lifetime.Token > s.Pins.Next || len(c.Members) < 1 || len(c.Members) > 64 || c.ClosedRevision > a.revision || c.DesiredSource == 0 || c.DesiredHash == ([32]byte{}) {
			return nil, ErrLease
		}
		for i, m := range c.Members {
			if !validReferenceSource(m.Source, a.cluster) || m.Since < c.Generation || m.Since > a.revision || i > 0 && compareMember(c.Members[i-1], m) >= 0 {
				return nil, ErrLease
			}
		}
		if !consumerCovers(c, c.Local, 0) {
			return nil, ErrLease
		}
		if c.Closed == nil {
			if c.ClosedRevision != 0 || active[c.Lifetime.Token] {
				return nil, ErrLease
			}
			active[c.Lifetime.Token] = true
		} else if c.ClosedRevision <= c.Generation || c.Closed.Target != ([32]byte{}) || c.Closed.Epoch != 0 || !validReferenceClose(a.cluster, c, *c.Closed) {
			return nil, ErrLease
		}
		out.Consumers = append(out.Consumers, ownReferenceConsumer(c))
	}
	if len(active) != pins.Count() {
		return nil, ErrLease
	}
	for _, p := range s.Pins.Active {
		if !active[p.Token] {
			return nil, ErrLease
		}
	}
	for id, f := range s.Fences {
		t := f.Target
		if id != f.ID || id != ReferenceTargetID(t) || f.Epoch == 0 || f.Epoch > a.revision || f.At <= 0 || f.At > a.at || !validReferenceSource(t.Source, a.cluster) || t.Allocation.Owner != poolOwner(t.Source) || t.Allocation.Pool != fullPool(t.Source) || t.Allocation.Endpoint == "" || t.Allocation.Generation == 0 || !t.Source.Prefix.Contains(t.Allocation.Address) || len(f.Required) > maxRecords || len(f.Closures) > len(f.Required) {
			return nil, ErrLease
		}
		// Recompute the complete required set from every original instance and
		// its coverage epoch. A later extension cannot erase an earlier owner.
		expected := map[[32]byte]ReferenceNeed{}
		for _, c := range s.Consumers {
			if c.Generation <= f.Epoch && (c.ClosedRevision == 0 || c.ClosedRevision > f.Epoch) && consumerNeedsAddress(c, t, f.Epoch) {
				expected[c.ID] = ReferenceNeed{c.ID, c.Generation, c.Lifetime, c.Local.Owner}
			}
		}
		for i, n := range f.Required {
			if n != expected[n.Consumer] || i > 0 && bytes.Compare(f.Required[i-1].Consumer[:], n.Consumer[:]) >= 0 {
				return nil, ErrLease
			}
			delete(expected, n.Consumer)
		}
		if len(expected) != 0 {
			return nil, ErrLease
		}
		for i, p := range f.Closures {
			c, ok := s.Consumers[p.Consumer]
			if !ok || p.Target != id || p.Epoch != f.Epoch || p.At < f.At || !validReferenceClose(a.cluster, c, p) || i > 0 && bytes.Compare(f.Closures[i-1].Consumer[:], p.Consumer[:]) >= 0 {
				return nil, ErrLease
			}
			found := false
			for _, n := range f.Required {
				if n.Consumer == p.Consumer {
					found = true
				}
			}
			if !found {
				return nil, ErrLease
			}
		}
		alloc, held := a.book.AllocationOf(t.Allocation.Endpoint, t.Allocation.Generation)
		if f.ReclaimedRevision == 0 {
			if !held || alloc != t.Allocation || f.OwnerClose != nil {
				return nil, ErrLease
			}
		} else {
			if f.ReclaimedRevision <= f.Epoch || f.ReclaimedRevision > a.revision || held && alloc == t.Allocation || !a.referencesSettled(f) {
				return nil, ErrLease
			}
			if f.OwnerClose == nil || !validAddressOwnerClose(a.cluster, f, *f.OwnerClose, f.OwnerClose.At) {
				return nil, ErrLease
			}
		}
		out.Fences = append(out.Fences, ownReferenceRetirement(f))
	}
	slices.SortFunc(out.Scopes, func(a, b referenceScope) int { return strings.Compare(a.Scope, b.Scope) })
	slices.SortFunc(out.Consumers, func(a, b ReferenceConsumer) int { return bytes.Compare(a.ID[:], b.ID[:]) })
	slices.SortFunc(out.Fences, func(a, b ReferenceRetirement) int { return bytes.Compare(a.ID[:], b.ID[:]) })
	return out, nil
}
func compareMember(a, b ReferenceMember) int {
	x, y := ReferenceTargetID(ReferenceTarget{Source: a.Source}), ReferenceTargetID(ReferenceTarget{Source: b.Source})
	return bytes.Compare(x[:], y[:])
}
func validReferenceSource(s Source, cluster [32]byte) bool {
	return s.Cluster == cluster && id(s.Tenant) && id(s.Network) && id(s.Pool) && id(s.Node) && s.Owner != ([32]byte{}) && s.NetworkGeneration > 0 && s.Prefix.IsValid() && s.Prefix == s.Prefix.Masked() && s.Prefix.Contains(s.Gateway) && s.Gateway != s.Prefix.Addr() && s.MTU >= 1280 && s.MTU <= 65535
}
func idValidReferenceConsumer(c ReferenceConsumer) bool {
	if c.RouteClosed != nil && !validRouteClosed(c, *c.RouteClosed) {
		return false
	}
	if c.Dispatch != nil && !validRouteDispatch(c, *c.Dispatch) {
		return false
	}
	if c.Native != nil && c.Route == nil {
		return false
	}
	if len(c.UnsupportedDHCP) != 0 {
		return false
	}
	if c.Route != nil {
		return validRouteReference(c)
	}
	return id(c.Name) && validReferenceSource(c.Local, c.Local.Cluster) && c.Scope == "dns/"+dnsKey(c.Local.Tenant, c.Name)+"/"+fullPool(c.Local)
}
func decodeReferences(s *referenceSnapshot) (referenceState, error) {
	if s == nil {
		return referenceState{}, ErrLease
	}
	if s.Schema != 1 || len(s.Scopes) > maxRecords || len(s.Consumers) > maxRecords || len(s.Fences) > maxRecords {
		return referenceState{}, ErrLease
	}
	r := referenceState{Pins: s.Pins, Consumers: map[[32]byte]ReferenceConsumer{}, Scopes: map[string][32]byte{}, Floors: map[string]uint64{}, Fences: map[[32]byte]ReferenceRetirement{}}
	r.Pins.Active = slices.Clone(s.Pins.Active)
	for _, v := range s.Scopes {
		if _, dup := r.Floors[v.Scope]; dup {
			return r, ErrLease
		}
		r.Floors[v.Scope] = v.Floor
		if v.Consumer != ([32]byte{}) {
			r.Scopes[v.Scope] = v.Consumer
		}
	}
	for _, v := range s.Consumers {
		if _, dup := r.Consumers[v.ID]; dup {
			return r, ErrLease
		}
		r.Consumers[v.ID] = ownReferenceConsumer(v)
	}
	for _, v := range s.Fences {
		if _, dup := r.Fences[v.ID]; dup {
			return r, ErrLease
		}
		r.Fences[v.ID] = ownReferenceRetirement(v)
	}
	return r, nil
}
