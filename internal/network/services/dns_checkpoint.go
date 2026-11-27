// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bytes"
	"encoding/json"
	"slices"
	"strconv"
	"strings"

	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/miekg/dns"
)

type dnsOrigin struct {
	Pin    reconcile.Lease
	Origin dnsQueryOrigin
}
type dnsStoredView struct {
	ID         [32]byte
	Projection dnsProjection
	Pins       reconcile.LeaseJournal
	Origins    []dnsOrigin
	Retired    bool
	Hold       Clock
	Completed  bool
	Last       Clock
}
type dnsScope struct {
	Key     string
	Floor   dnsFloor
	Current [32]byte
	Pending *dnsCandidate
}
type dnsSnapshot struct {
	Schema               uint8
	Cluster, Owner       [32]byte
	MaxViews, MaxQueries int
	Protected            []string
	Scopes               []dnsScope
	Views                []dnsStoredView
	ReferenceFloor       uint64
	Bindings             []dnsReferenceBinding
	Fenced               []localReferenceFence
	ClosedConsumers      []dnsClosedConsumer
}
type dnsReferenceBinding struct {
	Scope string
	Need  ReferenceNeed
}
type dnsClosedConsumer struct {
	ID         [32]byte
	Generation uint64
}

func generationText(g uint64) string { return strconv.FormatUint(g, 10) }

func validProjection(p dnsProjection, cluster, owner [32]byte) bool {
	c := p.Config
	if len(c.Leases) != 0 || !validDNSConfig(c) || p.Serial != c.Serial || p.Local.Cluster != cluster || p.Local.Owner != owner || p.Local.Tenant != c.Tenant || p.Local.Network != c.Network || p.Local.Pool != c.Pool || len(p.Members) < 1 || len(p.Members) > 64 || len(p.Records) != len(c.Names)+len(c.Leases) {
		return false
	}
	zone, e := Domain(c.Zone)
	if e != nil || zone != c.Zone {
		return false
	}
	if c.ClientZone != "" {
		z, e := Domain(c.ClientZone)
		if e != nil || z != c.ClientZone || dns.IsSubDomain(z, zone) {
			return false
		}
	}
	if c.Reverse {
		z, e := reverseZone(p.Local.Prefix)
		if e != nil || z != p.ReverseZone {
			return false
		}
	} else if p.ReverseZone != "" {
		return false
	}
	book, e := network.NewBook(maxRecords)
	if e != nil {
		return false
	}
	members := []string{}
	local := false
	for i, s := range p.Members {
		if s.Cluster != cluster || s.Tenant != c.Tenant || !id(s.Network) || !id(s.Pool) || !id(s.Node) || s.Owner == ([32]byte{}) || s.NetworkGeneration == 0 || i > 0 && fullPool(s) <= fullPool(p.Members[i-1]) {
			return false
		}
		if s == p.Local {
			local = true
		}
		members = append(members, s.Network)
		book, e = book.AddPool(network.Pool{ID: fullPool(s), Network: s.Tenant + "/" + s.Network, Owner: poolOwner(s), Prefix: s.Prefix, Gateway: s.Gateway, MTU: s.MTU})
		if e != nil {
			return false
		}
	}
	slices.Sort(members)
	members = slices.Compact(members)
	if !local || !slices.Equal(c.Members, members) || !validUpstreams(p) {
		return false
	}
	expected := map[string]bool{}
	for _, ref := range c.Names {
		name, e := canonicalName(ref.Name, c.Zone)
		if e != nil || c.ClientZone != "" && dns.IsSubDomain(c.ClientZone, name) {
			return false
		}
		key := name + "\x00" + ref.Endpoint + "\x00" + generationText(ref.Generation)
		if expected[key] {
			return false
		}
		expected[key] = true
	}
	for i, r := range p.Records {
		name, e := Domain(r.Name)
		if e != nil || name != r.Name || r.Address != r.Allocation.Address || r.Allocation.Generation == 0 || len(r.Allocation.Endpoint) > 256 || i > 0 && (r.Name < p.Records[i-1].Name || r.Name == p.Records[i-1].Name && r.Address.Compare(p.Records[i-1].Address) <= 0) {
			return false
		}
		key := r.Name + "\x00" + r.Allocation.Endpoint + "\x00" + generationText(r.Allocation.Generation)
		if !expected[key] {
			return false
		}
		delete(expected, key)
		member, ok := memberPool(p, r.Allocation.Pool)
		if !ok || r.Allocation.Owner != poolOwner(member) {
			return false
		}
		var alloc network.Allocation
		book, alloc, e = book.Reserve(r.Allocation.Endpoint, r.Allocation.Owner, member.Tenant+"/"+member.Network, r.Allocation.Pool, r.Allocation.Generation, r.Address)
		if e != nil || alloc != r.Allocation {
			return false
		}
		if r.Lease != ([32]byte{}) || r.ExpiresAt != 0 || r.LeaseGeneration != 0 || r.LeaseRevision != 0 || r.LeaseService != "" || r.LeaseClient != "" {
			return false
		}
	}
	names := make([]string, 0, len(p.Records))
	for _, r := range p.Records {
		names = append(names, r.Name)
	}
	return len(expected) == 0 && validConfigRecords(c, names)
}

func (m DNSManager) snapshot() (dnsSnapshot, error) {
	if m.cluster == ([32]byte{}) || m.owner == ([32]byte{}) || m.maxViews < 1 || m.maxViews > 1024 || m.maxQueries < 1 || m.maxQueries > 4096 || len(m.views)+len(m.pending) > m.maxViews || len(m.floors) > maxRecords || len(m.protected) > maxRecords || m.floors == nil || m.views == nil || m.pending == nil || m.current == nil {
		return dnsSnapshot{}, ErrProtocol
	}
	s := dnsSnapshot{Schema: 1, Cluster: m.cluster, Owner: m.owner, MaxViews: m.maxViews, MaxQueries: m.maxQueries, Protected: slices.Clone(m.protected)}
	s.ReferenceFloor = m.referenceFloor
	if len(m.bindings) > maxRecords || len(m.fenced) > maxRecords || len(m.closedConsumers) > maxRecords {
		return dnsSnapshot{}, ErrProtocol
	}
	for scope, need := range m.bindings {
		parts := strings.Split(scope, "/")
		if len(parts) != 2 || !id(parts[0]) || !id(parts[1]) || need.Consumer == ([32]byte{}) || need.Generation == 0 || need.Generation > m.referenceFloor || need.Lifetime.Generation != 1 || need.Lifetime.Token == 0 || need.Owner != m.owner {
			return dnsSnapshot{}, ErrProtocol
		}
		s.Bindings = append(s.Bindings, dnsReferenceBinding{scope, need})
	}
	for id, f := range m.fenced {
		if f.ID != id || ReferenceTargetID(f.Target) != id || f.Epoch == 0 || f.Epoch > m.referenceFloor || !validReferenceSource(f.Target.Source, m.cluster) || f.Target.Allocation.Pool != fullPool(f.Target.Source) || f.Target.Allocation.Owner != poolOwner(f.Target.Source) || f.Target.Allocation.Generation == 0 || !f.Target.Source.Prefix.Contains(f.Target.Allocation.Address) {
			return dnsSnapshot{}, ErrProtocol
		}
		s.Fenced = append(s.Fenced, f)
	}
	for id, g := range m.closedConsumers {
		if id == ([32]byte{}) || g == 0 || g > m.referenceFloor {
			return dnsSnapshot{}, ErrProtocol
		}
		s.ClosedConsumers = append(s.ClosedConsumers, dnsClosedConsumer{id, g})
	}
	protected := map[string]bool{}
	for i, z := range m.protected {
		v, e := Domain(z)
		if e != nil || v != z || i > 0 && z <= m.protected[i-1] {
			return dnsSnapshot{}, ErrProtocol
		}
		protected[z] = true
	}
	count := 0
	used := map[[32]byte]bool{}
	for k, f := range m.floors {
		parts := strings.Split(k, "/")
		if len(parts) != 2 || !id(parts[0]) || !id(parts[1]) || f.Source == 0 {
			return dnsSnapshot{}, ErrProtocol
		}
		item := dnsScope{Key: k, Floor: f, Current: m.current[k]}
		if candidate, exists := m.pending[k]; exists {
			p := candidate.Projection
			if !validProjection(p, m.cluster, m.owner) || dnsKey(p.Config.Tenant, p.Config.ID) != k || p.Config.Source != f.Source || p.Serial != f.Serial || candidate.Base != m.Applied(p.Config.Tenant, p.Config.ID) || !protected[p.Config.Zone] || p.Config.ClientZone != "" && !protected[p.Config.ClientZone] {
				return dnsSnapshot{}, ErrProtocol
			}
			v := candidate
			v.Projection = ownProjection(v.Projection)
			item.Pending = &v
			if p.Config.Enabled && !m.validReferenceBinding(p) {
				return dnsSnapshot{}, ErrProtocol
			}
		}
		if current, exists := m.current[k]; exists {
			v, known := m.views[current]
			if !known || v.Retired || dnsKey(v.Projection.Config.Tenant, v.Projection.Config.ID) != k {
				return dnsSnapshot{}, ErrProtocol
			}
			used[current] = true
		}
		s.Scopes = append(s.Scopes, item)
	}
	if len(m.current) > len(used) {
		return dnsSnapshot{}, ErrProtocol
	}
	for k := range m.pending {
		if _, exists := m.floors[k]; !exists {
			return dnsSnapshot{}, ErrProtocol
		}
	}
	for h, v := range m.views {
		p := v.Projection
		floor, exists := m.floors[dnsKey(p.Config.Tenant, p.Config.ID)]
		if !exists || !validProjection(p, m.cluster, m.owner) || h != projectionHash(p) || p.Config.Source > floor.Source || p.Config.Source == floor.Source && p.Serial != floor.Serial || v.Retired == used[h] || !v.Retired && v.Hold != (Clock{}) || v.Pins.Generation != p.Config.Source || v.Pins.Draining != v.Retired || v.Pins.Capacity != p.Config.MaxQueries || len(v.Origins) != len(v.Pins.Active) {
			return dnsSnapshot{}, ErrProtocol
		}
		if _, e := reconcile.RestoreLeases(v.Pins); e != nil {
			return dnsSnapshot{}, ErrProtocol
		}
		if p.Config.Enabled && !m.validReferenceBinding(p) {
			return dnsSnapshot{}, ErrProtocol
		}
		if !v.Completed && v.Last != (Clock{}) || v.Last != (Clock{}) && !validClock(v.Last) {
			return dnsSnapshot{}, ErrProtocol
		}
		if !protected[p.Config.Zone] || p.Config.ClientZone != "" && !protected[p.Config.ClientZone] {
			return dnsSnapshot{}, ErrProtocol
		}
		stored := dnsStoredView{ID: h, Projection: ownProjection(p), Pins: v.Pins, Retired: v.Retired, Hold: v.Hold, Completed: v.Completed, Last: v.Last}
		stored.Pins.Active = slices.Clone(stored.Pins.Active)
		for _, pin := range v.Pins.Active {
			bound, ok := v.Origins[pin.Token]
			origin := bound.Allocation
			member, belongs := memberPool(p, origin.Pool)
			if !ok || !belongs || origin.Owner != poolOwner(member) || origin.Endpoint == "" || len(origin.Endpoint) > 256 || origin.Generation == 0 || !member.Prefix.Contains(origin.Address) || bound.Request == ([32]byte{}) || bound.Boot == ([32]byte{}) || bound.StartedMono < 0 {
				return dnsSnapshot{}, ErrProtocol
			}
			stored.Origins = append(stored.Origins, dnsOrigin{pin, bound})
		}
		count += len(v.Origins)
		s.Views = append(s.Views, stored)
	}
	if count > m.maxQueries {
		return dnsSnapshot{}, ErrProtocol
	}
	slices.SortFunc(s.Scopes, func(a, b dnsScope) int { return strings.Compare(a.Key, b.Key) })
	slices.SortFunc(s.Views, func(a, b dnsStoredView) int { return bytes.Compare(a.ID[:], b.ID[:]) })
	slices.SortFunc(s.Bindings, func(a, b dnsReferenceBinding) int { return strings.Compare(a.Scope, b.Scope) })
	slices.SortFunc(s.Fenced, func(a, b localReferenceFence) int { return bytes.Compare(a.ID[:], b.ID[:]) })
	slices.SortFunc(s.ClosedConsumers, func(a, b dnsClosedConsumer) int { return bytes.Compare(a.ID[:], b.ID[:]) })
	return s, nil
}
func (m DNSManager) validReferenceBinding(p dnsProjection) bool {
	need, ok := m.bindings[dnsKey(p.Config.Tenant, p.Config.ID)]
	return ok && need.Consumer == referenceID(dnsReferenceScope(p), need.Generation) && need.Owner == m.owner && m.closedConsumers[need.Consumer] < need.Generation
}
func (m DNSManager) Encode() ([]byte, error) {
	s, e := m.snapshot()
	if e != nil {
		return nil, e
	}
	raw, e := json.Marshal(s)
	if e != nil || len(raw) > 32<<20 {
		return nil, ErrProtocol
	}
	return raw, nil
}
func DecodeDNSManager(raw []byte) (DNSManager, error) {
	var s dnsSnapshot
	if len(raw) > 32<<20 || json.Unmarshal(raw, &s) != nil || s.Schema != 1 || len(s.Scopes) > maxRecords || len(s.Views) > 1024 || len(s.Bindings) > maxRecords || len(s.Fenced) > maxRecords || len(s.ClosedConsumers) > maxRecords {
		return DNSManager{}, ErrProtocol
	}
	m, e := NewDNSManager(s.Cluster, s.Owner, s.Protected, s.MaxViews, s.MaxQueries)
	if e != nil {
		return DNSManager{}, e
	}
	m.referenceFloor = s.ReferenceFloor
	for _, v := range s.Bindings {
		if _, dup := m.bindings[v.Scope]; dup {
			return DNSManager{}, ErrProtocol
		}
		m.bindings[v.Scope] = v.Need
	}
	for _, v := range s.Fenced {
		if _, dup := m.fenced[v.ID]; dup {
			return DNSManager{}, ErrProtocol
		}
		m.fenced[v.ID] = v
	}
	for _, v := range s.ClosedConsumers {
		if _, dup := m.closedConsumers[v.ID]; dup {
			return DNSManager{}, ErrProtocol
		}
		m.closedConsumers[v.ID] = v.Generation
	}
	for _, v := range s.Scopes {
		if _, dup := m.floors[v.Key]; dup {
			return DNSManager{}, ErrProtocol
		}
		m.floors[v.Key] = v.Floor
		if v.Current != ([32]byte{}) {
			m.current[v.Key] = v.Current
		}
		if v.Pending != nil {
			m.pending[v.Key] = *v.Pending
		}
	}
	for _, v := range s.Views {
		if _, dup := m.views[v.ID]; dup {
			return DNSManager{}, ErrProtocol
		}
		origins := map[uint64]dnsQueryOrigin{}
		for _, o := range v.Origins {
			if _, dup := origins[o.Pin.Token]; dup || o.Pin.Generation != v.Pins.Generation {
				return DNSManager{}, ErrProtocol
			}
			origins[o.Pin.Token] = o.Origin
		}
		m.views[v.ID] = dnsView{Projection: v.Projection, Pins: v.Pins, Origins: origins, Retired: v.Retired, Hold: v.Hold, Completed: v.Completed, Last: v.Last}
	}
	canonical, e := m.Encode()
	if e != nil || !bytes.Equal(raw, canonical) {
		return DNSManager{}, ErrProtocol
	}
	return m, nil
}
