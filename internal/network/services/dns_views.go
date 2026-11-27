// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"slices"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/tenancy"
)

var ErrDNSQueryCapacity = fmt.Errorf("%w: DNS query capacity exhausted", ErrProtocol)

type dnsFloor struct {
	Source uint64
	Serial uint32
}
type dnsCandidate struct {
	Projection dnsProjection
	Base       uint64
}
type dnsQueryOrigin struct {
	Allocation  network.Allocation
	Request     [32]byte
	Boot        [32]byte
	StartedMono int64
}
type dnsView struct {
	Projection dnsProjection
	Pins       reconcile.LeaseJournal
	Origins    map[uint64]dnsQueryOrigin
	Retired    bool
	Hold       Clock
	Completed  bool
	Last       Clock
}

// DNSManager is the network owner's reusable view/query lifecycle core. All
// mutation returns an immutable candidate; the native owner syncs it before
// publishing borrows or view switches. It does not claim socket/native Ready.
type DNSManager struct {
	cluster, owner       [32]byte
	maxViews, maxQueries int
	protected            []string
	floors               map[string]dnsFloor
	current              map[string][32]byte
	pending              map[string]dnsCandidate
	views                map[[32]byte]dnsView
	cache                map[dnsCacheKey]dnsCacheEntry
	referenceFloor       uint64
	bindings             map[string]ReferenceNeed
	fenced               map[[32]byte]localReferenceFence
	closedConsumers      map[[32]byte]uint64
}

func NewDNSManager(cluster, owner [32]byte, internalRoots []string, maxViews, maxQueries int) (DNSManager, error) {
	if cluster == ([32]byte{}) || owner == ([32]byte{}) || maxViews < 1 || maxViews > 1024 || maxQueries < 1 || maxQueries > 4096 || len(internalRoots) > maxRecords {
		return DNSManager{}, ErrProtocol
	}
	m := DNSManager{cluster: cluster, owner: owner, maxViews: maxViews, maxQueries: maxQueries, floors: map[string]dnsFloor{}, current: map[string][32]byte{}, pending: map[string]dnsCandidate{}, views: map[[32]byte]dnsView{}, cache: map[dnsCacheKey]dnsCacheEntry{}}
	m.bindings = map[string]ReferenceNeed{}
	m.fenced = map[[32]byte]localReferenceFence{}
	m.closedConsumers = map[[32]byte]uint64{}
	for _, z := range internalRoots {
		v, e := Domain(z)
		if e != nil {
			return DNSManager{}, e
		}
		m.protected = append(m.protected, v)
	}
	slices.Sort(m.protected)
	m.protected = slices.Compact(m.protected)
	return m, nil
}
func (m DNSManager) clone() DNSManager {
	q := m
	q.protected = slices.Clone(m.protected)
	q.floors = map[string]dnsFloor{}
	q.current = map[string][32]byte{}
	q.pending = map[string]dnsCandidate{}
	q.views = map[[32]byte]dnsView{}
	q.cache = map[dnsCacheKey]dnsCacheEntry{}
	q.bindings = map[string]ReferenceNeed{}
	q.fenced = map[[32]byte]localReferenceFence{}
	q.closedConsumers = map[[32]byte]uint64{}
	for k, v := range m.bindings {
		q.bindings[k] = v
	}
	for k, v := range m.fenced {
		q.fenced[k] = v
	}
	for k, v := range m.closedConsumers {
		q.closedConsumers[k] = v
	}
	for k, v := range m.cache {
		q.cache[k] = v
	}
	for k, v := range m.floors {
		q.floors[k] = v
	}
	for k, v := range m.current {
		q.current[k] = v
	}
	for k, v := range m.pending {
		v.Projection = ownProjection(v.Projection)
		q.pending[k] = v
	}
	for k, v := range m.views {
		v.Projection = ownProjection(v.Projection)
		v.Pins.Active = slices.Clone(v.Pins.Active)
		v.Origins = ownOrigins(v.Origins)
		q.views[k] = v
	}
	return q
}
func ownOrigins(in map[uint64]dnsQueryOrigin) map[uint64]dnsQueryOrigin {
	out := map[uint64]dnsQueryOrigin{}
	for k, v := range in {
		out[k] = v
	}
	return out
}
func (m DNSManager) Applied(tenant, id string) uint64 {
	v, ok := m.views[m.current[dnsKey(tenant, id)]]
	if !ok {
		return 0
	}
	return v.Projection.Config.Source
}

func (m DNSManager) Prepare(c access.Catalog, n tenancy.Networks, a Authority, actor string, expected uint64, input DNSConfig) (DNSManager, error) {
	k := dnsKey(input.Tenant, input.ID)
	floor := m.floors[k]
	if m.cluster == ([32]byte{}) || a.cluster != m.cluster || expected != floor.Source || input.Source <= floor.Source || len(m.views)+len(m.pending) >= m.maxViews {
		return m, ErrProtocol
	}
	if _, known := m.floors[k]; !known && len(m.floors) >= maxRecords {
		return m, ErrProtocol
	}
	if _, exists := m.pending[k]; exists {
		return m, ErrProtocol
	}
	if floor.Source != 0 && !SerialAfter(input.Serial, floor.Serial) {
		return m, ErrProtocol
	}
	p, err := buildDNS(c, n, a, actor, input)
	if !input.Enabled {
		p, err = buildRetiringDNS(c, n, a, actor, input)
	}
	if err != nil || p.Local.Owner != m.owner {
		return m, ErrProtocol
	}
	if a.revision < m.referenceFloor {
		return m, ErrProtocol
	}
	ref, covered := referenceForProjection(a, p)
	if input.Enabled && (!covered || m.closedConsumers[ref.ID] >= ref.Generation) {
		return m, ErrProtocol
	}
	if covered && (ref.DesiredSource != input.Source || ref.DesiredHash != projectionHash(p)) {
		return m, ErrProtocol
	}
	for _, record := range p.Records {
		if m.addressBlocked(a, record.Allocation) {
			return m, ErrProtocol
		}
	}
	if covered {
		if old, known := m.bindings[k]; known && old.Consumer != ref.ID && m.scopeInUse(k) {
			return m, ErrProtocol
		}
	}
	q := m.clone()
	q.referenceFloor = max(q.referenceFloor, a.revision)
	if covered {
		q.bindings[k] = ReferenceNeed{ref.ID, ref.Generation, ref.Lifetime, ref.Local.Owner}
	}
	q.floors[k] = dnsFloor{input.Source, input.Serial}
	q.pending[k] = dnsCandidate{p, m.Applied(input.Tenant, input.ID)}
	q.protected = append(q.protected, p.Config.Zone)
	if p.Config.ClientZone != "" {
		q.protected = append(q.protected, p.Config.ClientZone)
	}
	for _, member := range p.Members {
		if reverse, err := reverseZone(member.Prefix); err == nil {
			q.protected = append(q.protected, reverse)
		}
	}
	slices.Sort(q.protected)
	q.protected = slices.Compact(q.protected)
	if len(q.protected) > maxRecords {
		return m, ErrProtocol
	}
	return q, nil
}
func (m DNSManager) Discard(tenant, id string, source uint64) (DNSManager, error) {
	k := dnsKey(tenant, id)
	v, ok := m.pending[k]
	if !ok || v.Projection.Config.Source != source {
		return m, ErrProtocol
	}
	// Only a pure, unserved view candidate exists here. Dispatched native
	// operations belong to the runtime coordinator and cannot use this API.
	q := m.clone()
	delete(q.pending, k)
	return q, nil
}
func validClock(c Clock) bool {
	return c.Certain && c.Boot != ([32]byte{}) && c.Wall > 0 && c.Mono >= 0
}

// ProtectZones joins the cluster's private namespace to the SAME local DNS
// core before forwarding. Protection is additive: deletion is not permission
// to disclose a recently private name to an external upstream.
func (m DNSManager) ProtectZones(zones []string) (DNSManager, error) {
	q := m.clone()
	for _, zone := range zones {
		name, err := Domain(zone)
		if err != nil {
			return m, err
		}
		q.protected = append(q.protected, name)
	}
	slices.Sort(q.protected)
	q.protected = slices.Compact(q.protected)
	if len(q.protected) > maxRecords {
		return m, ErrProtocol
	}
	return q, nil
}
func elapsed(mark, now Clock) (int64, bool) {
	if !validClock(mark) || !validClock(now) || mark.Boot != now.Boot || now.Wall < mark.Wall || now.Mono < mark.Mono {
		return 0, false
	}
	w, m := now.Wall-mark.Wall, now.Mono-mark.Mono
	if w-m > 5 || m-w > 5 {
		return 0, false
	}
	if w < m {
		return w, true
	}
	return m, true
}
func completionClock(last Clock, seen bool, now Clock) Clock {
	if !validClock(now) {
		return Clock{}
	}
	if seen {
		if _, known := elapsed(last, now); !known {
			return Clock{}
		}
	}
	return now
}
func (m DNSManager) Publish(c access.Catalog, n tenancy.Networks, a Authority, tenant, id string, source uint64, now Clock) (DNSManager, error) {
	k := dnsKey(tenant, id)
	v, ok := m.pending[k]
	if !ok || v.Projection.Config.Source != source || m.Applied(tenant, id) != v.Base || !freshDNSProjection(c, n, a, v.Projection) || !projectionReferences(a, v.Projection) || a.revision < m.referenceFloor || v.Projection.Config.Enabled && !m.referenceActive(a, v.Projection) {
		return m, ErrProtocol
	}
	for _, record := range v.Projection.Records {
		if m.addressBlocked(a, record.Allocation) {
			return m, ErrProtocol
		}
	}
	if ref, covered := referenceForProjection(a, v.Projection); v.Projection.Config.Enabled && (!covered || ref.DesiredSource != source || ref.DesiredHash != projectionHash(v.Projection)) {
		return m, ErrProtocol
	}
	q := m.clone()
	if oldID, exists := q.current[k]; exists {
		old := q.views[oldID]
		pins, e := reconcile.RestoreLeases(old.Pins)
		if e != nil {
			return m, ErrProtocol
		}
		pins.Drain()
		old.Pins = pins.Checkpoint()
		old.Retired = true
		old.Hold = completionClock(old.Last, old.Completed, now)
		q.views[oldID] = old
	}
	q.referenceFloor = max(q.referenceFloor, a.revision)
	pins, e := reconcile.NewLeases(source, v.Projection.Config.MaxQueries)
	if e != nil {
		return m, ErrProtocol
	}
	h := projectionHash(v.Projection)
	if _, exists := q.views[h]; exists {
		return m, ErrProtocol
	}
	q.views[h] = dnsView{Projection: ownProjection(v.Projection), Pins: pins.Checkpoint(), Origins: map[uint64]dnsQueryOrigin{}}
	q.current[k] = h
	delete(q.pending, k)
	return q, nil
}

// DNSQuery is process-local and cannot be fabricated from client wire fields.
// Native query journals persist through DNSManager's explicit snapshot codec.
type DNSQuery struct {
	scope  string
	view   [32]byte
	pin    reconcile.Lease
	origin dnsQueryOrigin
}

func (q DNSQuery) Source() uint64               { return q.pin.Generation }
func (q DNSQuery) MarshalJSON() ([]byte, error) { return nil, ErrProtocol }
func (q DNSQuery) ID() [32]byte {
	return sha256.Sum256(append(append(slices.Clone(q.view[:]), []byte(generationText(q.pin.Generation)+"/"+generationText(q.pin.Token))...), q.origin.Request[:]...))
}

type DNSViewStatus struct {
	ID              [32]byte
	Tenant, Service string
	Source          uint64
	Serial          uint32
	Retired         bool
	Queries         int
	Hold            Clock
}

func (m DNSManager) Views() []DNSViewStatus {
	var out []DNSViewStatus
	for h, v := range m.views {
		out = append(out, DNSViewStatus{h, v.Projection.Config.Tenant, v.Projection.Config.ID, v.Projection.Config.Source, v.Projection.Serial, v.Retired, len(v.Origins), v.Hold})
	}
	slices.SortFunc(out, func(a, b DNSViewStatus) int { return bytes.Compare(a.ID[:], b.ID[:]) })
	return out
}
func (m DNSManager) Queries() []DNSQuery {
	var out []DNSQuery
	for h, v := range m.views {
		for _, pin := range v.Pins.Active {
			out = append(out, DNSQuery{dnsKey(v.Projection.Config.Tenant, v.Projection.Config.ID), h, pin, v.Origins[pin.Token]})
		}
	}
	slices.SortFunc(out, func(a, b DNSQuery) int { x, y := a.ID(), b.ID(); return bytes.Compare(x[:], y[:]) })
	return out
}
func freshDNSProjection(c access.Catalog, n tenancy.Networks, a Authority, p dnsProjection) bool {
	if n.Cluster() != a.cluster || p.Local.Cluster != a.cluster {
		return false
	}
	for _, s := range p.Members {
		current := currentSource(c, n, s)
		if !p.Config.Enabled {
			actual, ok := retainedSource(n, a.cluster, s.Tenant, s.Network, s.Pool)
			current = ok && actual == s
		}
		if !current {
			return false
		}
	}
	return true
}
func originAllowed(a Authority, p dnsProjection, origin network.Allocation, now Clock) bool {
	current, ok := a.book.Allocation(origin.Endpoint)
	_, member := memberPool(p, origin.Pool)
	if !ok || current != origin || !member {
		return false
	}
	return true
}
func (m DNSManager) Acquire(c access.Catalog, n tenancy.Networks, a Authority, tenant, id string, origin network.Allocation, raw []byte, now Clock) (DNSManager, DNSQuery, error) {
	k := dnsKey(tenant, id)
	h := m.current[k]
	v, ok := m.views[h]
	if !ok || v.Retired || !v.Projection.Config.Enabled || !m.referenceActive(a, v.Projection) || m.addressBlocked(a, origin) || !freshDNSProjection(c, n, a, v.Projection) || !originAllowed(a, v.Projection, origin, now) || now.Boot == ([32]byte{}) || now.Mono < 0 {
		return m, DNSQuery{}, ErrProtocol
	}
	if _, e := DecodeDNSQuery(raw, min(v.Projection.Config.MaxResponseBytes, 4096)); e != nil {
		return m, DNSQuery{}, ErrProtocol
	}
	count := 0
	for _, view := range m.views {
		count += len(view.Origins)
	}
	if count >= m.maxQueries {
		return m, DNSQuery{}, ErrDNSQueryCapacity
	}
	if len(v.Origins) >= v.Projection.Config.MaxQueries {
		return m, DNSQuery{}, ErrDNSQueryCapacity
	}
	pins, e := reconcile.RestoreLeases(v.Pins)
	if e != nil {
		return m, DNSQuery{}, ErrProtocol
	}
	pin, e := pins.Acquire()
	if e != nil {
		return m, DNSQuery{}, ErrProtocol
	}
	bound := dnsQueryOrigin{origin, sha256.Sum256(raw), now.Boot, now.Mono}
	q := m.clone()
	v = q.views[h]
	q.referenceFloor = max(q.referenceFloor, a.revision)
	v.Pins = pins.Checkpoint()
	v.Origins[pin.Token] = bound
	q.views[h] = v
	return q, DNSQuery{k, h, pin, bound}, nil
}
func (m DNSManager) query(h DNSQuery) (dnsView, bool) {
	v, ok := m.views[h.view]
	if !ok || dnsKey(v.Projection.Config.Tenant, v.Projection.Config.ID) != h.scope || h.pin.Generation != v.Pins.Generation {
		return dnsView{}, false
	}
	origin, exists := v.Origins[h.pin.Token]
	return v, exists && origin == h.origin
}
func queryLive(h DNSQuery, p dnsProjection, now Clock) bool {
	return now.Boot == h.origin.Boot && now.Mono >= h.origin.StartedMono && now.Mono-h.origin.StartedMono < int64(p.Config.QuerySeconds)
}
func (m DNSManager) Release(h DNSQuery, now Clock) (DNSManager, error) {
	v, ok := m.query(h)
	if !ok {
		return m, ErrProtocol
	}
	pins, e := reconcile.RestoreLeases(v.Pins)
	if e != nil || pins.Release(h.pin) != nil {
		return m, ErrProtocol
	}
	q := m.clone()
	v = q.views[h.view]
	v.Pins = pins.Checkpoint()
	delete(v.Origins, h.pin.Token)
	v.Last = completionClock(v.Last, v.Completed, now)
	v.Completed = true
	if v.Retired {
		if validClock(v.Last) {
			v.Hold = completionClock(v.Hold, true, now)
		} else {
			v.Hold = Clock{}
		}
	}
	q.views[h.view] = v
	return q, nil
}
func (m DNSManager) RebaseHold(view [32]byte, now Clock) (DNSManager, error) {
	v, ok := m.views[view]
	if !ok || !v.Retired || len(v.Origins) != 0 || !validClock(now) {
		return m, ErrProtocol
	}
	if _, known := elapsed(v.Hold, now); known {
		return m, ErrProtocol
	}
	// A ceiling-rounded native event may still be just ahead of the current
	// floor clock. Do not move that deadline forward on every retirement poll.
	if validClock(v.Hold) && v.Hold.Boot == now.Boot && (now.Wall < v.Hold.Wall || now.Mono < v.Hold.Mono) {
		return m, ErrProtocol
	}
	if v.Completed && validClock(v.Last) && v.Last.Boot == now.Boot {
		// Query pins are zero. Starting a NEW full TTL needs a time after both
		// original completion coordinates, not proof of the old clock's rate.
		if now.Wall < v.Last.Wall || now.Mono < v.Last.Mono {
			return m, ErrProtocol
		}
	}
	q := m.clone()
	v = q.views[view]
	v.Hold = now
	q.views[view] = v
	return q, nil
}
func (m DNSManager) Collect(view [32]byte, now Clock) (DNSManager, error) {
	v, ok := m.views[view]
	age, certain := elapsed(v.Hold, now)
	if !ok || !v.Retired || len(v.Origins) != 0 || !certain || age < int64(v.Projection.Config.TTL) {
		return m, ErrProtocol
	}
	q := m.clone()
	delete(q.views, view)
	for k := range q.cache {
		if k.View == view {
			delete(q.cache, k)
		}
	}
	return q, nil
}

// CanReleaseAddress is consumed by the shared retirement transaction before
// releasing a static endpoint. TTL alone never
// proves native termination; the original native proof is required separately.
// This is one owner's local DNS gate. The shared FSM must join every required
// DNS owner's closure; one manager cannot attest another node's pins or TTL.
func (m DNSManager) CanReleaseAddress(alloc network.Allocation) bool {
	for _, v := range m.pending {
		for _, r := range v.Projection.Records {
			if r.Allocation == alloc {
				return false
			}
		}
	}
	for _, v := range m.views {
		if !v.Projection.Config.Enabled && !v.Retired && len(v.Origins) == 0 {
			continue
		}
		for _, r := range v.Projection.Records {
			if r.Allocation == alloc {
				return false
			}
		}
		for _, origin := range v.Origins {
			if origin.Allocation == alloc {
				return false
			}
		}
	}
	return true
}
func (m DNSManager) HoldsPool(pool string) bool {
	for _, v := range m.pending {
		if _, ok := memberPool(v.Projection, pool); ok {
			return true
		}
	}
	for _, v := range m.views {
		if !v.Projection.Config.Enabled && !v.Retired && len(v.Origins) == 0 {
			continue
		}
		if _, ok := memberPool(v.Projection, pool); ok {
			return true
		}
	}
	return false
}
