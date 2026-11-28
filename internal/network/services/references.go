// SPDX-License-Identifier: Apache-2.0

package services

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/tenancy"
)

// ReferenceMember records when this instance acquired responsibility for a
// pool. Coverage only grows until the entire instance is durably fenced.
// Native effects in added coverage cannot start from a pre-extension snapshot.
type ReferenceMember struct {
	Source Source
	Since  uint64
}
type ReferenceConsumer struct {
	ID              [32]byte
	Scope, Name     string
	Local           Source
	Generation      uint64
	Lifetime        reconcile.Lease
	Members         []ReferenceMember
	DesiredSource   uint64
	DesiredHash     [32]byte
	Serial          uint32
	Route           *RouteReference       `json:",omitempty"`
	Native          *RouteNativeBinding   `json:",omitempty"`
	Dispatch        *RouteDispatch        `json:",omitempty"`
	RouteClosed     *tenancy.RouteClosure `json:",omitempty"`
	UnsupportedDHCP json.RawMessage       `json:"DHCP,omitempty"`
	ClosedRevision  uint64
	Closed          *ReferenceClose
}
type ReferenceTarget struct {
	Source     Source
	Allocation network.Allocation
}

// AddressReferencesSettled is a read-only preflight over the SAME retirement
// proof set used by Reclaim. It does not grant deletion, bypass permission or
// replace the guard/lease/CAS checks of that state transition.
func (a Authority) AddressReferencesSettled(allocation network.Allocation) bool {
	f, held := a.AddressRetirement(allocation)
	return held && f.ReclaimedRevision == 0 && a.referencesSettled(f)
}

type ReferenceNeed struct {
	Consumer   [32]byte
	Generation uint64
	Lifetime   reconcile.Lease
	Owner      [32]byte
}
type ReferenceRetirement struct {
	ID                [32]byte
	Target            ReferenceTarget
	Epoch             uint64
	At                int64
	Required          []ReferenceNeed
	Closures          []ReferenceClose
	ReclaimedRevision uint64
	OwnerClose        *AddressOwnerClose
}

// ReferenceClose is a PERMANENT durable fence, not a temporary report of zero
// requests. Target==0 closes the whole instance; otherwise it closes exactly
// the named allocation/fence epoch. Native collectors must stop/wait unknown
// work and observe TTL before signing; a metadata count alone is insufficient.
type ReferenceClose struct {
	Cluster                                   [32]byte
	Consumer                                  [32]byte
	Generation                                uint64
	Lifetime                                  reconcile.Lease
	Owner, Boot                               [32]byte
	Target                                    [32]byte
	Epoch                                     uint64
	At                                        int64
	Native                                    string
	Fenced, Settled, TTLExpired               bool
	PendingQueries, PendingFlows, PendingPins uint64
	Signature                                 []byte
}

func ReferenceCloseBytes(p ReferenceClose) []byte {
	p.Signature = nil
	raw, _ := json.Marshal(p)
	return append([]byte("sfc-network-reference-close-1\x00"), raw...)
}
func ReferenceTargetID(t ReferenceTarget) [32]byte {
	raw, _ := json.Marshal(t)
	return sha256.Sum256(append([]byte("sfc-network-reference-target-1\x00"), raw...))
}
func referenceID(scope string, generation uint64) [32]byte {
	return sha256.Sum256([]byte("sfc-network-reference-consumer-1\x00" + scope + "/" + generationText(generation)))
}
func dnsReferenceScope(p dnsProjection) string {
	return "dns/" + dnsKey(p.Config.Tenant, p.Config.ID) + "/" + fullPool(p.Local)
}
func ownReferenceClose(p ReferenceClose) ReferenceClose {
	p.Signature = slices.Clone(p.Signature)
	return p
}
func ownReferenceConsumer(c ReferenceConsumer) ReferenceConsumer {
	if c.RouteClosed != nil {
		closed := *c.RouteClosed
		closed.Signature = slices.Clone(closed.Signature)
		c.RouteClosed = &closed
	}
	if c.Dispatch != nil {
		dispatch := ownRouteDispatch(*c.Dispatch)
		c.Dispatch = &dispatch
	}
	if c.Native != nil {
		binding := *c.Native
		c.Native = &binding
	}
	c.Members = slices.Clone(c.Members)
	if c.Route != nil {
		r := ownRouteReference(*c.Route)
		c.Route = &r
	}
	if c.Closed != nil {
		p := ownReferenceClose(*c.Closed)
		c.Closed = &p
	}
	return c
}

// ReferenceConsumers includes every original DNS/route generation, including
// superseded references awaiting their own closure. Current policy alone is
// insufficient for node retirement or reference collection.
func (a Authority) ReferenceConsumers() []ReferenceConsumer {
	var result []ReferenceConsumer
	for _, reference := range a.references.Consumers {
		result = append(result, ownReferenceConsumer(reference))
	}
	slices.SortFunc(result, func(a, b ReferenceConsumer) int {
		return strings.Compare(a.Scope+"/"+generationText(a.Generation), b.Scope+"/"+generationText(b.Generation))
	})
	return result
}
func ownReferenceRetirement(f ReferenceRetirement) ReferenceRetirement {
	f.Required = slices.Clone(f.Required)
	f.Closures = slices.Clone(f.Closures)
	for i := range f.Closures {
		f.Closures[i] = ownReferenceClose(f.Closures[i])
	}
	if f.OwnerClose != nil {
		p := *f.OwnerClose
		p.Signature = slices.Clone(p.Signature)
		f.OwnerClose = &p
	}
	return f
}

type referenceState struct {
	Pins      reconcile.LeaseJournal
	Consumers map[[32]byte]ReferenceConsumer
	Scopes    map[string][32]byte
	Floors    map[string]uint64
	Fences    map[[32]byte]ReferenceRetirement
}

func (s referenceState) clone() referenceState {
	if s.Pins.Schema == 0 {
		return referenceState{}
	}
	q := referenceState{Pins: s.Pins, Consumers: map[[32]byte]ReferenceConsumer{}, Scopes: map[string][32]byte{}, Floors: map[string]uint64{}, Fences: map[[32]byte]ReferenceRetirement{}}
	q.Pins.Active = slices.Clone(s.Pins.Active)
	for k, v := range s.Consumers {
		q.Consumers[k] = ownReferenceConsumer(v)
	}
	for k, v := range s.Scopes {
		q.Scopes[k] = v
	}
	for k, v := range s.Floors {
		q.Floors[k] = v
	}
	for k, v := range s.Fences {
		q.Fences[k] = ownReferenceRetirement(v)
	}
	return q
}
func (s *referenceState) init() {
	if s.Pins.Schema != 0 {
		return
	}
	pins, _ := reconcile.NewLeases(1, maxRecords)
	*s = referenceState{Pins: pins.Checkpoint(), Consumers: map[[32]byte]ReferenceConsumer{}, Scopes: map[string][32]byte{}, Floors: map[string]uint64{}, Fences: map[[32]byte]ReferenceRetirement{}}
}
func (a Authority) ReferenceConsumer(id [32]byte) (ReferenceConsumer, bool) {
	c, ok := a.references.Consumers[id]
	return ownReferenceConsumer(c), ok
}
func (a Authority) DNSReference(tenant, id string, local Source) (ReferenceConsumer, bool) {
	scope := "dns/" + dnsKey(tenant, id) + "/" + fullPool(local)
	key := a.references.Scopes[scope]
	c, ok := a.references.Consumers[key]
	return ownReferenceConsumer(c), ok && c.Local == local
}
func (a Authority) DNSReferenceGeneration(tenant, id string, local Source) uint64 {
	return a.references.Floors["dns/"+dnsKey(tenant, id)+"/"+fullPool(local)]
}
func (a Authority) ReferenceRetirement(id [32]byte) (ReferenceRetirement, bool) {
	f, ok := a.references.Fences[id]
	return ownReferenceRetirement(f), ok
}
func (a Authority) AddressRetirement(alloc network.Allocation) (ReferenceRetirement, bool) {
	for _, f := range a.references.Fences {
		if f.Target.Allocation == alloc {
			return ownReferenceRetirement(f), true
		}
	}
	return ReferenceRetirement{}, false
}
func memberEqual(a, b Source) bool { return a == b }
func consumerCovers(c ReferenceConsumer, s Source, before uint64) bool {
	for _, m := range c.Members {
		if memberEqual(m.Source, s) && (before == 0 || m.Since <= before) {
			return true
		}
	}
	return false
}

// Every live DNS/route reader of an address participates in its retirement.
func consumerNeedsAddress(c ReferenceConsumer, target ReferenceTarget, before uint64) bool {
	return consumerCovers(c, target.Source, before)
}
func referenceForProjection(a Authority, p dnsProjection) (ReferenceConsumer, bool) {
	c, ok := a.DNSReference(p.Config.Tenant, p.Config.ID, p.Local)
	if !ok || c.Closed != nil {
		return ReferenceConsumer{}, false
	}
	for _, s := range p.Members {
		if !consumerCovers(c, s, 0) {
			return ReferenceConsumer{}, false
		}
	}
	return c, true
}

// GrantDNSInstance is a management transition BEFORE any instance can serve.
// It reserves one A3 lifetime for all hot view generations and grows coverage
// from the complete validated projection, never a caller-supplied subset.
// Existing/unknown instances keep their original identity and lifetime.
func (a Authority) GrantDNSInstance(c access.Catalog, n tenancy.Networks, actor string, expected uint64, cfg DNSConfig) (Authority, ReferenceConsumer, error) {
	p, e := buildDNS(c, n, a, actor, cfg)
	if e != nil {
		return a, ReferenceConsumer{}, e
	}
	for _, r := range p.Records {
		if a.addressFenced(r.Allocation) {
			return a, ReferenceConsumer{}, ErrLease
		}
	}
	want := ReferenceConsumer{Scope: dnsReferenceScope(p), Name: cfg.ID, Local: p.Local, DesiredSource: cfg.Source, DesiredHash: projectionHash(p), Serial: cfg.Serial}
	for _, s := range p.Members {
		want.Members = append(want.Members, ReferenceMember{Source: s})
	}
	return a.grantReference(want, expected, true)
}

// grantReference is the one shared instance allocator for DNS and route owners.
// Callers derive coverage and desired hashes from validated product projections.
func (a Authority) grantReference(want ReferenceConsumer, expected uint64, hot bool) (Authority, ReferenceConsumer, error) {
	s := a.references
	last := s.Floors[want.Scope]
	old, known := s.Consumers[s.Scopes[want.Scope]]
	if last != expected {
		return a, ReferenceConsumer{}, ErrLease
	}
	if known && old.Closed == nil {
		if old.Local != want.Local || (old.Route == nil) != (want.Route == nil) {
			return a, ReferenceConsumer{}, ErrLease
		}
		if want.DesiredSource < old.DesiredSource || want.DesiredSource == old.DesiredSource && want.DesiredHash != old.DesiredHash || want.DesiredSource > old.DesiredSource && (!hot || !SerialAfter(want.Serial, old.Serial)) {
			return a, ReferenceConsumer{}, ErrLease
		}
		all := true
		for _, m := range want.Members {
			if !consumerCovers(old, m.Source, 0) {
				all = false
			}
		}
		if all && want.DesiredSource == old.DesiredSource {
			return a, ownReferenceConsumer(old), nil
		}
	}
	q, e := a.clone()
	if e != nil {
		return a, ReferenceConsumer{}, e
	}
	q.references.init()
	if !known || old.Closed != nil {
		if len(q.references.Consumers) >= maxRecords || len(q.references.Floors) >= maxRecords && last == 0 {
			return a, ReferenceConsumer{}, ErrLease
		}
		pins, e := reconcile.RestoreLeases(q.references.Pins)
		if e != nil {
			return a, ReferenceConsumer{}, ErrLease
		}
		life, e := pins.Acquire()
		if e != nil {
			return a, ReferenceConsumer{}, ErrLease
		}
		q.references.Pins = pins.Checkpoint()
		old = ReferenceConsumer{Scope: want.Scope, Name: want.Name, Local: want.Local, Generation: q.revision, Lifetime: life}
		old.ID = referenceID(old.Scope, old.Generation)
		q.references.Scopes[old.Scope] = old.ID
		q.references.Floors[old.Scope] = old.Generation
	}
	for _, m := range want.Members {
		if !consumerCovers(old, m.Source, 0) {
			old.Members = append(old.Members, ReferenceMember{m.Source, q.revision})
		}
	}
	old.DesiredSource = want.DesiredSource
	old.DesiredHash = want.DesiredHash
	old.Serial = want.Serial
	old.Route = want.Route
	old.Native = want.Native
	if len(old.Members) > 64 {
		return a, ReferenceConsumer{}, ErrLease
	}
	sortReferenceMembers(old.Members)
	q.references.Consumers[old.ID] = ownReferenceConsumer(old)
	return q, ownReferenceConsumer(old), nil
}
func sortReferenceMembers(m []ReferenceMember) {
	slices.SortFunc(m, func(a, b ReferenceMember) int {
		x, y := ReferenceTargetID(ReferenceTarget{Source: a.Source}), ReferenceTargetID(ReferenceTarget{Source: b.Source})
		return strings.Compare(hex.EncodeToString(x[:]), hex.EncodeToString(y[:]))
	})
}
func (a Authority) addressFenced(alloc network.Allocation) bool {
	_, ok := a.AddressRetirement(alloc)
	return ok
}
func (a *Authority) startAddressRetirement(target ReferenceTarget, at int64) error {
	a.references.init()
	id := ReferenceTargetID(target)
	if _, exists := a.references.Fences[id]; exists || len(a.references.Fences) >= maxRecords {
		return ErrLease
	}
	f := ReferenceRetirement{ID: id, Target: target, Epoch: a.revision, At: at}
	for _, c := range a.references.Consumers {
		if c.Closed == nil && consumerNeedsAddress(c, target, a.revision) {
			f.Required = append(f.Required, ReferenceNeed{c.ID, c.Generation, c.Lifetime, c.Local.Owner})
		}
	}
	slices.SortFunc(f.Required, func(a, b ReferenceNeed) int {
		return strings.Compare(hex.EncodeToString(a.Consumer[:]), hex.EncodeToString(b.Consumer[:]))
	})
	a.references.Fences[id] = f
	return nil
}
func validReferenceClose(cluster [32]byte, c ReferenceConsumer, p ReferenceClose) bool {
	return p.Cluster == cluster && p.Consumer == c.ID && p.Generation == c.Generation && p.Lifetime == c.Lifetime && p.Owner == c.Local.Owner && p.Boot != ([32]byte{}) && p.At > 0 && len(p.Native) > 0 && len(p.Native) <= 256 && !strings.ContainsAny(p.Native, "\x00\r\n") && p.Fenced && p.Settled && p.TTLExpired && p.PendingQueries == 0 && p.PendingFlows == 0 && p.PendingPins == 0 && ed25519.Verify(ed25519.PublicKey(p.Owner[:]), ReferenceCloseBytes(p), p.Signature)
}
func (a Authority) ObserveReferenceClose(p ReferenceClose, now int64) (Authority, error) {
	c, known := a.references.Consumers[p.Consumer]
	if !known || now <= 0 || now > 1<<62 || p.At > now || !validReferenceClose(a.cluster, c, p) {
		return a, ErrLease
	}
	if p.Target == ([32]byte{}) {
		if p.Epoch != 0 {
			return a, ErrLease
		}
		if c.Closed != nil {
			return a, nil
		}
		q, e := a.clone()
		if e != nil {
			return a, e
		}
		pins, e := reconcile.RestoreLeases(q.references.Pins)
		if e != nil || pins.Release(c.Lifetime) != nil {
			return a, ErrLease
		}
		q.references.Pins = pins.Checkpoint()
		q.at = max(q.at, now)
		c.ClosedRevision = q.revision
		v := ownReferenceClose(p)
		c.Closed = &v
		q.references.Consumers[c.ID] = c
		return q, nil
	}
	f, ok := a.references.Fences[p.Target]
	if !ok || f.ReclaimedRevision != 0 || f.Epoch != p.Epoch || p.At < f.At {
		return a, ErrLease
	}
	need := false
	for _, n := range f.Required {
		if n.Consumer == p.Consumer && n.Generation == p.Generation && n.Lifetime == p.Lifetime {
			need = true
		}
	}
	if !need {
		return a, ErrLease
	}
	for _, v := range f.Closures {
		if v.Consumer == p.Consumer {
			return a, nil
		}
	}
	q, e := a.clone()
	if e != nil {
		return a, e
	}
	q.at = max(q.at, now)
	f = ownReferenceRetirement(f)
	f.Closures = append(f.Closures, ownReferenceClose(p))
	slices.SortFunc(f.Closures, func(a, b ReferenceClose) int {
		return strings.Compare(hex.EncodeToString(a.Consumer[:]), hex.EncodeToString(b.Consumer[:]))
	})
	q.references.Fences[f.ID] = f
	return q, nil
}
func (a Authority) referencesSettled(f ReferenceRetirement) bool {
	for _, need := range f.Required {
		c, ok := a.references.Consumers[need.Consumer]
		if !ok || c.Generation != need.Generation || c.Lifetime != need.Lifetime {
			return false
		}
		if c.Closed != nil {
			continue
		}
		closed := false
		for _, p := range f.Closures {
			if p.Consumer == need.Consumer {
				closed = true
			}
		}
		if !closed {
			return false
		}
	}
	return true
}

// AddressConsumersSettled is the same gate used by ReleaseStatic. Whole-
// instance closure or the exact address/fence receipts may satisfy it; idle
// observations and a disabled policy never do. The address owner's positive
// native close is still required separately by ReleaseStatic.
func (a Authority) AddressConsumersSettled(allocation network.Allocation) bool {
	fence, exists := a.AddressRetirement(allocation)
	return exists && a.referencesSettled(fence)
}

type AddressOwnerClose struct {
	Cluster, Target           [32]byte
	Epoch                     uint64
	Owner, Boot               [32]byte
	At                        int64
	Native                    string
	Fenced, Stopped           bool
	PendingFlows, PendingPins uint64
	Signature                 []byte
}

func AddressOwnerCloseBytes(p AddressOwnerClose) []byte {
	p.Signature = nil
	raw, _ := json.Marshal(p)
	return append([]byte("sfc-address-owner-close-1\x00"), raw...)
}
func validAddressOwnerClose(cluster [32]byte, f ReferenceRetirement, p AddressOwnerClose, now int64) bool {
	return p.Cluster == cluster && p.Target == f.ID && p.Epoch == f.Epoch && p.Owner == f.Target.Source.Owner && p.Boot != ([32]byte{}) && p.At >= f.At && p.At <= now && p.Fenced && p.Stopped && p.PendingFlows == 0 && p.PendingPins == 0 && p.Native != "" && len(p.Native) <= 256 && ed25519.Verify(ed25519.PublicKey(p.Owner[:]), AddressOwnerCloseBytes(p), p.Signature)
}
func allocationSource(n tenancy.Networks, cluster [32]byte, alloc network.Allocation) (Source, bool) {
	parts := strings.Split(alloc.Pool, "/")
	if len(parts) != 3 || n.Cluster() != cluster {
		return Source{}, false
	}
	v, ok := n.Network(parts[0], parts[1])
	if !ok {
		return Source{}, false
	}
	for _, p := range v.Pools {
		if p.ID == parts[2] && poolOwner(Source{Owner: v.Owner}) == alloc.Owner && p.Prefix.Contains(alloc.Address) {
			return Source{cluster, v.Tenant, v.ID, p.ID, v.Node, v.Owner, v.Generation, p.Prefix, p.Gateway, p.MTU}, true
		}
	}
	return Source{}, false
}
func (a Authority) BeginStaticRetirement(c access.Catalog, n tenancy.Networks, actor string, expected uint64, alloc network.Allocation, at int64) (Authority, error) {
	current, ok := a.book.AllocationOf(alloc.Endpoint, alloc.Generation)
	s, known := allocationSource(n, a.cluster, alloc)
	if !ok || current != alloc || !known || strings.HasPrefix(alloc.Endpoint, "dhcp/") || expected != a.revision || at < a.at || at <= 0 || at > 1<<62 || c.AuthorizeCleanup(actor, s.Tenant, access.ManageNetwork) != nil {
		return a, ErrLease
	}
	q, e := a.clone()
	if e != nil {
		return a, e
	}
	q.at = at
	if e = q.startAddressRetirement(ReferenceTarget{s, alloc}, at); e != nil {
		return a, e
	}
	return q, nil
}

// CompactReferences drops only already-finished history. It grants no new
// release: completed target facts cannot authorize an operation on a live old
// allocation. Native owners advance their persisted root floor before dropping
// a corresponding local fence, so an old snapshot cannot revive admission.
func (a Authority) CompactReferences() (Authority, error) {
	q, e := a.clone()
	if e != nil {
		return a, e
	}
	for id, f := range q.references.Fences {
		if alloc, held := q.book.AllocationOf(f.Target.Allocation.Endpoint, f.Target.Allocation.Generation); f.ReclaimedRevision != 0 && (!held || alloc != f.Target.Allocation) {
			delete(q.references.Fences, id)
		}
	}
	for id, c := range q.references.Consumers {
		if c.Closed == nil {
			continue
		}
		needed := false
		for _, f := range q.references.Fences {
			for _, n := range f.Required {
				if n.Consumer == id {
					needed = true
				}
			}
		}
		if needed {
			continue
		}
		delete(q.references.Consumers, id)
		if q.references.Scopes[c.Scope] == id {
			delete(q.references.Scopes, c.Scope)
		}
	}
	return q, nil
}
