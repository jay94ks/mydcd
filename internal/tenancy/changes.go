// SPDX-License-Identifier: Apache-2.0

package tenancy

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/network"
)

type ChangePhase string

const (
	ChangeReserved  ChangePhase = "reserved"
	ChangeDraining  ChangePhase = "draining"
	ChangeFenced    ChangePhase = "fenced"
	ChangeCommitted ChangePhase = "committed"
	ChangeCancelled ChangePhase = "cancelled"
)

// NetworkChange is an administrative reservation/fence/owner-CAS workflow.
// Native Applied/Observed and pending native calls stay in the local journal.
type NetworkChange struct {
	ID                                                     string
	Generation, Revision, TargetRevision, DrainingRevision uint64
	Original, Target                                       Network
	Phase                                                  ChangePhase
	MetadataOnly                                           bool `json:",omitempty"`
	SourceClosed                                           *NetworkClosure
	CandidateClosed                                        *ChangeCandidateClose
	Previous                                               []ClosedCandidate
	Committed                                              Network
}
type ClosedCandidate struct {
	TargetRevision uint64
	Target         Network
	Closed         ChangeCandidateClose
}

type NetworkChangeVersion struct {
	Tenant, ID           string
	Generation, Revision uint64
}

// Clone returns owned metadata, including every original signature/target.
func (c NetworkChange) Clone() NetworkChange { return ownChange(c) }

// CheckRetired reuses the original change validator after its live catalog row
// has moved to Authority's history. It grants no current/native permission.
func (c NetworkChange) CheckRetired(cluster [32]byte, original Network) error {
	n, err := New(cluster)
	expected := ownNetwork(c.Original)
	expected.Draining, expected.Revision, expected.PendingChange = true, c.DrainingRevision, c.Generation
	if err != nil || c.Phase != ChangeFenced || !validNetwork(original) || !sameNetwork(expected, original) {
		return ErrPolicy
	}
	n.revision = c.Revision
	n.networks[key(original.Tenant, original.ID)] = ownNetwork(original)
	n.changes[key(original.Tenant, original.ID)] = ownChange(c)
	if !n.validChange(c) {
		return ErrPolicy
	}
	if _, err := n.AddressPlan(1); err != nil {
		return err
	}
	return nil
}

type ChangeCandidateClose struct {
	Cluster                    [32]byte
	Change                     string
	Generation, TargetRevision uint64
	Target                     [32]byte
	Owner, Boot                [32]byte
	Native                     string
	Fenced, Gone, NoPending    bool
	Signature                  []byte
}

// Empty distinguishes absent native evidence from a supplied closure claim.
func (p ChangeCandidateClose) Empty() bool {
	return p.Cluster == ([32]byte{}) && p.Change == "" && p.Generation == 0 && p.TargetRevision == 0 && p.Target == ([32]byte{}) && p.Owner == ([32]byte{}) && p.Boot == ([32]byte{}) && p.Native == "" && !p.Fenced && !p.Gone && !p.NoPending && len(p.Signature) == 0
}

func ChangeCandidateBytes(p ChangeCandidateClose) []byte {
	p.Signature = nil
	raw, _ := json.Marshal(p)
	return append([]byte("mydc-network-candidate-close-1\x00"), raw...)
}
func ChangeTargetHash(v Network) [32]byte {
	raw, _ := json.Marshal(v)
	return sha256.Sum256(append([]byte("mydc-network-change-target-1\x00"), raw...))
}
func CandidateNativeID(c NetworkChange) string {
	if c.MetadataOnly {
		return ""
	}
	raw, _ := json.Marshal(struct {
		ID                         string
		Generation, TargetRevision uint64
	}{c.ID, c.Generation, c.TargetRevision})
	h := sha256.Sum256(raw)
	return "network-candidate/" + hex.EncodeToString(h[:])
}
func ownCandidate(p ChangeCandidateClose) ChangeCandidateClose {
	p.Signature = slices.Clone(p.Signature)
	return p
}
func ownChange(c NetworkChange) NetworkChange {
	c.Original = ownNetwork(c.Original)
	c.Target = ownNetwork(c.Target)
	c.Committed = ownNetwork(c.Committed)
	if c.SourceClosed != nil {
		p := *c.SourceClosed
		p.Signature = slices.Clone(p.Signature)
		c.SourceClosed = &p
	}
	if c.CandidateClosed != nil {
		p := ownCandidate(*c.CandidateClosed)
		c.CandidateClosed = &p
	}
	c.Previous = slices.Clone(c.Previous)
	for i := range c.Previous {
		c.Previous[i].Target = ownNetwork(c.Previous[i].Target)
		c.Previous[i].Closed = ownCandidate(c.Previous[i].Closed)
	}
	return c
}
func changeActive(c NetworkChange) bool {
	return c.Phase == ChangeReserved || c.Phase == ChangeDraining || c.Phase == ChangeFenced
}
func (n Networks) Change(tenant, id string) (NetworkChange, bool) {
	c, ok := n.changes[key(tenant, id)]
	return ownChange(c), ok
}
func validDefinition(v Network) bool {
	if v.Generation != 0 || v.Revision != 0 || v.Draining || v.PendingChange != 0 {
		return false
	}
	q := ownNetwork(v)
	q.Generation = 1
	q.Revision = 1
	if !validNetwork(q) {
		return false
	}
	book, _ := network.NewBook(1)
	for _, p := range v.Pools {
		var e error
		book, e = book.AddPool(network.Pool{ID: p.ID, Network: key(v.Tenant, v.ID), Owner: hex.EncodeToString(v.Owner[:]), Prefix: p.Prefix, Gateway: p.Gateway, MTU: p.MTU, IPAM: p.IPAM})
		if e != nil {
			return false
		}
	}
	return true
}

// A same-network overlapping candidate is a reservation, never a second live
// address pool. All other networks and their staged targets are excluded.
func (n Networks) reservedOverlap(v Network, except string) bool {
	for k, old := range n.networks {
		if k == except {
			continue
		}
		if reservationsOverlap(v, old) {
			return true
		}
	}
	for k, c := range n.changes {
		if k == except || !changeActive(c) {
			continue
		}
		if reservationsOverlap(v, c.Target) {
			return true
		}
	}
	return false
}

// sameNetwork compares one member's definition and state. Toggles are left
// out: they are the network's options, set on every member by SetToggle
// (which a change in progress refuses), and a kept change record must stay
// valid after one.
func sameNetwork(a, b Network) bool {
	return a.Tenant == b.Tenant && a.ID == b.ID && a.Node == b.Node && a.Owner == b.Owner && a.Generation == b.Generation && a.Revision == b.Revision && a.Draining == b.Draining && a.PendingChange == b.PendingChange && a.Logical == b.Logical && a.System == b.System && slices.Equal(a.TunnelAddresses, b.TunnelAddresses) && slices.Equal(a.Pools, b.Pools)
}
func (n Networks) PlanChange(c access.Catalog, actor, tenant, id, request string, expected uint64, target Network) (Networks, error) {
	return n.planChange(c, actor, tenant, id, request, expected, target, false)
}

// PlanMetadataChange is the product management reservation. No native source
// or permit is published for its candidate before the original source closes.
// The persisted marker distinguishes it from older native-candidate records.
func (n Networks) PlanMetadataChange(c access.Catalog, actor, tenant, id, request string, expected uint64, target Network) (Networks, error) {
	return n.planChange(c, actor, tenant, id, request, expected, target, true)
}

func (n Networks) planChange(c access.Catalog, actor, tenant, id, request string, expected uint64, target Network, metadataOnly bool) (Networks, error) {
	if tenant == "" || target.System {
		return n, ErrPolicy
	}
	v, ok := n.networks[key(tenant, id)]
	old, planned := n.changes[key(tenant, id)]
	target = ownNetwork(target)
	original := v
	if planned && old.ID == request {
		original = old.Original
	}
	if target.GatewayMode == "" {
		target.GatewayMode = original.GatewayMode
	}
	// A change keeps the network's toggles; SetToggle changes them.
	if target.Toggles == nil {
		target.Toggles = slices.Clone(original.Toggles)
	}
	slices.SortFunc(target.Pools, func(a, b Subnet) int { return strings.Compare(a.ID, b.ID) })
	initial := old.Target
	if len(old.Previous) > 0 {
		initial = old.Previous[0].Target
	}
	if planned && old.ID == request && old.Original.Revision == expected && sameNetwork(initial, target) {
		if old.MetadataOnly != metadataOnly {
			return n, ErrPolicy
		}
		if c.AuthorizeCleanup(actor, tenant, access.ManageNetwork) != nil {
			return n, access.ErrDenied
		}
		return n, nil
	}
	if !ok || v.Draining || v.Revision != expected || !validID(request) || target.Tenant != tenant || target.ID != id || !slices.Equal(target.Toggles, v.Toggles) || !validDefinition(target) || planned && changeActive(old) || n.reservedOverlap(target, key(tenant, id)) {
		return n, ErrPolicy
	}
	if c.Authorize(actor, tenant, access.ManageNetwork, v.Node) != nil || c.Authorize(actor, tenant, access.ManageNetwork, target.Node) != nil {
		return n, access.ErrDenied
	}
	q, e := n.clone()
	if e != nil {
		return n, e
	}
	marker := ownNetwork(v)
	marker.PendingChange = q.revision
	q.networks[key(tenant, id)] = marker
	q.changes[key(tenant, id)] = NetworkChange{ID: request, Generation: q.revision, Revision: q.revision, TargetRevision: q.revision, Original: ownNetwork(v), Target: target, Phase: ChangeReserved, MetadataOnly: metadataOnly}
	return q, nil
}
func (n Networks) BeginChangeDrain(c access.Catalog, actor, tenant, id string, generation, expected uint64) (Networks, error) {
	ch, ok := n.changes[key(tenant, id)]
	if !ok || ch.Generation != generation || ch.Revision != expected || ch.Phase != ChangeReserved {
		return n, ErrPolicy
	}
	return n.Drain(c, actor, tenant, id, ch.Original.Revision)
}
func (n Networks) verifiesCandidate(c NetworkChange, p ChangeCandidateClose) bool {
	return p.Cluster == n.cluster && p.Change == c.ID && p.Generation == c.Generation && p.TargetRevision == c.TargetRevision && p.Target == ChangeTargetHash(c.Target) && p.Owner == c.Target.Owner && p.Boot != ([32]byte{}) && p.Native == CandidateNativeID(c) && p.Fenced && p.Gone && p.NoPending && ed25519.Verify(ed25519.PublicKey(p.Owner[:]), ChangeCandidateBytes(p), p.Signature)
}
func (n Networks) CancelChange(c access.Catalog, actor, tenant, id string, generation, expected uint64, p ChangeCandidateClose) (Networks, error) {
	ch, ok := n.changes[key(tenant, id)]
	if !ok || ch.Generation != generation || ch.Revision != expected || ch.Phase != ChangeReserved || ch.MetadataOnly && !p.Empty() || !ch.MetadataOnly && !n.verifiesCandidate(ch, p) {
		return n, ErrPolicy
	}
	if !mayRetire(c, actor, tenant, access.ManageNetwork) {
		return n, access.ErrDenied
	}
	q, e := n.clone()
	if e != nil {
		return n, e
	}
	current := q.networks[key(tenant, id)]
	current.PendingChange = 0
	q.networks[key(tenant, id)] = current
	ch.Phase = ChangeCancelled
	ch.Revision = q.revision
	if !ch.MetadataOnly {
		proof := ownCandidate(p)
		ch.CandidateClosed = &proof
	}
	q.changes[key(tenant, id)] = ch
	return q, nil
}
func (n Networks) validSourceClose(c NetworkChange, p NetworkClosure) bool {
	v := c.Original
	return p.Cluster == n.cluster && p.Tenant == v.Tenant && p.Network == v.ID && p.Node == v.Node && p.Owner == v.Owner && p.Generation == v.Generation && p.Revision == c.DrainingRevision && p.NativeGone && p.PendingEndpoints == 0 && p.PendingFlows == 0 && p.PendingPins == 0 && ed25519.Verify(ed25519.PublicKey(v.Owner[:]), NetworkClosureBytes(p), p.Signature)
}

// FenceChange must be joined with Authority's complete Book/lease/reference
// closure checks in the enclosing FSM. It grants no early native admission.
func (n Networks) FenceChange(c access.Catalog, actor, tenant, id string, generation, expected uint64, p NetworkClosure) (Networks, error) {
	ch, ok := n.changes[key(tenant, id)]
	v, live := n.networks[key(tenant, id)]
	if !ok || !live || !v.Draining || v.Generation != ch.Original.Generation || v.Revision != ch.DrainingRevision || ch.Generation != generation || ch.Revision != expected || ch.Phase != ChangeDraining || !n.validSourceClose(ch, p) {
		return n, ErrPolicy
	}
	if !mayRetire(c, actor, tenant, access.ManageNetwork) {
		return n, access.ErrDenied
	}
	for _, r := range n.routes {
		if r.Source.Tenant == tenant && r.Source.Network == id || r.Destination.Tenant == tenant && r.Destination.Network == id {
			return n, ErrPolicy
		}
	}
	q, e := n.clone()
	if e != nil {
		return n, e
	}
	proof := p
	proof.Signature = slices.Clone(p.Signature)
	ch.SourceClosed = &proof
	ch.Phase = ChangeFenced
	ch.Revision = q.revision
	q.changes[key(tenant, id)] = ch
	return q, nil
}

// RecoverChange changes the target only after the old target's permanent fence
// and exact native completion. Source remains fenced; commit uses a NEW epoch.
func (n Networks) RecoverChange(c access.Catalog, actor, tenant, id string, generation, expected uint64, target Network, p ChangeCandidateClose) (Networks, error) {
	ch, ok := n.changes[key(tenant, id)]
	target = ownNetwork(target)
	slices.SortFunc(target.Pools, func(a, b Subnet) int { return strings.Compare(a.ID, b.ID) })
	if !ok || ch.MetadataOnly || ch.Generation != generation || ch.Revision != expected || ch.Phase != ChangeFenced || !n.verifiesCandidate(ch, p) || len(ch.Previous) >= 64 || target.Tenant != tenant || target.ID != id || !validDefinition(target) || n.reservedOverlap(target, key(tenant, id)) {
		return n, ErrPolicy
	}
	if c.Authorize(actor, tenant, access.ManageNetwork, target.Node) != nil {
		return n, access.ErrDenied
	}
	q, e := n.clone()
	if e != nil {
		return n, e
	}
	ch.Previous = append(ch.Previous, ClosedCandidate{ch.TargetRevision, ownNetwork(ch.Target), ownCandidate(p)})
	ch.Target = target
	ch.TargetRevision = q.revision
	ch.Revision = q.revision
	q.changes[key(tenant, id)] = ch
	return q, nil
}
func (n Networks) CommitChange(c access.Catalog, actor, tenant, id string, generation, expected uint64) (Networks, error) {
	return n.CommitChanges(c, actor, []NetworkChangeVersion{{Tenant: tenant, ID: id, Generation: generation, Revision: expected}})
}

// CommitChanges validates every original CAS/closure before cloning once.
// All target definitions become one new catalog generation. In particular a
// group-wide MTU change cannot expose an invalid intermediate member graph.
// Native/source and complete-group authority remain with the enclosing FSM.
func (n Networks) CommitChanges(c access.Catalog, actor string, versions []NetworkChangeVersion) (Networks, error) {
	if len(versions) == 0 || len(versions) > 32 {
		return n, ErrPolicy
	}
	last := ""
	for _, version := range versions {
		k := key(version.Tenant, version.ID)
		ch, ok := n.changes[k]
		v, held := n.networks[k]
		if k <= last || !ok || !held || !v.Draining || v.Generation != ch.Original.Generation || v.Revision != ch.DrainingRevision || ch.Generation != version.Generation || ch.Revision != version.Revision || ch.Phase != ChangeFenced || ch.SourceClosed == nil || !n.validSourceClose(ch, *ch.SourceClosed) || n.reservedOverlap(ch.Target, k) {
			return n, ErrPolicy
		}
		if c.Authorize(actor, version.Tenant, access.ManageNetwork, ch.Target.Node) != nil {
			return n, access.ErrDenied
		}
		last = k
	}
	q, e := n.clone()
	if e != nil {
		return n, e
	}
	for _, version := range versions {
		k := key(version.Tenant, version.ID)
		ch := q.changes[k]
		next := ownNetwork(ch.Target)
		next.Generation = q.revision
		next.Revision = q.revision
		q.networks[k] = next
		ch.Committed = ownNetwork(next)
		ch.Phase = ChangeCommitted
		ch.Revision = q.revision
		q.changes[k] = ch
	}
	if _, e := q.AddressPlan(1); e != nil {
		return n, e
	}
	if _, e := q.Encode(); e != nil {
		return n, e
	}
	return q, nil
}
func (n Networks) validChange(ch NetworkChange) bool {
	original := ownNetwork(ch.Original)
	original.Generation = 0
	original.Revision = 0
	original.Draining = false
	if !validID(ch.ID) || !validNetwork(ch.Original) || ch.Original.PendingChange != 0 || !validDefinition(original) || ch.Original.Draining || ch.Generation <= ch.Original.Revision || ch.Revision < ch.Generation || ch.Revision > n.revision || ch.TargetRevision < ch.Generation || ch.TargetRevision > ch.Revision || !validDefinition(ch.Target) || ch.Target.Tenant != ch.Original.Tenant || ch.Target.ID != ch.Original.ID || len(ch.Previous) > 64 {
		return false
	}
	if ch.MetadataOnly && (ch.CandidateClosed != nil || len(ch.Previous) != 0) {
		return false
	}
	last := uint64(0)
	for i, old := range ch.Previous {
		prev := ch
		prev.TargetRevision = old.TargetRevision
		prev.Target = old.Target
		if (i == 0 && old.TargetRevision != ch.Generation || i > 0 && old.TargetRevision <= last) || old.Target.Tenant != ch.Original.Tenant || old.Target.ID != ch.Original.ID || !validDefinition(old.Target) || !n.verifiesCandidate(prev, old.Closed) {
			return false
		}
		last = old.TargetRevision
	}
	if len(ch.Previous) == 0 && ch.TargetRevision != ch.Generation {
		return false
	}
	if len(ch.Previous) > 0 && ch.TargetRevision <= ch.Previous[len(ch.Previous)-1].TargetRevision {
		return false
	}
	current, live := n.networks[key(ch.Original.Tenant, ch.Original.ID)]
	switch ch.Phase {
	case ChangeReserved:
		expected := ownNetwork(ch.Original)
		expected.PendingChange = ch.Generation
		return live && sameNetwork(current, expected) && ch.DrainingRevision == 0 && ch.SourceClosed == nil && ch.CandidateClosed == nil && sameNetwork(ch.Committed, Network{}) && len(ch.Previous) == 0
	case ChangeCancelled:
		return ch.DrainingRevision == 0 && ch.SourceClosed == nil && (ch.MetadataOnly && ch.CandidateClosed == nil || !ch.MetadataOnly && ch.CandidateClosed != nil && n.verifiesCandidate(ch, *ch.CandidateClosed)) && sameNetwork(ch.Committed, Network{}) && len(ch.Previous) == 0
	case ChangeDraining, ChangeFenced, ChangeCommitted:
		if ch.DrainingRevision <= ch.Generation || ch.DrainingRevision > ch.Revision || ch.CandidateClosed != nil {
			return false
		}
		if ch.Phase == ChangeDraining {
			return live && current.PendingChange == ch.Generation && current.Draining && current.Generation == ch.Original.Generation && current.Revision == ch.DrainingRevision && ch.SourceClosed == nil && sameNetwork(ch.Committed, Network{}) && len(ch.Previous) == 0
		}
		if ch.SourceClosed == nil || !n.validSourceClose(ch, *ch.SourceClosed) {
			return false
		}
		if ch.Phase == ChangeFenced {
			return live && current.PendingChange == ch.Generation && current.Draining && current.Generation == ch.Original.Generation && current.Revision == ch.DrainingRevision && sameNetwork(ch.Committed, Network{})
		}
		installed := ownNetwork(ch.Target)
		installed.Generation = ch.Committed.Generation
		installed.Revision = ch.Committed.Generation
		return sameNetwork(ch.Committed, installed) && installed.Generation > ch.DrainingRevision && installed.Generation >= ch.TargetRevision && installed.Generation == ch.Revision && (!live || current.Generation >= installed.Generation)
	}
	return false
}
