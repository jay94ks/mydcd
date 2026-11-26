// SPDX-License-Identifier: Apache-2.0

package services

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

type settingsScope struct {
	Settled                   *SettingsProof
	Aborted                   uint64
	Desired                   SettingsTarget
	Switch                    reconcile.State
	Current, Observed, Staged uint64
	LastGood                  SettingsTarget
	Serial                    bool
	Proof                     *SettingsProof
}
type settingsGroup struct {
	Assignment *settingsAssignment
	Settled    *SettingsProof
	Aborted    uint64
	ID         uint64
	Key        string
	Source     Source
	Instance   [32]byte
	Binding    settingBinding
	State      reconcile.State
	Pins       reconcile.LeaseJournal
	Proof      *SettingsProof
}
type settingsSlot struct {
	ActivationNetwork *tenancy.Network
	ID                uint64
	Target            SettingsTarget
	Group             uint64
	GroupPin          reconcile.Lease
	Pins              reconcile.LeaseJournal
	Users             map[uint64][32]byte
	Retired           bool
}

// Settings coordinates all node-local network/DNS settings. Its candidates
// are synced by one native owner before publication. It does no OS I/O.
type Settings struct {
	cluster, owner, boot                       [32]byte
	referenceFloor, networkFloor, catalogFloor uint64
	next                                       uint64
	maxSlots, maxUsers                         int
	scopes                                     map[string]settingsScope
	groups                                     map[uint64]settingsGroup
	slots                                      map[uint64]settingsSlot
}

func NewSettings(cluster, owner, boot [32]byte, maxSlots, maxUsers int) (Settings, error) {
	if cluster == ([32]byte{}) || owner == ([32]byte{}) || boot == ([32]byte{}) || maxSlots < 1 || maxSlots > 1024 || maxUsers < 1 || maxUsers > 4096 {
		return Settings{}, ErrLease
	}
	return Settings{cluster: cluster, owner: owner, boot: boot, maxSlots: maxSlots, maxUsers: maxUsers, scopes: map[string]settingsScope{}, groups: map[uint64]settingsGroup{}, slots: map[uint64]settingsSlot{}}, nil
}
func cloneRuntimeState(s reconcile.State) reconcile.State {
	if s.Pending != nil {
		op := *s.Pending
		s.Pending = &op
	}
	return s
}
func (m Settings) clone() Settings {
	q := m
	q.scopes = map[string]settingsScope{}
	q.groups = map[uint64]settingsGroup{}
	q.slots = map[uint64]settingsSlot{}
	for k, s := range m.scopes {
		if s.Settled != nil {
			p := ownSettingsProof(*s.Settled)
			s.Settled = &p
		}
		s.Desired = ownSettingsTarget(s.Desired)
		s.LastGood = ownSettingsTarget(s.LastGood)
		s.Switch = cloneRuntimeState(s.Switch)
		if s.Proof != nil {
			p := ownSettingsProof(*s.Proof)
			s.Proof = &p
		}
		q.scopes[k] = s
	}
	for id, g := range m.groups {
		if g.Assignment != nil {
			a := *g.Assignment
			a.Target = targetSnapshot(restoreTarget(a.Target))
			a.Network.Pools = slices.Clone(a.Network.Pools)
			a.Proof = ownSettingsProof(a.Proof)
			g.Assignment = &a
		}
		if g.Settled != nil {
			p := ownSettingsProof(*g.Settled)
			g.Settled = &p
		}
		g.Binding.Listeners = slices.Clone(g.Binding.Listeners)
		g.Binding.Prefixes = slices.Clone(g.Binding.Prefixes)
		g.State = cloneRuntimeState(g.State)
		g.Pins.Active = slices.Clone(g.Pins.Active)
		if g.Proof != nil {
			p := ownSettingsProof(*g.Proof)
			g.Proof = &p
		}
		q.groups[id] = g
	}
	for id, s := range m.slots {
		if s.ActivationNetwork != nil {
			n := *s.ActivationNetwork
			n.Pools = slices.Clone(n.Pools)
			s.ActivationNetwork = &n
		}
		s.Target = ownSettingsTarget(s.Target)
		s.Pins.Active = slices.Clone(s.Pins.Active)
		s.Users = map[uint64][32]byte{}
		for token, h := range m.slots[id].Users {
			s.Users[token] = h
		}
		q.slots[id] = s
	}
	return q
}
func (m Settings) fresh(c access.Catalog, n tenancy.Networks, a Authority) bool {
	return a.cluster == m.cluster && n.Cluster() == m.cluster && a.revision >= m.referenceFloor && n.Revision() >= m.networkFloor && c.Revision() >= m.catalogFloor
}
func (m *Settings) floors(c access.Catalog, n tenancy.Networks, a Authority) {
	m.referenceFloor = a.revision
	m.networkFloor = n.Revision()
	m.catalogFloor = c.Revision()
}
func (m Settings) Desired(c access.Catalog, n tenancy.Networks, a Authority, actor string, expected uint64, t SettingsTarget) (Settings, error) {
	old, known := m.scopes[t.key]
	if !m.fresh(c, n, a) || t.source.Owner != m.owner || t.revision == 0 || expected != old.Desired.revision || t.revision < old.Desired.revision || !t.preparable(c, n, a) || !known && len(m.scopes) >= m.maxSlots {
		return m, ErrLease
	}
	action := access.ManageServices
	if t.kind == SettingNetwork {
		action = access.ManageNetwork
	}
	if t.enabled {
		if c.Authorize(actor, t.source.Tenant, action, t.source.Node) != nil {
			return m, ErrLease
		}
	} else if c.AuthorizeCleanup(actor, t.source.Tenant, action) != nil {
		return m, ErrLease
	}
	if t.revision == old.Desired.revision {
		if t.hash() != old.Desired.hash() {
			return m, ErrLease
		}
		return m, nil
	}
	q := m.clone()
	q.floors(c, n, a)
	old.Desired = ownSettingsTarget(t)
	q.scopes[t.key] = old
	return q, nil
}
func slotSpec(s settingsSlot) string {
	raw, _ := json.Marshal(struct {
		Target  settingsTargetDisk
		Network *tenancy.Network
	}{targetSnapshot(s.Target), s.ActivationNetwork})
	h := sha256.Sum256(raw)
	return generationText(s.ID) + "/" + hex.EncodeToString(h[:])
}
func groupSpec(g settingsGroup) string {
	raw, _ := json.Marshal(struct {
		Source   Source
		Instance [32]byte
		Binding  settingBinding
	}{g.Source, g.Instance, g.Binding})
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
func (m Settings) groupBusy(g settingsGroup) bool {
	return g.State.Desired.Present || g.State.Applied.Present || g.State.Pending != nil
}
func (m Settings) conflict(g settingsGroup) bool {
	for id, other := range m.groups {
		if id != g.ID && m.groupBusy(other) && bindingConflicts(g.Binding, other.Binding) {
			return true
		}
	}
	return false
}

// Stage retains an original accepted slot even if Desired has advanced. New
// targets are separate slots; the old original journals must still be settled.
func (m Settings) Stage(c access.Catalog, n tenancy.Networks, a Authority, key string) (Settings, uint64, error) {
	scope, ok := m.scopes[key]
	t := scope.Desired
	if !ok || !m.fresh(c, n, a) || !t.preparable(c, n, a) || m.next == ^uint64(0) {
		return m, 0, ErrLease
	}
	if s, exists := m.slots[scope.Staged]; exists && s.Target.hash() == t.hash() {
		return m, s.ID, nil
	}
	if len(m.slots) >= m.maxSlots {
		return m, 0, ErrLease
	}
	q := m.clone()
	q.floors(c, n, a)
	q.next++
	id := q.next
	var group settingsGroup
	if t.enabled {
		for _, g := range q.groups {
			if g.Key == key && m.compatibleGroup(g, t) && g.State.Desired.Present {
				group = g
				break
			}
		}
		if group.ID == 0 {
			pins, _ := reconcile.NewLeases(id, m.maxSlots)
			group = settingsGroup{ID: id, Key: key, Source: t.source, Instance: t.instance, Binding: t.binding, Pins: pins.Checkpoint()}
			// A conflicting candidate has a journal identity but is not allowed to bind.
			group.State, _ = reconcile.SetDesired(group.State, reconcile.Desired{Revision: 1, Resource: reconcile.Resource{Generation: id, Present: true, Spec: groupSpec(group)}})
			for _, other := range q.groups {
				if q.groupBusy(other) && bindingConflicts(group.Binding, other.Binding) && other.Key != key {
					return m, 0, ErrLease
				}
			}
		}
		pins, e := reconcile.RestoreLeases(group.Pins)
		if e != nil {
			return m, 0, e
		}
		pin, e := pins.Acquire()
		if e != nil {
			return m, 0, e
		}
		group.Pins = pins.Checkpoint()
		q.groups[group.ID] = group
		users, _ := reconcile.NewLeases(id, m.maxUsers)
		q.slots[id] = settingsSlot{ID: id, Target: ownSettingsTarget(t), Group: group.ID, GroupPin: pin, Pins: users.Checkpoint(), Users: map[uint64][32]byte{}}
	} else {
		users, _ := reconcile.NewLeases(id, m.maxUsers)
		q.slots[id] = settingsSlot{ID: id, Target: ownSettingsTarget(t), Pins: users.Checkpoint(), Users: map[uint64][32]byte{}}
	}
	// Only slots superseded before dispatch can be collected without native work.
	for oldID, s := range q.slots {
		if s.Target.key == key && oldID != id && oldID != scope.Current {
			s.Retired = true
			q.slots[oldID] = s
		}
	}
	scope = q.scopes[key]
	scope.Staged = id
	scope.Serial = t.enabled && q.conflict(group)
	q.scopes[key] = scope
	return q, id, nil
}
func (m Settings) nativeReady(g settingsGroup) bool {
	return g.State.Pending == nil && g.State.Desired.Present && g.State.Applied == g.State.Desired.Resource && g.Proof != nil && g.Proof.Boot == m.boot && g.Proof.Outcome == reconcile.EffectApplied && g.Proof.Kind == reconcile.Apply
}
func desiredSwitch(s settingsScope, d reconcile.Resource) (settingsScope, error) {
	if s.Switch.Desired.Resource == d {
		return s, nil
	}
	if s.Switch.Desired.Revision == ^uint64(0) {
		return s, ErrLease
	}
	want := reconcile.Desired{Revision: s.Switch.Desired.Revision + 1, Resource: d}
	if !d.Present {
		want.Retiring = s.Switch.GenerationFloor
	}
	var e error
	s.Switch, e = reconcile.SetDesired(s.Switch, want)
	return s, e
}

// PlanSwitch publishes no Ready. It journals the original serving transition;
// Observe and Publish require exact evidence and current typed policy later.
func (m Settings) PlanSwitch(c access.Catalog, n tenancy.Networks, a Authority, key string) (Settings, *reconcile.Operation, error) {
	scope, ok := m.scopes[key]
	slot, staged := m.slots[scope.Staged]
	if !ok || !staged || !m.fresh(c, n, a) {
		return m, nil, ErrLease
	}
	q := m.clone()
	q.floors(c, n, a)
	if scope.Switch.Pending != nil {
		return m, nil, reconcile.ErrPending
	}
	var desired reconcile.Resource
	if slot.Target.enabled {
		g := m.groups[slot.Group]
		if !slot.Target.live(c, n, a, true) {
			if slot.Target.live(c, n, a, false) {
				return m, nil, reconcile.ErrPending
			}
			if slot.Target.kind == SettingNetwork && slot.Target.preparable(c, n, a) {
				ch, _ := n.Change(slot.Target.source.Tenant, slot.Target.source.Network)
				if ch.Phase == tenancy.ChangeReserved {
					return m, nil, reconcile.ErrPending
				}
			}
		} else {
			if slot.Target.kind == SettingNetwork && slot.Target.changeGeneration != 0 {
				v, _ := n.Network(slot.Target.source.Tenant, slot.Target.source.Network)
				v.PendingChange = 0
				if slot.ActivationNetwork == nil {
					slot.ActivationNetwork = &v
					q.slots[slot.ID] = slot
				} else if slot.ActivationNetwork.Generation != v.Generation {
					return m, nil, ErrLease
				}
			}
			// Serial switch: deactivate old, settle users, close the original group;
			// only then may the new group's original preparation operation dispatch.
			if !m.nativeReady(g) {
				if !scope.Serial {
					return m, nil, reconcile.ErrPending
				}
			} else {
				generation := scope.Switch.GenerationFloor
				if generation == 0 || !scope.Switch.Desired.Present || scope.Serial {
					generation = slot.ID
				}
				desired = reconcile.Resource{Generation: generation, Present: true, Spec: slotSpec(slot)}
			}
		}
	}
	var e error
	scope, e = desiredSwitch(scope, desired)
	if e != nil {
		return m, nil, e
	}
	if !desired.Present && scope.Switch.Applied.Present {
		for _, old := range m.slots {
			if old.Target.key == key && len(old.Users) != 0 {
				return m, nil, reconcile.ErrPending
			}
		}
	}
	state, op, e := reconcile.Plan(scope.Switch)
	scope.Switch = state
	if e != nil {
		return m, nil, e
	}
	q.scopes[key] = scope
	return q, op, nil
}

// PlanGroup uses the existing A2 algorithm for exact original bind/close. A
// removal waits every slot dependency and original serving-switch reference.
func (m Settings) PlanGroup(id uint64) (Settings, *reconcile.Operation, error) {
	g, ok := m.groups[id]
	if !ok {
		return m, nil, ErrLease
	}
	if g.State.Desired.Present && m.conflict(g) {
		return m, nil, reconcile.ErrPending
	}
	if !g.State.Desired.Present && len(g.Pins.Active) != 0 {
		return m, nil, reconcile.ErrPending
	}
	s, op, e := reconcile.Plan(g.State)
	if e != nil {
		return m, nil, e
	}
	q := m.clone()
	g.State = s
	q.groups[id] = g
	return q, op, nil
}

// PublishDNS joins the exact native switch and existing DNS projection publish
// as one local candidate. The owner syncs BOTH before exposing its pointer.
func (m Settings) PublishDNS(c access.Catalog, n tenancy.Networks, a Authority, d DNSManager, actor, key string, now Clock) (Settings, DNSManager, error) {
	scope, ok := m.scopes[key]
	slot, exists := m.slots[scope.Staged]
	if !ok || !exists || slot.Target.kind != SettingDNS || !m.canPublish(c, n, a, key) {
		return m, d, ErrLease
	}
	cfg := slot.Target.dns.Config
	k := dnsKey(cfg.Tenant, cfg.ID)
	manager := d
	if pending, known := manager.pending[k]; known && projectionHash(pending.Projection) != projectionHash(*slot.Target.dns) {
		var e error
		manager, e = manager.Discard(cfg.Tenant, cfg.ID, pending.Projection.Config.Source)
		if e != nil {
			return m, d, e
		}
	}
	if _, known := manager.pending[k]; !known {
		var e error
		manager, e = manager.Prepare(c, n, a, actor, manager.floors[k].Source, cfg)
		if e != nil {
			return m, d, e
		}
	}
	var e error
	manager, e = manager.Publish(c, n, a, cfg.Tenant, cfg.ID, cfg.Source, now)
	if e != nil {
		return m, d, e
	}
	q, e := m.Publish(c, n, a, key)
	if e != nil {
		return m, d, e
	}
	return q, manager, nil
}
func (m Settings) canPublish(c access.Catalog, n tenancy.Networks, a Authority, key string) bool {
	scope, ok := m.scopes[key]
	slot, exists := m.slots[scope.Staged]
	if !ok || !exists || !m.fresh(c, n, a) || slot.Target.hash() != scope.Desired.hash() || scope.Switch.Pending != nil || !slot.Target.preparable(c, n, a) {
		return false
	}
	if !slot.Target.enabled {
		return !scope.Switch.Applied.Present
	}
	return scope.Proof != nil && scope.Proof.Boot == m.boot && scope.Switch.Applied.Present && scope.Switch.Applied.Spec == slotSpec(slot) && m.nativeReady(m.groups[slot.Group]) && slot.Target.live(c, n, a, true)
}
func (m Settings) Publish(c access.Catalog, n tenancy.Networks, a Authority, key string) (Settings, error) {
	if !m.canPublish(c, n, a, key) {
		return m, ErrLease
	}
	q := m.clone()
	q.floors(c, n, a)
	scope := q.scopes[key]
	slot := q.slots[scope.Staged]
	if old, exists := q.slots[scope.Current]; exists && old.ID != slot.ID {
		old.Retired = true
		q.slots[old.ID] = old
	}
	scope.Current = slot.ID
	scope.LastGood = ownSettingsTarget(slot.Target)
	q.scopes[key] = scope
	return q, nil
}

// SettingsUse pins the original config/socket dependency across replacement.
// Request is an opaque digest/ID supplied by the native request owner.
type SettingsUse struct {
	slot    uint64
	pin     reconcile.Lease
	request [32]byte
}

func (h SettingsUse) Slot() uint64           { return h.slot }
func (h SettingsUse) Lease() reconcile.Lease { return h.pin }
func (m Settings) Borrow(c access.Catalog, n tenancy.Networks, a Authority, key string, request [32]byte, existing bool) (Settings, SettingsUse, error) {
	scope, ok := m.scopes[key]
	slot, held := m.slots[scope.Current]
	if !ok || !held || !m.fresh(c, n, a) || request == ([32]byte{}) || slot.Retired || !scope.Desired.enabled || scope.Serial && scope.Staged != scope.Current || !slot.Target.live(c, n, a, false) || scope.Switch.Pending != nil || scope.Proof == nil || scope.Proof.Boot != m.boot || scope.Switch.Applied.Spec != slotSpec(slot) || !m.nativeReady(m.groups[slot.Group]) {
		return m, SettingsUse{}, ErrLease
	}
	count := 0
	for _, s := range m.slots {
		count += len(s.Users)
	}
	if count >= m.maxUsers {
		return m, SettingsUse{}, ErrLease
	}
	pins, e := reconcile.RestoreLeases(slot.Pins)
	if e != nil {
		return m, SettingsUse{}, e
	}
	pin, e := pins.Acquire()
	if e != nil {
		return m, SettingsUse{}, e
	}
	q := m.clone()
	q.floors(c, n, a)
	slot = q.slots[slot.ID]
	slot.Pins = pins.Checkpoint()
	slot.Users[pin.Token] = request
	q.slots[slot.ID] = slot
	return q, SettingsUse{slot.ID, pin, request}, nil
}
func (m Settings) CollectSlot(id uint64) (Settings, error) {
	s, ok := m.slots[id]
	if !ok || !s.Retired || len(s.Users) != 0 {
		return m, ErrLease
	}
	spec := slotSpec(s)
	for _, scope := range m.scopes {
		if scope.Current == id || scope.Staged == id || scope.Switch.Applied.Spec == spec || scope.Switch.Desired.Spec == spec || scope.Switch.Pending != nil && scope.Switch.Pending.Target.Spec == spec {
			return m, reconcile.ErrPending
		}
	}
	q := m.clone()
	if s.Group != 0 {
		g := q.groups[s.Group]
		pins, e := reconcile.RestoreLeases(g.Pins)
		if e != nil || pins.Release(s.GroupPin) != nil {
			return m, ErrLease
		}
		g.Pins = pins.Checkpoint()
		if pins.Count() == 0 {
			var e error
			g.State, e = reconcile.SetDesired(g.State, reconcile.Desired{Revision: g.State.Desired.Revision + 1, Retiring: g.ID})
			if e != nil {
				return m, e
			}
		}
		q.groups[g.ID] = g
	}
	delete(q.slots, id)
	return q, nil
}
func (m Settings) Resize(maxSlots, maxUsers int) (Settings, error) {
	if maxSlots < 1 || maxSlots > 1024 || maxUsers < 1 || maxUsers > 4096 {
		return m, ErrLease
	}
	q := m.clone()
	q.maxSlots = maxSlots
	q.maxUsers = maxUsers
	for id, s := range q.slots {
		pins, e := reconcile.RestoreLeases(s.Pins)
		if e != nil || pins.Resize(maxUsers) != nil {
			return m, ErrLease
		}
		s.Pins = pins.Checkpoint()
		q.slots[id] = s
	}
	for id, g := range q.groups {
		pins, e := reconcile.RestoreLeases(g.Pins)
		if e != nil || pins.Resize(maxSlots) != nil {
			return m, ErrLease
		}
		g.Pins = pins.Checkpoint()
		q.groups[id] = g
	}
	return q, nil
}

// SettingsDNSUse couples the native request pin with the SAME DNS view/query
// algorithm. The local owner syncs both returned candidates in one transaction.
type SettingsDNSUse struct {
	Runtime SettingsUse
	Query   DNSQuery
}

func (m Settings) AcquireDNS(c access.Catalog, n tenancy.Networks, a Authority, d DNSManager, tenant, id string, origin network.Allocation, raw []byte, now Clock) (Settings, DNSManager, SettingsDNSUse, error) {
	key := "dns/" + dnsKey(tenant, id)
	scope := m.scopes[key]
	slot, ok := m.slots[scope.Current]
	if !ok || now.Boot != m.boot || d.Applied(tenant, id) != slot.Target.revision {
		return m, d, SettingsDNSUse{}, ErrLease
	}
	request := sha256.Sum256(raw)
	next, use, e := m.Borrow(c, n, a, key, request, false)
	if e != nil {
		return m, d, SettingsDNSUse{}, e
	}
	manager, query, e := d.Acquire(c, n, a, tenant, id, origin, raw, now)
	if e != nil {
		return m, d, SettingsDNSUse{}, e
	}
	use.request = settingsDNSRequest(query)
	pinned := next.slots[use.slot]
	pinned.Users[use.pin.Token] = use.request
	next.slots[use.slot] = pinned
	return next, manager, SettingsDNSUse{use, query}, nil
}
func settingsDNSRequest(q DNSQuery) [32]byte {
	id := q.ID()
	return sha256.Sum256(append([]byte("mydc/settings/dns-query/1/"), id[:]...))
}
func (m Settings) ReleaseDNS(d DNSManager, h SettingsDNSUse, now Clock, p SettingsUseClose) (Settings, DNSManager, error) {
	if h.Runtime.request != settingsDNSRequest(h.Query) {
		return m, d, ErrLease
	}
	next, e := m.Return(h.Runtime, p)
	if e != nil {
		return m, d, e
	}
	manager, e := d.Release(h.Query, now)
	if e != nil {
		return m, d, e
	}
	return next, manager, nil
}

type settingsAssignment struct {
	Slot    uint64
	Target  settingsTargetDisk
	Network tenancy.Network
	Proof   SettingsProof
}

func (m Settings) compatibleGroup(g settingsGroup, t SettingsTarget) bool {
	if !bindingEqual(g.Binding, t.binding) {
		return false
	}
	if g.Instance == t.instance && g.Source == t.source {
		return true
	}
	if g.Assignment == nil || t.kind != SettingNetwork || t.changeGeneration != 0 || t.network == nil {
		return false
	}
	n := g.Assignment.Network
	return n.Generation == t.network.Generation && n.Tenant == t.source.Tenant && n.ID == t.source.Network && n.Owner == t.source.Owner && n.Node == t.source.Node && slices.Equal(n.Pools, t.network.Pools)
}
