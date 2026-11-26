// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"

	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

type settingsTargetDisk struct {
	Kind                             SettingKind
	Key                              string
	Revision                         uint64
	Source                           Source
	Instance                         [32]byte
	Enabled                          bool
	Binding                          settingBinding
	DNS                              *dnsProjection
	DHCP                             json.RawMessage
	Network                          *tenancy.Network
	ChangeGeneration, TargetRevision uint64
}

func targetSnapshot(t SettingsTarget) settingsTargetDisk {
	t = ownSettingsTarget(t)
	return settingsTargetDisk{t.kind, t.key, t.revision, t.source, t.instance, t.enabled, t.binding, t.dns, nil, t.network, t.changeGeneration, t.targetRevision}
}
func restoreTarget(t settingsTargetDisk) SettingsTarget {
	if len(t.DHCP) != 0 && string(t.DHCP) != "null" {
		return SettingsTarget{}
	}
	return ownSettingsTarget(SettingsTarget{kind: t.Kind, key: t.Key, revision: t.Revision, source: t.Source, instance: t.Instance, enabled: t.Enabled, binding: t.Binding, dns: t.DNS, network: t.Network, changeGeneration: t.ChangeGeneration, targetRevision: t.TargetRevision})
}
func validSetting(t SettingsTarget, cluster, owner [32]byte) bool {
	if t.revision == 0 || t.source.Owner != owner || !validReferenceSource(t.source, cluster) || !validNativeScope(t.binding.Native) || len(t.binding.Listeners) > 32 || len(t.binding.Prefixes) > 16 || t.enabled && t.instance == ([32]byte{}) {
		return false
	}
	switch t.kind {
	case SettingDNS:
		if t.dns == nil || t.network != nil || !validProjection(*t.dns, cluster, owner) || t.key != "dns/"+dnsKey(t.dns.Config.Tenant, t.dns.Config.ID) || t.revision != t.dns.Config.Source || t.source != t.dns.Local || t.enabled != t.dns.Config.Enabled || len(t.binding.Prefixes) != 0 || t.binding.Exclusive {
			return false
		}
		expected := 0
		if t.enabled {
			expected = 2
		}
		if len(t.binding.Listeners) != expected {
			return false
		}
		for i, l := range t.binding.Listeners {
			protocol := uint8(6)
			if i == 1 {
				protocol = 17
			}
			if l != (network.Listener{ID: generationText(uint64(protocol)), Owner: poolOwner(t.source), Generation: 1, Address: t.source.Gateway, Protocol: protocol, Port: 53}) {
				return false
			}
		}
	case SettingNetwork:
		if t.network == nil || t.dns != nil || t.key != "network/"+serviceKey(t.source.Tenant, t.source.Network) || t.network.Tenant != t.source.Tenant || t.network.ID != t.source.Network || t.network.Owner != owner || t.network.Node != t.source.Node || len(t.network.Pools) != len(t.binding.Prefixes) || len(t.network.Pools) == 0 || !t.binding.Exclusive || len(t.binding.Listeners) != 0 || t.enabled == t.network.Draining {
			return false
		}
		book, _ := network.NewBook(1)
		for i, p := range t.network.Pools {
			if p.Prefix != t.binding.Prefixes[i] {
				return false
			}
			var e error
			book, e = book.AddPool(network.Pool{ID: p.ID, Network: t.key, Owner: poolOwner(t.source), Prefix: p.Prefix, Gateway: p.Gateway, MTU: p.MTU, IPAM: p.IPAM})
			if e != nil {
				return false
			}
		}
		if t.changeGeneration == 0 {
			if t.targetRevision != 0 || t.source.NetworkGeneration != t.network.Generation || t.revision != t.network.Revision {
				return false
			}
		} else if t.changeGeneration != t.source.NetworkGeneration || t.targetRevision != t.revision || t.network.Generation != 0 || t.network.Revision != 0 {
			return false
		}
	default:
		return false
	}
	return true
}

type settingsScopeDisk struct {
	Settled                   *SettingsProof
	Aborted                   uint64
	Key                       string
	Desired, LastGood         settingsTargetDisk
	Switch                    reconcile.State
	Current, Observed, Staged uint64
	Serial                    bool
	Proof                     *SettingsProof
}
type settingsUserDisk struct {
	Pin     reconcile.Lease
	Request [32]byte
}
type settingsSlotDisk struct {
	ActivationNetwork *tenancy.Network
	ID                uint64
	Target            settingsTargetDisk
	Group             uint64
	GroupPin          reconcile.Lease
	Pins              reconcile.LeaseJournal
	Users             []settingsUserDisk
	Retired           bool
}
type settingsDisk struct {
	Schema                                           uint8
	Cluster, Owner, Boot                             [32]byte
	ReferenceFloor, NetworkFloor, CatalogFloor, Next uint64
	MaxSlots, MaxUsers                               int
	Scopes                                           []settingsScopeDisk
	Groups                                           []settingsGroup
	Slots                                            []settingsSlotDisk
}

func (m Settings) snapshot() (settingsDisk, error) {
	if m.cluster == ([32]byte{}) || m.owner == ([32]byte{}) || m.boot == ([32]byte{}) || m.maxSlots < 1 || m.maxSlots > 1024 || m.maxUsers < 1 || m.maxUsers > 4096 || len(m.scopes) > 1024 || len(m.slots) > 1024 || len(m.groups) > 1024 || m.scopes == nil || m.slots == nil || m.groups == nil {
		return settingsDisk{}, ErrLease
	}
	s := settingsDisk{Schema: 1, Cluster: m.cluster, Owner: m.owner, Boot: m.boot, ReferenceFloor: m.referenceFloor, NetworkFloor: m.networkFloor, CatalogFloor: m.catalogFloor, Next: m.next, MaxSlots: m.maxSlots, MaxUsers: m.maxUsers}
	specs := map[string]uint64{}
	groupPins := map[uint64]map[uint64]reconcile.Lease{}
	for id, slot := range m.slots {
		pins, e := reconcile.RestoreLeases(slot.Pins)
		if id == 0 || slot.ID != id || id > m.next || e != nil || slot.Pins.Generation != id || slot.Pins.Capacity != m.maxUsers || pins.Count() != len(slot.Users) || !validSetting(slot.Target, m.cluster, m.owner) {
			return s, ErrLease
		}
		if slot.ActivationNetwork != nil {
			n := slot.ActivationNetwork
			if slot.Target.kind != SettingNetwork || slot.Target.changeGeneration == 0 || n.Generation == 0 || n.Revision != n.Generation || n.Draining || n.PendingChange != 0 || n.Tenant != slot.Target.source.Tenant || n.ID != slot.Target.source.Network || n.Owner != slot.Target.source.Owner || !slices.Equal(n.Pools, slot.Target.network.Pools) {
				return s, ErrLease
			}
		}
		if _, ok := m.scopes[slot.Target.key]; !ok {
			return s, ErrLease
		}
		if slot.Target.enabled {
			g, ok := m.groups[slot.Group]
			if !ok || g.Key != slot.Target.key || !m.compatibleGroup(g, slot.Target) || slot.GroupPin.Generation != g.ID {
				return s, ErrLease
			}
			if groupPins[g.ID] == nil {
				groupPins[g.ID] = map[uint64]reconcile.Lease{}
			}
			if _, dup := groupPins[g.ID][slot.GroupPin.Token]; dup {
				return s, ErrLease
			}
			groupPins[g.ID][slot.GroupPin.Token] = slot.GroupPin
		} else if slot.Group != 0 || slot.GroupPin != (reconcile.Lease{}) {
			return s, ErrLease
		}
		d := settingsSlotDisk{ActivationNetwork: slot.ActivationNetwork, ID: id, Target: targetSnapshot(slot.Target), Group: slot.Group, GroupPin: slot.GroupPin, Pins: slot.Pins, Retired: slot.Retired}
		d.Pins.Active = slices.Clone(slot.Pins.Active)
		for _, pin := range slot.Pins.Active {
			request, ok := slot.Users[pin.Token]
			if !ok || request == ([32]byte{}) {
				return s, ErrLease
			}
			d.Users = append(d.Users, settingsUserDisk{pin, request})
		}
		specs[slotSpec(slot)] = id
		s.Slots = append(s.Slots, d)
	}
	for key, scope := range m.scopes {
		if key != scope.Desired.key || !validSetting(scope.Desired, m.cluster, m.owner) || reconcile.Validate(scope.Switch) != nil || scope.Switch.GenerationFloor > m.next {
			return s, ErrLease
		}
		for _, id := range []uint64{scope.Current, scope.Staged, scope.Observed} {
			if id != 0 {
				slot, ok := m.slots[id]
				if !ok || slot.Target.key != key {
					return s, ErrLease
				}
			}
		}
		if scope.Current != 0 && m.slots[scope.Current].Retired {
			return s, ErrLease
		}
		for _, resource := range []reconcile.Resource{scope.Switch.Desired.Resource, scope.Switch.Applied} {
			if resource.Present {
				id, ok := specs[resource.Spec]
				if !ok || m.slots[id].Target.key != key || resource.Generation > id {
					return s, ErrLease
				}
			}
		}
		if op := scope.Switch.Pending; op != nil {
			id, ok := specs[op.Target.Spec]
			if !ok || m.slots[id].Target.key != key || op.Target.Generation > id {
				return s, ErrLease
			}
		}
		if !m.validSettlement(scope.Switch, scope.Settled, scope.Aborted, SettingsActivate, key, 0) {
			return s, ErrLease
		}
		if scope.Proof != nil {
			p := *scope.Proof
			if !m.validProof(p, p.Boot) || p.Action != SettingsActivate || p.Key != key || p.Operation > scope.Switch.LastID || p.Outcome != reconcile.EffectApplied || scope.Switch.Applied.Present != (p.Kind == reconcile.Apply) || scope.Switch.Applied.Present && (scope.Switch.Applied.Spec != p.Spec || scope.Switch.Applied.Generation != p.Generation) {
				return s, ErrLease
			}
		} else if scope.Switch.Applied.Present {
			return s, ErrLease
		}
		if scope.LastGood.revision != 0 && !validSetting(scope.LastGood, m.cluster, m.owner) {
			return s, ErrLease
		}
		s.Scopes = append(s.Scopes, settingsScopeDisk{Settled: scope.Settled, Aborted: scope.Aborted, Key: key, Desired: targetSnapshot(scope.Desired), LastGood: targetSnapshot(scope.LastGood), Switch: cloneRuntimeState(scope.Switch), Current: scope.Current, Observed: scope.Observed, Staged: scope.Staged, Serial: scope.Serial, Proof: scope.Proof})
	}
	for id, g := range m.groups {
		if g.ID != id || id == 0 || id > m.next || reconcile.Validate(g.State) != nil || g.State.GenerationFloor != id || g.Pins.Generation != id || g.Pins.Capacity != m.maxSlots || g.Pins.Draining {
			return s, ErrLease
		}
		pins, e := reconcile.RestoreLeases(g.Pins)
		if e != nil || pins.Count() != len(groupPins[id]) {
			return s, ErrLease
		}
		for _, p := range g.Pins.Active {
			if p != groupPins[id][p.Token] {
				return s, ErrLease
			}
		}
		expected := reconcile.Resource{Generation: id, Spec: groupSpec(g), Present: true}
		if g.State.Desired.Present && g.State.Desired.Resource != expected || !g.State.Desired.Present && g.State.Desired.Retiring != id || g.State.Applied.Present && g.State.Applied != expected || g.State.Pending != nil && g.State.Pending.Target != expected {
			return s, ErrLease
		}
		if g.Assignment != nil {
			a := g.Assignment
			t := restoreTarget(a.Target)
			slot := settingsSlot{ID: a.Slot, Target: t, ActivationNetwork: &a.Network}
			if !validSetting(t, m.cluster, m.owner) || t.kind != SettingNetwork || t.changeGeneration == 0 || t.source != g.Source || t.instance != g.Instance || !bindingEqual(t.binding, g.Binding) || a.Slot > m.next || a.Network.Generation == 0 || a.Network.Owner != m.owner || !slices.Equal(a.Network.Pools, t.network.Pools) || !m.validProof(a.Proof, a.Proof.Boot) || a.Proof.Action != SettingsActivate || a.Proof.Kind != reconcile.Apply || a.Proof.Outcome != reconcile.EffectApplied || a.Proof.Key != g.Key || a.Proof.Spec != slotSpec(slot) {
				return s, ErrLease
			}
		}
		if !m.validSettlement(g.State, g.Settled, g.Aborted, SettingsPrepare, g.Key, g.ID) {
			return s, ErrLease
		}
		if g.Proof != nil {
			p := *g.Proof
			if !m.validProof(p, p.Boot) || p.Action != SettingsPrepare || p.Group != id || p.Key != g.Key || p.Operation > g.State.LastID || p.Spec != expected.Spec || p.Generation != id || p.Outcome != reconcile.EffectApplied || g.State.Applied.Present != (p.Kind == reconcile.Apply) {
				return s, ErrLease
			}
		} else if g.State.Applied.Present {
			return s, ErrLease
		}
		s.Groups = append(s.Groups, g)
	}
	slices.SortFunc(s.Scopes, func(a, b settingsScopeDisk) int { return strings.Compare(a.Key, b.Key) })
	slices.SortFunc(s.Slots, func(a, b settingsSlotDisk) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	slices.SortFunc(s.Groups, func(a, b settingsGroup) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	return s, nil
}
func (m Settings) Encode() ([]byte, error) {
	s, e := m.snapshot()
	if e != nil {
		return nil, e
	}
	raw, e := json.Marshal(s)
	if e != nil || len(raw) > 32<<20 {
		return nil, ErrLease
	}
	return raw, nil
}
func DecodeSettings(raw []byte) (Settings, error) {
	var s settingsDisk
	if len(raw) > 32<<20 || json.Unmarshal(raw, &s) != nil || s.Schema != 1 || len(s.Scopes) > 1024 || len(s.Groups) > 1024 || len(s.Slots) > 1024 {
		return Settings{}, ErrLease
	}
	m, e := NewSettings(s.Cluster, s.Owner, s.Boot, s.MaxSlots, s.MaxUsers)
	if e != nil {
		return Settings{}, e
	}
	m.referenceFloor = s.ReferenceFloor
	m.networkFloor = s.NetworkFloor
	m.catalogFloor = s.CatalogFloor
	m.next = s.Next
	for _, d := range s.Scopes {
		if _, dup := m.scopes[d.Key]; dup {
			return Settings{}, ErrLease
		}
		m.scopes[d.Key] = settingsScope{Settled: d.Settled, Aborted: d.Aborted, Desired: restoreTarget(d.Desired), LastGood: restoreTarget(d.LastGood), Switch: d.Switch, Current: d.Current, Observed: d.Observed, Staged: d.Staged, Serial: d.Serial, Proof: d.Proof}
	}
	for _, g := range s.Groups {
		if _, dup := m.groups[g.ID]; dup {
			return Settings{}, ErrLease
		}
		m.groups[g.ID] = g
	}
	for _, d := range s.Slots {
		if _, dup := m.slots[d.ID]; dup {
			return Settings{}, ErrLease
		}
		slot := settingsSlot{ActivationNetwork: d.ActivationNetwork, ID: d.ID, Target: restoreTarget(d.Target), Group: d.Group, GroupPin: d.GroupPin, Pins: d.Pins, Users: map[uint64][32]byte{}, Retired: d.Retired}
		for _, u := range d.Users {
			if _, dup := slot.Users[u.Pin.Token]; dup {
				return Settings{}, ErrLease
			}
			slot.Users[u.Pin.Token] = u.Request
		}
		m.slots[d.ID] = slot
	}
	canonical, e := m.Encode()
	if e != nil || !bytes.Equal(raw, canonical) {
		return Settings{}, ErrLease
	}
	return m.clone(), nil
}

func (m Settings) validSettlement(state reconcile.State, p *SettingsProof, aborted uint64, action SettingsAction, key string, group uint64) bool {
	if aborted > state.LastID {
		return false
	}
	if p != nil && (!m.validProof(*p, p.Boot) || p.Action != action || p.Key != key || p.Group != group || p.Operation > state.LastID) {
		return false
	}
	if state.Pending == nil && state.LastID != 0 {
		return aborted == state.LastID || p != nil && p.Operation == state.LastID
	}
	if state.Pending != nil {
		return aborted < state.LastID && (p == nil || p.Operation < state.LastID)
	}
	return p == nil && aborted == 0
}
