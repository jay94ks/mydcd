// SPDX-License-Identifier: Apache-2.0

package services

import (
	"crypto/ed25519"
	"encoding/json"
	"slices"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

type SettingsAction string

const (
	SettingsPrepare  SettingsAction = "prepare"
	SettingsActivate SettingsAction = "activate"
)

type SettingsStep struct {
	Action    SettingsAction
	Key       string
	Group     uint64
	Operation reconcile.Operation
}

// SettingsProof is positive original native-journal evidence. Prepare Apply is
// inactive; Activate Apply stops old admission while retaining original users.
// NoPending refers to the original operation, not old pinned requests.
type SettingsProof struct {
	Cluster, Owner, Boot                                                        [32]byte
	Action                                                                      SettingsAction
	Key                                                                         string
	Group                                                                       uint64
	Operation                                                                   uint64
	Kind                                                                        reconcile.Kind
	Generation                                                                  uint64
	Spec                                                                        string
	Outcome                                                                     reconcile.Outcome
	Synced, Inactive, Serving, Gone, NotApplied, OldAdmissionStopped, NoPending bool
	Signature                                                                   []byte
}

func SettingsProofBytes(p SettingsProof) []byte {
	p.Signature = nil
	raw, _ := json.Marshal(p)
	return append([]byte("mydc-settings-native-1\x00"), raw...)
}
func ownSettingsProof(p SettingsProof) SettingsProof {
	p.Signature = slices.Clone(p.Signature)
	return p
}
func (m Settings) validProof(p SettingsProof, boot [32]byte) bool {
	if p.Cluster != m.cluster || p.Owner != m.owner || boot == ([32]byte{}) || p.Boot != boot || p.Key == "" || p.Operation == 0 || p.Generation == 0 || p.Spec == "" || !p.Synced || !p.NoPending || p.Kind != reconcile.Apply && p.Kind != reconcile.Remove || p.Outcome != reconcile.EffectApplied && p.Outcome != reconcile.EffectNotApplied {
		return false
	}
	if p.Outcome == reconcile.EffectNotApplied {
		if !p.NotApplied || p.Inactive || p.Serving || p.Gone || p.OldAdmissionStopped {
			return false
		}
	} else if p.NotApplied {
		return false
	} else if p.Kind == reconcile.Remove {
		if !p.Gone || p.Inactive || p.Serving || p.Action == SettingsActivate && !p.OldAdmissionStopped {
			return false
		}
	} else if p.Action == SettingsPrepare {
		if !p.Inactive || p.Serving || p.Gone || p.Group == 0 {
			return false
		}
	} else if p.Action == SettingsActivate {
		if !p.Serving || p.Inactive || p.Gone || !p.OldAdmissionStopped || p.Group != 0 {
			return false
		}
	} else {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(m.owner[:]), SettingsProofBytes(p), p.Signature)
}
func (m Settings) stepState(step SettingsStep) (reconcile.State, bool) {
	if step.Action == SettingsPrepare {
		g, ok := m.groups[step.Group]
		return g.State, ok && g.Key == step.Key
	}
	if step.Action == SettingsActivate {
		s, ok := m.scopes[step.Key]
		return s.Switch, ok && step.Group == 0
	}
	return reconcile.State{}, false
}
func (m *Settings) setStepState(step SettingsStep, state reconcile.State) {
	if step.Action == SettingsPrepare {
		g := m.groups[step.Group]
		g.State = state
		m.groups[step.Group] = g
	} else {
		s := m.scopes[step.Key]
		s.Switch = state
		m.scopes[step.Key] = s
	}
}
func sameOperation(a, b reconcile.Operation) bool {
	return a.ID == b.ID && a.Kind == b.Kind && a.Target == b.Target && a.Phase == b.Phase
}
func (m Settings) Dispatch(c access.Catalog, n tenancy.Networks, a Authority, step SettingsStep) (Settings, error) {
	state, ok := m.stepState(step)
	if !ok || !m.fresh(c, n, a) || state.Pending == nil || !sameOperation(*state.Pending, step.Operation) {
		return m, ErrLease
	}
	if step.Operation.Kind == reconcile.Apply {
		scope := m.scopes[step.Key]
		slot, held := m.slots[scope.Staged]
		if !held || slot.Target.hash() != scope.Desired.hash() || !slot.Target.preparable(c, n, a) {
			return m, ErrLease
		}
		if step.Action == SettingsActivate {
			if !slot.Target.live(c, n, a, true) || step.Operation.Target.Spec != slotSpec(slot) || !m.nativeReady(m.groups[slot.Group]) {
				return m, ErrLease
			}
		} else if slot.Group != step.Group || m.conflict(m.groups[step.Group]) {
			return m, ErrLease
		}
	}
	s, e := reconcile.Dispatch(state, step.Operation.ID)
	if e != nil {
		return m, e
	}
	q := m.clone()
	q.floors(c, n, a)
	q.setStepState(step, s)
	return q, nil
}
func (m Settings) Unknown(step SettingsStep) (Settings, error) {
	state, ok := m.stepState(step)
	if !ok {
		return m, ErrLease
	}
	s, e := reconcile.Settle(state, step.Operation.ID, reconcile.EffectUnknown)
	if e != nil {
		return m, e
	}
	q := m.clone()
	q.setStepState(step, s)
	return q, nil
}
func (m Settings) AbortPrepared(step SettingsStep) (Settings, error) {
	state, ok := m.stepState(step)
	if !ok {
		return m, ErrLease
	}
	s, e := reconcile.AbortPrepared(state, step.Operation.ID)
	if e != nil {
		return m, e
	}
	q := m.clone()
	q.setStepState(step, s)
	if step.Action == SettingsPrepare {
		g := q.groups[step.Group]
		g.Aborted = step.Operation.ID
		q.groups[g.ID] = g
	} else {
		scope := q.scopes[step.Key]
		scope.Aborted = step.Operation.ID
		q.scopes[step.Key] = scope
	}
	return q, nil
}
func (m Settings) Observe(p SettingsProof) (Settings, error) {
	step := SettingsStep{Action: p.Action, Key: p.Key, Group: p.Group}
	state, ok := m.stepState(step)
	op := state.Pending
	if !ok || op == nil || op.ID != p.Operation || op.Kind != p.Kind || op.Target.Generation != p.Generation || op.Target.Spec != p.Spec || !m.validProof(p, m.boot) {
		return m, ErrLease
	}
	s, e := reconcile.Settle(state, p.Operation, p.Outcome)
	if e != nil {
		return m, e
	}
	q := m.clone()
	q.setStepState(step, s)
	receipt := ownSettingsProof(p)
	if p.Action == SettingsPrepare {
		g := q.groups[p.Group]
		g.Settled = &receipt
		q.groups[g.ID] = g
	} else {
		scope := q.scopes[p.Key]
		scope.Settled = &receipt
		q.scopes[p.Key] = scope
	}
	if p.Outcome != reconcile.EffectApplied {
		return q, nil
	}
	proof := ownSettingsProof(p)
	if p.Action == SettingsPrepare {
		g := q.groups[p.Group]
		g.Proof = &proof
		q.groups[g.ID] = g
	} else {
		scope := q.scopes[p.Key]
		scope.Proof = &proof
		if p.Kind == reconcile.Apply {
			found := false
			for id, slot := range q.slots {
				if slot.Target.key == p.Key && slotSpec(slot) == p.Spec {
					scope.Observed = id
					if slot.ActivationNetwork != nil {
						g := q.groups[slot.Group]
						g.Assignment = &settingsAssignment{Slot: id, Target: targetSnapshot(slot.Target), Network: *slot.ActivationNetwork, Proof: ownSettingsProof(p)}
						q.groups[g.ID] = g
					}
					found = true
				}
			}
			if !found {
				return m, ErrLease
			}
		} else {
			scope.Observed = 0
			if old, held := q.slots[scope.Current]; held {
				old.Retired = true
				q.slots[old.ID] = old
				scope.LastGood = ownSettingsTarget(old.Target)
				scope.Current = 0
			}
			// Revoked old stage has no future serving authority, but its original
			// group/slot remains until explicit native cleanup below.
			if old, held := q.slots[scope.Staged]; held && old.Target.hash() != scope.Desired.hash() {
				old.Retired = true
				q.slots[old.ID] = old
				scope.Staged = 0
			}
		}
		q.scopes[p.Key] = scope
	}
	return q, nil
}
func (m Settings) ResumeBoot(boot [32]byte) (Settings, error) {
	if boot == ([32]byte{}) {
		return m, ErrLease
	}
	q := m.clone()
	q.boot = boot
	return q, nil
}

// Revalidate accepts read-back of the exact original Applied operation only;
// boot change never clears pending operations, users or group dependencies.
func (m Settings) Revalidate(p SettingsProof) (Settings, error) {
	step := SettingsStep{Action: p.Action, Key: p.Key, Group: p.Group}
	state, ok := m.stepState(step)
	if !ok || state.Pending != nil || !state.Applied.Present || state.Applied.Generation != p.Generation || state.Applied.Spec != p.Spec || p.Kind != reconcile.Apply || p.Outcome != reconcile.EffectApplied || !m.validProof(p, m.boot) {
		return m, ErrLease
	}
	var old *SettingsProof
	if p.Action == SettingsPrepare {
		old = m.groups[p.Group].Proof
	} else {
		old = m.scopes[p.Key].Proof
	}
	if old == nil || old.Operation != p.Operation {
		return m, ErrLease
	}
	q := m.clone()
	proof := ownSettingsProof(p)
	if p.Action == SettingsPrepare {
		g := q.groups[p.Group]
		g.Proof = &proof
		q.groups[g.ID] = g
	} else {
		s := q.scopes[p.Key]
		s.Proof = &proof
		q.scopes[p.Key] = s
	}
	return q, nil
}

// DropGroup removes only a positively closed original native group. A prepared
// but never dispatched Apply may abort and close without inventing Gone.
func (m Settings) DropGroup(id uint64) (Settings, error) {
	g, ok := m.groups[id]
	if !ok || g.State.Desired.Present || g.State.Pending != nil || g.State.Applied.Present || len(g.Pins.Active) != 0 {
		return m, ErrLease
	}
	if g.Proof != nil && (g.Proof.Kind != reconcile.Remove || g.Proof.Outcome != reconcile.EffectApplied || g.Proof.Boot != m.boot) {
		return m, ErrLease
	}
	q := m.clone()
	delete(q.groups, id)
	return q, nil
}

type SettingsUseClose struct {
	Cluster, Owner, Boot       [32]byte
	Slot                       uint64
	Pin                        reconcile.Lease
	Request                    [32]byte
	Synced, Stopped, NoPending bool
	Signature                  []byte
}

func SettingsUseCloseBytes(p SettingsUseClose) []byte {
	p.Signature = nil
	raw, _ := json.Marshal(p)
	return append([]byte("mydc-settings-user-close-1\x00"), raw...)
}
func (m Settings) UseFacts(h SettingsUse) (SettingsUseClose, error) {
	slot, ok := m.slots[h.slot]
	if !ok || slot.Users[h.pin.Token] != h.request || h.request == ([32]byte{}) || h.pin.Generation != slot.ID {
		return SettingsUseClose{}, ErrLease
	}
	found := false
	for _, pin := range slot.Pins.Active {
		if pin == h.pin {
			found = true
		}
	}
	if !found {
		return SettingsUseClose{}, ErrLease
	}
	return SettingsUseClose{Cluster: m.cluster, Owner: m.owner, Boot: m.boot, Slot: h.slot, Pin: h.pin, Request: h.request}, nil
}
func (m Settings) Return(h SettingsUse, p SettingsUseClose) (Settings, error) {
	expected, e := m.UseFacts(h)
	if e != nil || expected.Cluster != p.Cluster || expected.Owner != p.Owner || expected.Boot != p.Boot || expected.Slot != p.Slot || expected.Pin != p.Pin || expected.Request != p.Request || !p.Synced || !p.Stopped || !p.NoPending || !ed25519.Verify(ed25519.PublicKey(m.owner[:]), SettingsUseCloseBytes(p), p.Signature) {
		return m, ErrLease
	}
	slot := m.slots[h.slot]
	pins, e := reconcile.RestoreLeases(slot.Pins)
	if e != nil || pins.Release(h.pin) != nil {
		return m, ErrLease
	}
	q := m.clone()
	slot = q.slots[h.slot]
	slot.Pins = pins.Checkpoint()
	delete(slot.Users, h.pin.Token)
	q.slots[h.slot] = slot
	return q, nil
}

type SettingsStatus struct {
	Key                        string
	Desired, Applied, Observed uint64
	Current, Staged            uint64
	Serial                     bool
	Pending                    int
	Users                      int
}

func (m Settings) Status(key string) SettingsStatus {
	s := m.scopes[key]
	out := SettingsStatus{Key: key, Desired: s.Desired.revision, Current: s.Current, Staged: s.Staged, Serial: s.Serial}
	if slot, ok := m.slots[s.Current]; ok {
		out.Applied = slot.Target.revision
	}
	if slot, ok := m.slots[s.Observed]; ok {
		out.Observed = slot.Target.revision
	}
	if s.Switch.Pending != nil {
		out.Pending++
	}
	for _, slot := range m.slots {
		if slot.Target.key == key {
			out.Users += len(slot.Users)
		}
	}
	for _, g := range m.groups {
		if g.Key == key && g.State.Pending != nil {
			out.Pending++
		}
	}
	return out
}

// NativePlan materializes the immutable ORIGINAL journal target for the real
// driver. Recovery never reconstructs it from the newest Desired/shared root.
func (m Settings) NativePlan(step SettingsStep) ([]byte, error) {
	state, ok := m.stepState(step)
	if !ok || state.Pending == nil || state.Pending.ID != step.Operation.ID || state.Pending.Kind != step.Operation.Kind || state.Pending.Target != step.Operation.Target {
		return nil, ErrLease
	}
	if step.Action == SettingsPrepare {
		g := m.groups[step.Group]
		return json.Marshal(struct {
			Action   SettingsAction
			ID       uint64
			Key      string
			Source   Source
			Instance [32]byte
			Binding  settingBinding
		}{step.Action, g.ID, g.Key, g.Source, g.Instance, g.Binding})
	}
	for _, slot := range m.slots {
		if slot.Target.key == step.Key && slotSpec(slot) == step.Operation.Target.Spec {
			return json.Marshal(struct {
				Action  SettingsAction
				Slot    uint64
				Target  settingsTargetDisk
				Network *tenancy.Network
			}{step.Action, slot.ID, targetSnapshot(slot.Target), slot.ActivationNetwork})
		}
	}
	return nil, ErrLease
}
