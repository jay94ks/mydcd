// SPDX-License-Identifier: Apache-2.0

package volumes

import "slices"

// Preparation is an authenticated observation of the original inactive target,
// not ownership, a filesystem reservation or permission to start an app writer.
type TargetPreparation struct {
	Binding                                       Binding
	Target                                        NativeReady
	Empty, NoWriters, SpaceChecked, ProtocolReady bool
	Signature                                     []byte
	Inputs                                        *[32]byte `json:",omitempty"`
	InputsAt                                      int64     `json:",omitempty"`
}

func TargetPreparationBytes(p TargetPreparation) []byte {
	p.Signature = nil
	return signedBytes("mydc-volume-target-prepare-1", p)
}
func validPreparation(p TargetPreparation, b Binding) bool {
	return (p.Inputs == nil && p.InputsAt == 0 || p.Inputs != nil && *p.Inputs != ([32]byte{}) && p.InputsAt > 0) && p.Binding == b && p.Target.Verify() == nil && p.Target.Owner == b.Target && p.Target.Spec.Scope == b.Scope && p.Target.Generation == 1 && p.Empty && p.NoWriters && p.SpaceChecked && p.ProtocolReady && verify(b.Target.Key, TargetPreparationBytes(p), p.Signature)
}
func (s State) RecordTargetPreparation(p TargetPreparation) (State, error) {
	i := s.moveIndex(p.Binding.ID)
	if i < 0 || !validPreparation(p, s.d.Moves[i].Binding) {
		return s, ErrVolume
	}
	m := s.d.Moves[i]
	if m.Preparation != nil {
		if same(m.Preparation, &p) {
			return s, nil
		}
		// A new current input observation may refresh only the original empty
		// target while Prepared. Never replace the native identity/physical
		// evidence, drop input evidence, or rewrite a proof after fencing.
		old, next := *m.Preparation, p
		old.Inputs, next.Inputs = nil, nil
		old.InputsAt, next.InputsAt = 0, 0
		old.Signature, next.Signature = nil, nil
		if p.Inputs == nil || !same(old, next) {
			return s, ErrVolume
		}
	}
	if s.d.Active != p.Binding.ID || m.Phase != Prepared {
		return s, ErrVolume
	}
	n, err := s.clone()
	if err != nil {
		return s, err
	}
	p.Signature = slices.Clone(p.Signature)
	p.Target.Signature = slices.Clone(p.Target.Signature)
	if p.Inputs != nil {
		x := *p.Inputs
		p.Inputs = &x
	}
	n.d.Moves[i].Preparation = &p
	return n, nil
}
