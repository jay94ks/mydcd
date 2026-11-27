// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"slices"

	"github.com/jay94ks/seafield/internal/access"
)

// BeginRetainedDelete names a completed move's immutable physical source.
// Its pending deletion retains the physical hold, current writer and fence.
func (s State) BeginRetainedDelete(c access.Catalog, actor, id string, expected uint64) (State, error) {
	if c.Authorize(actor, s.d.Scope.Tenant, access.ManageVolumes, "") != nil {
		return s, access.ErrDenied
	}
	i := s.moveIndex(id)
	if i < 0 || expected != s.d.Revision || s.d.Deletion != nil {
		return s, ErrVolume
	}
	m := s.d.Moves[i]
	if m.Phase != Completed || m.SourceDeletion != nil || m.Binding.Source == s.d.Owner || !slices.Contains(s.d.Retained, Retained{m.Binding.Source, m.Binding.SourceOwnerRevision, id}) {
		return s, ErrVolume
	}
	n, err := s.clone()
	if err != nil {
		return s, err
	}
	n.d.Moves[i].SourceDeletion = &Deletion{Revision: n.d.Revision}
	return n, nil
}

func (s State) CompleteRetainedDelete(id string, proof NativeRemoved) (State, error) {
	i := s.moveIndex(id)
	if i < 0 || proof.Verify() != nil {
		return s, ErrVolume
	}
	m := s.d.Moves[i]
	if m.Phase != Completed || m.SourceDeletion == nil || proof.Scope != s.d.Scope || proof.Owner != m.Binding.Source || proof.DeleteRevision != m.SourceDeletion.Revision {
		return s, ErrVolume
	}
	if m.SourceDeletion.Gone != nil {
		if same(m.SourceDeletion.Gone, &proof) {
			return s, nil
		}
		return s, ErrVolume
	}
	n, err := s.clone()
	if err != nil {
		return s, err
	}
	proof.Signature = slices.Clone(proof.Signature)
	n.d.Moves[i].SourceDeletion.Gone = &proof
	n.d.Retained = slices.DeleteFunc(n.d.Retained, func(r Retained) bool { return r.Move == id })
	return n, nil
}
