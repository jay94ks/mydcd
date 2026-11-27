// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"bytes"
	"encoding/json"
	"slices"

	"github.com/jay94ks/seafield/internal/reconcile"
)

func validMove(m Move, revision uint64) bool {
	b := m.Binding
	if b.Scope.TenantManaged() {
		return false
	}
	if d := m.SourceDeletion; d != nil {
		if m.Phase != Completed || d.Revision <= m.CommitRevision || d.Revision > revision || d.Gone != nil && (d.Gone.Verify() != nil || d.Gone.Scope != b.Scope || d.Gone.Owner != b.Source || d.Gone.DeleteRevision != d.Revision || d.Revision >= revision) {
			return false
		}
	}
	if m.Preparation != nil && !validPreparation(*m.Preparation, b) {
		return false
	}
	if !validScope(b.Scope) || !identifier(b.ID) || !validOwner(b.Source) || !validOwner(b.Target) || b.Source.Node == b.Target.Node || b.StartedRevision <= b.SourceOwnerRevision || b.StartedRevision > revision || b.Compatibility == ([32]byte{}) || b.MaxBytes == 0 || b.MaxBytes > 1<<50 {
		return false
	}
	if m.Fence != nil && !validFence(*m.Fence, b) || m.Manifest != nil && (m.Fence == nil || !validManifest(*m.Manifest, b)) || m.Verified != nil && (m.Manifest == nil || !validCopy(*m.Verified, m)) || m.CancelledTarget != nil && !validCancel(*m.CancelledTarget, b) || m.Activated != nil && !validActive(*m.Activated, m) || m.SourceCleanup != nil && (m.SourceCleanup.Owner != b.Source || !validCleanup(*m.SourceCleanup, m)) || m.TargetCleanup != nil && (m.TargetCleanup.Owner != b.Target || !validCleanup(*m.TargetCleanup, m)) {
		return false
	}
	if m.ReaderClosed != nil && (m.Fence == nil || !validMoveReaderClosure(*m.ReaderClosed, b) || m.Phase == Prepared) {
		return false
	}
	committed := m.CommitRevision != 0
	if committed && (m.CommitRevision <= b.StartedRevision || m.CommitRevision > revision || m.Verified == nil) {
		return false
	}
	if m.CancelRevision != 0 && (m.CancelRevision <= b.StartedRevision || m.CancelRevision > revision || committed) {
		return false
	}
	switch m.Phase {
	case Prepared:
		if m.Fence != nil || m.Manifest != nil || m.Verified != nil || committed {
			return false
		}
	case SourceFenced:
		if m.Fence == nil || m.Manifest != nil || committed {
			return false
		}
	case Copying:
		if m.Manifest == nil || m.Verified != nil || committed {
			return false
		}
	case Verified:
		if m.Verified == nil || committed {
			return false
		}
	case OwnerCommitted, Activating, Active, Completed:
		if !committed {
			return false
		}
	case Cancelling:
		if committed || m.CancelRevision != 0 {
			return false
		}
	case Cancelled:
		if committed || m.CancelRevision == 0 || m.CancelledTarget == nil || m.SourceCleanup == nil || m.Fence == nil && !m.SourceCleanup.Unchanged {
			return false
		}
	default:
		return false
	}
	armed := m.Phase == Activating || m.Phase == Active || m.Phase == Completed
	if m.Irreversible != armed || (m.Activated != nil) != (m.Phase == Active || m.Phase == Completed) || m.CancelledTarget != nil && m.Phase != Cancelling && m.Phase != Cancelled || m.CancelRevision != 0 && m.Phase != Cancelled || m.SourceCleanup != nil && m.Phase != Active && m.Phase != Completed && m.Phase != Cancelling && m.Phase != Cancelled || m.TargetCleanup != nil && m.Phase != Active && m.Phase != Completed || (m.SourceCleanup != nil && m.TargetCleanup != nil) != (m.Phase == Completed) {
		return false
	}
	return true
}
func (s State) validate() error {
	d := s.d
	if d.Schema != 1 || !validScope(d.Scope) || d.Fixed != d.Scope.TenantManaged() || d.Fixed && (len(d.Moves) != 0 || len(d.Retained) != 0 || d.Active != "" || d.OwnerRevision != 1) || d.Revision < 1 || d.OwnerRevision < 1 || d.OwnerRevision > d.Revision || !validOwner(d.Owner) || !d.Retain || d.Pins.Generation != d.Scope.Generation || d.Pins.Capacity < 1 || d.Pins.Capacity > maxRecords || d.Pins.Draining || len(d.Consumers) != len(d.Pins.Active) || len(d.Floors) > maxRecords || len(d.Moves) > maxRecords || len(d.Used) != len(d.Moves)+1 {
		return ErrVolume
	}
	if !s.validDeletion() {
		return ErrVolume
	}
	if _, e := reconcile.RestoreLeases(d.Pins); e != nil {
		return e
	}
	for i, f := range d.Floors {
		if !identifier(f.ID) || f.Generation == 0 || i > 0 && d.Floors[i-1].ID >= f.ID {
			return ErrVolume
		}
	}
	// A writer beside other consumers exists only under a share record
	// (single-writer readers, shared writers), which the codec cannot see;
	// Acquire and AcquireShared enforce the writer rule.
	for i, c := range d.Consumers {
		if !validConsumer(c, d.Scope) || c.Owner != d.Owner || c.OwnerRevision != d.OwnerRevision || c.Lease != d.Pins.Active[i] {
			return ErrVolume
		}
		if !slices.Contains(d.Floors, Floor{c.ID, c.Generation}) {
			return ErrVolume
		}
		for j := 0; j < i; j++ {
			if d.Consumers[j].ID == c.ID {
				return ErrVolume
			}
		}
	}
	for i, o := range d.Used {
		if !validOwner(o) {
			return ErrVolume
		}
		for j := 0; j < i; j++ {
			if sameNative(d.Used[j], o) {
				return ErrVolume
			}
		}
	}
	owner := d.Used[0]
	ownerRev := uint64(1)
	previousEnd := uint64(1)
	active := ""
	var retained []Retained
	seen := map[string]bool{}
	for i, m := range d.Moves {
		b := m.Binding
		if !validMove(m, d.Revision) || b.Scope != d.Scope || seen[b.ID] || b.Source != owner || b.SourceOwnerRevision != ownerRev || b.StartedRevision <= previousEnd || b.Target != d.Used[i+1] || active != "" {
			return ErrVolume
		}
		if m.ReaderClosed != nil {
			reader := m.ReaderClosed.Consumer
			if !slices.Contains(d.Floors, Floor{reader.ID, reader.Generation}) || reader.Lease.Token > d.Pins.Next || slices.Contains(d.Pins.Active, reader.Lease) {
				return ErrVolume
			}
		}
		if m.SourceCleanup != nil && m.SourceCleanup.Unchanged && s.HadMoveReader(b) {
			return ErrVolume
		}
		seen[b.ID] = true
		if m.CommitRevision > 0 {
			owner = b.Target
			ownerRev = m.CommitRevision
			if m.SourceDeletion == nil || m.SourceDeletion.Gone == nil {
				retained = append(retained, Retained{b.Source, b.SourceOwnerRevision, b.ID})
			}
		}
		if m.Phase == Cancelled && !m.SourceCleanup.Unchanged {
			ownerRev = m.CancelRevision
		}
		if m.Phase != Completed && m.Phase != Cancelled {
			active = b.ID
		}
		previousEnd = b.StartedRevision
		if m.CommitRevision > previousEnd {
			previousEnd = m.CommitRevision
		}
		if m.CancelRevision > previousEnd {
			previousEnd = m.CancelRevision
		}
		if m.Fence != nil && m.CommitRevision == 0 && active != "" && len(d.Consumers) != 0 {
			if m.SourceCleanup != nil || len(d.Consumers) != 1 || !isMoveReader(b, d.Consumers[0]) || (m.Phase != SourceFenced && m.Phase != Copying && m.Phase != Verified && m.Phase != Cancelling) {
				return ErrVolume
			}
		}
		if active != "" && m.Phase == OwnerCommitted && len(d.Consumers) != 0 {
			return ErrVolume
		}
	}
	if d.Owner != owner || d.OwnerRevision != ownerRev || d.Active != active || !slices.Equal(d.Retained, retained) {
		return ErrVolume
	}
	return nil
}
func (s State) Encode() ([]byte, error) {
	if e := s.validate(); e != nil {
		return nil, e
	}
	return json.Marshal(s.d)
}
func Decode(b []byte) (State, error) {
	if len(b) > 4<<20 {
		return State{}, ErrVolume
	}
	var d snapshot
	if json.Unmarshal(b, &d) != nil {
		return State{}, ErrVolume
	}
	s := State{d}
	if e := s.validate(); e != nil {
		return State{}, e
	}
	canonical, _ := json.Marshal(d)
	if !bytes.Equal(b, canonical) {
		return State{}, ErrVolume
	}
	return s, nil
}
