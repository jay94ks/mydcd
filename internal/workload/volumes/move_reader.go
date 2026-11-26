// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/jay94ks/mydcd/internal/access"
)

// The identity fits the existing consumer namespace even for a 63-byte move
// ID. The digest binds the original scope/owner revisions and both native IDs;
// it is an identifier, not another log or synchronization authority.
func moveReaderID(b Binding) string {
	digest := sha256.Sum256(signedBytes("mydc-volume-move-reader-1", b))
	return "m-" + hex.EncodeToString(digest[:24])
}

func isMoveReader(b Binding, c Consumer) bool {
	return !c.Writable && c.ID == moveReaderID(b) && c.Generation == b.StartedRevision && c.Owner == b.Source && c.OwnerRevision == b.SourceOwnerRevision && validConsumer(c, b.Scope)
}

// MatchesReader checks immutable identity only; current I/O authorization
// still requires State.CheckMoveReader under the adapter's quorum barrier.
func (b Binding) MatchesReader(c Consumer) bool { return isMoveReader(b, c) }

// HadMoveReader is a generation-floor fact, including after a legacy release.
// Absence of a live consumer is not evidence that it was never dispatched.
func (s State) HadMoveReader(b Binding) bool {
	i := s.moveIndex(b.ID)
	if i < 0 || s.d.Moves[i].Binding != b {
		return false
	}
	for _, floor := range s.d.Floors {
		if floor.ID == moveReaderID(b) {
			return true
		}
	}
	return false
}

// MoveReader finds an existing original pin even during cancellation. This is
// a reference lookup, not authority to continue copying or to release it.
func (s State) MoveReader(b Binding) (Consumer, bool) {
	i := s.moveIndex(b.ID)
	if i < 0 || s.d.Moves[i].Binding != b {
		return Consumer{}, false
	}
	for _, c := range s.d.Consumers {
		if isMoveReader(b, c) {
			return c, true
		}
	}
	return Consumer{}, false
}

// CheckMoveReader permits only the original fenced source archive. It never
// grants a Task mount/Start/Recover through CheckActivation or PermitStart.
// A real adapter must run it under fresh quorum authorization before/after I/O.
func (s State) CheckMoveReader(b Binding, c Consumer) error {
	i := s.moveIndex(b.ID)
	if i < 0 {
		return ErrVolume
	}
	m := s.d.Moves[i]
	if m.Binding != b || s.d.Active != b.ID || m.Fence == nil || m.SourceCleanup != nil || m.ReaderClosed != nil || (m.Phase != SourceFenced && m.Phase != Copying) || s.d.Owner != b.Source || s.d.OwnerRevision != b.SourceOwnerRevision || !isMoveReader(b, c) || s.consumerIndex(c) < 0 {
		return ErrVolume
	}
	return nil
}

// AcquireMoveReader uses the SAME original A3 journal as workload/backup pins.
// Prepare blocks new Tasks; only a positively fenced source can acquire this
// readonly pin. Cancellation/verification prevents new acquisition while an
// already admitted reader remains pinned until its original signed closure.
func (s State) AcquireMoveReader(c access.Catalog, actor string, expected uint64, b Binding) (State, Consumer, error) {
	i := s.moveIndex(b.ID)
	if i < 0 {
		return s, Consumer{}, ErrVolume
	}
	m := s.d.Moves[i]
	if err := s.authorizeMove(c, actor, m); err != nil {
		return s, Consumer{}, err
	}
	if m.Binding != b || s.d.Active != b.ID || m.Fence == nil || m.SourceCleanup != nil || m.ReaderClosed != nil || (m.Phase != SourceFenced && m.Phase != Copying) || s.d.Owner != b.Source || s.d.OwnerRevision != b.SourceOwnerRevision {
		return s, Consumer{}, ErrVolume
	}
	return s.acquire(c, actor, expected, moveReaderID(b), b.StartedRevision, false, true)
}

// CloseMoveReader atomically retains the original signed receipt while the
// SAME shared A3 returns its consumer. Later transfer cleanup must not invent
// a replacement reader identity after that consumer disappears from the live set.
func (s State) CloseMoveReader(b Binding, g Gone) (State, error) {
	i := s.moveIndex(b.ID)
	if i < 0 || s.d.Moves[i].Binding != b {
		return s, ErrVolume
	}
	m := s.d.Moves[i]
	if !validMoveReaderClosure(g, b) {
		return s, ErrVolume
	}
	if m.ReaderClosed != nil {
		if same(*m.ReaderClosed, g) {
			return s, nil
		}
		return s, ErrVolume
	}
	if m.Phase != SourceFenced && m.Phase != Copying && m.Phase != Verified && m.Phase != Cancelling {
		return s, ErrVolume
	}
	n, err := s.release(g)
	if err != nil {
		return s, err
	}
	g.Signature = append([]byte(nil), g.Signature...)
	n.d.Moves[i].ReaderClosed = &g
	return n, nil
}

func validMoveReaderClosure(g Gone, b Binding) bool {
	return g.Scope == b.Scope && isMoveReader(b, g.Consumer) && g.Stopped && g.MountsGone && verify(b.Source.Key, GoneBytes(g), g.Signature)
}
