// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"bytes"
	"encoding/json"
	"slices"

	"github.com/jay94ks/mydcd/internal/access"
)

type Phase string

const (
	Prepared       Phase = "Prepared"
	SourceFenced   Phase = "SourceFenced"
	Copying        Phase = "Copying"
	Verified       Phase = "Verified"
	OwnerCommitted Phase = "OwnerCommitted"
	Activating     Phase = "Activating"
	Active         Phase = "Active"
	Completed      Phase = "Completed"
	Cancelling     Phase = "Cancelling"
	Cancelled      Phase = "Cancelled"
)

type Binding struct {
	Scope                                Scope
	ID                                   string
	StartedRevision, SourceOwnerRevision uint64
	Source, Target                       Owner
	Compatibility                        [32]byte // same pinned image/platform/storage-format contract
	MaxBytes                             uint64
}
type Move struct {
	Binding                        Binding
	Phase                          Phase
	Preparation                    *TargetPreparation `json:",omitempty"`
	ReaderClosed                   *Gone              `json:",omitempty"`
	Fence                          *FenceProof
	Manifest                       *Manifest
	Verified                       *CopyProof
	CancelledTarget                *CancelProof
	Activated                      *ActiveProof
	SourceCleanup, TargetCleanup   *CleanupProof
	SourceDeletion                 *Deletion `json:",omitempty"`
	CommitRevision, CancelRevision uint64
	Irreversible                   bool // armed before the first target writable dispatch
}

func (b Binding) Validate() error {
	if !validMove(Move{Binding: b, Phase: Prepared}, b.StartedRevision) {
		return ErrVolume
	}
	return nil
}

func ownMove(m Move) Move {
	if m.SourceDeletion != nil {
		d := *m.SourceDeletion
		if d.Gone != nil {
			proof := *d.Gone
			proof.Signature = slices.Clone(proof.Signature)
			d.Gone = &proof
		}
		m.SourceDeletion = &d
	}
	if m.ReaderClosed != nil {
		x := *m.ReaderClosed
		x.Signature = slices.Clone(x.Signature)
		m.ReaderClosed = &x
	}
	if m.Preparation != nil {
		x := *m.Preparation
		x.Signature = slices.Clone(x.Signature)
		x.Target.Signature = slices.Clone(x.Target.Signature)
		if x.Inputs != nil {
			d := *x.Inputs
			x.Inputs = &d
		}
		m.Preparation = &x
	}
	if m.Fence != nil {
		x := *m.Fence
		x.Signature = slices.Clone(x.Signature)
		m.Fence = &x
	}
	if m.Manifest != nil {
		x := *m.Manifest
		x.Signature = slices.Clone(x.Signature)
		m.Manifest = &x
	}
	if m.Verified != nil {
		x := *m.Verified
		x.Signature = slices.Clone(x.Signature)
		m.Verified = &x
	}
	if m.CancelledTarget != nil {
		x := *m.CancelledTarget
		x.Signature = slices.Clone(x.Signature)
		m.CancelledTarget = &x
	}
	if m.Activated != nil {
		x := *m.Activated
		x.Signature = slices.Clone(x.Signature)
		m.Activated = &x
	}
	if m.SourceCleanup != nil {
		x := *m.SourceCleanup
		x.Signature = slices.Clone(x.Signature)
		m.SourceCleanup = &x
	}
	if m.TargetCleanup != nil {
		x := *m.TargetCleanup
		x.Signature = slices.Clone(x.Signature)
		m.TargetCleanup = &x
	}
	return m
}
func same(a, b any) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return bytes.Equal(ab, bb)
}
func (s State) authorizeMove(c access.Catalog, actor string, m Move) error {
	if c.Authorize(actor, s.d.Scope.Tenant, access.ManageVolumes, m.Binding.Source.Node) != nil || c.Authorize(actor, s.d.Scope.Tenant, access.ManageVolumes, m.Binding.Target.Node) != nil {
		return access.ErrDenied
	}
	return nil
}

// Prepare reserves the exact target native identity. Actual capacity/format/
// credentials and native journals must be prepared before a side effect. The
// full current node keys are resolved from committed admission by the adapter.
func (s State) Prepare(c access.Catalog, actor string, expected, ownerRevision uint64, id string, target Owner, compatibility [32]byte, maxBytes uint64) (State, error) {
	if s.d.Fixed {
		if c.Authorize(actor, s.d.Scope.Tenant, access.ManageVolumes, s.d.Owner.Node) != nil {
			return s, access.ErrDenied
		}
		return s, ErrNotMovable
	}
	if c.Authorize(actor, s.d.Scope.Tenant, access.ManageVolumes, s.d.Owner.Node) != nil || c.Authorize(actor, s.d.Scope.Tenant, access.ManageVolumes, target.Node) != nil {
		return s, access.ErrDenied
	}
	if i := s.moveIndex(id); i >= 0 {
		b := s.d.Moves[i].Binding
		if b.SourceOwnerRevision == ownerRevision && b.Target == target && b.Compatibility == compatibility && b.MaxBytes == maxBytes {
			return s, nil
		}
		return s, ErrVolume
	}
	if s.d.Deletion != nil || expected != s.d.Revision || ownerRevision != s.d.OwnerRevision || s.d.Active != "" || !identifier(id) || !validOwner(target) || target.Node == s.d.Owner.Node || compatibility == ([32]byte{}) || maxBytes == 0 || maxBytes > 1<<50 || len(s.d.Moves) >= maxRecords || len(s.d.Used) >= maxRecords+1 {
		return s, ErrVolume
	}
	if slices.ContainsFunc(s.d.Used, func(o Owner) bool { return sameNative(o, target) }) {
		return s, ErrVolume
	}
	n, e := s.clone()
	if e != nil {
		return s, e
	}
	b := Binding{s.d.Scope, id, n.d.Revision, s.d.OwnerRevision, s.d.Owner, target, compatibility, maxBytes}
	n.d.Moves = append(n.d.Moves, Move{Binding: b, Phase: Prepared})
	n.d.Active = id
	n.d.Used = append(n.d.Used, target)
	return n, nil
}

type FenceProof struct {
	Binding                                    Binding
	FenceThrough                               uint64
	Stopped, MountsGone, StartsSettled, Synced bool
	Signature                                  []byte
}

func FenceBytes(p FenceProof) []byte { p.Signature = nil; return signedBytes("mydc-volume-fence-1", p) }
func validFence(p FenceProof, b Binding) bool {
	return p.Binding == b && p.FenceThrough == b.SourceOwnerRevision && p.Stopped && p.MountsGone && p.StartsSettled && p.Synced && verify(b.Source.Key, FenceBytes(p), p.Signature)
}
func (s State) RecordFence(p FenceProof) (State, error) {
	i := s.moveIndex(p.Binding.ID)
	if i < 0 {
		return s, ErrVolume
	}
	m := s.d.Moves[i]
	if !validFence(p, m.Binding) {
		return s, ErrVolume
	}
	if m.Fence != nil {
		if same(m.Fence, &p) {
			return s, nil
		}
		return s, ErrVolume
	}
	if s.d.Active != m.Binding.ID || (m.Phase != Prepared && m.Phase != Cancelling) || m.SourceCleanup != nil || len(s.d.Consumers) != 0 {
		return s, ErrVolume
	}
	n, e := s.clone()
	if e != nil {
		return s, e
	}
	p.Signature = slices.Clone(p.Signature)
	n.d.Moves[i].Fence = &p
	if m.Phase == Prepared {
		n.d.Moves[i].Phase = SourceFenced
	}
	return n, nil
}

type Manifest struct {
	Binding   Binding
	Artifact  [32]byte
	Bytes     uint64
	Files     uint32
	DataBytes uint64 `json:",omitempty"`
	ReadOnly  bool
	Signature []byte
}

func ManifestBytes(p Manifest) []byte {
	p.Signature = nil
	return signedBytes("mydc-volume-manifest-1", p)
}
func validManifest(p Manifest, b Binding) bool {
	return p.Binding == b && p.Artifact != ([32]byte{}) && p.Bytes <= b.MaxBytes && p.DataBytes <= p.Bytes && (p.Bytes == 0 || p.Files > 0) && p.Files <= 1000000 && p.ReadOnly && verify(b.Source.Key, ManifestBytes(p), p.Signature)
}

func (p Manifest) ArchiveReceipt() ArchiveReceipt {
	return ArchiveReceipt{Schema: 1, Digest: p.Artifact, Bytes: p.Bytes, DataBytes: p.DataBytes, Entries: p.Files}
}
func (s State) BeginCopy(p Manifest) (State, error) {
	i := s.moveIndex(p.Binding.ID)
	if i < 0 {
		return s, ErrVolume
	}
	m := s.d.Moves[i]
	if !validManifest(p, m.Binding) {
		return s, ErrVolume
	}
	if m.Manifest != nil {
		if same(m.Manifest, &p) {
			return s, nil
		}
		return s, ErrVolume
	}
	if s.d.Active != m.Binding.ID || m.Phase != SourceFenced {
		return s, ErrVolume
	}
	n, e := s.clone()
	if e != nil {
		return s, e
	}
	p.Signature = slices.Clone(p.Signature)
	n.d.Moves[i].Manifest = &p
	n.d.Moves[i].Phase = Copying
	return n, nil
}

type CopyProof struct {
	Binding                           Binding
	Artifact                          [32]byte
	Bytes                             uint64
	DigestVerified, Synced, NoWriters bool
	Signature                         []byte
}

func CopyBytes(p CopyProof) []byte { p.Signature = nil; return signedBytes("mydc-volume-copy-1", p) }
func validCopy(p CopyProof, m Move) bool {
	return m.Manifest != nil && p.Binding == m.Binding && p.Artifact == m.Manifest.Artifact && p.Bytes == m.Manifest.Bytes && p.DigestVerified && p.Synced && p.NoWriters && verify(m.Binding.Target.Key, CopyBytes(p), p.Signature)
}
func (s State) VerifyCopy(p CopyProof) (State, error) {
	i := s.moveIndex(p.Binding.ID)
	if i < 0 {
		return s, ErrVolume
	}
	m := s.d.Moves[i]
	if !validCopy(p, m) {
		return s, ErrVolume
	}
	if m.Verified != nil {
		if same(m.Verified, &p) {
			return s, nil
		}
		return s, ErrVolume
	}
	if s.d.Active != m.Binding.ID || m.Phase != Copying {
		return s, ErrVolume
	}
	n, e := s.clone()
	if e != nil {
		return s, e
	}
	p.Signature = slices.Clone(p.Signature)
	n.d.Moves[i].Verified = &p
	n.d.Moves[i].Phase = Verified
	return n, nil
}

// CommitOwner is the only forward ownership transition. An ACK loss is a read
// of this same ID, not a fresh move. It grants no writable activation by itself.
func (s State) CommitOwner(c access.Catalog, actor, id string, expected, ownerRevision uint64) (State, error) {
	i := s.moveIndex(id)
	if i < 0 {
		return s, ErrVolume
	}
	m := s.d.Moves[i]
	if e := s.authorizeMove(c, actor, m); e != nil {
		return s, e
	}
	if m.CommitRevision != 0 {
		return s, nil
	}
	if expected != s.d.Revision || ownerRevision != m.Binding.SourceOwnerRevision || ownerRevision != s.d.OwnerRevision || s.d.Owner != m.Binding.Source || s.d.Active != id || m.Phase != Verified || m.Fence == nil || m.Verified == nil || len(s.d.Consumers) != 0 || s.HadMoveReader(m.Binding) && m.ReaderClosed == nil {
		return s, ErrVolume
	}
	n, e := s.clone()
	if e != nil {
		return s, e
	}
	n.d.Owner = m.Binding.Target
	n.d.OwnerRevision = n.d.Revision
	n.d.Moves[i].CommitRevision = n.d.Revision
	n.d.Moves[i].Phase = OwnerCommitted
	n.d.Retained = append(n.d.Retained, Retained{m.Binding.Source, m.Binding.SourceOwnerRevision, id})
	return n, nil
}

// Arm marks the irreversible boundary BEFORE target writable pin/start. Even a
// lost native response can include database recovery writes. Old-source unfence
// is therefore never a rollback after owner commit or target dispatch.
func (s State) Arm(c access.Catalog, actor, id string, expected uint64) (State, error) {
	i := s.moveIndex(id)
	if i < 0 {
		return s, ErrVolume
	}
	m := s.d.Moves[i]
	if e := s.authorizeMove(c, actor, m); e != nil {
		return s, e
	}
	if m.Irreversible {
		return s, nil
	}
	if expected != s.d.Revision || s.d.Active != id || m.Phase != OwnerCommitted {
		return s, ErrVolume
	}
	n, e := s.clone()
	if e != nil {
		return s, e
	}
	n.d.Moves[i].Irreversible = true
	n.d.Moves[i].Phase = Activating
	return n, nil
}

type ActiveProof struct {
	Binding   Binding
	Consumer  Consumer
	Running   bool
	Idle      bool `json:",omitempty"`
	Signature []byte
}

func ActiveBytes(p ActiveProof) []byte {
	p.Signature = nil
	return signedBytes("mydc-volume-active-1", p)
}
func validActive(p ActiveProof, m Move) bool {
	if p.Binding != m.Binding || !verify(m.Binding.Target.Key, ActiveBytes(p), p.Signature) {
		return false
	}
	if p.Idle {
		return !p.Running && p.Consumer == (Consumer{})
	}
	return p.Consumer.Owner == m.Binding.Target && p.Consumer.OwnerRevision == m.CommitRevision && validConsumer(p.Consumer, m.Binding.Scope) && p.Running
}
func (s State) RecordActive(p ActiveProof) (State, error) {
	i := s.moveIndex(p.Binding.ID)
	if i < 0 {
		return s, ErrVolume
	}
	m := s.d.Moves[i]
	if !validActive(p, m) {
		return s, ErrVolume
	}
	if m.Activated != nil {
		if same(m.Activated, &p) {
			return s, nil
		}
		return s, ErrVolume
	}
	if s.d.Active != m.Binding.ID || m.Phase != Activating || p.Idle && len(s.d.Consumers) != 0 || !p.Idle && s.consumerIndex(p.Consumer) < 0 {
		return s, ErrVolume
	}
	n, e := s.clone()
	if e != nil {
		return s, e
	}
	p.Signature = slices.Clone(p.Signature)
	n.d.Moves[i].Activated = &p
	n.d.Moves[i].Phase = Active
	return n, nil
}

type CleanupProof struct {
	Binding                        Binding
	Owner                          Owner
	TransferClosed, RetainedFenced bool
	Unchanged                      bool `json:",omitempty"`
	Signature                      []byte
}

func CleanupBytes(p CleanupProof) []byte {
	p.Signature = nil
	return signedBytes("mydc-volume-move-cleanup-1", p)
}
func validCleanup(p CleanupProof, m Move) bool {
	source := p.Owner == m.Binding.Source && (p.RetainedFenced && !p.Unchanged && m.Fence != nil || p.Unchanged && !p.RetainedFenced && m.Fence == nil && m.Manifest == nil && m.Verified == nil && m.ReaderClosed == nil && (m.Phase == Cancelling || m.Phase == Cancelled))
	return p.Binding == m.Binding && (source || p.Owner == m.Binding.Target && !p.RetainedFenced && !p.Unchanged) && p.TransferClosed && verify(p.Owner.Key, CleanupBytes(p), p.Signature)
}
func (s State) RecordCleanup(p CleanupProof) (State, error) {
	i := s.moveIndex(p.Binding.ID)
	if i < 0 {
		return s, ErrVolume
	}
	m := s.d.Moves[i]
	if !validCleanup(p, m) {
		return s, ErrVolume
	}
	prior := m.TargetCleanup
	if p.Owner == m.Binding.Source {
		prior = m.SourceCleanup
	}
	if prior != nil {
		if same(prior, &p) {
			return s, nil
		}
		return s, ErrVolume
	}
	if s.d.Active != m.Binding.ID || !(m.Phase == Active || m.Phase == Cancelling && p.Owner == m.Binding.Source) {
		return s, ErrVolume
	}
	if p.Owner == m.Binding.Source && (!p.Unchanged && slices.ContainsFunc(s.d.Consumers, func(c Consumer) bool { return c.Owner == m.Binding.Source }) || p.Unchanged && s.HadMoveReader(m.Binding)) {
		return s, ErrVolume
	}
	n, e := s.clone()
	if e != nil {
		return s, e
	}
	p.Signature = slices.Clone(p.Signature)
	if p.Owner == m.Binding.Source {
		n.d.Moves[i].SourceCleanup = &p
	} else {
		n.d.Moves[i].TargetCleanup = &p
	}
	if n.d.Moves[i].SourceCleanup != nil && n.d.Moves[i].TargetCleanup != nil {
		n.d.Moves[i].Phase = Completed
		n.d.Active = ""
	}
	return n, nil
}
func (s State) Cancel(c access.Catalog, actor, id string, expected uint64) (State, error) {
	i := s.moveIndex(id)
	if i < 0 {
		return s, ErrVolume
	}
	m := s.d.Moves[i]
	if e := c.AuthorizeCleanup(actor, s.d.Scope.Tenant, access.ManageVolumes); e != nil {
		return s, e
	}
	if m.Phase == Cancelling || m.Phase == Cancelled {
		return s, nil
	}
	if expected != s.d.Revision || s.d.Active != id || m.CommitRevision != 0 {
		return s, ErrVolume
	}
	n, e := s.clone()
	if e != nil {
		return s, e
	}
	n.d.Moves[i].Phase = Cancelling
	return n, nil
}

type CancelProof struct {
	Binding                                                Binding
	StagingGone, StartsSettled, MountsGone, TransferClosed bool
	Signature                                              []byte
}

func CancelBytes(p CancelProof) []byte {
	p.Signature = nil
	return signedBytes("mydc-volume-cancel-target-1", p)
}
func validCancel(p CancelProof, b Binding) bool {
	return p.Binding == b && p.StagingGone && p.StartsSettled && p.MountsGone && p.TransferClosed && verify(b.Target.Key, CancelBytes(p), p.Signature)
}
func (s State) RecordCancelTarget(p CancelProof) (State, error) {
	i := s.moveIndex(p.Binding.ID)
	if i < 0 {
		return s, ErrVolume
	}
	m := s.d.Moves[i]
	if !validCancel(p, m.Binding) {
		return s, ErrVolume
	}
	if m.CancelledTarget != nil {
		if same(m.CancelledTarget, &p) {
			return s, nil
		}
		return s, ErrVolume
	}
	if s.d.Active != m.Binding.ID || m.Phase != Cancelling {
		return s, ErrVolume
	}
	n, e := s.clone()
	if e != nil {
		return s, e
	}
	p.Signature = slices.Clone(p.Signature)
	n.d.Moves[i].CancelledTarget = &p
	return n, nil
}
func (s State) FinishCancel(c access.Catalog, actor, id string, expected, ownerRevision uint64) (State, error) {
	i := s.moveIndex(id)
	if i < 0 {
		return s, ErrVolume
	}
	m := s.d.Moves[i]
	if e := c.AuthorizeCleanup(actor, s.d.Scope.Tenant, access.ManageVolumes); e != nil {
		return s, e
	}
	if ownerRevision != m.Binding.SourceOwnerRevision {
		return s, ErrVolume
	}
	return s.SettleCancel(m.Binding, expected)
}

// SettleCancel consumes the accepted cancellation and both signed original
// closure facts. It grants no new effect or Start permission. The authenticated
// adapter must commit this same candidate/result at its current root CAS.
func (s State) SettleCancel(b Binding, expected uint64) (State, error) {
	i := s.moveIndex(b.ID)
	if i < 0 || s.d.Moves[i].Binding != b {
		return s, ErrVolume
	}
	m := s.d.Moves[i]
	if m.Phase == Cancelled {
		return s, nil
	}
	if expected != s.d.Revision || s.d.Active != b.ID || m.Phase != Cancelling || m.CommitRevision != 0 || s.d.Owner != b.Source || s.d.OwnerRevision != b.SourceOwnerRevision || m.SourceCleanup == nil || m.CancelledTarget == nil {
		return s, ErrVolume
	}
	if m.SourceCleanup.Unchanged {
		if m.Fence != nil || s.HadMoveReader(b) || m.Manifest != nil {
			return s, ErrVolume
		}
	} else if m.Fence == nil || len(s.d.Consumers) != 0 {
		return s, ErrVolume
	}
	n, e := s.clone()
	if e != nil {
		return s, e
	}
	if !m.SourceCleanup.Unchanged {
		n.d.OwnerRevision = n.d.Revision
	}
	n.d.Moves[i].CancelRevision = n.d.Revision
	n.d.Moves[i].Phase = Cancelled
	n.d.Active = ""
	return n, nil
}
