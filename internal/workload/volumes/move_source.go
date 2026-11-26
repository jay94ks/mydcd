// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
)

// SourceAuthority must verify the CURRENT exact prepared move under an
// authenticated quorum barrier. An adapter must not authorize a move solely
// from this node's local checkpoint or from its original user session.
type SourceAuthority func(context.Context, Binding) error

// SourceUnfenced observes this exact native journal and local gate. It neither
// returns original Task/Unknown pins nor asserts that the old writer is stopped.
// The caller must also prove that no move retirement/reader was admitted and
// join its move worker before/after the current cancellation permission.
func (s *Activations) SourceUnfenced(ctx context.Context, ready NativeReady, b Binding) (bool, error) {
	if ready.Verify() != nil || b.Validate() != nil || ready.Spec.Scope != b.Scope || ready.Owner != b.Source || b.Scope.Cluster != s.cluster || b.Source.Key != s.node {
		return false, ErrActivation
	}
	s.life.RLock()
	defer s.life.RUnlock()
	if s.closed {
		return false, ErrActivation
	}
	owner, scope, err := s.native.Owner(ctx, NativeKey(ready.Spec))
	if err != nil || owner != ready.Owner || scope != ready.Spec.Scope {
		return false, errors.Join(ErrActivation, err)
	}
	row, err := s.native.View(NativeKey(ready.Spec))
	raw, _ := json.Marshal(ready.Spec)
	if err != nil || row.State.Pending != nil || !row.State.Applied.Present || row.State.Applied != row.State.Desired.Resource || row.State.Applied.Generation != ready.Generation || row.State.Applied.Spec != string(raw) {
		return false, errors.Join(ErrActivation, err)
	}
	s.mu.Lock()
	e := s.entries[ready.Owner.Native]
	s.mu.Unlock()
	if e == nil {
		return true, nil // exact native journal, no local activation ever installed
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.disk.Scope != b.Scope || e.disk.Owner != b.Source {
		return false, ErrActivation
	}
	return e.disk.Gate.FenceThrough < b.SourceOwnerRevision, nil
}

// FenceSource joins the existing clean-exit/native closure and synced Start
// gate. It does not stop a task, release shared consumers, or infer closure
// from timeout. The app retirement controller must settle those first.
// A failed final authorization leaves the durable fence in place, with no
// signed successful proof; recovery must query the same original move.
func (s *Activations) FenceSource(ctx context.Context, ready NativeReady, b Binding, authorize SourceAuthority, private ed25519.PrivateKey) (FenceProof, error) {
	return s.fenceSource(ctx, ready, b, authorize, private, s.ColdSource)
}

// FenceStoppedSource fences a cancelled move's source. It needs every
// writer stopped but not a clean exit: see StoppedSource.
func (s *Activations) FenceStoppedSource(ctx context.Context, ready NativeReady, b Binding, authorize SourceAuthority, private ed25519.PrivateKey) (FenceProof, error) {
	return s.fenceSource(ctx, ready, b, authorize, private, s.StoppedSource)
}

func (s *Activations) fenceSource(ctx context.Context, ready NativeReady, b Binding, authorize SourceAuthority, private ed25519.PrivateKey, source func(context.Context, NativeReady) (ColdSource, error)) (FenceProof, error) {
	if ready.Verify() != nil || ready.Spec.Scope != b.Scope || ready.Owner != b.Source || !validMove(Move{Binding: b, Phase: Prepared}, b.StartedRevision) || authorize == nil || len(private) != ed25519.PrivateKeySize || [32]byte(private.Public().(ed25519.PublicKey)) != b.Source.Key {
		return FenceProof{}, activationProblem("fence-input")
	}
	if err := authorize(ctx, b); err != nil {
		return FenceProof{}, err
	}
	original, err := source(ctx, ready)
	if err != nil {
		return FenceProof{}, err
	}
	if _, err = s.Fence(original.Writer, b.SourceOwnerRevision); err != nil {
		return FenceProof{}, err
	}
	current, err := source(ctx, ready)
	if err != nil || current != original {
		return FenceProof{}, errors.Join(activationProblem("source-changed-while-fencing"), err)
	}
	if err = authorize(ctx, b); err != nil {
		return FenceProof{}, err
	}
	proof := FenceProof{Binding: b, FenceThrough: b.SourceOwnerRevision, Stopped: true, MountsGone: true, StartsSettled: true, Synced: true}
	proof.Signature = ed25519.Sign(private, FenceBytes(proof))
	return proof, nil
}

// ExportMoveCold reuses the real archive/native A3 implementation. Its caller
// retains the shared original reader and owns durable artifact publication.
// A receipt proves file sync only, never directory/job publication or target
// copy/ownership. Unknown/partial artifacts must not be silently recopied.
func (s *Activations) ExportMoveCold(ctx context.Context, ready NativeReady, fence FenceProof, reader Consumer, authorize ColdAuthority, out *os.File, options ArchiveOptions) (ArchiveReceipt, error) {
	b := fence.Binding
	if ready.Verify() != nil || ready.Spec.Scope != b.Scope || ready.Owner != b.Source || !validFence(fence, b) || !isMoveReader(b, reader) || options.MaxBytes > b.MaxBytes || authorize == nil {
		return ArchiveReceipt{}, ErrActivation
	}
	if err := authorize(ctx, ready, reader); err != nil {
		return ArchiveReceipt{}, err
	}
	source, err := s.ColdSource(ctx, ready)
	if err != nil {
		return ArchiveReceipt{}, err
	}
	check := func(ctx context.Context, ready NativeReady, c Consumer) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		gate, err := s.Checkpoint(source.Writer)
		if err != nil || gate.FenceThrough < b.SourceOwnerRevision || gate.Starting != nil {
			return ErrActivation
		}
		return authorize(ctx, ready, c)
	}
	return s.native.ExportCold(ctx, ready, reader, check, out, options)
}
