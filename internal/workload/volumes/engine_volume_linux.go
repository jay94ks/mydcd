// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"context"
	"errors"

	"github.com/jay94ks/seafield/internal/nodestorage"
	"golang.org/x/sys/unix"
)

// Answers for the Seafield engine's built-in "sfc" volume driver
// (seafield/docs/sfcd-socket.md, purpose 35 EngineVolume). The engine asks;
// sfcd decides. Mount never borrows: the pin was taken before create and is
// returned only after the original Task/Wait closure, never on Unmount.
var (
	// ErrEngineNotOwner: the volume or container is not one sfcd placed
	// here (for example a `docker run -v sfc-fixed-…` the user typed).
	ErrEngineNotOwner = errors.New("volume mount not owned by a sfcd consumer")
	// ErrEngineNotReady: the consumer is ours but the volume is moving,
	// restoring or not applied yet. The engine fails the start.
	ErrEngineNotReady = errors.New("volume not ready for mount")
)

// EngineMount is the body of a Mount answer. The directory descriptor rides
// beside it (SCM_RIGHTS); the engine checks Dev and Ino on what it received.
type EngineMount struct {
	ReadOnly bool   `json:"read_only"`
	Dev      uint64 `json:"dev"`
	Ino      uint64 `json:"ino"`
}

// EngineMount returns the held original directory for one of this node's
// fixed volume consumers. The caller sends h.FD() with the answer and closes
// h after sending. It does not change any journal or activation record.
func (s *Activations) EngineMount(ctx context.Context, volume, containerID string) (EngineMount, *nodestorage.DirectoryHandle, error) {
	if !validNativeID(containerID) || volume == "" || len(volume) > 512 {
		return EngineMount{}, nil, ErrEngineNotOwner
	}
	s.life.RLock()
	defer s.life.RUnlock()
	if s.closed {
		return EngineMount{}, nil, ErrEngineNotReady
	}
	s.mu.Lock()
	e := s.entries[volume]
	s.mu.Unlock()
	if e == nil {
		return EngineMount{}, nil, ErrEngineNotOwner
	}
	// Copy the binding and release the entry before filesystem I/O. If the
	// consumer retires meanwhile, the journal check in the source opener
	// fails and the answer is not-ready, never a stale directory.
	e.mu.Lock()
	var found *activationBinding
	dup := false
	for i := range e.disk.Bindings {
		b := e.disk.Bindings[i]
		if b.NativeID == containerID && !b.Closed && b.Lease.Pin.Token != 0 {
			dup = dup || found != nil
			found = &b
		}
	}
	e.mu.Unlock()
	if dup || found == nil || !found.Ref.Scope.TenantManaged() || found.Ref.Consumer.Owner.Native != volume {
		return EngineMount{}, nil, ErrEngineNotOwner
	}
	open := s.engineSource
	if open == nil {
		if s.native == nil || s.native.fixed == nil {
			return EngineMount{}, nil, ErrEngineNotReady
		}
		open = func(ctx context.Context, l NativeLease) (*nodestorage.DirectoryHandle, error) {
			_, h, err := s.native.fixed.InspectBindSource(ctx, l)
			return h, err
		}
	}
	h, err := open(ctx, found.Lease)
	if err != nil {
		return EngineMount{}, nil, errors.Join(ErrEngineNotReady, err)
	}
	id := h.Identity()
	return EngineMount{ReadOnly: !found.Ref.Consumer.Writable, Dev: unix.Mkdev(id.DeviceMajor, id.DeviceMinor), Ino: id.Inode}, h, nil
}

// ServedSource opens ready's original directory for a remote consumer this
// home serves (FixedManager.ServedSource).
func (s *Activations) ServedSource(ctx context.Context, ready NativeReady) (*nodestorage.DirectoryHandle, error) {
	s.life.RLock()
	defer s.life.RUnlock()
	if s.closed || s.native == nil || s.native.fixed == nil {
		return nil, ErrEngineNotReady
	}
	return s.native.fixed.ServedSource(ctx, ready)
}
