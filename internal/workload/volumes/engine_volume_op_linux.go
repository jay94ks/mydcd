// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"context"
	"errors"
	"os"
	"sort"

	"github.com/jay94ks/seafield/internal/engineops"
)

// Purpose 35 EngineVolume op structs (seafield/docs/sfcd-socket.md,
// "op 구조체"). The engine mirrors these byte for byte, so field order,
// names and types are part of the contract. Op fields carry no omitempty.
type (
	VolumeMountQ struct {
		engineops.Request
		Name, MountID, ContainerID string
	}
	VolumeMountA struct {
		engineops.Reply
		ReadOnly bool
		Dev, Ino uint64
	}
	VolumeUnmountQ struct {
		engineops.Request
		Name, MountID string
	}
	VolumeUnmountA struct{ engineops.Reply }
	VolumeCreateQ  struct {
		engineops.Request
		Name string
		Opts map[string]string
	}
	VolumeCreateA struct {
		engineops.Reply
		Name string
	}
	VolumeGetQ struct {
		engineops.Request
		Name string
	}
	VolumeGetA struct {
		engineops.Reply
		Name, Status string
	}
	VolumeListQ struct{ engineops.Request }
	VolumeListA struct {
		engineops.Reply
		Volumes []string
	}
	VolumeRemoveQ struct {
		engineops.Request
		Name string
	}
	VolumeRemoveA struct{ engineops.Reply }
)

// Nothing here changes a journal or activation record: sfcd creates, pins
// and removes volumes on its own schedule. The table fills the envelope,
// Fds and refusals; a refusal closes any returned file.

func engineName(name string) error {
	if name == "" || len(name) > 512 {
		return engineops.Refuse(engineops.Invalid, nil)
	}
	return nil
}

func engineMountID(id string) error {
	if id == "" || len(id) > 128 {
		return engineops.Refuse(engineops.Invalid, nil)
	}
	return nil
}

func (s *Activations) EngineVolumeMount(ctx context.Context, q VolumeMountQ) (VolumeMountA, []*os.File, error) {
	if err := errors.Join(engineName(q.Name), engineMountID(q.MountID)); err != nil {
		return VolumeMountA{}, nil, engineops.Refuse(engineops.Invalid, nil)
	}
	m, h, err := s.EngineMount(ctx, q.Name, q.ContainerID)
	switch {
	case errors.Is(err, ErrEngineNotOwner):
		return VolumeMountA{}, nil, engineops.Refuse(engineops.NotOwner, err)
	case err != nil:
		return VolumeMountA{}, nil, engineops.Refuse(engineops.NotReady, err)
	}
	f := h.Release()
	return VolumeMountA{ReadOnly: m.ReadOnly, Dev: m.Dev, Ino: m.Ino}, []*os.File{f}, nil
}

// Unmount: the engine detaches its own clone; the pin stays until Task/Wait
// closure, so there is nothing to undo here.
func (s *Activations) EngineVolumeUnmount(_ context.Context, q VolumeUnmountQ) (VolumeUnmountA, []*os.File, error) {
	if err := errors.Join(engineName(q.Name), engineMountID(q.MountID)); err != nil {
		return VolumeUnmountA{}, nil, engineops.Refuse(engineops.Invalid, nil)
	}
	return VolumeUnmountA{}, nil, nil
}

// Create accepts only names sfcd placed here; the engine API cannot make
// volumes, so `docker volume create sfc-…` is refused.
func (s *Activations) EngineVolumeCreate(_ context.Context, q VolumeCreateQ) (VolumeCreateA, []*os.File, error) {
	if err := engineName(q.Name); err != nil || q.Opts == nil {
		return VolumeCreateA{}, nil, engineops.Refuse(engineops.Invalid, nil)
	}
	if !s.engineVolumeKnown(q.Name) {
		return VolumeCreateA{}, nil, engineops.Refuse(engineops.NotOwner, nil)
	}
	return VolumeCreateA{Name: q.Name}, nil, nil
}

func (s *Activations) EngineVolumeGet(_ context.Context, q VolumeGetQ) (VolumeGetA, []*os.File, error) {
	if err := engineName(q.Name); err != nil {
		return VolumeGetA{}, nil, err
	}
	if !s.engineVolumeKnown(q.Name) {
		return VolumeGetA{}, nil, engineops.Refuse(engineops.NotFound, nil)
	}
	return VolumeGetA{Name: q.Name, Status: "ready"}, nil, nil
}

func (s *Activations) EngineVolumeList(context.Context, VolumeListQ) (VolumeListA, []*os.File, error) {
	return VolumeListA{Volumes: s.engineVolumes()}, nil, nil
}

// Remove: sfcd removes a volume only through its own retirement.
func (s *Activations) EngineVolumeRemove(_ context.Context, q VolumeRemoveQ) (VolumeRemoveA, []*os.File, error) {
	if err := engineName(q.Name); err != nil {
		return VolumeRemoveA{}, nil, err
	}
	if !s.engineVolumeKnown(q.Name) {
		return VolumeRemoveA{}, nil, engineops.Refuse(engineops.NotFound, nil)
	}
	return VolumeRemoveA{}, nil, engineops.Refuse(engineops.Refused, nil)
}

func (s *Activations) engineVolumeKnown(name string) bool {
	s.life.RLock()
	defer s.life.RUnlock()
	if s.closed {
		return false
	}
	s.mu.Lock()
	e := s.entries[name]
	s.mu.Unlock()
	return e != nil && e.scope.TenantManaged()
}

// engineVolumes is never nil, so the reply carries [] rather than null.
func (s *Activations) engineVolumes() []string {
	out := []string{}
	s.life.RLock()
	defer s.life.RUnlock()
	if s.closed {
		return out
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, e := range s.entries {
		if e.scope.TenantManaged() {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
