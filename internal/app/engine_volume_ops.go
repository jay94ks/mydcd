// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"os"
	"sort"

	"github.com/jay94ks/seafield/internal/engineops"
	"github.com/jay94ks/seafield/internal/volumeshare/front/mount"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// remoteVolumeMounts serves engine volumes whose data lives on another
// server: sfcd mounts them locally (VolumeFS) and the engine binds that
// mount. The shared-volume side owns when a mount exists and when it goes.
type remoteVolumeMounts interface {
	// EngineMountDir returns the local mount directory for name if this
	// container is a consumer sfcd bound to it, and holds the mount for
	// mountID (the engine keeps a clone of it; a repeat of the same mountID
	// takes no second hold). found=false means "not a remote volume of
	// ours"; an error means ours but not mountable now, with no hold.
	EngineMountDir(ctx context.Context, name, mountID, containerID string) (dir string, readOnly, found bool, err error)
	// EngineUnmounted releases the hold for mountID: the engine detached it,
	// or the answer could not be built.
	EngineUnmounted(name, mountID string)
	// EngineVolumeNames lists the remote volume names served on this node.
	EngineVolumeNames() []string
}

// volumeEngineOps answers the engine's built-in "sfc" volume driver
// (purpose 35). Local fixed volumes are decided by volumes.Activations,
// remote shared volumes by remoteVolumes. Before either is open, a request
// that neither can answer is not-ready rather than not-owner.
func (r *Runtime) volumeEngineOps() []engineops.Entry {
	return []engineops.Entry{
		engineops.Op(engineops.Volume, "mount", r.engineVolumeMount),
		engineops.Op(engineops.Volume, "unmount", r.engineVolumeUnmount),
		engineops.Op(engineops.Volume, "create", r.engineVolumeCreate),
		engineops.Op(engineops.Volume, "get", r.engineVolumeGet),
		engineops.Op(engineops.Volume, "list", r.engineVolumeList),
		engineops.Op(engineops.Volume, "remove", r.engineVolumeRemove),
	}
}

func refusedAs(err error, reason string) bool {
	var refusal *engineops.Refusal
	return errors.As(err, &refusal) && refusal.Reason == reason
}

func notReady() error { return engineops.Refuse(engineops.NotReady, nil) }

func (r *Runtime) remoteKnown(name string) bool {
	if r.remoteVolumes == nil {
		return false
	}
	for _, n := range r.remoteVolumes.EngineVolumeNames() {
		if n == name {
			return true
		}
	}
	return false
}

func (r *Runtime) engineVolumeMount(ctx context.Context, q volumes.VolumeMountQ) (volumes.VolumeMountA, []*os.File, error) {
	var a volumes.VolumeMountA
	var files []*os.File
	err := notReady()
	if r.activations != nil {
		if a, files, err = r.activations.EngineVolumeMount(ctx, q); !refusedAs(err, engineops.NotOwner) {
			return a, files, err
		}
	}
	if r.remoteVolumes == nil || q.MountID == "" || len(q.MountID) > 128 {
		return volumes.VolumeMountA{}, nil, err
	}
	dir, readOnly, found, rerr := r.remoteVolumes.EngineMountDir(ctx, q.Name, q.MountID, q.ContainerID)
	switch {
	case !found:
		return volumes.VolumeMountA{}, nil, err
	case rerr != nil:
		return volumes.VolumeMountA{}, nil, engineops.Refuse(engineops.NotReady, rerr)
	}
	// RootFD uses plain open(2): this process serves the FUSE mount, and
	// os.Open would register it with the netpoller (FUSE_POLL can hang).
	fd, dev, ino, ferr := mount.RootFD(dir)
	if ferr != nil {
		r.remoteVolumes.EngineUnmounted(q.Name, q.MountID)
		return volumes.VolumeMountA{}, nil, engineops.Refuse(engineops.NotReady, ferr)
	}
	return volumes.VolumeMountA{ReadOnly: readOnly, Dev: dev, Ino: ino}, []*os.File{os.NewFile(uintptr(fd), dir)}, nil
}

func (r *Runtime) engineVolumeUnmount(ctx context.Context, q volumes.VolumeUnmountQ) (volumes.VolumeUnmountA, []*os.File, error) {
	if r.activations == nil && r.remoteVolumes == nil {
		return volumes.VolumeUnmountA{}, nil, notReady()
	}
	if r.activations != nil {
		if _, _, err := r.activations.EngineVolumeUnmount(ctx, q); err != nil {
			return volumes.VolumeUnmountA{}, nil, err
		}
	} else if q.Name == "" || len(q.Name) > 512 || q.MountID == "" || len(q.MountID) > 128 {
		return volumes.VolumeUnmountA{}, nil, engineops.Refuse(engineops.Invalid, nil)
	}
	if r.remoteKnown(q.Name) {
		r.remoteVolumes.EngineUnmounted(q.Name, q.MountID)
	}
	return volumes.VolumeUnmountA{}, nil, nil
}

func (r *Runtime) engineVolumeCreate(ctx context.Context, q volumes.VolumeCreateQ) (volumes.VolumeCreateA, []*os.File, error) {
	err := notReady()
	if r.activations != nil {
		var a volumes.VolumeCreateA
		if a, _, err = r.activations.EngineVolumeCreate(ctx, q); !refusedAs(err, engineops.NotOwner) {
			return a, nil, err
		}
	}
	if r.remoteKnown(q.Name) && q.Opts != nil {
		return volumes.VolumeCreateA{Name: q.Name}, nil, nil
	}
	return volumes.VolumeCreateA{}, nil, err
}

func (r *Runtime) engineVolumeGet(ctx context.Context, q volumes.VolumeGetQ) (volumes.VolumeGetA, []*os.File, error) {
	err := notReady()
	if r.activations != nil {
		var a volumes.VolumeGetA
		if a, _, err = r.activations.EngineVolumeGet(ctx, q); !refusedAs(err, engineops.NotFound) {
			return a, nil, err
		}
	}
	if r.remoteKnown(q.Name) {
		return volumes.VolumeGetA{Name: q.Name, Status: "ready"}, nil, nil
	}
	return volumes.VolumeGetA{}, nil, err
}

func (r *Runtime) engineVolumeList(ctx context.Context, q volumes.VolumeListQ) (volumes.VolumeListA, []*os.File, error) {
	if r.activations == nil && r.remoteVolumes == nil {
		return volumes.VolumeListA{}, nil, notReady()
	}
	names := []string{}
	if r.activations != nil {
		a, _, err := r.activations.EngineVolumeList(ctx, q)
		if err != nil {
			return volumes.VolumeListA{}, nil, err
		}
		names = append(names, a.Volumes...)
	}
	if r.remoteVolumes != nil {
		names = append(names, r.remoteVolumes.EngineVolumeNames()...)
	}
	sort.Strings(names)
	return volumes.VolumeListA{Volumes: names}, nil, nil
}

// Remove: sfcd removes local and shared volumes only through its own
// retirement, so a known name is refused.
func (r *Runtime) engineVolumeRemove(ctx context.Context, q volumes.VolumeRemoveQ) (volumes.VolumeRemoveA, []*os.File, error) {
	err := notReady()
	if r.activations != nil {
		if _, _, err = r.activations.EngineVolumeRemove(ctx, q); !refusedAs(err, engineops.NotFound) {
			return volumes.VolumeRemoveA{}, nil, err
		}
	}
	if r.remoteKnown(q.Name) {
		return volumes.VolumeRemoveA{}, nil, engineops.Refuse(engineops.Refused, nil)
	}
	return volumes.VolumeRemoveA{}, nil, err
}
