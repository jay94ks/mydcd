// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"errors"

	"github.com/jay94ks/seafield/internal/volumeshare/remote"
	"github.com/jay94ks/seafield/internal/workload/volumes"
	"github.com/moby/moby/api/types/mount"
)

// RemoteVolumeMount is a shared Volume whose home is another server: the
// task's consumer runs here and reaches the data over SFCP VolumeFS
// (devel/proposals/shared-volumes-over-sfcp.md). Home is the owner's
// current key when the recipe was made.
type RemoteVolumeMount struct {
	Scope    volumes.Scope
	Consumer volumes.Consumer
	Home     [32]byte
	Target   string
}

func (v RemoteVolumeMount) spec() remote.Spec {
	return remote.Spec{Scope: v.Scope, Consumer: v.Consumer, Home: v.Home}
}

// RemoteVolumes is the runner's journal of remote consumers (remote.Mounts).
type RemoteVolumes interface {
	Hold(ctx context.Context, spec remote.Spec) (string, error)
	Bind(name, container string) error
	BeginStart(name string) error
	EndStart(name string) error
	Release(name string) error
}

// remoteDriver is the Seafield engine's built-in volume driver; sfcd answers
// its Mount with the local FUSE mount of the consumer.
const remoteDriver = "sfc"

func mountDriver(m mount.Mount) string {
	if m.VolumeOptions != nil && m.VolumeOptions.DriverConfig != nil {
		return m.VolumeOptions.DriverConfig.Name
	}
	return "local"
}

func remoteMounts(values []RemoteVolumeMount) []mount.Mount {
	out := make([]mount.Mount, 0, len(values))
	for _, v := range values {
		out = append(out, mount.Mount{Type: mount.TypeVolume, Source: v.spec().Name(), Target: v.Target, ReadOnly: !v.Consumer.Writable, VolumeOptions: &mount.VolumeOptions{NoCopy: true, DriverConfig: &mount.Driver{Name: remoteDriver}}})
	}
	return out
}

// specMounts is every Volume mount of s: local ones first, then remote.
func (d *DockerDriver) specMounts(s ContainerSpec) ([]mount.Mount, error) {
	local, err := d.taskMounts(s.Volumes)
	if err != nil {
		return nil, err
	}
	return append(local, remoteMounts(s.RemoteVolumes)...), nil
}

func validateRemoteVolumes(s ContainerSpec) error {
	if len(s.RemoteVolumes) == 0 {
		return nil
	}
	if len(s.Volumes)+len(s.RemoteVolumes) > 32 || s.Process == nil {
		return ErrVolumeMount
	}
	for i, v := range s.RemoteVolumes {
		if !MountTarget(v.Target) || !v.Consumer.Remote() || v.Home == ([32]byte{}) || v.Scope.RegistryManaged() || v.Consumer.ID == "" {
			return ErrVolumeMount
		}
		if _, ok := v.Consumer.GoneKey(); !ok {
			return ErrVolumeMount
		}
		for _, p := range s.Volumes {
			if OverlappingMounts(p.Target, v.Target) || p.Scope.Cluster != v.Scope.Cluster || p.Scope.Tenant != v.Scope.Tenant {
				return ErrVolumeMount
			}
		}
		for _, p := range s.RemoteVolumes[:i] {
			if OverlappingMounts(p.Target, v.Target) || p.Scope.Key() == v.Scope.Key() || p.Scope.Cluster != v.Scope.Cluster || p.Scope.Tenant != v.Scope.Tenant {
				return ErrVolumeMount
			}
		}
	}
	return nil
}

// holdRemote mounts every remote Volume of s before the container is made.
func (d *DockerDriver) holdRemote(ctx context.Context, s ContainerSpec) error {
	if len(s.RemoteVolumes) == 0 {
		return nil
	}
	if d.Remote == nil {
		return ErrVolumeMount
	}
	for _, v := range s.RemoteVolumes {
		if _, err := d.Remote.Hold(ctx, v.spec()); err != nil {
			return err
		}
	}
	return nil
}

// bindRemote names the container that may mount s's remote Volumes.
func (d *DockerDriver) bindRemote(s ContainerSpec, container string) error {
	for _, v := range s.RemoteVolumes {
		if d.Remote == nil {
			return ErrVolumeMount
		}
		if err := d.Remote.Bind(v.spec().Name(), container); err != nil {
			return err
		}
	}
	return nil
}

// beginRemoteStart journals the coming Start; endRemoteStart settles it once
// its outcome is known.
func (d *DockerDriver) beginRemoteStart(s ContainerSpec) error {
	for _, v := range s.RemoteVolumes {
		if d.Remote == nil {
			return ErrVolumeMount
		}
		if err := d.Remote.BeginStart(v.spec().Name()); err != nil {
			return err
		}
	}
	return nil
}

func (d *DockerDriver) endRemoteStart(s ContainerSpec) error {
	var err error
	for _, v := range s.RemoteVolumes {
		if d.Remote != nil {
			err = errors.Join(err, d.Remote.EndStart(v.spec().Name()))
		}
	}
	return err
}

// releaseRemote runs only once the container is proven gone.
func (d *DockerDriver) releaseRemote(s ContainerSpec) error {
	for _, v := range s.RemoteVolumes {
		if d.Remote == nil {
			return ErrVolumeMount
		}
		if err := d.Remote.Release(v.spec().Name()); err != nil {
			return err
		}
	}
	return nil
}
