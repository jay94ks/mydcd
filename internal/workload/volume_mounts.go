// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/storage"
	"github.com/jay94ks/seafield/internal/workload/volumes"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
)

var ErrVolumeMount = errors.New("invalid or unavailable managed task volume mount")

// VolumeMount contains only public native ownership and the original shared
// consumer. A host filesystem path or arbitrary external volume is not input.
type VolumeMount struct {
	Scope            volumes.Scope
	Consumer         volumes.Consumer
	NativeKey        string
	NativeGeneration uint64
	Target           string
	NativeBinding    string `json:",omitempty"`
}

func volumeReferences(s ContainerSpec, key string, op reconcile.Operation) ([]volumes.Activation, error) {
	refs := make([]volumes.Activation, 0, len(s.Volumes))
	for _, v := range s.Volumes {
		r := volumes.Activation{Scope: v.Scope, Consumer: v.Consumer, NativeKey: v.NativeKey, NativeGeneration: v.NativeGeneration, TaskKey: key, Task: op.Target, Operation: op.ID, NativeBinding: v.NativeBinding}
		if r.Operation == 0 {
			r.Operation = 1 // Read-only Status has no dispatch; resolved below.
		}
		if engine.Owner(r.Scope.Cluster, r.Consumer.Owner.Key) != s.Node {
			r.TaskOwner = s.Node
		}
		if r.Validate() != nil || !s.resourceOwner(r.Scope.Cluster, r.Consumer.Owner.Node, r.Consumer.Owner.Key) {
			return nil, ErrVolumeMount
		}
		refs = append(refs, r)
	}
	return refs, nil
}

func validateVolumeMounts(s ContainerSpec) error {
	if len(s.Volumes) == 0 {
		return nil
	}
	if len(s.Volumes) > 32 || s.Process == nil {
		return ErrVolumeMount
	}
	var targets []string
	for i, v := range s.Volumes {
		if !MountTarget(v.Target) {
			return ErrVolumeMount
		}
		for _, p := range s.Volumes[:i] {
			if OverlappingMounts(p.Target, v.Target) || p.Consumer.Owner.Native == v.Consumer.Owner.Native || p.Scope.Cluster != v.Scope.Cluster || p.Scope.Tenant != v.Scope.Tenant || p.Scope.App != "" && v.Scope.App != "" && p.Scope.App != v.Scope.App {
				return ErrVolumeMount
			}
		}
		targets = append(targets, v.Target)
		raw, _ := json.Marshal(s)
		resource := reconcile.Resource{Present: true, Generation: v.Consumer.Generation, Spec: string(raw)}
		app := v.Scope.App
		if v.Scope.TenantManaged() {
			app = "validate"
		} // validation only; the actual Task key is required at dispatch
		if _, err := volumeReferences(ContainerSpec{ResourceKeys: s.ResourceKeys, Node: s.Node, Volumes: []VolumeMount{v}}, "workload/task/"+v.Scope.Tenant+"/"+app+"/validate", reconcile.Operation{ID: 1, Target: resource}); err != nil {
			return err
		}
	}
	return ValidateTmpfs(s.Tmpfs, s.Memory, targets)
}

func namedMounts(values []VolumeMount) []mount.Mount {
	var result []mount.Mount
	for _, v := range values {
		result = append(result, mount.Mount{Type: mount.TypeVolume, Source: v.Consumer.Owner.Native, Target: v.Target, ReadOnly: !v.Consumer.Writable, VolumeOptions: &mount.VolumeOptions{NoCopy: true}})
	}
	return result
}

func matchTaskMounts(got container.InspectResponse, files []InputFile, values []VolumeMount) bool {
	for _, v := range values {
		if v.Scope.TenantManaged() {
			return false
		}
	}
	return matchResolvedTaskMounts(got, files, len(values), namedMounts(values))
}

func (d *DockerDriver) taskMounts(values []VolumeMount) ([]mount.Mount, error) {
	result := make([]mount.Mount, 0, len(values))
	for _, v := range values {
		if d.Volumes == nil {
			return nil, ErrVolumeMount
		}
		source, bind, err := d.Volumes.MountSource(v.NativeKey, v.Scope, v.Consumer.Owner, v.NativeGeneration, v.NativeBinding)
		if err != nil {
			return nil, err
		}
		m := mount.Mount{Type: mount.TypeVolume, Source: source, Target: v.Target, ReadOnly: !v.Consumer.Writable, VolumeOptions: &mount.VolumeOptions{NoCopy: true}}
		if bind {
			// A fixed volume is an engine "sfc" volume; the engine asks sfcd
			// for the held directory when it mounts it (purpose 35).
			m.VolumeOptions.DriverConfig = &mount.Driver{Name: volumes.EngineVolumeDriver}
		}
		result = append(result, m)
	}
	return result, nil
}

func matchResolvedTaskMounts(got container.InspectResponse, files []InputFile, values int, mounts []mount.Mount) bool {
	files = mountedInputFiles(files)
	if len(mounts) != values {
		return false
	}
	if got.HostConfig == nil || len(got.Mounts) != len(files)+values || len(got.HostConfig.Mounts) != len(files)+values {
		return false
	}
	binds := got
	binds.Mounts = nil
	host := *got.HostConfig
	host.Mounts = nil
	binds.HostConfig = &host
	// Every bind is an input file; volumes, fixed ones included, are
	// engine volumes and are matched below.
	for _, m := range got.Mounts {
		if m.Type == mount.TypeBind {
			binds.Mounts = append(binds.Mounts, m)
		}
	}
	for _, m := range got.HostConfig.Mounts {
		if m.Type == mount.TypeBind {
			host.Mounts = append(host.Mounts, m)
		}
	}
	if !matchInputMounts(binds, files) {
		return false
	}
	for _, want := range mounts {
		config, actual := 0, 0
		for _, m := range got.HostConfig.Mounts {
			if reflect.DeepEqual(m, want) {
				config++
			}
		}
		for _, m := range got.Mounts {
			if m.Destination == want.Target && m.RW == !want.ReadOnly && (want.Type == mount.TypeVolume && m.Type == mount.TypeVolume && m.Name == want.Source && m.Driver == mountDriver(want)) {
				actual++
			}
		}
		if config != 1 || actual != 1 {
			return false
		}
	}
	return true
}

func (d *DockerDriver) originalVolumes(s ContainerSpec, key string, op reconcile.Operation) ([]volumes.Activation, error) {
	refs, err := volumeReferences(s, key, op)
	if err != nil || len(refs) == 0 {
		return refs, err
	}
	if d.Volumes == nil {
		return nil, ErrVolumeMount
	}
	for i := range refs {
		r := refs[i]
		r.Operation = 0
		refs[i], err = d.Volumes.Original(r)
		if err != nil || op.Kind == reconcile.Apply && op.ID != 0 && refs[i].Operation != op.ID {
			return nil, errors.Join(ErrVolumeMount, err)
		}
	}
	return refs, nil
}

// A missing local record is not evidence of an untransmitted SDK request.
// Only the positive whole-task CreatePrepared flag permits original resume.
func (d *DockerDriver) preparedVolumes(s ContainerSpec, key string, op reconcile.Operation) (bool, error) {
	refs, err := d.originalVolumes(s, key, op)
	if errors.Is(err, storage.ErrMissing) {
		return false, nil
	}
	if err != nil || len(refs) == 0 {
		return false, err
	}
	return d.Volumes.CreatePreparedAll(refs)
}

func (d *DockerDriver) retireVolumes(ctx context.Context, s ContainerSpec, key string, op reconcile.Operation) error {
	refs, err := d.originalVolumes(s, key, op)
	if err != nil || len(refs) == 0 {
		return err
	}
	return d.Volumes.RetireAll(ctx, refs)
}
