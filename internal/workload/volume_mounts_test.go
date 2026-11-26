// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
)

func TestManagedVolumeMountPolicyAndExactSDKInspection(t *testing.T) {
	cluster, node := [32]byte{1}, [32]byte{2}
	v := VolumeMount{Scope: volumes.Scope{Cluster: cluster, Tenant: "tenant", App: "app", ID: "data", Generation: 1}, Consumer: volumes.Consumer{ID: "database", Generation: 1, Writable: true, Lease: reconcile.Lease{Generation: 1, Token: 1}, Owner: volumes.Owner{Node: "node-a", Key: node, Native: "original-native"}, OwnerRevision: 1}, NativeKey: "volume/tenant/app/data/initial", NativeGeneration: 1, Target: "/data"}
	s := ContainerSpec{Node: engine.Owner(cluster, node), Process: &Process{}, Memory: 32 << 20, Volumes: []VolumeMount{v}}
	if err := validateVolumeMounts(s); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*VolumeMount){func(v *VolumeMount) { v.Target = "/proc/data" }, func(v *VolumeMount) { v.NativeGeneration = 0 }, func(v *VolumeMount) { v.Consumer.Lease.Token = 0 }, func(v *VolumeMount) { v.Consumer.Owner.Key = [32]byte{3} }} {
		bad := v
		mutate(&bad)
		s.Volumes = []VolumeMount{bad}
		if validateVolumeMounts(s) == nil {
			t.Fatal("invalid public mount admitted")
		}
	}
	s.Volumes = []VolumeMount{v, v}
	if validateVolumeMounts(s) == nil {
		t.Fatal("duplicate volume/target")
	}
	s.Volumes = []VolumeMount{v}
	// Internally consistent public refs may still belong to another local
	// owner. Reject them before publishing a permanent task identity.
	image := "sha256:" + strings.Repeat("a", 64)
	process, err := ResolveProcess(image, &container.Config{User: "10001:10001", Cmd: []string{"/backend"}}, ProcessOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	s.Schema, s.Image, s.Process = 1, image, &process
	s.Bridge, s.BridgeGeneration, s.IPv4, s.NanoCPU = "bridge", 1, netip.MustParseAddr("198.19.1.2"), 100000000
	m := &Manager{driver: &DockerDriver{Engine: &engine.Client{Owner: "other-local-owner"}, Volumes: new(volumes.Activations)}}
	if err = m.Desired("workload/task/tenant/app/database", 1, 1, &s, 4); !errors.Is(err, ErrVolumeMount) {
		t.Fatal("foreign local owner admitted", err)
	}
	s.Tmpfs = []Tmpfs{{Target: "/data/cache", SizeBytes: 4 << 20}}
	if validateVolumeMounts(s) == nil {
		t.Fatal("nested tmpfs hides volume")
	}
	got := container.InspectResponse{HostConfig: &container.HostConfig{Mounts: namedMounts([]VolumeMount{v})}, Mounts: []container.MountPoint{{Type: mount.TypeVolume, Name: v.Consumer.Owner.Native, Driver: "local", Destination: v.Target, RW: true}}}
	if !matchTaskMounts(got, nil, []VolumeMount{v}) {
		t.Fatal("original no-copy local mount rejected")
	}
	for _, mutate := range []func(*container.InspectResponse){func(g *container.InspectResponse) { g.HostConfig.Mounts[0].VolumeOptions.NoCopy = false }, func(g *container.InspectResponse) { g.HostConfig.Mounts[0].ReadOnly = true }, func(g *container.InspectResponse) { g.Mounts[0].Name = "external" }, func(g *container.InspectResponse) { g.Mounts[0].Driver = "remote" }, func(g *container.InspectResponse) { g.Mounts[0].RW = false }, func(g *container.InspectResponse) {
		g.Mounts = append(g.Mounts, container.MountPoint{Type: mount.TypeVolume, Name: "anonymous", Destination: "/other"})
	}} {
		copy := got
		h := *got.HostConfig
		h.Mounts = namedMounts([]VolumeMount{v})
		copy.HostConfig = &h
		copy.Mounts = append([]container.MountPoint(nil), got.Mounts...)
		mutate(&copy)
		if matchTaskMounts(copy, nil, []VolumeMount{v}) {
			t.Fatal("foreign native configuration admitted")
		}
	}
}

func TestFixedVolumePublicReferenceAndExactResolvedBind(t *testing.T) {
	cluster, node := [32]byte{1}, [32]byte{2}
	scope := volumes.Scope{Cluster: cluster, Tenant: "tenant", ID: "fixed-data", Generation: 3}
	v := VolumeMount{Scope: scope, Consumer: volumes.Consumer{ID: "database", Generation: 5, Writable: true, Lease: reconcile.Lease{Generation: 3, Token: 1}, Owner: volumes.Owner{Node: "node-a", Key: node, Native: volumes.FixedNativeName(scope)}, OwnerRevision: 1}, NativeKey: volumes.FixedNativeKey(scope), NativeGeneration: 3, Target: "/data", NativeBinding: strings.Repeat("a", 64)}
	s := ContainerSpec{Node: engine.Owner(cluster, node), Process: &Process{}, Memory: 32 << 20, Volumes: []VolumeMount{v}}
	if err := validateVolumeMounts(s); err != nil {
		t.Fatal("tenant-managed name reference", err)
	}
	resource := reconcile.Resource{Present: true, Generation: 5, Spec: "original-task"}
	if _, err := volumeReferences(s, "workload/task/tenant/actual-app/database", reconcile.Operation{ID: 1, Target: resource}); err != nil {
		t.Fatal("real app Task using tenant fixed scope", err)
	}
	if _, err := volumeReferences(s, "workload/task/other/actual-app/database", reconcile.Operation{ID: 1, Target: resource}); err == nil {
		t.Fatal("cross-tenant Task accepted")
	}
	m := mount.Mount{Type: mount.TypeBind, Source: "/private-state/mounts/original/data", Target: v.Target, ReadOnly: false, BindOptions: &mount.BindOptions{Propagation: mount.PropagationRPrivate, CreateMountpoint: false, NonRecursive: true}}
	got := container.InspectResponse{HostConfig: &container.HostConfig{Mounts: []mount.Mount{m}}, Mounts: []container.MountPoint{{Type: mount.TypeBind, Source: m.Source, Destination: m.Target, RW: true, Propagation: mount.PropagationRPrivate}}}
	if !matchResolvedTaskMounts(got, nil, []VolumeMount{v}, []mount.Mount{m}) {
		t.Fatal("exact adapter-resolved bind rejected")
	}
	if matchTaskMounts(got, nil, []VolumeMount{v}) {
		t.Fatal("fixed mount accepted without original source resolution")
	}
	for _, change := range []func(*container.InspectResponse){func(g *container.InspectResponse) { g.Mounts[0].Source = "/foreign" }, func(g *container.InspectResponse) { g.Mounts[0].RW = false }, func(g *container.InspectResponse) { g.HostConfig.Mounts[0].BindOptions.CreateMountpoint = true }, func(g *container.InspectResponse) { g.Mounts[0].Propagation = mount.PropagationRShared }} {
		bad := got
		host := *got.HostConfig
		opts := *m.BindOptions
		copyMount := m
		copyMount.BindOptions = &opts
		host.Mounts = []mount.Mount{copyMount}
		bad.HostConfig = &host
		bad.Mounts = append([]container.MountPoint(nil), got.Mounts...)
		change(&bad)
		if matchResolvedTaskMounts(bad, nil, []VolumeMount{v}, []mount.Mount{m}) {
			t.Fatal("foreign/implicit creation bind accepted")
		}
	}
}
