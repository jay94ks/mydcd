// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"encoding/hex"
	"testing"

	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/workload/volumes"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
)

// A remote Volume is an "sfc" driver volume named after its consumer; the
// container matches only with that driver, name and access.
func TestRemoteVolumeMounts(t *testing.T) {
	cluster, node, home := [32]byte{1}, [32]byte{2}, [32]byte{3}
	scope := volumes.Scope{Cluster: cluster, Tenant: "tenant", ID: "shared", Generation: 3}
	consumer := volumes.Consumer{ID: "web", Generation: 5, Owner: volumes.Owner{Node: "node-b", Key: home, Native: volumes.FixedNativeName(scope)}, OwnerRevision: 1, Runner: "node-a", RunnerKey: hex.EncodeToString(node[:])}
	v := RemoteVolumeMount{Scope: scope, Consumer: consumer, Home: home, Target: "/srv/data"}
	s := ContainerSpec{Node: engine.Owner(cluster, node), Process: &Process{}, Memory: 32 << 20, RemoteVolumes: []RemoteVolumeMount{v}}
	if err := validateRemoteVolumes(s); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*ContainerSpec){
		"local consumer": func(s *ContainerSpec) { s.RemoteVolumes[0].Consumer.Runner = "" },
		"no home":        func(s *ContainerSpec) { s.RemoteVolumes[0].Home = [32]byte{} },
		"bad target":     func(s *ContainerSpec) { s.RemoteVolumes[0].Target = "relative" },
		"twice":          func(s *ContainerSpec) { s.RemoteVolumes = append(s.RemoteVolumes, s.RemoteVolumes[0]) },
		"overlap local": func(s *ContainerSpec) {
			s.Volumes = []VolumeMount{{Scope: scope, Target: "/srv"}}
		},
	} {
		bad := s
		bad.RemoteVolumes = append([]RemoteVolumeMount(nil), s.RemoteVolumes...)
		change(&bad)
		if validateRemoteVolumes(bad) == nil {
			t.Fatal(name, "accepted")
		}
	}
	m := remoteMounts(s.RemoteVolumes)
	if len(m) != 1 || m[0].Source != v.spec().Name() || !m[0].ReadOnly || mountDriver(m[0]) != "sfc" {
		t.Fatalf("%+v", m)
	}
	got := container.InspectResponse{HostConfig: &container.HostConfig{Mounts: m}, Mounts: []container.MountPoint{{Type: mount.TypeVolume, Name: m[0].Source, Driver: "sfc", Destination: v.Target, RW: false}}}
	if !matchResolvedTaskMounts(got, nil, 1, m) {
		t.Fatal("remote mount rejected")
	}
	for _, change := range []func(*container.MountPoint){
		func(p *container.MountPoint) { p.Driver = "local" },
		func(p *container.MountPoint) { p.RW = true },
		func(p *container.MountPoint) { p.Name = "other" },
	} {
		bad := got
		bad.Mounts = append([]container.MountPoint(nil), got.Mounts...)
		change(&bad.Mounts[0])
		if matchResolvedTaskMounts(bad, nil, 1, m) {
			t.Fatal("changed remote mount accepted")
		}
	}
}
