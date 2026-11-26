// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"slices"
	"testing"

	"github.com/jay94ks/mydcd/internal/network"
	"github.com/moby/moby/api/types/container"
	dockernet "github.com/moby/moby/api/types/network"
)

func TestPublishedPortsNormalizationAndFixedOverlap(t *testing.T) {
	normal, err := NormalizePublishedPorts([]PublishedPort{{Target: 80, Published: "08080", HostIP: "2001:0db8::1"}, {Target: 53, Protocol: "UDP", Published: "0"}})
	if err != nil || len(normal) != 2 || normal[0].Protocol != "udp" || normal[0].Published != "" || normal[1].HostIP != "2001:db8::1" || normal[1].Published != "8080" || normal[1].Mode != "ingress" {
		t.Fatal(normal, err)
	}
	for _, bad := range []PublishedPort{{Target: 0}, {Target: 65536}, {Target: 80, Protocol: "sctp"}, {Target: 80, Published: "65536"}, {Target: 80, Published: "9-8"}, {Target: 80, HostIP: "localhost"}, {Target: 80, HostIP: "fe80::1%eth0"}, {Target: 80, Mode: "foreign"}} {
		if _, err := NormalizePublishedPorts([]PublishedPort{bad}); err == nil {
			t.Fatal("invalid publication accepted", bad)
		}
	}
	a := PublishedPort{Target: 80, Published: "8080", Protocol: "tcp"}
	b := a
	b.HostIP = "127.0.0.1"
	if !PublishedPortsConflict(a, b) {
		t.Fatal("wildcard did not overlap IPv4")
	}
	b.HostIP = "::1"
	if !PublishedPortsConflict(a, b) {
		t.Fatal("wildcard did not overlap IPv6")
	}
	b.Protocol = "udp"
	if PublishedPortsConflict(a, b) {
		t.Fatal("protocols conflated")
	}
	b.Protocol = "tcp"
	b.Published = "8080-8082"
	if PublishedPortsConflict(a, b) {
		t.Fatal("Docker selection range reserved wholesale")
	}
	b.Published = ""
	if PublishedPortsConflict(a, b) {
		t.Fatal("dynamic allocation preallocated")
	}
}

func publishedStartFixture(t *testing.T) *startFixture {
	t.Helper()
	f := makeStartFixture(t)
	var err error
	f.spec.Ports, err = NormalizePublishedPorts([]PublishedPort{{HostIP: "127.0.0.1", Target: 8080, Published: "18080"}, {HostIP: "127.0.0.1", Target: 53100, Published: "18080", Protocol: "udp"}, {Target: 9000, Published: "19000-19010"}, {Target: 9001}})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(f.spec)
	f.op.Target.Spec = string(raw)
	id, err := f.engine.Identity("container", "task", f.op.Target)
	if err != nil {
		t.Fatal(err)
	}
	f.native.Name = "/" + id.Name
	f.native.Config.Labels = id.Labels
	f.native.Config.ExposedPorts, f.native.HostConfig.PortBindings, err = nativePublishedPorts(f.spec.Ports)
	if err != nil {
		t.Fatal(err)
	}
	f.onStart = func() error {
		f.native.State = &container.State{Running: true, Status: container.StateRunning, StartedAt: "2026-11-24T01:00:00Z", Pid: 123}
		f.native.NetworkSettings.Ports = dockernet.PortMap{}
		for port, bindings := range f.native.HostConfig.PortBindings {
			for _, binding := range bindings {
				if binding.HostPort == "" {
					binding.HostPort = "49100"
				} else if binding.HostPort == "19000-19010" {
					binding.HostPort = "19003"
				}
				if !binding.HostIP.IsValid() {
					binding.HostIP = netip.IPv4Unspecified()
				}
				f.native.NetworkSettings.Ports[port] = append(f.native.NetworkSettings.Ports[port], binding)
			}
		}
		return nil
	}
	return f
}

func TestPublishedPortsDockerSDKOptionsAndExactInspection(t *testing.T) {
	f := publishedStartFixture(t)
	f.bridge.lease.Spec.Pools = []network.Pool{{Prefix: netip.MustParsePrefix("192.0.2.0/24"), Gateway: netip.MustParseAddr("192.0.2.1")}}
	d := DockerDriver{Engine: f.engine, Network: f.bridge}
	id, _ := f.engine.Identity("container", "task", f.op.Target)
	options, err := d.options(context.Background(), f.spec, id, "task", 1)
	if err != nil {
		t.Fatal(err)
	}
	tcp, udp := dockernet.MustParsePort("8080/tcp"), dockernet.MustParsePort("53100/udp")
	if options.HostConfig.PublishAllPorts || options.HostConfig.PortBindings[tcp][0].HostPort != "18080" || options.HostConfig.PortBindings[udp][0].HostPort != "18080" || options.HostConfig.PortBindings[tcp][0].HostIP != netip.MustParseAddr("127.0.0.1") {
		t.Fatal("SDK lost exact TCP/UDP publishing", options.HostConfig.PortBindings)
	}
	if len(options.Config.ExposedPorts) != 4 {
		t.Fatal("SDK targets missing")
	}
	if !d.matchContainer(context.Background(), f.native, f.spec, id, f.bridge.lease, nil) {
		t.Fatal("configured stopped original did not match")
	}
	_ = f.onStart()
	if !d.matchContainer(context.Background(), f.native, f.spec, id, f.bridge.lease, nil) {
		t.Fatal("selected original bindings did not match")
	}
	// Docker's configured default bind address can be specific when HostIP
	// was omitted. It is still the exact original native, not a new allocator.
	defaultPort := dockernet.MustParsePort("9001/tcp")
	f.native.NetworkSettings.Ports[defaultPort][0].HostIP = netip.MustParseAddr("127.0.0.1")
	if !d.matchContainer(context.Background(), f.native, f.spec, id, f.bridge.lease, nil) {
		t.Fatal("Docker default host address rejected")
	}
	for name, mutate := range map[string]func(*startFixture){
		"owner": func(f *startFixture) { f.native.Config.Labels["org.mydc.owner"] = "foreign" },
		"range": func(f *startFixture) {
			p := dockernet.MustParsePort("9000/tcp")
			f.native.NetworkSettings.Ports[p][0].HostPort = "19011"
		},
		"missing": func(f *startFixture) { delete(f.native.NetworkSettings.Ports, tcp) },
		"foreign-ip": func(f *startFixture) {
			f.native.NetworkSettings.Ports[tcp][0].HostIP = netip.MustParseAddr("192.0.2.9")
		},
		"extra-protocol": func(f *startFixture) {
			f.native.NetworkSettings.Ports[dockernet.MustParsePort("8080/udp")] = []dockernet.PortBinding{{HostPort: "18080"}}
		},
		"publish-all": func(f *startFixture) { f.native.HostConfig.PublishAllPorts = true },
	} {
		t.Run(name, func(t *testing.T) {
			f := publishedStartFixture(t)
			_ = f.onStart()
			mutate(f)
			id, _ := f.engine.Identity("container", "task", f.op.Target)
			d := DockerDriver{Engine: f.engine, Network: f.bridge}
			if d.matchContainer(context.Background(), f.native, f.spec, id, f.bridge.lease, nil) {
				t.Fatal("foreign publication adopted")
			}
		})
	}
}

func TestPublishedPortsOriginalManagerRecoveryAndLegacyBytes(t *testing.T) {
	f := publishedStartFixture(t)
	path := filepath.Join(t.TempDir(), "workload.db")
	m, err := OpenManager(path, f.engine, f.bridge)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Desired("task", 1, 1, &f.spec, 4); err != nil {
		t.Fatal(err)
	}
	if err = m.Step(context.Background(), "task"); err != nil {
		t.Fatal(err)
	}
	id, running, err := m.NetworkIdentity(context.Background(), "task", 1)
	if err != nil || !running || id != f.native.ID {
		t.Fatal(id, running, err)
	}
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	m, err = OpenManager(path, f.engine, f.bridge)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	recovered, running, err := m.NetworkIdentity(context.Background(), "task", 1)
	if err != nil || !running || recovered != id || f.starts != 1 {
		t.Fatal("recovery changed publication/original", recovered, running, f.starts, err)
	}
	f.native.State.Running = false
	f.native.State.Status = container.StateExited
	f.native.NetworkSettings.Ports = nil
	if _, running, err = m.NetworkIdentity(context.Background(), "task", 1); err != nil || running {
		t.Fatal("stopped configured original rejected", err)
	}
	original := f.spec
	original.Ports = nil
	raw, _ := json.Marshal(original)
	if bytes.Contains(raw, []byte(`"Ports"`)) {
		t.Fatal("legacy nil bytes changed")
	}
	restored, err := DecodeContainer(string(raw))
	if err != nil || restored.Ports != nil {
		t.Fatal(err)
	}
	with, _ := json.Marshal(f.spec)
	again, err := DecodeContainer(string(with))
	if err != nil || !slices.Equal(again.Ports, f.spec.Ports) {
		t.Fatal("frozen publication lost", err)
	}
	again.Ports[0].Published = "1"
	if slices.Equal(again.Ports, f.spec.Ports) {
		t.Fatal("decoded ports alias original")
	}
}
