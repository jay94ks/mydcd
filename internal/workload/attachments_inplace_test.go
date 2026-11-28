// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/moby/moby/api/types/container"
	dockernet "github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
)

func TestInPlaceAcceptsOnlyAttachmentSetChanges(t *testing.T) {
	f, _ := twoNetworkFixture(t)
	one := makeStartFixture(t)
	raw := func(s ContainerSpec) reconcile.Resource {
		b, _ := json.Marshal(s)
		return reconcile.Resource{Present: true, Generation: 1, Spec: string(b)}
	}
	single, two := raw(one.spec), raw(f.spec)
	if !inPlaceAttachments(single, two) || !inPlaceAttachments(two, single) {
		t.Fatal("attach/detach of an extra network is not in place")
	}
	if TaskIdentityResource(two) != single {
		t.Fatal("extra attachments changed the Task's native identity")
	}
	if inPlaceAttachments(single, single) {
		t.Fatal("an unchanged spec reported as an update")
	}
	for name, mutate := range map[string]func(*ContainerSpec){
		"kept address": func(s *ContainerSpec) {
			s.Attachments = []TaskAttachment{{Bridge: "bridge-b", BridgeGeneration: 3, IPv4: netip.MustParseAddr("198.51.100.8")}}
		},
		"primary address": func(s *ContainerSpec) { s.IPv4 = netip.MustParseAddr("192.0.2.3") },
		"primary bridge":  func(s *ContainerSpec) { s.Bridge = "bridge-c" },
		"image":           func(s *ContainerSpec) { s.Memory *= 2 },
		"volumes": func(s *ContainerSpec) {
			s.Process = &Process{ImageID: s.Image, Command: s.Command}
			s.Command = nil
			s.Volumes = []VolumeMount{{Target: "/data"}}
		},
	} {
		next := f.spec
		next.Attachments = append([]TaskAttachment(nil), f.spec.Attachments...)
		mutate(&next)
		if inPlaceAttachments(two, raw(next)) {
			t.Fatal("non-attachment change treated as in place", name)
		}
	}
	other := two
	other.Generation = 2
	if inPlaceAttachments(two, other) {
		t.Fatal("another generation treated as in place")
	}
}

// The real workload Manager and journal over a fixture engine: attach then
// detach an extra network on the running original container.
func TestManagerAttachesAndDetachesAnExtraNetworkInPlace(t *testing.T) {
	f, b := twoNetworkFixture(t)
	single := makeStartFixture(t)
	f.native.Name, f.native.Config.Labels = single.native.Name, single.native.Config.Labels
	delete(f.native.NetworkSettings.Networks, "fixture-bridge-b")
	f.onStart = func() error {
		f.native.State = &container.State{Running: true, Status: container.StateRunning, StartedAt: "2026-11-28T07:00:00Z", Pid: 77}
		return nil
	}
	var connected, disconnected []string
	f.onConnect = func(network string, body []byte) error {
		var q struct {
			Container      string
			EndpointConfig *dockernet.EndpointSettings
		}
		if err := json.Unmarshal(body, &q); err != nil || q.Container != f.native.ID || q.EndpointConfig == nil || q.EndpointConfig.IPAMConfig == nil {
			t.Error("connect without the original container and fixed address", string(body))
		}
		connected = append(connected, network)
		ip := q.EndpointConfig.IPAMConfig.IPv4Address
		f.native.NetworkSettings.Networks["fixture-bridge-b"] = &dockernet.EndpointSettings{NetworkID: network, EndpointID: "ep-b", IPAddress: ip, IPAMConfig: &dockernet.EndpointIPAMConfig{IPv4Address: ip}}
		return nil
	}
	f.onDisconnect = func(network string, _ []byte) error {
		disconnected = append(disconnected, network)
		delete(f.native.NetworkSettings.Networks, "fixture-bridge-b")
		return nil
	}
	db := filepath.Join(t.TempDir(), "workload.db")
	m, err := OpenManager(db, f.engine, b)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	ctx := context.Background()
	base := single.spec
	if err = m.Desired("task", 1, 1, &base, 4); err != nil {
		t.Fatal(err)
	}
	if err = m.Step(ctx, "task"); err != nil {
		t.Fatal("original start", err)
	}
	if f.starts != 1 {
		t.Fatal("original not started once", f.starts)
	}
	attached := f.spec
	if err = m.Desired("task", 2, 1, &attached, 4); err != nil {
		t.Fatal(err)
	}
	if err = m.Step(ctx, "task"); err != nil {
		t.Fatal("in-place attach", err)
	}
	r, _ := m.View("task")
	if len(connected) != 1 || connected[0] != "fixture-network-b" || f.starts != 1 || f.removes != 0 || r.State.Applied.Spec != r.State.Desired.Spec {
		t.Fatal("attach replaced the container or did not connect", connected, f.starts, f.removes)
	}
	// Maintenance of the attached original keeps its first Start witness.
	if err = m.Step(ctx, "task"); err != nil {
		t.Fatal("maintenance after in-place attach", err)
	}
	extra := f.spec.Attachments[0]
	if closed, err := m.AttachmentClosed(ctx, "task", 1, extra); err != nil || closed {
		t.Fatal("attached network reported closed", closed, err)
	}
	// The record stays valid across a restart of the node.
	_ = m.Close()
	if m, err = OpenManager(db, f.engine, b); err != nil {
		t.Fatal("record invalid after in-place attach", err)
	}
	if err = m.Desired("task", 3, 1, &base, 4); err != nil {
		t.Fatal(err)
	}
	if err = m.Step(ctx, "task"); err != nil {
		t.Fatal("in-place detach", err)
	}
	if len(disconnected) != 1 || disconnected[0] != "fixture-network-b" || b.pinned["bridge-b"] || !b.pinned["bridge"] || f.starts != 1 || f.removes != 0 {
		t.Fatal("detach did not disconnect and return only the dropped pin", disconnected, b.pinned)
	}
	if closed, err := m.AttachmentClosed(ctx, "task", 1, extra); err != nil || !closed {
		t.Fatal("detached network not reported closed", closed, err)
	}
	if closed, _ := m.AttachmentClosed(ctx, "task", 2, extra); closed {
		t.Fatal("closure reported for another generation")
	}
	// A pin of the same consumer at another Bridge generation is not closed,
	// although InspectConsumer at the detached generation finds no pin.
	b.otherGeneration = map[string]bool{"bridge-b": true}
	if closed, err := m.AttachmentClosed(ctx, "task", 1, extra); err != nil || closed {
		t.Fatal("pin at another Bridge generation reported closed", closed, err)
	}
	b.otherGeneration = nil
	status, err := m.Status(ctx, "task")
	if err != nil || !status.Running || status.NativeID != f.native.ID {
		t.Fatal("original container lost", status, err)
	}
	_ = client.ContainerInspectOptions{}
}
