// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/moby/moby/api/types/container"
	dockernet "github.com/moby/moby/api/types/network"
)

// multiBridge is a fixture Bridge owner holding one lease per Bridge key.
type multiBridge struct {
	leases   map[string]network.BridgeLease
	acquired []string
	returned []string
	fail     string // ReturnConsumer of this key fails
	pinned   map[string]bool
	// otherGeneration keys hold this consumer's pin at another generation.
	otherGeneration map[string]bool
	consumer        string
}

func (b *multiBridge) View(key string) (reconcile.Record, error) {
	if _, ok := b.leases[key]; !ok {
		return reconcile.Record{}, network.ErrPolicy
	}
	r := reconcile.Record{Consumers: map[string]reconcile.Lease{}}
	if b.pinned[key] || b.otherGeneration[key] {
		r.Consumers[b.consumer] = reconcile.Lease{}
	}
	return r, nil
}

func (b *multiBridge) Acquire(_ context.Context, key, consumer string, _ uint64) (network.BridgeLease, error) {
	l, ok := b.leases[key]
	if !ok {
		return l, network.ErrPolicy
	}
	b.consumer = consumer
	b.acquired = append(b.acquired, key)
	if b.pinned == nil {
		b.pinned = map[string]bool{}
	}
	b.pinned[key] = true
	return l, nil
}
func (b *multiBridge) InspectConsumer(_ context.Context, key, _ string, _ uint64) (network.BridgeLease, error) {
	l, ok := b.leases[key]
	if !ok {
		return l, network.ErrPolicy
	}
	if b.pinned != nil && !b.pinned[key] || b.otherGeneration[key] {
		return l, reconcile.ErrLease
	}
	return l, nil
}
func (b *multiBridge) ReturnConsumer(key, _ string, _ uint64) error {
	b.returned = append(b.returned, key)
	if key == b.fail {
		return errors.New("stuck bridge")
	}
	if b.pinned != nil {
		b.pinned[key] = false
	}
	return nil
}

func twoNetworkFixture(t *testing.T) (*startFixture, *multiBridge) {
	t.Helper()
	f := makeStartFixture(t)
	f.spec.Attachments = []TaskAttachment{{Bridge: "bridge-b", BridgeGeneration: 3, IPv4: netip.MustParseAddr("198.51.100.7")}}
	raw, _ := json.Marshal(f.spec)
	f.op.Target.Spec = string(raw)
	id, err := f.engine.Identity("container", "task", f.op.Target)
	if err != nil {
		t.Fatal(err)
	}
	f.native.Name = "/" + id.Name
	f.native.Config.Labels = id.Labels
	f.native.NetworkSettings.Networks["fixture-bridge-b"] = &dockernet.EndpointSettings{NetworkID: "fixture-network-b", IPAddress: netip.MustParseAddr("198.51.100.7"), IPAMConfig: &dockernet.EndpointIPAMConfig{IPv4Address: netip.MustParseAddr("198.51.100.7")}}
	b := &multiBridge{leases: map[string]network.BridgeLease{
		"bridge":   {Key: "bridge", NetworkID: "fixture-network", NetworkName: "fixture-bridge", Spec: network.BridgeSpec{Pools: []network.Pool{{Prefix: netip.MustParsePrefix("192.0.2.0/24"), Gateway: netip.MustParseAddr("192.0.2.1")}}}},
		"bridge-b": {Key: "bridge-b", NetworkID: "fixture-network-b", NetworkName: "fixture-bridge-b", Spec: network.BridgeSpec{Pools: []network.Pool{{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Gateway: netip.MustParseAddr("198.51.100.1")}}}},
	}}
	return f, b
}

func TestDecodeContainerAttachmentsKeepSingleNetworkBytes(t *testing.T) {
	f := makeStartFixture(t)
	raw, _ := json.Marshal(f.spec)
	if strings.Contains(string(raw), "Attachments") {
		t.Fatal("a single-network Task changed its recipe bytes", string(raw))
	}
	two, _ := twoNetworkFixture(t)
	if _, err := DecodeContainer(two.op.Target.Spec); err != nil {
		t.Fatal("two-network Task refused", err)
	}
	if got := two.spec.Networks(); len(got) != 2 || got[0].Bridge != "bridge" || got[1].Bridge != "bridge-b" {
		t.Fatal("attachments out of recipe order", got)
	}
	for name, mutate := range map[string]func(*ContainerSpec){
		"same bridge twice": func(s *ContainerSpec) { s.Attachments[0].Bridge = s.Bridge },
		"same address":      func(s *ContainerSpec) { s.Attachments[0].IPv4 = s.IPv4 },
		"no address":        func(s *ContainerSpec) { s.Attachments[0].IPv4 = netip.Addr{} },
		"no generation":     func(s *ContainerSpec) { s.Attachments[0].BridgeGeneration = 0 },
		"no bridge":         func(s *ContainerSpec) { s.Attachments[0].Bridge = "" },
		"foreign owner":     func(s *ContainerSpec) { s.Attachments[0].BridgeOwner = "not/an-owner" },
		"too many": func(s *ContainerSpec) {
			for i := len(s.Networks()); i <= MaxTaskNetworks; i++ {
				s.Attachments = append(s.Attachments, TaskAttachment{Bridge: "extra-" + string(rune('a'+i)), BridgeGeneration: 1, IPv4: netip.AddrFrom4([4]byte{203, 0, 113, byte(i)})})
			}
		},
	} {
		s := two.spec
		s.Attachments = append([]TaskAttachment(nil), two.spec.Attachments...)
		mutate(&s)
		raw, _ := json.Marshal(s)
		if _, err := DecodeContainer(string(raw)); err == nil {
			t.Fatal("invalid attachment accepted", name)
		}
	}
}

func TestOptionsCreateEveryAttachmentEndpointBeforeStart(t *testing.T) {
	f, b := twoNetworkFixture(t)
	d := DockerDriver{Engine: f.engine, Network: b}
	id, _ := f.engine.Identity("container", "task", f.op.Target)
	options, err := d.options(context.Background(), f.spec, id, "task", 1)
	if err != nil {
		t.Fatal(err)
	}
	endpoints := options.NetworkingConfig.EndpointsConfig
	if len(endpoints) != 2 || endpoints["fixture-network"].IPAMConfig.IPv4Address != f.spec.IPv4 || endpoints["fixture-network-b"].IPAMConfig.IPv4Address != netip.MustParseAddr("198.51.100.7") || options.HostConfig.NetworkMode != "fixture-network" {
		t.Fatal("create does not carry every attachment", endpoints, options.HostConfig.NetworkMode)
	}
	if len(b.acquired) != 2 {
		t.Fatal("every attachment needs its own Bridge pin", b.acquired)
	}
	outside := f.spec
	outside.Attachments = []TaskAttachment{{Bridge: "bridge-b", BridgeGeneration: 3, IPv4: netip.MustParseAddr("192.0.2.9")}}
	if _, err = d.options(context.Background(), outside, id, "task", 1); !errors.Is(err, network.ErrPolicy) {
		t.Fatal("address outside its own attachment's pool accepted", err)
	}
}

func TestMatchContainerRequiresEveryAttachment(t *testing.T) {
	f, b := twoNetworkFixture(t)
	d := DockerDriver{Engine: f.engine, Network: b}
	id, _ := f.engine.Identity("container", "task", f.op.Target)
	leases, err := d.inspectNetworks(context.Background(), f.spec, id)
	if err != nil {
		t.Fatal(err)
	}
	if !d.matchContainer(context.Background(), f.native, f.spec, id, leases, nil) {
		t.Fatal("original two-network container not matched")
	}
	if d.matchContainer(context.Background(), f.native, f.spec, id, leases[:1], nil) {
		t.Fatal("matched while holding only some attachment pins")
	}
	missing := f.native
	missing.NetworkSettings = &container.NetworkSettings{Networks: map[string]*dockernet.EndpointSettings{"fixture-bridge": f.native.NetworkSettings.Networks["fixture-bridge"]}}
	if d.matchContainer(context.Background(), missing, f.spec, id, leases, nil) {
		t.Fatal("container missing an attachment matched")
	}
	moved := *f.native.NetworkSettings.Networks["fixture-bridge-b"]
	moved.IPAMConfig = &dockernet.EndpointIPAMConfig{IPv4Address: netip.MustParseAddr("198.51.100.8")}
	wrong := f.native
	wrong.NetworkSettings = &container.NetworkSettings{Networks: map[string]*dockernet.EndpointSettings{"fixture-bridge": f.native.NetworkSettings.Networks["fixture-bridge"], "fixture-bridge-b": &moved}}
	if d.matchContainer(context.Background(), wrong, f.spec, id, leases, nil) {
		t.Fatal("attachment with another address matched")
	}
}

func TestReturnNetworksReturnsEveryPinPastAFailure(t *testing.T) {
	f, b := twoNetworkFixture(t)
	b.fail = "bridge"
	d := DockerDriver{Engine: f.engine, Network: b}
	if err := d.returnNetworks(f.spec, "workload/x"); err == nil {
		t.Fatal("stuck Bridge return reported success")
	}
	if len(b.returned) != 2 || b.returned[1] != "bridge-b" {
		t.Fatal("one stuck Bridge kept the others pinned", b.returned)
	}
}

func TestRoutesLeaveThroughTheirOwnAttachment(t *testing.T) {
	f, b := twoNetworkFixture(t)
	f.spec.Attachments[0].Routes = []ContainerRoute{{Destination: netip.MustParsePrefix("10.9.0.0/16"), Gateway: netip.MustParseAddr("198.51.100.1")}}
	specs := []network.BridgeSpec{b.leases["bridge"].Spec, b.leases["bridge-b"].Spec}
	if err := ValidateContainerRoutes(f.spec, specs...); err != nil {
		t.Fatal("route through the second network refused", err)
	}
	if all := f.spec.allRoutes(); len(all) != 1 || all[0].at != 1 {
		t.Fatal("route not tied to its attachment", all)
	}
	if err := ValidateContainerRoutes(f.spec, specs[0]); err == nil {
		t.Fatal("routes checked against only some attachments")
	}
	// The same route on the primary attachment has no gateway there.
	wrong := f.spec
	wrong.Routes, wrong.Attachments = f.spec.Attachments[0].Routes, []TaskAttachment{{Bridge: "bridge-b", BridgeGeneration: 3, IPv4: netip.MustParseAddr("198.51.100.7")}}
	if err := ValidateContainerRoutes(wrong, specs...); err == nil {
		t.Fatal("route accepted through another attachment's gateway")
	}
	over := f.spec
	over.Attachments = []TaskAttachment{{Bridge: "bridge-b", BridgeGeneration: 3, IPv4: netip.MustParseAddr("198.51.100.7"), Routes: []ContainerRoute{{Destination: netip.MustParsePrefix("192.0.0.0/16"), Gateway: netip.MustParseAddr("198.51.100.1")}}}}
	if err := ValidateContainerRoutes(over, specs...); err == nil {
		t.Fatal("route over another attachment's own pool accepted")
	}
}

// A created, not yet started container keys its extra endpoints by the
// network ID given at create; started ones by name (seen on sfed).
func TestTaskEndpointFindsCreatedEndpointsByNetworkID(t *testing.T) {
	l := network.BridgeLease{NetworkID: "id-b", NetworkName: "name-b"}
	created := &container.NetworkSettings{Networks: map[string]*dockernet.EndpointSettings{"id-b": {}}}
	started := &container.NetworkSettings{Networks: map[string]*dockernet.EndpointSettings{"name-b": {NetworkID: "id-b"}}}
	if taskEndpoint(created, l) == nil || taskEndpoint(started, l) == nil || taskEndpoint(&container.NetworkSettings{}, l) != nil || taskEndpoint(nil, l) != nil {
		t.Fatal("endpoint lookup by name or create ID")
	}
}
