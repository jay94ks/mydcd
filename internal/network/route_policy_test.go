// SPDX-License-Identifier: Apache-2.0

package network

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/google/nftables/expr"
)

func routeTunnelSpec(source bool) TunnelSpec {
	policy := &PacketRoutePolicy{Source: netip.MustParsePrefix("10.1.0.0/24"), Destination: netip.MustParsePrefix("10.2.0.0/24"), LocalSource: source, Protocol: 6, Ports: []RoutePortRange{{First: 3306, Last: 3306}, {First: 8000, Last: 8010}}}
	remote := policy.Source
	if source {
		remote = policy.Destination
	}
	return TunnelSpec{Schema: 1, Owner: "owner", Network: "route/frontend/database", MTU: 1280, RouteMetric: 100, Routes: []netip.Prefix{remote}, RoutePolicy: policy}
}

func TestRouteTunnelSpecPinsSideRemotePrefixPortsAndOwnsPolicy(t *testing.T) {
	decode := func(spec TunnelSpec) error {
		raw, _ := json.Marshal(spec)
		_, err := DecodeTunnel(string(raw))
		return err
	}
	for _, source := range []bool{false, true} {
		spec := routeTunnelSpec(source)
		if err := decode(spec); err != nil {
			t.Fatal("valid explicit native policy rejected", source, err)
		}
		for label, mutate := range map[string]func(*TunnelSpec){
			"wrong-side":           func(s *TunnelSpec) { s.RoutePolicy.LocalSource = !source },
			"wrong-remote":         func(s *TunnelSpec) { s.Routes[0] = netip.MustParsePrefix("10.3.0.0/24") },
			"host-address":         func(s *TunnelSpec) { s.Addresses = []netip.Prefix{netip.MustParsePrefix("10.4.0.1/32")} },
			"overlap":              func(s *TunnelSpec) { s.RoutePolicy.Source = s.RoutePolicy.Destination },
			"unsupported-protocol": func(s *TunnelSpec) { s.RoutePolicy.Protocol = 1 },
			"port-zero":            func(s *TunnelSpec) { s.RoutePolicy.Ports[0].First = 0 },
			"port-overlap":         func(s *TunnelSpec) { s.RoutePolicy.Ports[1].First = 3306 },
		} {
			bad := spec.Clone()
			mutate(&bad)
			if decode(bad) == nil {
				t.Fatal("accepted ambiguous native route policy", label, source)
			}
		}
		before, _ := json.Marshal(spec)
		copy := spec.Clone()
		copy.RoutePolicy.Ports[0].Last++
		copy.Routes[0] = netip.MustParsePrefix("10.9.0.0/24")
		after, _ := json.Marshal(spec)
		if !bytes.Equal(before, after) {
			t.Fatal("owned route lifetime aliased caller policy")
		}
	}
	legacy := routeTunnelSpec(true)
	legacy.RoutePolicy = nil
	raw, _ := json.Marshal(legacy)
	if bytes.Contains(raw, []byte("RoutePolicy")) {
		t.Fatal("ordinary schema1 native bytes gained an empty field")
	}
}

func TestRouteNativeFilterAndPacketBoundaryUseSameDirectionAndPort(t *testing.T) {
	forward := transportPacket(4, 6)
	reply := append([]byte(nil), forward...)
	copy(reply[12:16], forward[16:20])
	copy(reply[16:20], forward[12:16])
	copy(reply[20:22], forward[22:24])
	copy(reply[22:24], forward[20:22])
	for _, source := range []bool{false, true} {
		spec := routeTunnelSpec(source)
		firewall := tunnelRules(spec, tunnelIdentity{name: "owned-tun", alias: "owned-alias", table: "owned-table"})
		for _, localPacket := range []bool{false, true} {
			packet, wrong := forward, reply
			if source != localPacket {
				packet, wrong = reply, forward
			}
			if !spec.RoutePolicy.allows(localPacket, packet) || spec.RoutePolicy.allows(localPacket, wrong) {
				t.Fatal("native side admitted the opposite direction", source, localPacket)
			}
			chain := "from"
			if localPacket {
				chain = "to"
			}
			rules := firewall.rules[chain]
			if len(rules) != 3 {
				t.Fatal("missing per-range rules or final deny", chain)
			}
			last, ok := rules[len(rules)-1].Exprs[0].(*expr.Verdict)
			if !ok || last.Kind != expr.VerdictDrop {
				t.Fatal("native route chain did not end in drop")
			}
			for _, rule := range rules[:len(rules)-1] {
				if string(rule.UserData) != "owned-alias" {
					t.Fatal("native rule lost original identity")
				}
				foundPort := false
				for _, expression := range rule.Exprs {
					if payload, ok := expression.(*expr.Payload); ok && payload.Base == expr.PayloadBaseTransportHeader {
						want := uint32(0)
						if source == localPacket {
							want = 2
						}
						if payload.Offset != want || payload.Len != 2 {
							t.Fatal("native rule selected the wrong port", source, localPacket)
						}
						foundPort = true
					}
				}
				if !foundPort {
					t.Fatal("native rule omitted the transport port")
				}
			}
		}
	}
}

type deniedRouteIO struct{}

func (deniedRouteIO) Read([]byte) (int, error)        { panic("route gate validation must precede IO") }
func (deniedRouteIO) Write([]byte) (int, error)       { panic("route gate validation must precede IO") }
func (deniedRouteIO) SetReadDeadline(time.Time) error { panic("route gate validation must precede IO") }
func (deniedRouteIO) SetWriteDeadline(time.Time) error {
	panic("route gate validation must precede IO")
}

type routeGateModel struct {
	allow bool
	calls int
}

func (g *routeGateModel) Allows([32]byte, []byte) bool { g.calls++; return g.allow }
func (g *routeGateModel) PacketBinding([32]byte, []byte) (PacketBinding, bool) {
	return PacketBinding{}, false
}

func TestRoutePacketPlaneRequiresOriginalFlowGateAndRevokesMissingGate(t *testing.T) {
	spec := routeTunnelSpec(true)
	if plane, err := NewPacketPlane(t.Context(), [32]byte{1}, [16]byte{2}, spec, deniedRouteIO{}, PacketLimits{QueuePackets: 1, QueueBytes: 1280}, PacketPlan{}); !errors.Is(err, ErrPolicy) || plane != nil {
		t.Fatal("port policy started a packet plane without coordinated flow pins", err)
	}
	// A model plan exercises the product read-only admission/revocation path.
	// It starts no worker, native IO, socket or peer authentication.
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	plane := &PacketPlane{ctx: ctx, cancel: cancel, spec: spec}
	gate := &routeGateModel{allow: true}
	plane.SetPlan(PacketPlan{Gate: gate})
	packet := transportPacket(4, 6)
	if !plane.permitted(plane.plan.Load(), [32]byte{1}, true, packet) || gate.calls != 1 {
		t.Fatal("approved packet skipped its original flow gate")
	}
	bad := append([]byte(nil), packet...)
	bad[23]++
	if plane.permitted(plane.plan.Load(), [32]byte{1}, true, bad) || gate.calls != 1 {
		t.Fatal("unapproved port reached the flow owner")
	}
	gate.allow = false
	if plane.permitted(plane.plan.Load(), [32]byte{1}, true, packet) {
		t.Fatal("flow revocation continued forwarding")
	}
	plane.SetPlan(PacketPlan{})
	if !errors.Is(plane.Err(), ErrPolicy) || ctx.Err() == nil || plane.permitted(plane.plan.Load(), [32]byte{1}, true, packet) {
		t.Fatal("missing gate left a route plane serving")
	}
}
