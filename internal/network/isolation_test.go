// SPDX-License-Identifier: Apache-2.0

package network

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"slices"
	"testing"

	"github.com/google/nftables/expr"
	"github.com/jay94ks/mydcd/internal/engine"
)

func isolationFixture(t *testing.T) IsolationSpec {
	t.Helper()
	p := PacketRoutePolicy{Source: netip.MustParsePrefix("10.1.0.0/24"), Destination: netip.MustParsePrefix("10.2.0.0/24"), LocalSource: true, Protocol: 6, Ports: []RoutePortRange{{First: 3306, Last: 3306}}, Bridge: "md0123456789ab"}
	spec, err := NormalizeIsolation(IsolationSpec{Schema: 1, Owner: engine.Owner([32]byte{1}, [32]byte{2}), Prefixes: []TenantPrefix{{"first", p.Source}, {"second", p.Destination}, {"first", netip.MustParsePrefix("10.3.0.0/24")}, {"second", netip.MustParsePrefix("fd00:2::/64")}}, Bridges: []IsolationBridge{{Tenant: "first", Device: p.Bridge}, {Tenant: "second", Device: "md1123456789ab"}}, Routes: []IsolationRoute{{Device: "mt0123456789ab", Policy: p}}})
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func TestIsolationNormalizationOwnsCanonicalSourcesAndRejectsTenantAlias(t *testing.T) {
	spec := isolationFixture(t)
	input := spec
	input.Prefixes = append(slices.Clone(spec.Prefixes), spec.Prefixes[0])
	input.Bridges = append(slices.Clone(spec.Bridges), spec.Bridges[0])
	slices.Reverse(input.Prefixes)
	slices.Reverse(input.Bridges)
	normalized, err := NormalizeIsolation(input)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(spec)
	b, _ := json.Marshal(normalized)
	if !bytes.Equal(a, b) {
		t.Fatal("equivalent committed sources produced different native policy")
	}
	decoded, err := DecodeIsolation(string(b))
	if err != nil {
		t.Fatal(err)
	}
	decoded.Routes[0].Policy.Ports[0].Last++
	still, _ := json.Marshal(spec)
	if !bytes.Equal(a, still) {
		t.Fatal("native policy retained caller's mutable ports")
	}
	for _, mutate := range []func(*IsolationSpec){
		func(s *IsolationSpec) { s.Schema = 2 },
		func(s *IsolationSpec) { s.Owner = "owner" },
		func(s *IsolationSpec) {
			s.Prefixes = append(s.Prefixes, TenantPrefix{"other", netip.MustParsePrefix("10.1.0.0/25")})
		},
		func(s *IsolationSpec) {
			s.Bridges = append(s.Bridges, IsolationBridge{Tenant: "other", Device: s.Bridges[0].Device})
		},
		func(s *IsolationSpec) { s.Routes[0].Policy.Bridge = "mdffffffffffff" },
		func(s *IsolationSpec) { s.Routes[0].Policy.LocalSource = false },
		func(s *IsolationSpec) { s.Routes = append(s.Routes, s.Routes[0]) },
	} {
		raw, _ := json.Marshal(spec)
		var candidate IsolationSpec
		_ = json.Unmarshal(raw, &candidate)
		mutate(&candidate)
		if _, err := NormalizeIsolation(candidate); err == nil {
			t.Fatal("invalid/foreign source was accepted")
		}
	}
	if _, err := DecodeIsolation(string(a) + " "); err == nil {
		t.Fatal("noncanonical journal policy accepted")
	}
}

func TestIsolationNativeRulesBindRouteDeviceDirectionPortAndCrossTenantDrop(t *testing.T) {
	spec := isolationFixture(t)
	f := isolationRules(spec)
	if len(f.chains) != 2+2*len(spec.Bridges)+2 {
		t.Fatal("missing owner base/Bridge/host-input tenant chains")
	}
	for i, bridge := range spec.Bridges {
		for _, out := range []bool{true, false} {
			prefix := "in_"
			if out {
				prefix = "out_"
			}
			rules := f.rules[fmtIsolationChain(prefix, i)]
			drops, returns, exceptions := 0, 0, 0
			for _, rule := range rules {
				last, ok := rule.Exprs[len(rule.Exprs)-1].(*expr.Verdict)
				if !ok {
					t.Fatal("native isolation rule has no terminal verdict")
				}
				if last.Kind == expr.VerdictDrop {
					drops++
				}
				if len(rule.Exprs) == 1 && last.Kind == expr.VerdictReturn {
					returns++
				}
				if len(rule.Exprs) > 1 && last.Kind == expr.VerdictReturn {
					exceptions++
					meta, ok := rule.Exprs[0].(*expr.Meta)
					wanted := expr.MetaKeyIIFNAME
					if out {
						wanted = expr.MetaKeyOIFNAME
					}
					if !ok || meta.Key != wanted {
						t.Fatal("route exception omitted its exact native direction")
					}
					device := rule.Exprs[1].(*expr.Cmp)
					if string(bytes.TrimRight(device.Data, "\x00")) != spec.Routes[0].Device {
						t.Fatal("exception allowed an arbitrary interface")
					}
					port := false
					for _, expression := range rule.Exprs {
						if p, ok := expression.(*expr.Payload); ok && p.Base == expr.PayloadBaseTransportHeader {
							port = true
						}
					}
					if !port {
						t.Fatal("route exception omitted approved service port")
					}
				}
			}
			foreign := 0
			for _, p := range spec.Prefixes {
				if p.Tenant != bridge.Tenant {
					foreign++
				}
			}
			if drops != foreign || returns != 1 {
				t.Fatal("foreign CIDR default drop or same-tenant return missing")
			}
			wantedExceptions := 0
			if bridge.Device == spec.Routes[0].Policy.Bridge {
				wantedExceptions = len(spec.Routes[0].Policy.Ports)
			}
			if exceptions != wantedExceptions {
				t.Fatal("unapproved Bridge acquired a route exception")
			}
		}
	}
	// Input and forward are protected; this cross-tenant policy intentionally
	// does not replace system/Ingress host-output authorization.
	for _, chain := range f.chains {
		if chain.Name == "output" {
			t.Fatal("isolation added an unrelated host-output policy")
		}
	}
}
