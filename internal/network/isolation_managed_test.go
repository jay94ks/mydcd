// SPDX-License-Identifier: Apache-2.0

package network

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/google/nftables/expr"
	"github.com/jay94ks/seafield/internal/reconcile"
)

func managedIsolationFixture(t *testing.T) IsolationSpec {
	t.Helper()
	s := isolationFixture(t)
	for i := range s.Bridges {
		b := &s.Bridges[i]
		b.Managed = true
		for _, p := range s.Prefixes {
			if p.Tenant == b.Tenant && p.Prefix.String() != "10.3.0.0/24" {
				b.Prefixes = append(b.Prefixes, p.Prefix)
			}
		}
	}
	s.Tunnels = []IsolationTunnel{{Tenant: "first", Device: "mt2123456789ab", Prefixes: []netip.Prefix{netip.MustParsePrefix("10.3.0.0/24")}}}
	s, err := NormalizeIsolation(s)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestManagedIsolationOwnsExactBridgeAndTunnelSources(t *testing.T) {
	s := managedIsolationFixture(t)
	raw, _ := json.Marshal(s)
	for _, mutate := range []func(*IsolationSpec){
		func(s *IsolationSpec) { s.Bridges[0].Prefixes = nil },
		func(s *IsolationSpec) { s.Bridges[0].Prefixes[0] = netip.MustParsePrefix("10.2.0.0/24") },
		func(s *IsolationSpec) { s.Tunnels[0].Tenant = "second" },
		func(s *IsolationSpec) { s.Tunnels[0].Device = s.Routes[0].Device },
		func(s *IsolationSpec) {
			s.Tunnels = append(s.Tunnels, IsolationTunnel{Tenant: "second", Device: s.Tunnels[0].Device, Prefixes: s.Bridges[1].Prefixes})
		},
	} {
		var bad IsolationSpec
		if err := json.Unmarshal(raw, &bad); err != nil {
			t.Fatal(err)
		}
		mutate(&bad)
		if _, err := NormalizeIsolation(bad); err == nil {
			t.Fatal("foreign, missing or conflicting native provenance accepted")
		}
	}
	clone, err := NormalizeIsolation(s)
	if err != nil {
		t.Fatal(err)
	}
	clone.Bridges[0].Prefixes[0] = netip.MustParsePrefix("10.9.0.0/24")
	clone.Tunnels[0].Prefixes[0] = clone.Bridges[0].Prefixes[0]
	after, _ := json.Marshal(s)
	if !bytes.Equal(raw, after) {
		t.Fatal("normalization retained mutable Bridge/TUN prefix aliases")
	}
}

func TestManagedIsolationDropsUnknownTrafficAndRequiresExactInterfaceBeforeReply(t *testing.T) {
	s := managedIsolationFixture(t)
	firewall := isolationRules(s)
	for index := range s.Bridges {
		for _, direction := range []string{"in_", "out_", "gateway_"} {
			rules := firewall.rules[fmtIsolationChain(direction, index)]
			if len(rules) == 0 {
				t.Fatal("managed direction missing", direction)
			}
			last := rules[len(rules)-1].Exprs
			if len(last) != 1 || last[0].(*expr.Verdict).Kind != expr.VerdictDrop {
				t.Fatal("unknown traffic is not denied", direction)
			}
			seenForeignDrop, seenReply := false, false
			for _, rule := range rules[:len(rules)-1] {
				verdict := rule.Exprs[len(rule.Exprs)-1].(*expr.Verdict)
				if verdict.Kind == expr.VerdictDrop {
					seenForeignDrop = true
				}
				state, reply := false, false
				for pos, expression := range rule.Exprs {
					ct, ok := expression.(*expr.Ct)
					if !ok {
						continue
					}
					if ct.Key == expr.CtKeySTATE {
						mask, ok := rule.Exprs[pos+1].(*expr.Bitwise)
						state = ok && binary.NativeEndian.Uint32(mask.Mask) == expr.CtStateBitESTABLISHED
					}
					if ct.Key == expr.CtKeyDIRECTION {
						cmp, ok := rule.Exprs[pos+1].(*expr.Cmp)
						reply = ok && cmp.Op == expr.CmpOpEq && bytes.Equal(cmp.Data, []byte{1})
					}
				}
				if state || reply {
					if !state || !reply || direction != "gateway_" && !seenForeignDrop {
						t.Fatal("reply bypassed foreign drop/state/direction", direction)
					}
					seenReply = true
				} else if verdict.Kind == expr.VerdictReturn {
					meta, ok := rule.Exprs[0].(*expr.Meta)
					if !ok || meta.Key != expr.MetaKeyIIFNAME && meta.Key != expr.MetaKeyOIFNAME {
						t.Fatal("prefix-only forwarding bypasses interface authority", direction)
					}
				}
			}
			if !seenReply {
				t.Fatal("normal original connection replies cannot return", direction)
			}
		}
		for _, direction := range []string{"src_", "dst_"} {
			rules := firewall.rules[fmtIsolationChain(direction, index)]
			last := rules[len(rules)-1].Exprs
			if len(last) != 1 || last[0].(*expr.Verdict).Kind != expr.VerdictDrop {
				t.Fatal("Bridge address spoof/misdirection lacks final drop")
			}
		}
	}
}

func TestManagedBridgeProtectionCoversOnlyOriginalNativeSpecAndGeneration(t *testing.T) {
	s := managedIsolationFixture(t)
	p := pool("pool", "10.1.0.0/24")
	p.Owner = s.Owner
	bridge := BridgeSpec{Schema: 1, Network: p.Network, Owner: s.Owner, MTU: p.MTU, Pools: []Pool{p}, GatewayMode: ManagedGatewayMode}
	raw, _ := json.Marshal(bridge)
	target := reconcile.Resource{Generation: 7, Present: true, Spec: string(raw)}
	device, err := BridgeDeviceName(s.Owner, "original", target.Generation, sha256.Sum256(raw))
	if err != nil {
		t.Fatal(err)
	}
	s.Bridges[0].Device = device
	s.Routes = nil
	s, err = NormalizeIsolation(s)
	if err != nil || !IsolationCoversBridge(s, "original", target) {
		t.Fatal("original protected Bridge not covered", err)
	}
	if IsolationCoversBridge(s, "foreign", target) {
		t.Fatal("different source key borrowed protection")
	}
	changed := target
	changed.Generation++
	if IsolationCoversBridge(s, "original", changed) {
		t.Fatal("new native generation borrowed old protection")
	}
	for i := range s.Bridges {
		if s.Bridges[i].Device == device {
			s.Bridges[i].Managed = false
		}
	}
	if IsolationCoversBridge(s, "original", target) {
		t.Fatal("legacy CIDR deny mistaken for managed default deny")
	}
}

func TestManagedNeighborDiscoveryKeepsOnlyScopedNSNAWithHopLimit255(t *testing.T) {
	s := managedIsolationFixture(t)
	f := isolationRules(s)
	checked := 0
	for _, rule := range f.rules["forward"] {
		nd, hop, code := false, false, false
		for n, expression := range rule.Exprs {
			payload, ok := expression.(*expr.Payload)
			if !ok || n+1 == len(rule.Exprs) {
				continue
			}
			if payload.Base == expr.PayloadBaseNetworkHeader && payload.Offset == 7 {
				cmp, ok := rule.Exprs[n+1].(*expr.Cmp)
				hop = ok && bytes.Equal(cmp.Data, []byte{255})
			}
			if payload.Base == expr.PayloadBaseTransportHeader && payload.Offset == 0 {
				rangeMatch, ok := rule.Exprs[n+1].(*expr.Range)
				nd = ok && bytes.Equal(rangeMatch.FromData, []byte{135}) && bytes.Equal(rangeMatch.ToData, []byte{136})
			}
			if payload.Base == expr.PayloadBaseTransportHeader && payload.Offset == 1 {
				cmp, ok := rule.Exprs[n+1].(*expr.Cmp)
				code = ok && bytes.Equal(cmp.Data, []byte{0})
			}
		}
		if !nd {
			continue
		}
		if !hop || !code || len(rule.Exprs) < 5 {
			t.Fatal("neighbor exception omitted hop-limit/code")
		}
		out, outOK := rule.Exprs[0].(*expr.Meta)
		in, inOK := rule.Exprs[2].(*expr.Meta)
		if !outOK || !inOK || out.Key != expr.MetaKeyOIFNAME || in.Key != expr.MetaKeyIIFNAME || !bytes.Equal(rule.Exprs[1].(*expr.Cmp).Data, rule.Exprs[3].(*expr.Cmp).Data) {
			t.Fatal("neighbor exception permits cross-interface forwarding")
		}
		checked++
	}
	if checked != 3 { // Local IPv6 pool, link-local and solicited-node multicast.
		t.Fatal("missing or widened IPv6 discovery destinations", checked)
	}
}

// A lone member's TUN has no routes: it is isolated with no allowed prefix,
// and its spec round-trips.
func TestManagedIsolationAcceptsALoneTunnelWithNoRoutes(t *testing.T) {
	s := managedIsolationFixture(t)
	s.Tunnels[0].Prefixes = []netip.Prefix{}
	s, err := NormalizeIsolation(s)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(s)
	if _, err = DecodeIsolation(string(raw)); err != nil {
		t.Fatal(err)
	}
	for index := range s.Bridges {
		for _, rule := range isolationRules(s).rules[fmtIsolationChain("out_", index)] {
			for _, e := range rule.Exprs {
				if m, ok := e.(*expr.Meta); ok && m.Key == expr.MetaKeyOIFNAME {
					continue
				}
				if c, ok := e.(*expr.Cmp); ok && bytes.HasPrefix(c.Data, []byte(s.Tunnels[0].Device)) {
					t.Fatal("a lone TUN got an allow rule")
				}
			}
		}
	}
}

// A TUN's route set changes in place (a server joins the system network):
// until the change settles its old and new route sets name the same device,
// and both stay allowed instead of refusing the whole isolation spec.
func TestManagedIsolationMergesOneTunnelsOldAndNewRoutes(t *testing.T) {
	s := managedIsolationFixture(t)
	s.Prefixes = append(s.Prefixes, TenantPrefix{Tenant: "first", Prefix: netip.MustParsePrefix("10.3.1.0/24")})
	old := s.Tunnels[0]
	next := IsolationTunnel{Tenant: old.Tenant, Device: old.Device, Prefixes: []netip.Prefix{netip.MustParsePrefix("10.3.0.0/24"), netip.MustParsePrefix("10.3.1.0/24")}}
	s.Tunnels = append(s.Tunnels, next)
	got, err := NormalizeIsolation(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Tunnels) != 1 || len(got.Tunnels[0].Prefixes) != 2 {
		t.Fatalf("tunnels %+v", got.Tunnels)
	}
	raw, _ := json.Marshal(got)
	if _, err = DecodeIsolation(string(raw)); err != nil {
		t.Fatal(err)
	}
	// one device under two tenants is still refused
	s.Tunnels[1].Tenant = "second"
	s.Prefixes = append(s.Prefixes, TenantPrefix{Tenant: "second", Prefix: netip.MustParsePrefix("10.4.0.0/24")})
	s.Tunnels[1].Prefixes = []netip.Prefix{netip.MustParsePrefix("10.4.0.0/24")}
	if _, err = NormalizeIsolation(s); err == nil {
		t.Fatal("one TUN device under two tenants accepted")
	}
}
