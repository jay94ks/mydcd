// SPDX-License-Identifier: Apache-2.0

package network

import (
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
	"slices"
	"strings"

	"github.com/google/nftables/expr"
	"github.com/jay94ks/seafield/internal/reconcile"
	"golang.org/x/sys/unix"
)

func isolationPrefixes(known []TenantPrefix, tenant string, input []netip.Prefix) ([]netip.Prefix, error) {
	if len(input) > 4096 {
		return nil, ErrPolicy
	}
	out := slices.Clone(input)
	slices.SortFunc(out, func(a, b netip.Prefix) int { return strings.Compare(a.String(), b.String()) })
	out = slices.Compact(out)
	for _, prefix := range out {
		if prefix.IsValid() && prefix == prefix.Masked() && SharedServerPrefix(prefix) {
			continue // a server address, shared by every network on that server
		}
		if !prefix.IsValid() || prefix != prefix.Masked() || !packetAddress(prefix.Addr()) || !slices.ContainsFunc(known, func(p TenantPrefix) bool {
			return p.Tenant == tenant && p.Prefix.Bits() <= prefix.Bits() && p.Prefix.Contains(prefix.Addr())
		}) {
			return nil, ErrPolicy
		}
	}
	return out, nil
}

// Exact native target coverage, independent of current user permissions. The
// runtime separately verifies the original kernel-boot journal and real table.
func IsolationCoversBridge(s IsolationSpec, key string, target reconcile.Resource) bool {
	bridge, err := DecodeBridge(target.Spec)
	if err != nil || !target.Present || target.Generation == 0 || bridge.GatewayMode != ManagedGatewayMode || s.Owner != bridge.Owner {
		return false
	}
	device, err := BridgeDeviceName(s.Owner, key, target.Generation, sha256.Sum256([]byte(target.Spec)))
	if err != nil {
		return false
	}
	for _, binding := range s.Bridges {
		if binding.Device != device || !binding.Managed {
			continue
		}
		var prefixes []netip.Prefix
		for _, pool := range bridge.Pools {
			prefixes = append(prefixes, pool.Prefix)
		}
		prefixes, err := isolationPrefixes(s.Prefixes, binding.Tenant, prefixes)
		return err == nil && slices.Equal(prefixes, binding.Prefixes)
	}
	return false
}

type isolationInterfaceMatch func(expr.MetaKey, string) []expr.Any
type isolationAddressMatch func(netip.Prefix, bool) []expr.Any

func isolationReply() []expr.Any {
	mask := make([]byte, 4)
	binary.NativeEndian.PutUint32(mask, expr.CtStateBitESTABLISHED)
	return []expr.Any{
		&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: mask, Xor: make([]byte, 4)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: make([]byte, 4)},
		&expr.Ct{Key: expr.CtKeyDIRECTION, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1}},
		&expr.Verdict{Kind: expr.VerdictReturn},
	}
}

// This is reached only AFTER the original route exceptions and foreign CIDR
// drops. It grants neither internet egress nor arbitrary established traffic.
func isolationManagedTraffic(s IsolationSpec, bridge IsolationBridge, outgoing bool, iface isolationInterfaceMatch, address isolationAddressMatch) [][]expr.Any {
	var rules [][]expr.Any
	if outgoing {
		for _, peer := range s.Bridges {
			if peer.Tenant != bridge.Tenant {
				continue
			}
			for _, prefix := range peer.Prefixes {
				rule := append(iface(expr.MetaKeyOIFNAME, peer.Device), address(prefix, true)...)
				rules = append(rules, append(rule, &expr.Verdict{Kind: expr.VerdictReturn}))
			}
		}
		for _, peer := range s.Tunnels {
			if peer.Tenant != bridge.Tenant {
				continue
			}
			for _, prefix := range peer.Prefixes {
				rule := append(iface(expr.MetaKeyOIFNAME, peer.Device), address(prefix, true)...)
				rules = append(rules, append(rule, &expr.Verdict{Kind: expr.VerdictReturn}))
			}
		}
	} else {
		for _, peer := range s.Bridges {
			if peer.Tenant != bridge.Tenant {
				continue
			}
			for _, prefix := range peer.Prefixes {
				rule := append(iface(expr.MetaKeyIIFNAME, peer.Device), address(prefix, false)...)
				rules = append(rules, append(rule, &expr.Verdict{Kind: expr.VerdictReturn}))
			}
		}
		for _, peer := range s.Tunnels {
			if peer.Tenant != bridge.Tenant {
				continue
			}
			for _, prefix := range peer.Prefixes {
				rule := append(iface(expr.MetaKeyIIFNAME, peer.Device), address(prefix, false)...)
				rules = append(rules, append(rule, &expr.Verdict{Kind: expr.VerdictReturn}))
			}
		}
	}
	rules = append(rules, isolationReply(), []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}})
	return rules
}

// These run only in INPUT, where the kernel already selected a local address.
// No prefix-only return in FORWARD can route same-tenant traffic via an
// arbitrary underlay interface. The original source Bridge/pool is required.
func isolationLocalInputRules(s IsolationSpec, bridge IsolationBridge, iface isolationInterfaceMatch, address isolationAddressMatch) [][]expr.Any {
	var rules [][]expr.Any
	for _, source := range bridge.Prefixes {
		for _, peer := range s.Bridges {
			if peer.Tenant != bridge.Tenant {
				continue
			}
			for _, destination := range peer.Prefixes {
				if source.Addr().Is4() != destination.Addr().Is4() {
					continue
				}
				rule := append(iface(expr.MetaKeyIIFNAME, bridge.Device), address(source, false)...)
				rule = append(rule, address(destination, true)...)
				rules = append(rules, append(rule, &expr.Verdict{Kind: expr.VerdictReturn}))
			}
		}
	}
	return rules
}

// Kernel IPv6 address discovery only. No DHCP/RA service and no cross-Bridge
// forwarding exception: the caller pins the same output Bridge for FORWARD.
func isolationNeighborRules(bridge IsolationBridge, iface isolationInterfaceMatch, address isolationAddressMatch) [][]expr.Any {
	var destinations []netip.Prefix
	for _, prefix := range bridge.Prefixes {
		if prefix.Addr().Is6() {
			destinations = append(destinations, prefix)
		}
	}
	if len(destinations) == 0 {
		return nil
	}
	destinations = append(destinations, netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("ff02::1:ff00:0/104"))
	var rules [][]expr.Any
	for _, destination := range destinations {
		rule := iface(expr.MetaKeyIIFNAME, bridge.Device)
		rule = append(rule, address(destination, true)...)
		rule = append(rule,
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_ICMPV6}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 7, Len: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{255}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1}, &expr.Range{Op: expr.CmpOpEq, Register: 1, FromData: []byte{135}, ToData: []byte{136}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 1, Len: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0}},
			&expr.Verdict{Kind: expr.VerdictReturn})
		rules = append(rules, rule)
	}
	return rules
}
