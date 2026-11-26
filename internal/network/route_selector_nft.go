// SPDX-License-Identifier: Apache-2.0

package network

import (
	"encoding/binary"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func selectorInterface(name string) []expr.Any {
	raw := make([]byte, 16)
	copy(raw, name)
	return []expr.Any{&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: raw}}
}

func selectorCTMark(mark uint32) []expr.Any {
	raw := make([]byte, 4)
	binary.NativeEndian.PutUint32(raw, mark)
	return []expr.Any{&expr.Ct{Key: expr.CtKeyMARK, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: raw}}
}

func selectorSetMark(mark uint32, packet bool) []expr.Any {
	raw := make([]byte, 4)
	binary.NativeEndian.PutUint32(raw, mark)
	out := []expr.Any{&expr.Immediate{Register: 1, Data: raw}, &expr.Ct{Key: expr.CtKeyMARK, Register: 1, SourceRegister: true}}
	if packet {
		out = append(out, &expr.Meta{Key: expr.MetaKeyMARK, Register: 1, SourceRegister: true})
	}
	return append(out, &expr.Verdict{Kind: expr.VerdictReturn})
}

func selectorNewConnection(protocol uint8) []expr.Any {
	newState := make([]byte, 4)
	binary.NativeEndian.PutUint32(newState, expr.CtStateBitNEW)
	out := []expr.Any{&expr.Ct{Key: expr.CtKeySTATE, Register: 1}, &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: newState, Xor: make([]byte, 4)}, &expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: make([]byte, 4)}}
	if protocol == 6 {
		out = append(out, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 13, Len: 1}, &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1, Mask: []byte{0x17}, Xor: []byte{0}}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{2}})
	}
	return out
}

// Selection happens after conntrack and before FIB lookup. It does not grant
// flow admission: PacketPlane still requires both original durable A3 pins.
func addRouteSelectorFirewallMode(f *tunnelFirewall, s TunnelSpec, id tunnelIdentity, accepting bool) {
	accept := nftables.ChainPolicyAccept
	chain := &nftables.Chain{Name: "select", Table: f.table, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityMangle, Policy: &accept}
	f.chains = append(f.chains, chain)
	add := func(expressions []expr.Any) {
		f.rules[chain.Name] = append(f.rules[chain.Name], &nftables.Rule{Table: f.table, Chain: chain, Exprs: expressions, UserData: []byte(id.alias)})
	}
	mark := routeMark(s)
	for _, match := range routePacketRules(*s.RoutePolicy, true) {
		// Existing local requests/replies preserve their exact original policy.
		rule := append(selectorInterface(s.RoutePolicy.Bridge), match[:len(match)-1]...)
		rule = append(rule, selectorCTMark(mark)...)
		add(append(rule, selectorSetMark(mark, true)...))
		if accepting && s.RoutePolicy.LocalSource {
			rule = append(selectorInterface(s.RoutePolicy.Bridge), match[:len(match)-1]...)
			rule = append(rule, selectorCTMark(0)...)
			rule = append(rule, selectorNewConnection(s.RoutePolicy.Protocol)...)
			add(append(rule, selectorSetMark(mark, true)...))
		}
	}
	if accepting {
		for _, match := range routePacketRules(*s.RoutePolicy, false) {
			for _, original := range []uint32{0, mark} {
				rule := append(selectorInterface(id.name), match[:len(match)-1]...)
				rule = append(rule, selectorCTMark(original)...)
				// Forward addresses do not match this Bridge-specific RPDB rule,
				// so main still delivers to the local Bridge. IPv4 source validation
				// reverses those addresses and needs this SAME mark to find TUN.
				add(append(rule, selectorSetMark(mark, true)...))
			}
		}
	}
	add(append(selectorInterface(id.name), &expr.Verdict{Kind: expr.VerdictDrop}))
}
