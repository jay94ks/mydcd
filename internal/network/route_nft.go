// SPDX-License-Identifier: Apache-2.0

package network

import (
	"encoding/binary"
	"net/netip"

	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// routePacketRules uses the existing owned TUN from/to chains and their native
// create/read-back/remove boundary. It is a port filter, not a flow grant.
func routePacketRules(policy PacketRoutePolicy, localPacket bool) [][]expr.Any {
	source, destination, destinationPort := policy.direction(localPacket)
	family := byte(unix.NFPROTO_IPV6)
	if source.Addr().Is4() {
		family = unix.NFPROTO_IPV4
	}
	var rules [][]expr.Any
	for _, ports := range policy.Ports {
		expressions := []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{family}},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{policy.Protocol}},
		}
		expressions = append(expressions, routePrefixExpressions(source, true)...)
		expressions = append(expressions, routePrefixExpressions(destination, false)...)
		offset := uint32(0)
		if destinationPort {
			offset = 2
		}
		expressions = append(expressions, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: offset, Len: 2})
		first, last := make([]byte, 2), make([]byte, 2)
		binary.BigEndian.PutUint16(first, ports.First)
		binary.BigEndian.PutUint16(last, ports.Last)
		if ports.First == ports.Last {
			expressions = append(expressions, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: first})
		} else {
			expressions = append(expressions, &expr.Range{Op: expr.CmpOpEq, Register: 1, FromData: first, ToData: last})
		}
		expressions = append(expressions, &expr.Verdict{Kind: expr.VerdictReturn})
		rules = append(rules, expressions)
	}
	return rules
}

func routePrefixExpressions(prefix netip.Prefix, source bool) []expr.Any {
	offset := uint32(8)
	if prefix.Addr().Is4() {
		offset = 12
	}
	address := prefix.Addr().AsSlice()
	if !source {
		offset += uint32(len(address))
	}
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: uint32(len(address))},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: uint32(len(address)), Mask: []byte(prefixNet(prefix).Mask), Xor: make([]byte, len(address))},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: address},
	}
}
