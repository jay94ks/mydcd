// SPDX-License-Identifier: Apache-2.0

package network

import (
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
)

// Endpoint is compiled from committed objects, never learned from a packet.
type Endpoint struct {
	Owner       [32]byte
	Network, ID [16]byte
	Address     netip.Addr
}

func NetworkID(cluster [32]byte, name string) [16]byte {
	b := append([]byte("sfc-network-1\x00"), cluster[:]...)
	b = append(b, []byte(name)...)
	h := sha256.Sum256(b)
	return [16]byte(h[:16])
}
func EndpointID(cluster [32]byte, network, owner, key string, generation uint64, address netip.Addr) [16]byte {
	b := append([]byte("sfc-endpoint-1\x00"), cluster[:]...)
	for _, part := range []string{network, owner, key, address.String()} {
		b = binary.LittleEndian.AppendUint32(b, uint32(len(part)))
		b = append(b, part...)
	}
	b = binary.LittleEndian.AppendUint64(b, generation)
	h := sha256.Sum256(b)
	return [16]byte(h[:16])
}

type PacketPolicy struct{ byAddress map[netip.Addr]Endpoint }

func NewPacketPolicy(endpoints []Endpoint) (PacketPolicy, error) {
	p := PacketPolicy{byAddress: make(map[netip.Addr]Endpoint, len(endpoints))}
	ids := map[[16]byte]bool{}
	for _, e := range endpoints {
		if !packetAddress(e.Address) || e.Owner == [32]byte{} || e.Network == [16]byte{} || e.ID == [16]byte{} || ids[e.ID] {
			return PacketPolicy{}, ErrPolicy
		}
		if _, exists := p.byAddress[e.Address]; exists {
			return PacketPolicy{}, ErrPolicy
		}
		p.byAddress[e.Address], ids[e.ID] = e, true
	}
	return p, nil
}
func packetAddress(a netip.Addr) bool {
	return a.IsValid() && !a.Is4In6() && a.Zone() == "" && !a.IsUnspecified() && !a.IsMulticast() && !a.IsLoopback() && !a.IsLinkLocalUnicast() && a != netip.MustParseAddr("255.255.255.255")
}

// PacketAddresses validates the complete IP envelope. Source routing cannot
// substitute an unapproved ultimate destination after endpoint admission.
func PacketAddresses(b []byte) (netip.Addr, netip.Addr, error) {
	invalid := func() (netip.Addr, netip.Addr, error) { return netip.Addr{}, netip.Addr{}, ErrPolicy }
	if len(b) < 20 {
		return invalid()
	}
	var src, dst netip.Addr
	switch b[0] >> 4 {
	case 4:
		h := int(b[0]&15) * 4
		if h < 20 || h > len(b) || int(binary.BigEndian.Uint16(b[2:4])) != len(b) {
			return invalid()
		}
		for i := 20; i < h; {
			kind := b[i]
			if kind == 0 {
				break
			}
			if kind == 1 {
				i++
				continue
			}
			if i+2 > h || b[i+1] < 2 || i+int(b[i+1]) > h || kind == 131 || kind == 137 {
				return invalid()
			}
			i += int(b[i+1])
		}
		src, dst = netip.AddrFrom4([4]byte(b[12:16])), netip.AddrFrom4([4]byte(b[16:20]))
	case 6:
		if len(b) < 40 || int(binary.BigEndian.Uint16(b[4:6]))+40 != len(b) {
			return invalid()
		}
		src, dst = netip.AddrFrom16([16]byte(b[8:24])), netip.AddrFrom16([16]byte(b[24:40]))
		next, offset := b[6], 40
		for {
			if next == 43 {
				return invalid()
			}
			if next != 0 && next != 60 && next != 44 && next != 51 {
				break
			}
			if offset+8 > len(b) {
				return invalid()
			}
			n := (int(b[offset+1]) + 1) * 8
			if next == 51 {
				n = (int(b[offset+1]) + 2) * 4
			}
			if next == 44 {
				n = 8
				// Non-initial fragments contain no parseable upper header.
				// A routing header is forbidden even as fragment Next Header.
				if b[offset] != 6 && b[offset] != 17 && b[offset] != 58 && b[offset] != 50 && b[offset] != 59 {
					return invalid()
				}
				if binary.BigEndian.Uint16(b[offset+2:offset+4])&0xfff8 != 0 {
					break
				}
			}
			if offset+n > len(b) {
				return invalid()
			}
			next, offset = b[offset], offset+n
		}
	default:
		return invalid()
	}
	if !packetAddress(src) || !packetAddress(dst) {
		return invalid()
	}
	return src, dst, nil
}

func (p PacketPolicy) Outbound(local [32]byte, network [16]byte, mtu int, packet []byte) (Endpoint, error) {
	return p.outbound(local, network, mtu, packet, false)
}

// LocalRoute is only for two tenant route owners on this exact node. Ordinary
// same-tenant PacketPolicy admission still rejects a local destination.
func (p PacketPolicy) LocalRoute(local [32]byte, network [16]byte, mtu int, packet []byte) (Endpoint, error) {
	return p.outbound(local, network, mtu, packet, true)
}

func (p PacketPolicy) outbound(local [32]byte, network [16]byte, mtu int, packet []byte, relay bool) (Endpoint, error) {
	src, dst, err := PacketAddresses(packet)
	a, source := p.byAddress[src]
	b, target := p.byAddress[dst]
	if err != nil || mtu < 1280 || len(packet) > mtu || !source || !target || a.Owner != local || (b.Owner == local) != relay || a.Network != network || b.Network != network {
		return Endpoint{}, ErrPolicy
	}
	return b, nil
}
func (p PacketPolicy) Inbound(local, sender [32]byte, network, endpoint [16]byte, mtu int, packet []byte) error {
	return p.inbound(local, sender, network, endpoint, mtu, packet, false)
}

func (p PacketPolicy) LocalInbound(local [32]byte, network, endpoint [16]byte, mtu int, packet []byte) error {
	return p.inbound(local, local, network, endpoint, mtu, packet, true)
}

func (p PacketPolicy) inbound(local, sender [32]byte, network, endpoint [16]byte, mtu int, packet []byte, relay bool) error {
	src, dst, err := PacketAddresses(packet)
	a, source := p.byAddress[src]
	b, target := p.byAddress[dst]
	if err != nil || mtu < 1280 || len(packet) > mtu || !source || !target || (sender == local) != relay || a.Owner != sender || b.Owner != local || a.Network != network || b.Network != network || b.ID != endpoint {
		return ErrPolicy
	}
	return nil
}
