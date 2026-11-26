// SPDX-License-Identifier: Apache-2.0

package network

import (
	"encoding/binary"
	"net/netip"
)

// TransportPacket is a validated TCP/UDP tuple, not endpoint authentication or
// conntrack state. Cross-tenant policy never guesses ports from a fragment.
type TransportPacket struct {
	Source, Destination         netip.Addr
	SourcePort, DestinationPort uint16
	Protocol, TCPFlags          uint8
}

func PacketTransport(packet []byte) (TransportPacket, error) {
	source, destination, err := PacketAddresses(packet)
	if err != nil {
		return TransportPacket{}, err
	}
	var protocol byte
	var offset int
	if packet[0]>>4 == 4 {
		// Only DF may be set. Even an initial fragment cannot authorize later
		// fragments with ports that were never inspected by this owner.
		if binary.BigEndian.Uint16(packet[6:8])&0xbfff != 0 {
			return TransportPacket{}, ErrPolicy
		}
		offset, protocol = int(packet[0]&15)*4, packet[9]
	} else {
		offset, protocol = 40, packet[6]
		for count := 0; protocol == 0 || protocol == 60; count++ {
			if count >= 8 || offset+8 > len(packet) {
				return TransportPacket{}, ErrPolicy
			}
			length := (int(packet[offset+1]) + 1) * 8
			if offset+length > len(packet) {
				return TransportPacket{}, ErrPolicy
			}
			protocol, offset = packet[offset], offset+length
		}
	}
	if protocol != 6 && protocol != 17 || offset+4 > len(packet) {
		return TransportPacket{}, ErrPolicy
	}
	payload := packet[offset:]
	tuple := TransportPacket{Source: source, Destination: destination, SourcePort: binary.BigEndian.Uint16(payload[:2]), DestinationPort: binary.BigEndian.Uint16(payload[2:4]), Protocol: protocol}
	if tuple.SourcePort == 0 || tuple.DestinationPort == 0 {
		return TransportPacket{}, ErrPolicy
	}
	if protocol == 17 {
		if len(payload) < 8 || int(binary.BigEndian.Uint16(payload[4:6])) != len(payload) {
			return TransportPacket{}, ErrPolicy
		}
	} else {
		if len(payload) < 20 || int(payload[12]>>4)*4 < 20 || int(payload[12]>>4)*4 > len(payload) {
			return TransportPacket{}, ErrPolicy
		}
		tuple.TCPFlags = payload[13]
	}
	return tuple, nil
}
