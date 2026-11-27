// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"bytes"
	"encoding/binary"
)

// A Packet datagram has its own fixed head instead of the 24B frame header
// and TLVs (design O6): "MDG1" | schema u16 = 1 | purpose u8 = 6 | kind u8 |
// network 16 | endpoint or flow token 16 | IP bytes. The sender's key is not
// sent: the authenticated connection already names it, and the receiver puts
// the peer key in field 1 so handlers see the same four fields as before.
const packetHeadSize = 8

// PacketFrameOverhead is the fixed Packet head before the IP bytes.
const PacketFrameOverhead = packetHeadSize + 16 + 16

const maxPacketIP = 65535

func encodePacket(f Frame) ([]byte, error) {
	if f.Purpose != Packet || f.Kind != 1 && f.Kind != 2 || f.Request != 0 || len(f.Fields) != 4 {
		return nil, ErrFrame
	}
	for i, n := range []int{32, 16, 16} {
		if f.Fields[i].Tag != uint16(i+1) || len(f.Fields[i].Value) != n {
			return nil, ErrFrame
		}
	}
	ip := f.Fields[3].Value
	if f.Fields[3].Tag != 4 || len(ip) > maxPacketIP {
		return nil, ErrFrame
	}
	b := make([]byte, 0, PacketFrameOverhead+len(ip))
	b = append(b, "MDG1"...)
	b = binary.LittleEndian.AppendUint16(b, 1)
	b = append(b, byte(Packet), f.Kind)
	b = append(b, f.Fields[1].Value...)
	b = append(b, f.Fields[2].Value...)
	return append(b, ip...), nil
}

// decodePacket parses a Packet datagram from peer. The returned fields
// alias b.
func decodePacket(b []byte, peer Identity) (Frame, error) {
	if len(b) < PacketFrameOverhead || len(b)-PacketFrameOverhead > maxPacketIP || !bytes.Equal(b[:4], []byte("MDG1")) || binary.LittleEndian.Uint16(b[4:6]) != 1 || Purpose(b[6]) != Packet || b[7] != 1 && b[7] != 2 {
		return Frame{}, ErrFrame
	}
	key := peer
	return Frame{Purpose: Packet, Kind: b[7], Fields: []Field{
		{Tag: 1, Required: true, Value: key[:]},
		{Tag: 2, Required: true, Value: b[8:24]},
		{Tag: 3, Required: true, Value: b[24:40]},
		{Tag: 4, Required: true, Value: b[40:]},
	}}, nil
}
