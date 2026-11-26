// SPDX-License-Identifier: Apache-2.0

package network

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestPacketEndpointAndEnvelopeAdmission(t *testing.T) {
	a, b := [32]byte{1}, [32]byte{2}
	n := [16]byte{3}
	for _, family := range []int{4, 6} {
		src, dst := netip.MustParseAddr("10.1.0.1"), netip.MustParseAddr("10.2.0.1")
		header := 20
		if family == 6 {
			src, dst, header = netip.MustParseAddr("fd00::1"), netip.MustParseAddr("fd00::2"), 40
		}
		p, err := NewPacketPolicy([]Endpoint{{Owner: a, Network: n, ID: [16]byte{1}, Address: src}, {Owner: b, Network: n, ID: [16]byte{2}, Address: dst}})
		if err != nil {
			t.Fatal(err)
		}
		packet := make([]byte, 1280)
		if family == 4 {
			packet[0] = 0x45
			binary.BigEndian.PutUint16(packet[2:4], 1280)
			copy(packet[12:16], src.AsSlice())
			copy(packet[16:20], dst.AsSlice())
		} else {
			packet[0], packet[6] = 0x60, 17
			binary.BigEndian.PutUint16(packet[4:6], 1240)
			copy(packet[8:24], src.AsSlice())
			copy(packet[24:40], dst.AsSlice())
		}
		if target, err := p.Outbound(a, n, 1280, packet); err != nil || target.Owner != b {
			t.Fatal(target, err)
		}
		if p.Inbound(b, a, n, [16]byte{2}, 1280, packet) != nil {
			t.Fatal("valid native packet denied", family)
		}
		for _, bad := range []struct {
			owner             [32]byte
			network, endpoint [16]byte
			mtu               int
		}{{b, n, [16]byte{2}, 1280}, {a, [16]byte{4}, [16]byte{2}, 1280}, {a, n, [16]byte{1}, 1280}, {a, n, [16]byte{2}, 1279}} {
			if p.Inbound(b, bad.owner, bad.network, bad.endpoint, bad.mtu, packet) == nil {
				t.Fatal("spoof accepted", family, bad)
			}
		}
		if _, _, err := PacketAddresses(packet[:len(packet)-1]); err == nil {
			t.Fatal("truncated IP accepted")
		}
		if _, _, err := PacketAddresses(packet[:header-1]); err == nil {
			t.Fatal("truncated header accepted")
		}
		if family == 4 {
			packet[0], packet[20], packet[21] = 0x46, 131, 4
		} else {
			packet[6] = 43
		}
		if _, _, err := PacketAddresses(packet); err == nil {
			t.Fatal("source routing bypass accepted", family)
		}
	}
}
