// SPDX-License-Identifier: Apache-2.0

package network

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func transportPacket(family int, protocol uint8) []byte {
	header, length := 20, 20
	if family == 6 {
		header = 40
	}
	if protocol == 17 {
		length = 11
	}
	packet := make([]byte, header+length)
	if family == 4 {
		packet[0], packet[9] = 0x45, protocol
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		copy(packet[12:16], netip.MustParseAddr("10.1.0.10").AsSlice())
		copy(packet[16:20], netip.MustParseAddr("10.2.0.10").AsSlice())
	} else {
		packet[0], packet[6] = 0x60, protocol
		binary.BigEndian.PutUint16(packet[4:6], uint16(length))
		copy(packet[8:24], netip.MustParseAddr("fd00:1::10").AsSlice())
		copy(packet[24:40], netip.MustParseAddr("fd00:2::10").AsSlice())
	}
	binary.BigEndian.PutUint16(packet[header:header+2], 49000)
	binary.BigEndian.PutUint16(packet[header+2:header+4], 3306)
	if protocol == 17 {
		binary.BigEndian.PutUint16(packet[header+4:header+6], uint16(length))
	} else {
		packet[header+12], packet[header+13] = 0x50, 0x02
	}
	return packet
}

func TestPacketTransportUsesCompleteIPv4AndIPv6TCPUDPHeaders(t *testing.T) {
	for _, family := range []int{4, 6} {
		for _, protocol := range []uint8{6, 17} {
			packet := transportPacket(family, protocol)
			source, destination, err := PacketAddresses(packet)
			tuple, decodeErr := PacketTransport(packet)
			if err != nil || decodeErr != nil || tuple.Source != source || tuple.Destination != destination || tuple.Protocol != protocol || tuple.SourcePort != 49000 || tuple.DestinationPort != 3306 || protocol == 6 && tuple.TCPFlags != 2 {
				t.Fatal("transport boundary changed original addresses/ports", family, protocol, err, decodeErr)
			}
		}
	}
	// A bounded destination-options header must not shift the inspected ports.
	packet := transportPacket(6, 6)
	packet = append(append(append([]byte{}, packet[:40]...), 6, 0, 0, 0, 0, 0, 0, 0), packet[40:]...)
	packet[6] = 60
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)-40))
	if tuple, err := PacketTransport(packet); err != nil || tuple.DestinationPort != 3306 {
		t.Fatal("bounded IPv6 extension lost real TCP ports", err)
	}
}

func TestPacketTransportRejectsFragmentsAmbiguousPortsAndTruncatedHeaders(t *testing.T) {
	for label, mutate := range map[string]func([]byte) []byte{
		"fragment-more":         func(p []byte) []byte { p[6] = 0x20; return p },
		"fragment-offset":       func(p []byte) []byte { p[7] = 1; return p },
		"reserved-fragment-bit": func(p []byte) []byte { p[6] = 0x80; return p },
		"zero-port":             func(p []byte) []byte { p[20], p[21] = 0, 0; return p },
		"short-tcp-header":      func(p []byte) []byte { p[32] = 0x40; return p },
		"oversized-tcp-header":  func(p []byte) []byte { p[32] = 0xf0; return p },
		"unsupported-protocol":  func(p []byte) []byte { p[9] = 1; return p },
		"truncated-envelope":    func(p []byte) []byte { return p[:len(p)-1] },
	} {
		if _, err := PacketTransport(mutate(transportPacket(4, 6))); err == nil {
			t.Fatal("unsafe port inspection accepted", label)
		}
	}
	for _, protocol := range []uint8{44, 51, 50, 43} {
		packet := transportPacket(6, 6)
		if protocol == 44 || protocol == 51 {
			length := 8
			if protocol == 51 {
				length = 12
			}
			extension := make([]byte, length)
			extension[0] = 6
			if protocol == 51 {
				extension[1] = 1
			}
			packet = append(append(append([]byte{}, packet[:40]...), extension...), packet[40:]...)
			binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)-40))
		}
		packet[6] = protocol
		if protocol != 43 {
			if _, _, err := PacketAddresses(packet); err != nil {
				t.Fatal("test must reach the transport boundary with a valid IP envelope", protocol, err)
			}
		}
		if _, err := PacketTransport(packet); err == nil {
			t.Fatal("IPv6 fragment/routing/authenticated payload guessed TCP ports", protocol)
		}
	}
	for _, family := range []int{4, 6} {
		packet := transportPacket(family, 17)
		header := 20
		if family == 6 {
			header = 40
		}
		binary.BigEndian.PutUint16(packet[header+4:header+6], 8)
		if _, err := PacketTransport(packet); err == nil {
			t.Fatal("UDP length did not cover original IP payload", family)
		}
	}
}
