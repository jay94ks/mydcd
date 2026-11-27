// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"testing"
)

func sample() Frame {
	return Frame{Purpose: Management, Kind: 1, Request: 7, Fields: []Field{{Tag: 1, Required: true, Value: []byte("set network/tun")}, {Tag: 2, Required: true, Value: make([]byte, 32)}}}
}

func TestRoutePacketKindPreservesSchemaOneDatagramBudget(t *testing.T) {
	owner, network, identity := [32]byte{1}, [16]byte{2}, [16]byte{3}
	packet := bytes.Repeat([]byte{0x45}, 1280)
	frame := Frame{Purpose: Packet, Kind: 1, Fields: []Field{{Tag: 1, Required: true, Value: owner[:]}, {Tag: 2, Required: true, Value: network[:]}, {Tag: 3, Required: true, Value: identity[:]}, {Tag: 4, Required: true, Value: packet}}}
	ordinary, err := encodePacket(frame)
	if err != nil {
		t.Fatal(err)
	}
	frame.Kind = 2
	route, err := encodePacket(frame)
	if err != nil || len(route) != len(ordinary) || len(route)-len(packet) != PacketFrameOverhead || PacketFrameOverhead != 40 {
		t.Fatal("route incarnation changed the PMTU budget", err)
	}
	peer := Identity{9}
	decoded, err := decodePacket(route, peer)
	if err != nil || decoded.Kind != 2 || decoded.Purpose != Packet || !bytes.Equal(decoded.Fields[0].Value, peer[:]) || !bytes.Equal(decoded.Fields[1].Value, network[:]) || !bytes.Equal(decoded.Fields[2].Value, identity[:]) || !bytes.Equal(decoded.Fields[3].Value, packet) {
		t.Fatal("route packet did not round-trip", err)
	}
	for _, size := range []int{0, 15, 17, 32} {
		frame.Fields[2].Value = make([]byte, size)
		if _, err := encodePacket(frame); err == nil {
			t.Fatal("invalid route token size was accepted", size)
		}
	}
	frame.Fields[2].Value = identity[:]
	frame.Kind = 3
	if _, err := encodePacket(frame); err == nil {
		t.Fatal("unknown packet kind was accepted")
	}
	for _, bad := range [][]byte{route[:PacketFrameOverhead-1], append([]byte("MDG2"), route[4:]...), append(append([]byte{}, route[:7]...), append([]byte{3}, route[8:]...)...)} {
		if _, err := decodePacket(bad, peer); err == nil {
			t.Fatal("bad packet head accepted")
		}
	}
}
func TestFrameEverySplitTruncationAndCoalescing(t *testing.T) {
	wire, err := Encode(sample())
	if err != nil {
		t.Fatal(err)
	}
	for split := 0; split <= len(wire); split++ {
		d, _ := NewDecoder(MaxBody)
		a, n, err := d.Feed(wire[:split])
		if err != nil || n != split {
			t.Fatal(split, n, err)
		}
		if split < len(wire) {
			if a != nil {
				t.Fatal("early dispatch", split)
			}
			a, n, err = d.Feed(wire[split:])
			if err != nil || n != len(wire)-split {
				t.Fatal(split, n, err)
			}
		}
		if a == nil || !bytes.Equal(a.Fields[0].Value, sample().Fields[0].Value) || d.Close() != nil {
			t.Fatal("split lost frame", split)
		}
		if split > 0 && split < len(wire) {
			cut, _ := NewDecoder(MaxBody)
			_, _, _ = cut.Feed(wire[:split])
			if !errors.Is(cut.Close(), ErrTruncated) {
				t.Fatal("cut accepted", split)
			}
		}
	}
	d, _ := NewDecoder(MaxBody)
	for i := range wire {
		f, n, err := d.Feed(wire[i : i+1])
		if err != nil || n != 1 || (f != nil) != (i == len(wire)-1) {
			t.Fatal("bytewise decoder", i, err)
		}
	}
	d, _ = NewDecoder(MaxBody)
	both := append(append([]byte(nil), wire...), wire...)
	f, n, err := d.Feed(both)
	if err != nil || f == nil || n != len(wire) {
		t.Fatal("did not bound dispatch count")
	}
	f2, n2, err := d.Feed(both[n:])
	if err != nil || f2 == nil || n2 != n {
		t.Fatal(err)
	}
	f2.Fields[0].Value[0] = '!'
	if f.Fields[0].Value[0] == '!' {
		t.Fatal("decoder reused owned body")
	}
}
func TestMalformedFramesBeforeAllocationOrDispatch(t *testing.T) {
	wire, _ := Encode(sample())
	for _, mutate := range []func([]byte){
		func(b []byte) { b[0] = 'X' }, func(b []byte) { b[4] = 2 }, func(b []byte) { b[6] = 99 }, func(b []byte) { b[7] = 99 }, func(b []byte) { b[8] = 1 }, func(b []byte) { b[12] = 0 },
		func(b []byte) { binary.LittleEndian.PutUint32(b[20:], ^uint32(0)) },
		func(b []byte) { binary.LittleEndian.PutUint16(b[24:], 3) },
		func(b []byte) { b[26] = 0 }, func(b []byte) { b[27] = 1 },
		func(b []byte) { binary.LittleEndian.PutUint32(b[28:], ^uint32(0)) },
	} {
		b := append([]byte(nil), wire...)
		mutate(b)
		d, _ := NewDecoder(MaxBody)
		f, _, err := d.Feed(b)
		if err == nil || f != nil {
			t.Fatal("accepted malformed frame", b)
		}
		if _, _, err := d.Feed(wire); err == nil {
			t.Fatal("resynchronized poisoned stream")
		}
	}
	d, _ := NewDecoder(1)
	_, _, err := d.Feed(wire[:HeaderSize])
	if !errors.Is(err, ErrBudget) || d.Buffered() != HeaderSize {
		t.Fatal("allocated oversized body", err, d.Buffered())
	}
	f := sample()
	f.Fields = append(f.Fields, Field{Tag: 128, Required: false, Value: []byte("optional")})
	if _, err := Encode(f); err != nil {
		t.Fatal(err)
	}
	f.Fields[2].Required = true
	if _, err := Encode(f); err == nil {
		t.Fatal("unknown required extension")
	}
	f = sample()
	f.Fields = append(f.Fields, f.Fields[1])
	if _, err := Encode(f); err == nil {
		t.Fatal("duplicate field")
	}
	f = sample()
	f.Fields = f.Fields[:1]
	if _, err := Encode(f); err == nil {
		t.Fatal("missing required field")
	}
	if _, err := NewDecoder(0); err == nil {
		t.Fatal("zero budget")
	}
}
func TestPurposeSchemasAndAuthenticationAdmission(t *testing.T) {
	for p := Handshake; p <= Packet; p++ {
		for kind := uint8(1); kind <= 4; kind++ {
			rules, cap := fieldRule(p, kind)
			if cap == 0 {
				continue
			}
			f := Frame{Purpose: p, Kind: kind, Request: 1}
			if p == Packet {
				f.Request = 0
			}
			for i, n := range rules {
				if n < 0 {
					n = 1
				}
				f.Fields = append(f.Fields, Field{Tag: uint16(i + 1), Required: true, Value: make([]byte, n)})
			}
			b, err := Encode(f)
			if err != nil {
				t.Fatal(p, kind, err)
			}
			d, _ := NewDecoder(MaxBody)
			if got, _, err := d.Feed(b); err != nil || got == nil {
				t.Fatal(p, kind, err)
			}
		}
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, 32))
	var key Identity
	copy(key[:], private.Public().(ed25519.PublicKey))
	cluster, challenge := [32]byte{1}, [32]byte{2}
	binding := Binding{Key: key, TLSKey: key, Cluster: cluster, Challenge: challenge}
	binding.Signature = ed25519.Sign(private, ProofBytes(key, cluster, challenge))
	gate, _ := NewGate(cluster, challenge)
	policy := Policy{Key: key, Manage: true, Read: true, Member: true, Snapshot: true, Report: true, Tunnel: true}
	for p := Management; p <= Packet; p++ {
		if gate.Admit(Frame{Purpose: p, Kind: 1}, policy, false, p == Packet) == nil {
			t.Fatal("preauth bypass", p)
		}
	}
	if gate.Admit(Frame{Purpose: Handshake, Kind: 1}, Policy{}, false, false) != nil {
		t.Fatal("hello denied")
	}
	for _, bad := range []Binding{
		{Key: key, TLSKey: Identity{9}, Cluster: cluster, Challenge: challenge, Signature: binding.Signature},
		{Key: key, TLSKey: key, Cluster: [32]byte{9}, Challenge: challenge, Signature: binding.Signature},
		{Key: key, TLSKey: key, Cluster: cluster, Challenge: [32]byte{9}, Signature: binding.Signature},
		{Key: key, TLSKey: key, Cluster: cluster, Challenge: challenge, Signature: make([]byte, 64)},
	} {
		if gate.Authenticate(bad, true) == nil {
			t.Fatal("invalid proof accepted")
		}
	}
	if gate.Authenticate(binding, false) == nil || gate.Authenticate(binding, true) != nil || gate.Authenticate(binding, true) == nil {
		t.Fatal("approval/proof lifetime")
	}
	for p := Management; p <= Packet; p++ {
		f := Frame{Purpose: p, Kind: KindRequest}
		if p == Observation {
			f.Kind = KindWorkloadReport
		}
		if gate.AdmitOn(p, f, policy, false, p == Packet) != nil {
			t.Fatal("authorized purpose denied", p)
		}
		if gate.Admit(f, policy, true, p == Packet) == nil || gate.AdmitOn(Handshake, f, policy, false, p == Packet) == nil || gate.Admit(f, Policy{Key: key}, false, p == Packet) == nil {
			t.Fatal("early/purpose/revocation bypass", p)
		}
	}
	if gate.Admit(Frame{Purpose: Packet, Kind: 1}, policy, false, false) == nil {
		t.Fatal("packet stream bypass")
	}
	server := Policy{Key: key, Respond: true}
	if gate.Admit(Frame{Purpose: Management, Kind: 2}, server, false, false) != nil || gate.Admit(Frame{Purpose: Management, Kind: 1}, server, false, false) == nil {
		t.Fatal("reply authority granted management write access")
	}
	if gate.Admit(Frame{Purpose: Observation, Kind: 2}, server, false, false) != nil || gate.Admit(Frame{Purpose: Observation, Kind: 1}, server, false, false) == nil || gate.Admit(Frame{Purpose: Observation, Kind: 2}, Policy{Key: key, Report: true}, false, false) == nil {
		t.Fatal("report sender and acknowledgement authority mixed")
	}
	reader := Policy{Key: key, Read: true}
	if gate.Admit(Frame{Purpose: Management, Kind: KindManagementRead}, reader, false, false) != nil || gate.Admit(Frame{Purpose: Management, Kind: 1}, reader, false, false) == nil {
		t.Fatal("read authority granted management write access")
	}
	relay := Frame{Purpose: Management, Kind: KindRelay, Request: 2, Fields: []Field{{Tag: 1, Required: true, Value: []byte("signed original")}, {Tag: 2, Required: true, Value: make([]byte, 32)}}}
	if _, err := Encode(relay); err != nil {
		t.Fatal(err)
	}
	member := Policy{Key: key, Member: true}
	if gate.Admit(relay, member, false, false) != nil || gate.Admit(Frame{Purpose: Management, Kind: 1}, member, false, false) == nil || gate.Admit(relay, reader, false, false) == nil || gate.Admit(relay, Policy{Key: key, Manage: true}, false, false) == nil {
		t.Fatal("relay and actor management authority mixed")
	}
	if _, err := NewGate(cluster, [32]byte{}); err == nil {
		t.Fatal("zero challenge")
	}
}

// Transit numbers stay free until transit sessions define them (0.1.1), and
// a frame using them is refused like any unknown purpose or kind.
func TestTransitNumbersReserved(t *testing.T) {
	if _, taken := purposes[reservedTransitPurpose]; taken {
		t.Fatalf("purpose %d is reserved for transit", reservedTransitPurpose)
	}
	if _, taken := kindOf(Observation, reservedTransitLoad); taken || ReportKind(reservedTransitLoad) {
		t.Fatalf("Observation kind %d is reserved for transit load reports", reservedTransitLoad)
	}
	for _, f := range []Frame{
		{Purpose: reservedTransitPurpose, Kind: KindRequest, Request: 1},
		{Purpose: Observation, Kind: reservedTransitLoad, Request: 1, Fields: []Field{{Tag: 1, Required: true, Value: []byte("x")}}},
	} {
		if _, err := Encode(f); err == nil {
			t.Fatalf("reserved frame %d/%d encoded", f.Purpose, f.Kind)
		}
	}
}
