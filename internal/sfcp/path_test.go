// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/identity"
	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
)

func TestConnectionPathAdmissionAndMigration(t *testing.T) {
	p, other := newConnectionPath(), newConnectionPath()
	if b, _ := p.budget(); b.FrameBytes != 0 || !b.ObservedAt.IsZero() {
		t.Fatal("unknown peer parameters admitted packet", b)
	}
	p.RecordEvent(qlog.ParametersSet{Initiator: qlog.InitiatorRemote, MaxDatagramFrameSize: 16383, InitialSourceConnectionID: quic.ConnectionIDFromBytes(make([]byte, 4))})
	p.RecordEvent(qlog.MTUUpdated{Value: 1441, Done: true})
	old, changed := p.budget()
	if old.IPBytes < 1280 || old.ObservedAt.IsZero() {
		t.Fatal("acknowledged native path not observed", old)
	}
	p.RecordEvent(qlog.PacketSent{Header: qlog.PacketHeader{PacketType: qlog.PacketType1RTT, DestConnectionID: quic.ConnectionIDFromBytes(make([]byte, 20))}})
	if b, _ := p.budget(); b.IPBytes >= old.IPBytes || b.FrameBytes != 1441-44 || b.IPBytes != b.FrameBytes-PacketFrameOverhead {
		t.Fatal("longer CID bypassed complete wire overhead", b)
	}
	p.RecordEvent(qlog.ParametersSet{Initiator: qlog.InitiatorRemote, MaxDatagramFrameSize: 16383, InitialSourceConnectionID: quic.ConnectionIDFromBytes(make([]byte, 4))})
	old, changed = p.budget()
	if b, _ := other.budget(); b.FrameBytes != 0 {
		t.Fatal("another connection inherited path proof", b)
	}
	p.RecordEvent(qlog.TupleAssigned{TupleID: "probing"})
	if b, now := p.budget(); b != old || now != changed {
		t.Fatal("inactive tuple changed active proof", b)
	}
	p.RecordEvent(qlog.TupleAssigned{TupleID: ""})
	b, _ := p.budget()
	if b.Generation != old.Generation+1 || b.IPBytes >= 1280 || !b.ObservedAt.IsZero() {
		t.Fatal("migrated path inherited old MTU", b)
	}
	select {
	case <-changed:
	default:
		t.Fatal("path waiter not invalidated")
	}
	p.RecordEvent(qlog.MTUUpdated{Value: 1452})
	p.RecordEvent(qlog.ParametersSet{Initiator: qlog.InitiatorRemote, MaxDatagramFrameSize: 500})
	if b, _ = p.budget(); b.FrameBytes > 500-3 {
		t.Fatal("remote DATAGRAM cap ignored", b)
	}
	p.RecordEvent(qlog.ParametersSet{Initiator: qlog.InitiatorLocal, MaxDatagramFrameSize: 16383})
	if next, _ := p.budget(); next != b {
		t.Fatal("local receive cap replaced remote receive cap", next)
	}
}

func TestRealBoundaryNativePathBudgetBidirectionalIP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	a, err := identity.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b, err := identity.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	peers := map[Identity]Peer{
		Identity(a.Public): {ID: "path-a", Policy: Policy{Key: Identity(a.Public), Tunnel: true}},
		Identity(b.Public): {ID: "path-b", Policy: Policy{Key: Identity(b.Public), Tunnel: true}},
	}
	lookup := func(key Identity) (Peer, bool) { p, ok := peers[key]; return p, ok }
	client, err := NewTransport(a, [32]byte{7}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := NewTransport(b, [32]byte{7}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	type received struct {
		session *Session
		frame   Frame
	}
	up, down := make(chan received, 4), make(chan received, 4)
	for _, h := range []struct {
		transport *Transport
		queue     chan received
	}{{server, up}, {client, down}} {
		if err = h.transport.OnPacket(func(s *Session, f Frame) error {
			select {
			case h.queue <- received{s, f}:
				return nil
			default:
				return ErrBudget
			}
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err = server.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	target := peers[Identity(b.Public)]
	target.Endpoint = server.Addr().String()
	out, err := client.Dial(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	frame := func(owner []byte, n int) Frame {
		ip := make([]byte, n)
		ip[0], ip[8], ip[9] = 0x45, 64, 17
		binary.BigEndian.PutUint16(ip[2:], uint16(n))
		copy(ip[12:], []byte{192, 0, 2, 1, 198, 51, 100, 2})
		binary.BigEndian.PutUint16(ip[20:], 1234)
		binary.BigEndian.PutUint16(ip[22:], 5678)
		binary.BigEndian.PutUint16(ip[24:], uint16(n-20))
		for i := 28; i < n; i++ {
			ip[i] = byte(i)
		}
		var checksum uint32
		for i := 0; i < 20; i += 2 {
			checksum += uint32(binary.BigEndian.Uint16(ip[i:]))
		}
		for checksum > 65535 {
			checksum = checksum&65535 + checksum>>16
		}
		binary.BigEndian.PutUint16(ip[10:], ^uint16(checksum))
		return Frame{Purpose: Packet, Kind: 1, Fields: []Field{{Tag: 1, Required: true, Value: owner}, {Tag: 2, Required: true, Value: make([]byte, 16)}, {Tag: 3, Required: true, Value: make([]byte, 16)}, {Tag: 4, Required: true, Value: ip}}}
	}
	receive := func(ch chan received, want Frame) received {
		t.Helper()
		select {
		case r := <-ch:
			if !bytes.Equal(r.frame.Fields[3].Value, want.Fields[3].Value) {
				t.Fatal("IP bytes changed")
			}
			return r
		case <-ctx.Done():
			t.Fatal("IP DATAGRAM not delivered", ctx.Err())
			return received{}
		}
	}
	small := frame(a.Public[:], 28)
	if err = out.SendPacket(ctx, small); err != nil {
		t.Fatal(err)
	}
	in := receive(up, small).session
	for _, direction := range []struct {
		session *Session
		owner   []byte
		queue   chan received
	}{{out, a.Public[:], up}, {in, b.Public[:], down}} {
		budget, err := direction.session.WaitPacketBudget(ctx, 1280)
		if err != nil {
			current, _ := direction.session.PacketBudget()
			t.Fatal("native path did not admit minimum IP MTU", current, err)
		}
		if budget.Connection == [32]byte{} || budget.Connection != direction.session.gate.challenge {
			t.Fatal("path budget lost authenticated connection binding", budget)
		}
		for _, size := range []int{1280, budget.IPBytes} {
			f := frame(direction.owner, size)
			if err = direction.session.SendPacket(ctx, f); err != nil {
				t.Fatal("admitted IP failed native send", budget, err)
			}
			receive(direction.queue, f)
		}
		// The fixed Packet head has no optional fields. A packet larger than the
		// discovery ceiling is refused without wait or retry.
		f := frame(direction.owner, budget.IPBytes)
		f.Fields = append(f.Fields, Field{Tag: 128, Required: false, Value: make([]byte, 1024)})
		if err = direction.session.SendPacket(ctx, f); !errors.Is(err, ErrFrame) {
			t.Fatal("packet with an optional field was sent", err)
		}
		var tooLarge *quic.DatagramTooLargeError
		if err = direction.session.SendPacket(ctx, frame(direction.owner, budget.FrameBytes+1024)); !errors.As(err, &tooLarge) {
			t.Fatal("whole encoded size bypassed packet admission", err)
		}
		if budget.Done {
			f = frame(direction.owner, budget.IPBytes+1)
			if err = direction.session.SendPacket(ctx, f); !errors.As(err, &tooLarge) {
				t.Fatal("final safe IP maximum+1 bypassed admission", budget, err)
			}
		}
		t.Logf("peer=%s UDP=%d CID=%d frame=%d IP=%d path-generation=%d done=%t; real 1280B and %dB IP delivered", direction.session.Peer().ID, budget.UDPBytes, budget.CIDBytes, budget.FrameBytes, budget.IPBytes, budget.Generation, budget.Done, budget.IPBytes)
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if _, err = out.WaitPacketBudget(canceled, 65535); !errors.Is(err, context.Canceled) {
		t.Fatal("path budget wait ignored cancellation", err)
	}
	if err = client.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = out.WaitPacketBudget(ctx, 1280); !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed connection retained usable path proof", err)
	}
}
