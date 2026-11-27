// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/identity"
	quic "github.com/quic-go/quic-go"
)

func TestRealPurposeLookupKeepsRaftIndependentOfPacketPolicy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a, err := identity.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b, err := identity.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var member, tunnel atomic.Bool
	member.Store(true)
	tunnel.Store(true)
	var fullCalls, packetCalls atomic.Int32
	entered, release := make(chan struct{}, 1), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	lookup := func(key Identity, purpose Purpose) (Peer, bool) {
		id := "a"
		if key == Identity(b.Public) {
			id = "b"
		} else if key != Identity(a.Public) {
			return Peer{}, false
		}
		p := Peer{ID: id, Policy: Policy{Key: key, Member: member.Load(), Respond: true}}
		if purpose == 0 {
			fullCalls.Add(1)
		}
		if purpose == Packet {
			packetCalls.Add(1)
			select {
			case entered <- struct{}{}:
			default:
			}
			select {
			case <-release:
			case <-ctx.Done():
				return Peer{}, false
			}
		}
		if purpose == 0 || purpose == Packet || purpose == PathControl {
			p.Tunnel = tunnel.Load()
		}
		return p, true
	}
	server, err := NewTransportWithPurposeLookup(b, [32]byte{1}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	// A failed assertion must unblock the packet lookup before transport Close.
	defer unblock()
	var rpcCalls atomic.Int32
	if err = server.On(Raft, func(_ context.Context, _ *Session, stream *quic.Stream, f Frame) error {
		rpcCalls.Add(1)
		return WriteFrame(stream, f)
	}); err != nil {
		t.Fatal(err)
	}
	packets := make(chan struct{}, 1)
	if err = server.OnPacket(func(_ *Session, _ Frame) error { packets <- struct{}{}; return nil }); err != nil {
		t.Fatal(err)
	}
	if err = server.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	client, err := NewTransportWithPurposeLookup(a, [32]byte{1}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer unblock()
	peer := Peer{ID: "b", Endpoint: server.Addr().String(), Policy: Policy{Key: Identity(b.Public)}}
	session, err := client.Dial(ctx, peer)
	if err != nil {
		t.Fatal(err)
	}
	rpc := func() error {
		stream, err := session.Open(ctx)
		if err != nil {
			return err
		}
		defer stream.CancelRead(0)
		defer stream.Close()
		f := Frame{Purpose: Raft, Kind: 1, Request: client.NextRequest(), Fields: []Field{{Tag: 1, Required: true, Value: []byte("authenticated RPC")}}}
		if err = WriteFrame(stream, f); err != nil {
			return err
		}
		reply, err := ReadFrame(stream, MaxBody)
		if err != nil {
			return err
		}
		if reply.Request != f.Request {
			return ErrFrame
		}
		return session.Admit(reply, Raft, false)
	}
	if err = rpc(); err != nil || fullCalls.Load() != 0 || packetCalls.Load() != 0 {
		t.Fatal("control exchange required packet policy", err, fullCalls.Load(), packetCalls.Load())
	}
	ip := []byte{0x45, 0, 0, 28, 0, 1, 0, 0, 64, 17, 0x66, 0xce, 10, 0, 0, 1, 10, 0, 0, 2, 0x12, 0x34, 0x56, 0x78, 0, 8, 0, 0}
	packet := Frame{Purpose: Packet, Kind: 1, Fields: []Field{{Tag: 1, Required: true, Value: a.Public[:]}, {Tag: 2, Required: true, Value: append([]byte{1}, make([]byte, 15)...)}, {Tag: 3, Required: true, Value: append([]byte{2}, make([]byte, 15)...)}, {Tag: 4, Required: true, Value: ip}}}
	if err = session.SendPacket(ctx, packet); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("packet policy not consulted")
	}
	if err = rpc(); err != nil {
		t.Fatal("blocked packet derivation blocked Raft", err)
	}
	unblock()
	select {
	case <-packets:
	case <-ctx.Done():
		t.Fatal("permitted packet not delivered")
	}
	tunnel.Store(false)
	_, drops := server.PacketCounts()
	if err = session.SendPacket(ctx, packet); err != nil {
		t.Fatal(err)
	}
	for {
		_, now := server.PacketCounts()
		if now > drops {
			break
		}
		select {
		case <-time.After(time.Millisecond):
		case <-ctx.Done():
			t.Fatal("current tunnel revocation was cached")
		}
	}
	if packetCalls.Load() != 2 {
		t.Fatal("packet admission bypassed current policy", packetCalls.Load())
	}
	if err = rpc(); err != nil {
		t.Fatal("tunnel revocation revoked membership", err)
	}
	member.Store(false)
	if err = rpc(); err == nil {
		t.Fatal("current membership revocation was ignored")
	}
	if rpcCalls.Load() != 3 || !errors.Is(session.Admit(Frame{Purpose: Raft, Kind: 1}, Raft, false), ErrAdmission) {
		t.Fatal("revoked member reached handler", rpcCalls.Load())
	}
}
