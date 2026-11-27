// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"context"
	"github.com/jay94ks/seafield/internal/identity"
	quic "github.com/quic-go/quic-go"
	"net"
	"testing"
	"time"
)

func TestRealBoundaryQUICAuthenticationAndPurpose(t *testing.T) {
	a, err := identity.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b, err := identity.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	peers := map[Identity]Peer{Identity(a.Public): {ID: "a", Policy: Policy{Key: Identity(a.Public), Read: true}}, Identity(b.Public): {ID: "b", Policy: Policy{Key: Identity(b.Public), Read: true, Respond: true}}}
	lookup := func(key Identity) (Peer, bool) { p, ok := peers[key]; return p, ok }
	server, _ := NewTransport(b, [32]byte{1}, lookup)
	defer server.Close()
	if err := server.On(Management, func(ctx context.Context, s *Session, stream *quic.Stream, f Frame) error {
		f.Kind = 2
		return WriteFrame(stream, f)
	}); err != nil {
		t.Fatal(err)
	}
	if err := server.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	client, _ := NewTransport(a, [32]byte{1}, lookup)
	defer client.Close()
	peer := peers[Identity(b.Public)]
	peer.Endpoint = server.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	session, err := client.Dial(ctx, peer)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := session.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f := sample()
	f.Kind = KindManagementRead
	if err = WriteFrame(stream, f); err != nil {
		t.Fatal(err)
	}
	reply, err := ReadFrame(stream, MaxBody)
	if err != nil || session.Admit(reply, Management, false) != nil || reply.Request != f.Request {
		t.Fatal("authenticated response", err)
	}
	_ = stream.Close()
	stream.CancelRead(0)
	denied, err := session.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f.Kind = 1
	if err = WriteFrame(denied, f); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadFrame(denied, MaxBody); err == nil {
		t.Fatal("read-only peer issued write")
	}
	_ = denied.Close()
	denied.CancelRead(0)
	wrong, _ := NewTransport(a, [32]byte{2}, lookup)
	defer wrong.Close()
	if _, err = wrong.Dial(ctx, peer); err == nil {
		t.Fatal("cross-cluster authentication")
	}
	if err = server.Close(); err != nil {
		t.Fatal(err)
	}
	rebound, err := net.ListenPacket("udp", peer.Endpoint)
	if err != nil {
		t.Fatal("Close returned before releasing the owned UDP socket", err)
	}
	if err = rebound.Close(); err != nil {
		t.Fatal(err)
	}
}
