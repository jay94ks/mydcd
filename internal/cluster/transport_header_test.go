// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"context"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

func TestRaftResponseHeaderFollowsSDKTimeoutNowContract(t *testing.T) {
	for _, test := range []struct {
		name   string
		kind   uint8
		header raft.RPCHeader
		peer   string
		want   bool
	}{
		{"ordinary", 1, raft.RPCHeader{ID: []byte("node-b")}, "node-b", true},
		{"sdk-timeout-ack", 4, raft.RPCHeader{}, "node-b", true},
		{"empty-append", 1, raft.RPCHeader{}, "node-b", false},
		{"empty-vote", 2, raft.RPCHeader{}, "node-b", false},
		{"empty-prevote", 3, raft.RPCHeader{}, "node-b", false},
		{"foreign-timeout", 4, raft.RPCHeader{ID: []byte("node-c")}, "node-b", false},
		{"foreign-append", 1, raft.RPCHeader{ID: []byte("node-c")}, "node-b", false},
		{"partial-timeout", 4, raft.RPCHeader{Addr: []byte("foreign")}, "node-b", false},
		{"partial-version", 4, raft.RPCHeader{ProtocolVersion: 1}, "node-b", false},
		{"no-current-peer", 4, raft.RPCHeader{}, "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := rpcResponseHeader(test.kind, test.header, test.peer); got != test.want {
				t.Fatal(got, test.want)
			}
		})
	}
}

func TestRaftHeaderUsesCurrentMemberAfterPublicTLSConnection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a, err := identity.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b, err := identity.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var installed atomic.Bool
	pa := mydcp.Peer{ID: "node-a", Policy: mydcp.Policy{Key: mydcp.Identity(a.Public), Member: true, Snapshot: true, Respond: true}}
	pb := mydcp.Peer{ID: "node-b", Policy: mydcp.Policy{Key: mydcp.Identity(b.Public), Member: true, Snapshot: true, Respond: true}}
	server, err := mydcp.NewTransport(a, [32]byte{1}, func(k mydcp.Identity) (mydcp.Peer, bool) {
		if k != pb.Key {
			return mydcp.Peer{}, false
		}
		p := pb
		if !installed.Load() {
			p.ID = "public-key-before-directory"
			p.Member = false
			p.UserAuth = true
		}
		return p, true
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err = server.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	pa.Endpoint = server.Addr().String()
	client, err := mydcp.NewTransport(b, [32]byte{1}, func(k mydcp.Identity) (mydcp.Peer, bool) { return pa, k == pa.Key })
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err = client.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	pb.Endpoint = client.Addr().String()
	srv, err := newRaftTransport(server, raft.ServerAddress(pa.Endpoint), func(id raft.ServerID, addr raft.ServerAddress) (mydcp.Peer, bool) {
		return pb, installed.Load() && string(id) == pb.ID && string(addr) == pb.Endpoint
	}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	cli, err := newRaftTransport(client, raft.ServerAddress(pb.Endpoint), func(id raft.ServerID, addr raft.ServerAddress) (mydcp.Peer, bool) {
		return pa, string(id) == pa.ID && string(addr) == pa.Endpoint
	}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	request := raft.RequestVoteRequest{RPCHeader: raft.RPCHeader{ProtocolVersion: raft.ProtocolVersionMax, ID: []byte(pb.ID), Addr: []byte(pb.Endpoint)}, Term: 1}
	var response raft.RequestVoteResponse
	if err = cli.RequestVote(raft.ServerID(pa.ID), raft.ServerAddress(pa.Endpoint), &request, &response); err == nil {
		t.Fatal("uninstalled public peer voted")
	}
	session, err := client.Dial(ctx, pa)
	if err != nil {
		t.Fatal(err)
	}
	installed.Store(true)
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case rpc := <-srv.Consumer():
			rpc.Respond(&raft.RequestVoteResponse{RPCHeader: raft.RPCHeader{ProtocolVersion: raft.ProtocolVersionMax, ID: []byte(pa.ID), Addr: []byte(pa.Endpoint)}, Term: 1, Granted: true}, nil)
		case <-ctx.Done():
		}
	}()
	err = cli.RequestVote(raft.ServerID(pa.ID), raft.ServerAddress(pa.Endpoint), &request, &response)
	if err != nil || !response.Granted {
		t.Fatal("current member on original TLS connection was rejected", err)
	}
	<-done
	again, err := client.Dial(ctx, pa)
	if err != nil || again != session {
		t.Fatal("test replaced the original connection", err)
	}
	if srv.requestPeer(request.RPCHeader, pa.Key) {
		t.Fatal("another authenticated key used the member header")
	}
	for _, field := range []string{"id", "endpoint", "revoked"} {
		bad := request
		switch field {
		case "id":
			bad.ID = []byte("other-node")
		case "endpoint":
			bad.Addr = []byte("127.0.0.1:1")
		case "revoked":
			installed.Store(false)
		}
		if err = cli.RequestVote(raft.ServerID(pa.ID), raft.ServerAddress(pa.Endpoint), &bad, &response); err == nil {
			t.Fatal("invalid current member header admitted", field)
		}
	}
}
