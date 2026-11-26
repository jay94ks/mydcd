// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

type finiteRPCProbe struct {
	reading, writing chan struct{}
	done             chan error
}

type probedFiniteStream struct {
	mydcp.Stream
	probe               *finiteRPCProbe
	readOnce, writeOnce sync.Once
}

func (s *probedFiniteStream) Read(b []byte) (int, error) {
	s.readOnce.Do(func() { close(s.probe.reading) })
	return s.Stream.Read(b)
}
func (s *probedFiniteStream) Write(b []byte) (int, error) {
	s.writeOnce.Do(func() { close(s.probe.writing) })
	return s.Stream.Write(b)
}

// Real QUIC/handshake/frames and the product Service.handle, without Raft or
// Docker: the invalid finite body must be denied before binding, but only
// AFTER EOF. Channels expose the ordering; no timing sleep or RPC retry is used.
func TestFiniteUserRPCConsumesEOFBeforeReplyOrEffects(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	node, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(node.Private)
	user, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(user.Private)
	cluster := [32]byte{219}
	peer := mydcp.Peer{ID: "server", Policy: mydcp.Policy{Key: mydcp.Identity(node.Public), Respond: true, Read: true, Member: true}}
	server, err := mydcp.NewTransport(node, cluster, func(key mydcp.Identity) (mydcp.Peer, bool) {
		return mydcp.Peer{ID: "user", Policy: mydcp.Policy{Key: key, UserAuth: true}}, key == mydcp.Identity(user.Public)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	service := Service{Self: node} // No Engine/connection binding may be used.
	probes := [2]*finiteRPCProbe{}
	for i := range probes {
		probes[i] = &finiteRPCProbe{reading: make(chan struct{}), writing: make(chan struct{}), done: make(chan error, 1)}
	}
	if err := server.OnManagement(mydcp.User, func(ctx context.Context, conn *mydcp.Session, stream mydcp.Stream, frame mydcp.Frame) error {
		if frame.Request < 1 || frame.Request > 2 {
			return mydcp.ErrFrame
		}
		p := probes[frame.Request-1]
		err := service.handle(ctx, conn, &probedFiniteStream{Stream: stream, probe: p}, frame)
		p.done <- err
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := server.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	peer.Endpoint = server.Addr().String()
	client, err := mydcp.NewTransport(user, cluster, func(key mydcp.Identity) (mydcp.Peer, bool) { return peer, key == peer.Key })
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	conn, err := client.Dial(ctx, peer)
	if err != nil {
		t.Fatal(err)
	}
	for i, name := range []string{"request-FIN", "trailing-byte"} {
		t.Run(name, func(t *testing.T) {
			stream, err := conn.OpenManagement(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.CancelRead(1)
			defer stream.CancelWrite(1)
			body, _ := json.Marshal(Request{Schema: 1, Method: "whoami", Nonce: [32]byte{1}, AppOperation: &control.AppOperationRequest{App: "unused"}})
			raw, _ := json.Marshal(Envelope{Body: body})
			digest := sha256.Sum256(raw)
			frame := mydcp.Frame{Purpose: mydcp.User, Kind: 1, Request: uint64(i + 1), Fields: []mydcp.Field{{Tag: 1, Required: true, Value: raw}, {Tag: 2, Required: true, Value: digest[:]}}}
			if err := mydcp.WriteFrame(stream, frame); err != nil {
				t.Fatal(err)
			}
			p := probes[i]
			select {
			case <-p.reading:
			case <-p.writing:
				t.Fatal("finite RPC replied before consuming request EOF")
			case err := <-p.done:
				t.Fatal("finite handler ended without request EOF", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			select {
			case <-p.writing:
				t.Fatal("response preceded request EOF")
			default:
			}
			if i == 1 {
				if _, err := stream.Write([]byte{1}); err != nil {
					t.Fatal(err)
				}
				_ = stream.Close()
				select {
				case err := <-p.done:
					if !errors.Is(err, mydcp.ErrFrame) {
						t.Fatal("trailing input accepted", err)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				select {
				case <-p.writing:
					t.Fatal("trailing input received a normal reply")
				default:
				}
				return
			}
			if err := stream.Close(); err != nil {
				t.Fatal("request FIN", err)
			}
			response, err := mydcp.ReadFrame(stream, 128<<10)
			if err != nil || response.Request != frame.Request || response.Kind != 2 || len(response.Fields) != 2 {
				t.Fatal("finite response", err)
			}
			var reply Reply
			if json.Unmarshal(response.Fields[0].Value, &reply) != nil || reply.Code != "denied" {
				t.Fatal("invalid shape reached binding/effects")
			}
			if err := streamEOF(stream); err != nil {
				t.Fatal("response EOF", err)
			}
			select {
			case err := <-p.done:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		})
	}
}
