// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

func TestUnixReceiveFailurePreservesUnknownWithoutAutomaticReplay(t *testing.T) {
	root, err := os.MkdirTemp("", "mydc-c3-delivery-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	})
	node, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	user, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(node.Private); clear(user.Private) })
	cluster := [32]byte{41}
	path := filepath.Join(root, "api.sock")
	peer := mydcp.Peer{ID: "node", Endpoint: "unix://" + path, Policy: mydcp.Policy{Key: mydcp.Identity(node.Public), Respond: true}}
	lookup := func(key mydcp.Identity) (mydcp.Peer, bool) {
		if key == mydcp.Identity(user.Public) {
			return mydcp.Peer{ID: "user", Policy: mydcp.Policy{Key: key, UserAuth: true}}, true
		}
		return peer, key == peer.Key
	}
	server, err := mydcp.NewTransport(node, cluster, lookup)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	mesh, err := mydcp.NewTransport(user, cluster, lookup)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mesh.Close() })
	var calls atomic.Int32
	if err := server.OnManagement(mydcp.User, func(_ context.Context, _ *mydcp.Session, stream mydcp.Stream, _ mydcp.Frame) error {
		calls.Add(1)
		var extra [1]byte
		if n, err := stream.Read(extra[:]); n != 0 || err != io.EOF {
			return mydcp.ErrFrame
		}
		return io.ErrUnexpectedEOF // Request arrived; outcome/reply deliberately lost.
	}); err != nil {
		t.Fatal(err)
	}
	if err := server.ListenUnix(path); err != nil {
		t.Fatal(err)
	}
	client := Client{Mesh: mesh, Self: user, Cluster: cluster}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	body, err := requestBody(Request{Method: "whoami"})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = client.exchange(ctx, peer, func(*mydcp.Session) (Envelope, error) { return Envelope{Body: body}, nil }, false)
	var failure *Error
	if !errors.As(err, &failure) || failure.Phase != mydcp.Unknown || failure.stage != "receive" || calls.Load() != 1 {
		t.Fatalf("lost reply was retried/reclassified: calls=%d err=%v", calls.Load(), err)
	}
}
