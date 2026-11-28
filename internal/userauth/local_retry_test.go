// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// One cancelled call on the shared Unix connection closes it (records cannot
// resume mid-exchange); the call queued behind it dials a fresh connection
// instead of failing as "disconnected" (lab, 2026-11-28).
func TestQueuedCallSurvivesCancelledLocalCall(t *testing.T) {
	_, c, _, node := journalFixture(t)
	root, err := os.MkdirTemp("", "sfc-local-retry-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	peer := c.Peers[0]
	lookup := func(key sfcp.Identity) (sfcp.Peer, bool) {
		if key == sfcp.Identity(c.Self.Public) {
			return sfcp.Peer{ID: "user", Policy: sfcp.Policy{Key: key, UserAuth: true}}, true
		}
		return peer, key == peer.Key
	}
	server, err := sfcp.NewTransport(node, c.Cluster, lookup)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	binding := Service{Mesh: server, Self: node, Policy: control.Policy{Cluster: c.Cluster}}
	release := make(chan struct{})
	entered := make(chan struct{}, 4)
	var calls atomic.Int32
	err = server.OnManagement(sfcp.User, func(ctx context.Context, conn *sfcp.Session, stream sfcp.Stream, frame sfcp.Frame) error {
		if calls.Add(1) == 1 {
			entered <- struct{}{}
			<-release // the first call hangs until its client gives up
			return nil
		}
		if err := streamEOF(stream); err != nil {
			return err
		}
		return binding.respond(stream, frame, sha256.Sum256(frame.Fields[0].Value), Reply{Schema: 1, Code: "ok"})
	})
	if err != nil {
		t.Fatal(err)
	}
	peer.Endpoint = "unix://" + filepath.Join(root, "api.sock")
	if err = server.ListenUnix(filepath.Join(root, "api.sock")); err != nil {
		t.Fatal(err)
	}
	defer close(release)
	mesh, err := sfcp.NewTransport(c.Self, c.Cluster, lookup)
	if err != nil {
		t.Fatal(err)
	}
	defer mesh.Close()
	c.Mesh = mesh
	envelope := func(*sfcp.Session) (Envelope, error) { return Envelope{Body: []byte(`{}`)}, nil }

	first, cancel := context.WithCancel(context.Background())
	firstDone := make(chan error, 1)
	go func() {
		_, _, err := c.exchange(first, peer, envelope, false)
		firstDone <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first call did not reach the server")
	}
	ctx, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	second := make(chan error, 1)
	go func() {
		reply, _, err := c.exchange(ctx, peer, envelope, false)
		if err == nil && reply.Code != "ok" {
			err = &Error{Code: reply.Code}
		}
		second <- err
	}()
	time.Sleep(200 * time.Millisecond) // the second call waits its turn on the shared connection
	cancel()
	if err := <-firstDone; err == nil {
		t.Fatal("cancelled call succeeded")
	}
	if err := <-second; err != nil {
		t.Fatalf("queued call failed after another call's cancel: %v", err)
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("server saw %d calls, want 2", n)
	}
}
