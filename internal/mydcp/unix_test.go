// SPDX-License-Identifier: Apache-2.0

package mydcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/identity"
)

// These native cases are prepared for the U0 FINAL validation. Rollback owns
// only the short private temp directory, its socket/listeners and TLS clients;
// no /var/run path, kernel policy, Docker or existing daemon is touched.
func u0UnixPair(t *testing.T) (*Transport, *Transport, Peer, string) {
	t.Helper()
	root, err := os.MkdirTemp("", "mydc-u0-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	})
	a, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	b, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(a.Private); clear(b.Private) })
	path := filepath.Join(root, "management.sock")
	peer := Peer{ID: "server", Endpoint: "unix://" + path, Policy: Policy{Key: Identity(b.Public), Respond: true}}
	lookup := func(key Identity) (Peer, bool) {
		if key == Identity(a.Public) {
			// Even a registered member must not gain Unix Raft/packet access.
			return Peer{ID: "client", Policy: Policy{Key: key, UserAuth: true, Member: true, Snapshot: true, Tunnel: true}}, true
		}
		return peer, key == peer.Key
	}
	server, err := NewTransport(b, [32]byte{17}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewTransport(a, [32]byte{17}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	return server, client, peer, path
}

func u0UserFrame(id uint64, body []byte) Frame {
	digest := sha256.Sum256(body)
	return Frame{Purpose: User, Kind: 1, Request: id, Fields: []Field{{1, true, body}, {2, true, digest[:]}}}
}

func TestU0UnixStopAdmissionBeforeNetworkAndHandlerJoin(t *testing.T) {
	server, client, peer, path := u0UnixPair(t)
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	if err := server.OnManagement(User, func(ctx context.Context, _ *Session, stream Stream, f Frame) error {
		if bytes.Equal(f.Fields[0].Value, []byte("pending")) {
			close(entered)
			<-ctx.Done()
			close(canceled)
			<-release // Model a handler still completing its original work.
			return ctx.Err()
		}
		var extra [1]byte
		if n, err := stream.Read(extra[:]); n != 0 || err != io.EOF {
			return ErrFrame
		}
		f.Kind = 2
		return WriteFrame(stream, f)
	}); err != nil {
		t.Fatal(err)
	}
	if err := server.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	if err := server.ListenUnix(path); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	session, err := client.Dial(ctx, peer)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := session.OpenManagement(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(stream, u0UserFrame(1, []byte("pending"))); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("original request never entered", ctx.Err())
	}
	if err := server.CloseUnix(); err != nil {
		t.Fatal("stop owned local admission", err)
	}
	select {
	case <-canceled:
	case <-ctx.Done():
		t.Fatal("local request context was not canceled", ctx.Err())
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("owned socket left behind while original handler is pending", err)
	}
	if err := server.ListenUnix(path); err == nil {
		t.Fatal("stopped local admission reopened")
	}
	if _, err := ReadFrame(stream, MaxBody); err == nil {
		t.Fatal("stopped local I/O remained active")
	}
	// Peer traffic needed for module closure remains usable through the same
	// authenticated MYDCP transport and handler after Unix admission has ended.
	remote := peer
	remote.Endpoint = server.Addr().String()
	// Use a network client whose pinned endpoint is the network endpoint.
	// The original client's Unix endpoint must retain its strict admission.
	networkClient, err := NewTransport(client.self, client.cluster, func(key Identity) (Peer, bool) {
		p, ok := client.lookupFor(key, Handshake)
		if key == remote.Key {
			p.Endpoint = remote.Endpoint
		}
		return p, ok
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = networkClient.Close() })
	quicSession, err := networkClient.Dial(ctx, remote)
	if err != nil {
		t.Fatal("peer network was closed with the Unix listener", err)
	}
	quicStream, err := quicSession.OpenManagement(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = WriteFrame(quicStream, u0UserFrame(2, []byte("peer-closure"))); err != nil {
		t.Fatal(err)
	}
	if err = quicStream.Close(); err != nil {
		t.Fatal(err)
	}
	reply, err := ReadFrame(quicStream, MaxBody)
	if err != nil || reply.Request != 2 || !bytes.Equal(reply.Fields[0].Value, []byte("peer-closure")) {
		t.Fatal("peer closure traffic unavailable", err)
	}
	quicStream.CancelRead(0)
	done := make(chan error, 1)
	go func() { done <- server.Close() }()
	select {
	case err := <-done:
		t.Fatal("transport abandoned the pending original handler", err)
	case <-time.After(30 * time.Millisecond):
	}
	foreign, err := net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: path})
	if err != nil {
		t.Fatal("released path cannot be rebound", err)
	}
	defer foreign.Close()
	want, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	close(release)
	released = true
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("transport join failed", err)
		}
	case <-ctx.Done():
		t.Fatal("original handler was not joined", ctx.Err())
	}
	if err = server.CloseUnix(); err != nil {
		t.Fatal("local close is not idempotent", err)
	}
	if got, err := os.Lstat(path); err != nil || !os.SameFile(got, want) {
		t.Fatal("later join removed a new listener", err)
	}
}

func TestU0UnixTLSChallengeReuseAndHalfClose(t *testing.T) {
	server, client, peer, path := u0UnixPair(t)
	type observed struct {
		challenge [32]byte
		source    string
	}
	seen := make(chan observed, 3)
	if err := server.OnManagement(User, func(ctx context.Context, s *Session, stream Stream, f Frame) error {
		source, err := s.CredentialSource()
		if err != nil {
			return err
		}
		seen <- observed{s.Challenge(), source}
		var extra [1]byte
		if n, err := stream.Read(extra[:]); n != 0 || err != io.EOF {
			return ErrFrame
		}
		f.Kind = 2
		return WriteFrame(stream, f)
	}); err != nil {
		t.Fatal(err)
	}
	if err := server.ListenUnix(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 {
		t.Fatal("private native socket", info, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	var first *Session
	for index, body := range [][]byte{[]byte("challenge"), []byte("proof"), bytes.Repeat([]byte("x"), 96<<10)} {
		s, err := client.Dial(ctx, peer)
		if err != nil {
			t.Fatal(err)
		}
		if first == nil {
			first = s
		} else if first != s || first.PeerChallenge() != s.PeerChallenge() {
			t.Fatal("ticket binding replaced between exchanges")
		}
		stream, err := s.OpenManagement(ctx)
		if err != nil {
			t.Fatal(err)
		}
		f := u0UserFrame(uint64(index+2), body)
		if err := WriteFrame(stream, f); err != nil {
			t.Fatal(err)
		}
		if err := stream.Close(); err != nil {
			t.Fatal(err)
		}
		reply, err := ReadFrame(stream, MaxBody)
		if err != nil || reply.Request != f.Request || s.Admit(reply, User, false) != nil || !bytes.Equal(reply.Fields[0].Value, body) {
			t.Fatal("read after write EOF", err)
		}
		var extra [1]byte
		if n, err := stream.Read(extra[:]); n != 0 || err != io.EOF {
			t.Fatal("missing exchange EOF", n, err)
		}
		stream.CancelRead(0)
		stream.CancelWrite(0)
		o := <-seen
		if o.challenge != s.PeerChallenge() || o.source != "unix-uid:"+strconv.Itoa(os.Geteuid()) {
			t.Fatal("wrong native binding/rate source", o)
		}
	}
	if _, err := first.Open(ctx); !errors.Is(err, ErrAdmission) {
		t.Fatal("Unix exposed QUIC node stream", err)
	}
	if _, err := first.PacketBudget(); !errors.Is(err, ErrAdmission) {
		t.Fatal("Unix exposed datagram path", err)
	}
	if _, err := first.NativeRouteCurrent(); !errors.Is(err, ErrAdmission) {
		t.Fatal("Unix exposed native route", err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("owned socket remained", err)
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: path})
	if err != nil {
		t.Fatal("listener was not released", err)
	}
	_ = ln.Close()
}

func TestU0UnixRejectsCrossClusterPinNodePurposeAndOversizedRecords(t *testing.T) {
	for _, test := range []string{"cluster", "pin", "raft", "relay", "record"} {
		t.Run(test, func(t *testing.T) {
			server, client, peer, path := u0UnixPair(t)
			if err := server.OnManagement(User, func(context.Context, *Session, Stream, Frame) error {
				t.Error("denied request reached user service")
				return ErrAdmission
			}); err != nil {
				t.Fatal(err)
			}
			if err := server.ListenUnix(path); err != nil {
				t.Fatal(err)
			}
			if test == "cluster" {
				client.cluster = [32]byte{18}
			}
			if test == "pin" {
				peer.Key = Identity{99}
				client.lookup = func(key Identity) (Peer, bool) { return peer, key == peer.Key }
			}
			ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
			defer cancel()
			s, err := client.Dial(ctx, peer)
			if test == "cluster" || test == "pin" {
				if err == nil {
					t.Fatal("untrusted connection admitted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			stream, err := s.OpenManagement(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.CancelRead(0)
			if test == "record" {
				var header [4]byte
				binary.BigEndian.PutUint32(header[:], localRecordMax+1)
				_, _ = s.local.conn.Write(header[:])
			} else {
				f := u0UserFrame(2, []byte("{}"))
				if test == "raft" {
					f.Purpose, f.Fields = Raft, f.Fields[:1]
				} else {
					f.Kind = 3
				}
				_ = WriteFrame(stream, f)
				_ = stream.Close()
			}
			if _, err := ReadFrame(stream, MaxBody); err == nil {
				t.Fatal("forbidden request produced a response")
			}
		})
	}
}

func TestU0UnixPinsOriginalPathInodeThroughListenerClose(t *testing.T) {
	server, _, _, path := u0UnixPair(t)
	if err := server.ListenUnix(path); err != nil {
		t.Fatal(err)
	}
	owned := server.localListeners[0].socket
	if owned == nil || owned.pin == nil {
		t.Fatal("original pathname inode not pinned")
	}
	if err := server.localListeners[0].ln.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	foreign, err := net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: path})
	if err != nil {
		t.Fatal(err)
	}
	foreign.SetUnlinkOnClose(false)
	defer foreign.Close()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	pinned, err := owned.pin.Stat()
	if err != nil || !os.SameFile(pinned, owned.info) || os.SameFile(info, owned.info) {
		t.Fatal("original inode was released/reused before removal", err)
	}
	if err = server.Close(); err == nil {
		t.Fatal("foreign socket replacement was not reported")
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, after) {
		t.Fatal("foreign socket removed", err)
	}
	if _, err = owned.pin.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("original inode descriptor leaked", err)
	}
}

func TestU0UnixPreservesForeignPathsAndInterruptsOwnedConnections(t *testing.T) {
	server, client, peer, path := u0UnixPair(t)
	if err := os.WriteFile(path, []byte("foreign"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := server.ListenUnix(path); err == nil {
		t.Fatal("existing file adopted")
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "foreign" {
		t.Fatal("foreign file changed", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := server.ListenUnix(path); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := client.Dial(ctx, peer)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := s.OpenManagement(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Replace only our test-owned socket; shutdown must preserve this entry.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err == nil {
		t.Fatal("foreign replacement was not reported")
	}
	raw, err = os.ReadFile(path)
	if err != nil || string(raw) != "replacement" {
		t.Fatal("foreign replacement removed", err)
	}
	var one [1]byte
	if _, err := stream.Read(one[:]); err == nil {
		t.Fatal("shutdown left management I/O alive")
	}
	stream.CancelRead(0)
}

// A daemon that crashed leaves its socket file behind with nobody listening.
// The next start replaces it; a live listener on the same path still blocks.
func TestUnixReplacesStaleSocketButNotLiveOne(t *testing.T) {
	server, _, _, path := u0UnixPair(t)
	crashed, err := net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: path})
	if err != nil {
		t.Fatal(err)
	}
	crashed.SetUnlinkOnClose(false)
	if err = crashed.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(path); err != nil {
		t.Fatal("stale socket fixture", err)
	}
	if err = server.ListenUnix(path); err != nil {
		t.Fatal("stale socket blocked startup", err)
	}
	if err = server.Close(); err != nil {
		t.Fatal(err)
	}
	live, err := net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: path})
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	second, _, _, _ := u0UnixPair(t)
	if err = second.ListenUnix(path); err == nil {
		t.Fatal("live daemon socket replaced")
	}
	if _, err = os.Lstat(path); err != nil {
		t.Fatal("live daemon socket removed", err)
	}
}
