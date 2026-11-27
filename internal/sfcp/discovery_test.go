// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/identity"
)

// Prepared for U0 final validation. Only owned private temp sockets/loopback
// UDP, ephemeral TLS identities and their goroutines are created and closed.
func TestU0PublicDiscoveryUnixQUICWithoutAccountOrNodeAdmission(t *testing.T) {
	root, err := os.MkdirTemp("", "sfc-u0-discovery-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	})
	self, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(self.Private) })
	cluster := [32]byte{55}
	server, err := NewTransport(self, cluster, func(Identity) (Peer, bool) { return Peer{}, false })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	if err := server.EnableDiscovery("public-node"); err != nil {
		t.Fatal(err)
	}
	if err := server.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "management.sock")
	if err := server.ListenUnix(path); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	for _, endpoint := range []struct{ network, address string }{{"unix", path}, {"sfcp", server.Addr().String()}} {
		public, err := Discover(ctx, endpoint.network, endpoint.address)
		if err != nil || public.Cluster != cluster || public.Key != self.Public || public.Node != "public-node" {
			t.Fatal("public identity", endpoint.network, public, err)
		}
		// Public discovery approval must not replace ordinary TLS key approval.
		caller, err := identity.Ephemeral()
		if err != nil {
			t.Fatal(err)
		}
		peer := Peer{ID: "public-node", Endpoint: endpoint.address, Policy: Policy{Key: Identity(self.Public), Respond: true}}
		if endpoint.network == "unix" {
			peer.Endpoint = "unix://" + endpoint.address
		}
		client, err := NewTransport(caller, cluster, func(key Identity) (Peer, bool) { return peer, key == peer.Key })
		if err != nil {
			t.Fatal(err)
		}
		if session, err := client.Dial(ctx, peer); err == nil {
			_ = session.RetirePath()
			t.Error("discovery granted ordinary admission")
		}
		_ = client.Close()
		clear(caller.Private)
	}
}

func TestU0DiscoveryRejectsProofFromDifferentNonceKeyNodeOrTLSConnection(t *testing.T) {
	for _, mutation := range []string{"nonce", "key", "node", "cluster", "exporter", "signature"} {
		t.Run(mutation, func(t *testing.T) {
			root, err := os.MkdirTemp("", "sfc-u0-proof-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(root) })
			server, err := identity.Ephemeral()
			if err != nil {
				t.Fatal(err)
			}
			client, err := identity.Ephemeral()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { clear(server.Private); clear(client.Private) })
			path := filepath.Join(root, "proof.sock")
			ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = ln.Close() })
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			finished := make(chan error, 1)
			done := make(chan struct{})
			t.Cleanup(func() { cancel(); _ = ln.Close(); <-done })
			go func() {
				defer close(done)
				c, err := ln.AcceptUnix()
				if err != nil {
					finished <- err
					return
				}
				defer c.Close()
				stop := context.AfterFunc(ctx, func() { _ = c.Close() })
				defer stop()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				config := server.TLS(true, func([32]byte) bool { return true })
				config.NextProtos = []string{discoveryALPN}
				secure := tls.Server(c, config)
				if err := secure.HandshakeContext(ctx); err != nil {
					finished <- err
					return
				}
				request, err := ReadFrame(secure, 4096)
				if err != nil {
					finished <- err
					return
				}
				var nonce [32]byte
				copy(nonce[:], request.Fields[0].Value)
				peer := PublicIdentity{Cluster: [32]byte{1}, Key: server.Public, Node: "server"}
				binding, err := discoveryBinding(secure.ConnectionState())
				if err != nil {
					finished <- err
					return
				}
				if mutation == "exporter" {
					_, _ = rand.Read(binding)
				}
				signature := ed25519.Sign(server.Private, discoveryProof(peer, client.Public, nonce, binding))
				switch mutation {
				case "nonce":
					nonce[0] ^= 1
				case "key":
					peer.Key[0] ^= 1
				case "node":
					peer.Node = "other-server"
				case "cluster":
					peer.Cluster[0] ^= 1
				case "signature":
					signature[0] ^= 1
				}
				frame := Frame{Purpose: Handshake, Kind: 4, Request: 1, Fields: []Field{{Tag: 1, Required: true, Value: peer.Key[:]}, {Tag: 2, Required: true, Value: peer.Cluster[:]}, {Tag: 3, Required: true, Value: nonce[:]}, {Tag: 4, Required: true, Value: []byte(peer.Node)}, {Tag: 5, Required: true, Value: signature}}}
				finished <- WriteFrame(secure, frame)
			}()
			c, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			config := client.TLS(false, func([32]byte) bool { return true })
			config.NextProtos = []string{discoveryALPN}
			secure := tls.Client(c, config)
			if err := secure.HandshakeContext(ctx); err != nil {
				t.Fatal(err)
			}
			if peer, err := readDiscovery(secure, secure.ConnectionState(), client.Public); err == nil || peer != (PublicIdentity{}) {
				t.Fatal("mismatched proof accepted", peer, err)
			}
			if err := <-finished; err != nil && err != io.EOF {
				t.Fatal(err)
			}
		})
	}
}

func TestU0DiscoveryALPNNeverDispatchesManagementFrames(t *testing.T) {
	root, err := os.MkdirTemp("", "sfc-u0-public-only-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	self, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	caller, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(self.Private); clear(caller.Private) })
	server, err := NewTransport(self, [32]byte{31}, func(key Identity) (Peer, bool) {
		return Peer{ID: "caller", Policy: Policy{Key: key, UserAuth: true, Manage: true, Read: true, Member: true}}, true
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	if err := server.EnableDiscovery("server"); err != nil {
		t.Fatal(err)
	}
	if err := server.OnManagement(User, func(context.Context, *Session, Stream, Frame) error {
		t.Error("public ALPN reached authenticated management handler")
		return ErrAdmission
	}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "management.sock")
	if err := server.ListenUnix(path); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	for _, initialDiscovery := range []bool{false, true} {
		c, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
		if err != nil {
			t.Fatal(err)
		}
		config := caller.TLS(false, func(key [32]byte) bool { return key == self.Public })
		config.NextProtos = []string{discoveryALPN}
		secure := tls.Client(c, config)
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if err := secure.HandshakeContext(ctx); err != nil {
			_ = c.Close()
			t.Fatal(err)
		}
		if initialDiscovery {
			if _, err := readDiscovery(secure, secure.ConnectionState(), caller.Public); err != nil {
				_ = c.Close()
				t.Fatal(err)
			}
		}
		_ = WriteFrame(secure, u0UserFrame(2, []byte("{}")))
		if _, err := ReadFrame(secure, MaxBody); err == nil {
			_ = c.Close()
			t.Fatal("public ALPN produced a management reply")
		}
		_ = c.Close()
	}
}
