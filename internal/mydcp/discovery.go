// SPDX-License-Identifier: Apache-2.0

package mydcp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jay94ks/mydcd/internal/identity"
	quic "github.com/quic-go/quic-go"
)

const discoveryALPN = "mydcp-discovery-1"

// PublicIdentity proves possession of the peer TLS key on this connection.
// It grants no first trust, directory/membership authority or account access.
type PublicIdentity struct {
	Cluster, Key [32]byte
	Node         string
}

func publicNodeName(name string) bool {
	// Public node identity is not a local profile filename. Preserve installed
	// node IDs; the CLI separately validates the names it can register locally.
	if len(name) < 1 || len(name) > 128 || !utf8.ValidString(name) || strings.ContainsAny(name, "/\\") {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

// EnableDiscovery must run before any listener/dial starts. Discovery serves
// only this node's public identity, never an unverified directory of other keys.
func (t *Transport) EnableDiscovery(node string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !publicNodeName(node) || t.closed || t.publicNode != "" || t.underlay != nil || len(t.localListeners) != 0 || len(t.localConnections) != 0 || len(t.dials) != 0 {
		return ErrAdmission
	}
	t.publicNode = node
	return nil
}

func (t *Transport) serverTLS() *tls.Config {
	c := t.self.TLS(true, func(key [32]byte) bool { _, ok := t.lookupFor(Identity(key), Handshake); return ok })
	if t.publicNode == "" {
		return c
	}
	c.NextProtos = []string{"mydcp-go-1", discoveryALPN}
	approved := c.VerifyConnection
	c.VerifyConnection = func(state tls.ConnectionState) error {
		if state.NegotiatedProtocol == discoveryALPN {
			_, err := identity.PeerKey(state)
			return err
		}
		return approved(state)
	}
	return c
}

func discoveryProof(peer PublicIdentity, client, nonce [32]byte, binding []byte) []byte {
	b := append([]byte("mydc-public-discovery-1\x00"), peer.Cluster[:]...)
	b = append(b, peer.Key[:]...)
	b = append(b, client[:]...)
	b = append(b, nonce[:]...)
	b = append(b, binding...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(peer.Node)))
	return append(b, peer.Node...)
}

func discoveryBinding(state tls.ConnectionState) ([]byte, error) {
	if state.NegotiatedProtocol != discoveryALPN {
		return nil, ErrAdmission
	}
	return state.ExportKeyingMaterial(discoveryALPN, nil, 32)
}

func (t *Transport) serveDiscovery(stream io.ReadWriter, state tls.ConnectionState) error {
	if t.publicNode == "" {
		return ErrAdmission
	}
	select {
	case t.publicSlots <- struct{}{}:
	default:
		return ErrBudget
	}
	defer func() { <-t.publicSlots }()
	client, err := identity.PeerKey(state)
	if err != nil {
		return err
	}
	binding, err := discoveryBinding(state)
	if err != nil {
		return err
	}
	f, err := ReadFrame(stream, 4096)
	if err != nil {
		return err
	}
	if f.Purpose != Handshake || f.Kind != 3 || f.Request != 1 {
		return ErrAdmission
	}
	var nonce [32]byte
	copy(nonce[:], f.Fields[0].Value)
	if nonce == [32]byte{} {
		return ErrAdmission
	}
	peer := PublicIdentity{Cluster: t.cluster, Key: t.self.Public, Node: t.publicNode}
	signature := ed25519.Sign(t.self.Private, discoveryProof(peer, client, nonce, binding))
	reply := Frame{Purpose: Handshake, Kind: 4, Request: 1, Fields: []Field{
		{1, true, peer.Key[:]}, {2, true, peer.Cluster[:]}, {3, true, nonce[:]}, {4, true, []byte(peer.Node)}, {5, true, signature},
	}}
	if err := WriteFrame(stream, reply); err != nil {
		return err
	}
	// Discovery has no transition into an authenticated management session.
	// Wait for the client to finish receiving the response before closing QUIC;
	// all I/O is bounded by the caller's five-second handshake deadline.
	var extra [1]byte
	_, _ = stream.Read(extra[:])
	return nil
}

func readDiscovery(stream io.ReadWriter, state tls.ConnectionState, client [32]byte) (PublicIdentity, error) {
	server, err := identity.PeerKey(state)
	if err != nil {
		return PublicIdentity{}, err
	}
	binding, err := discoveryBinding(state)
	if err != nil {
		return PublicIdentity{}, err
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return PublicIdentity{}, err
	}
	if err := WriteFrame(stream, Frame{Purpose: Handshake, Kind: 3, Request: 1, Fields: []Field{{1, true, nonce[:]}}}); err != nil {
		return PublicIdentity{}, err
	}
	f, err := ReadFrame(stream, 4096)
	if err != nil {
		return PublicIdentity{}, err
	}
	if f.Purpose != Handshake || f.Kind != 4 || f.Request != 1 {
		return PublicIdentity{}, ErrAdmission
	}
	var peer PublicIdentity
	copy(peer.Key[:], f.Fields[0].Value)
	copy(peer.Cluster[:], f.Fields[1].Value)
	peer.Node = string(f.Fields[3].Value)
	if peer.Key != server || peer.Cluster == [32]byte{} || !publicNodeName(peer.Node) || !bytes.Equal(f.Fields[2].Value, nonce[:]) || !ed25519.Verify(ed25519.PublicKey(server[:]), discoveryProof(peer, client, nonce, binding), f.Fields[4].Value) {
		return PublicIdentity{}, ErrAdmission
	}
	return peer, nil
}

// Discover uses only a fresh, in-memory TLS key. The caller must explicitly
// approve the returned identity before saving pins or sending user credentials.
// network/address are supplied by the strict CLI endpoint parser; no fallback
// protocol, default host or alternate cluster is attempted on failure.
func Discover(ctx context.Context, network, address string) (PublicIdentity, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	self, err := identity.Ephemeral()
	if err != nil {
		return PublicIdentity{}, err
	}
	defer clear(self.Private)
	config := self.TLS(false, func([32]byte) bool { return true })
	config.NextProtos = []string{discoveryALPN}
	deadline, _ := ctx.Deadline()
	switch network {
	case "unix":
		if ValidateManagementSocket(address) != nil {
			return PublicIdentity{}, ErrAdmission
		}
		c, err := (&net.Dialer{}).DialContext(ctx, "unix", address)
		if err != nil {
			return PublicIdentity{}, err
		}
		defer c.Close()
		stop := context.AfterFunc(ctx, func() { _ = c.Close() })
		defer stop()
		if err := c.SetDeadline(deadline); err != nil {
			return PublicIdentity{}, err
		}
		secure := tls.Client(c, config)
		if err := secure.HandshakeContext(ctx); err != nil {
			return PublicIdentity{}, err
		}
		return readDiscovery(secure, secure.ConnectionState(), self.Public)
	case "mydcp":
		remote, err := resolveUDP(ctx, address)
		if err != nil {
			return PublicIdentity{}, err
		}
		c, err := quic.DialAddr(ctx, remote.String(), config, quicConfig())
		if err != nil {
			return PublicIdentity{}, err
		}
		defer c.CloseWithError(0, "discovery finished")
		stop := context.AfterFunc(ctx, func() { _ = c.CloseWithError(1, "discovery cancelled") })
		defer stop()
		stream, err := c.OpenStreamSync(ctx)
		if err != nil {
			return PublicIdentity{}, err
		}
		defer stream.CancelRead(0)
		if err := stream.SetDeadline(deadline); err != nil {
			return PublicIdentity{}, err
		}
		return readDiscovery(stream, c.ConnectionState().TLS, self.Public)
	default:
		return PublicIdentity{}, errors.New("unknown MYDCP discovery transport")
	}
}

func (t *Transport) serveQUICDiscovery(conn *quic.Conn) {
	defer t.forget(conn)
	defer conn.CloseWithError(0, "public discovery finished")
	ctx, cancel := context.WithTimeout(t.ctx, 5*time.Second)
	defer cancel()
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		t.serverFailure("quic", "discovery-accept", Identity{}, Frame{}, err)
		return
	}
	defer stream.CancelRead(0)
	deadline, _ := ctx.Deadline()
	if err := stream.SetDeadline(deadline); err != nil {
		t.serverFailure("quic", "discovery-deadline", Identity{}, Frame{}, err)
		return
	}
	if err := t.serveDiscovery(stream, conn.ConnectionState().TLS); err != nil {
		t.serverFailure("quic", "discovery", Identity{}, Frame{}, err)
	}
}
