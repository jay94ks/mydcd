// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

// Relay preserves the ingress proof context and binds the attestation to ONE
// approved destination and its fresh connection. It never carries user rights.
type Relay struct {
	Node, Target, Caller, Challenge, Connection [32]byte
	Signature                                   []byte
	ServiceCall                                 *ServiceCallRelay `json:",omitempty"`
}

type userBinding struct{ key, challenge [32]byte }

func sameSession(a, b access.Session) bool {
	// SessionBytes intentionally omits the separately signed user approval.
	// Exact request/original identity includes that approval as well.
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

// RelayBytes is the canonical signing payload. A missing relay has no payload.
func RelayBytes(cluster [32]byte, envelope Envelope) []byte {
	if envelope.Relay == nil {
		return nil
	}
	r := *envelope.Relay
	r.Signature = nil
	envelope.Relay = nil
	raw, _ := json.Marshal(struct {
		Relay    Relay
		Envelope Envelope
	}{r, envelope})
	b := append([]byte("mydc-user-relay-1\x00"), cluster[:]...)
	return append(b, raw...)
}

func (s Service) binding(conn *mydcp.Session, kind uint8, envelope Envelope) (userBinding, error) {
	b := userBinding{key: [32]byte(conn.Peer().Key), challenge: conn.Challenge()}
	if kind == 3 {
		r := envelope.Relay
		peer, current := s.Mesh.Peer(conn.Peer().Key)
		if r == nil || !current || !peer.Member || r.Node != [32]byte(conn.Peer().Key) || r.Target != s.Self.Public || r.Connection != conn.Challenge() || r.Caller == ([32]byte{}) || r.Challenge == ([32]byte{}) || !ed25519.Verify(ed25519.PublicKey(r.Node[:]), RelayBytes(s.Policy.Cluster, envelope), r.Signature) {
			return userBinding{}, mydcp.ErrAdmission
		}
		b = userBinding{key: r.Caller, challenge: r.Challenge}
	} else if envelope.Relay != nil {
		return userBinding{}, mydcp.ErrAdmission
	}
	if envelope.Session != nil {
		if envelope.Session.Key != b.key || access.VerifyRequest(*envelope.Session, b.challenge, envelope.Body, envelope.Signature) != nil {
			return userBinding{}, mydcp.ErrAdmission
		}
	} else if kind == 3 {
		return userBinding{}, mydcp.ErrAdmission
	}
	return b, nil
}

func (s Service) forward(ctx context.Context, envelope Envelope, binding userBinding) Reply {
	reply := Reply{Schema: 1, Code: "unavailable"}
	peer, ok := s.Engine.LeaderPeer()
	if !ok || [32]byte(peer.Key) == s.Self.Public {
		return reply
	}
	client := Client{Mesh: s.Mesh, Self: s.Self, Cluster: s.Policy.Cluster}
	forwarded, _, err := client.exchangeKind(ctx, peer, func(conn *mydcp.Session) (Envelope, error) {
		copy := envelope
		copy.Relay = &Relay{Node: s.Self.Public, Target: [32]byte(peer.Key), Caller: binding.key, Challenge: binding.challenge, Connection: conn.PeerChallenge()}
		copy.Relay.Signature = ed25519.Sign(s.Self.Private, RelayBytes(s.Policy.Cluster, copy))
		return copy, nil
	}, false, 3)
	if err == nil {
		forwarded.RelayedBy = s.Self.Actor()
		return forwarded
	}
	var failed *Error
	if errors.As(err, &failed) {
		if failed.Phase == mydcp.Completed {
			forwarded.RelayedBy = s.Self.Actor()
			return forwarded
		}
		if failed.Phase == mydcp.Unknown {
			reply.Code = "unknown"
		}
	}
	return reply
}
