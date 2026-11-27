// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/sfcp"
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
	b := append([]byte("sfc-user-relay-1\x00"), cluster[:]...)
	return append(b, raw...)
}

func (s Service) binding(conn *sfcp.Session, kind uint8, envelope Envelope) (userBinding, error) {
	return s.relayBinding(conn, kind, envelope, false)
}

// relayBinding is binding that, with login set, also takes a relayed
// sessionless private-key login (challenge or login) from a member node
// that cannot issue sessions itself: the caller key and connection
// challenge come from the relay, as for any other relayed request.
func (s Service) relayBinding(conn *sfcp.Session, kind uint8, envelope Envelope, login bool) (userBinding, error) {
	b := userBinding{key: [32]byte(conn.Peer().Key), challenge: conn.Challenge()}
	if kind == 3 {
		r := envelope.Relay
		peer, current := s.Mesh.Peer(conn.Peer().Key)
		if r == nil || !current || !peer.Member || r.Node != [32]byte(conn.Peer().Key) || r.Target != s.Self.Public || r.Connection != conn.Challenge() || r.Caller == ([32]byte{}) || r.Challenge == ([32]byte{}) || !ed25519.Verify(ed25519.PublicKey(r.Node[:]), RelayBytes(s.Policy.Cluster, envelope), r.Signature) {
			return userBinding{}, sfcp.ErrAdmission
		}
		b = userBinding{key: r.Caller, challenge: r.Challenge}
	} else if envelope.Relay != nil {
		return userBinding{}, sfcp.ErrAdmission
	}
	if envelope.Session != nil {
		if envelope.Session.Key != b.key || access.VerifyRequest(*envelope.Session, b.challenge, envelope.Body, envelope.Signature) != nil {
			return userBinding{}, sfcp.ErrAdmission
		}
	} else if kind == 3 && (!login || len(envelope.Signature) != 0) {
		return userBinding{}, sfcp.ErrAdmission
	}
	return b, nil
}

// forwardLogin relays a private-key login (challenge or login) from this
// member, which cannot issue sessions, to the leader when view holds the
// leader as a session issuer, and names it in the reply.
func (s Service) forwardLogin(ctx context.Context, view state.State, envelope Envelope, binding userBinding) Reply {
	members, err := s.Policy.Members(view)
	if err != nil {
		return Reply{Schema: 1, Code: "not-session-issuer"}
	}
	if !members.MemberKey(s.Self.Public) {
		// Just installed: this node's view has not reached its own admission
		// yet, so the login challenge retries rather than ends here.
		return Reply{Schema: 1, Code: "not-leader"}
	}
	// No known leader, or one this node's view does not yet hold as a session
	// issuer (just after joining, or during an election): "not-leader", which
	// a login challenge retries, rather than a final refusal.
	peer, ok := s.Engine.LeaderPeer()
	if ok && [32]byte(peer.Key) == s.Self.Public {
		return Reply{Schema: 1, Code: "not-session-issuer"} // an isolated leader
	}
	var issuer *config.Peer
	for _, e := range members.Entries {
		if current := e.CurrentPeer(); ok && membership.FullMember(e) && current.Key == hex.EncodeToString(peer.Key[:]) {
			issuer = &current
		}
	}
	if issuer == nil || !nodeSessionIssuer([32]byte(peer.Key), members) {
		return Reply{Schema: 1, Code: "not-leader"}
	}
	reply := s.forward(ctx, envelope, binding)
	if reply.Code == "ok" {
		reply.SessionIssuer = issuer
	}
	return reply
}

// forward relays a request to the leader over this node's connection to it
// (one the leader opened counts too), as caller binding.
func (s Service) forward(ctx context.Context, envelope Envelope, binding userBinding) Reply {
	reply := Reply{Schema: 1, Code: "unavailable"}
	peer, ok := s.Engine.LeaderPeer()
	if !ok || [32]byte(peer.Key) == s.Self.Public {
		return reply
	}
	client := Client{Mesh: s.Mesh, Self: s.Self, Cluster: s.Policy.Cluster}
	forwarded, _, err := client.exchangeKind(ctx, peer, func(conn *sfcp.Session) (Envelope, error) {
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
		if failed.Phase == sfcp.Completed {
			forwarded.RelayedBy = s.Self.Actor()
			return forwarded
		}
		if failed.Phase == sfcp.Unknown {
			reply.Code = "unknown"
		}
	}
	return reply
}
