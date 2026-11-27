// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"slices"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// A private-key login in three steps for a client whose user key is held
// elsewhere (the sfc-web daemon relays a browser's signatures):
//
//  1. KeyLoginChallenge asks the issuer for a Ticket bound to this client's
//     session key (c.Self) and to the challenge of the connection it used.
//  2. The key holder signs KeyLoginProof(ticket) (access.KeyProofBytes).
//  3. KeyLogin sends the proof to the SAME peer. The issuer accepts it only on
//     the connection that produced the ticket, so this must happen while the
//     cached connection is still reusable; otherwise it fails before sending.
//
// KeyLogin returns the issued session without a user approval. The key holder
// then signs access.SessionApprovalBytes for access.IssuedSessionDigest(session)
// and access.AttachSessionApproval adds it, as access.ApproveSession does for a
// local key. Login performs all steps with a local key.

// KeyLoginChallenge returns a verified Ticket and the peer that issued it.
func (c Client) KeyLoginChallenge(ctx context.Context, target sfcp.Peer, username string, userKey [32]byte) (Ticket, sfcp.Peer, error) {
	if c.Self == nil || userKey == ([32]byte{}) {
		return Ticket{}, target, sfcp.ErrAdmission
	}
	hello, err := sessionlessRequest(ChallengeMethod, ChallengeQuery{Username: username, UserKey: userKey})
	if err != nil {
		return Ticket{}, target, err
	}
	reply, selected, err := c.loginChallenge(ctx, target, hello)
	ticket, ok := replyData[Ticket](reply)
	if err != nil || !ok {
		if err == nil {
			err = sfcp.ErrFrame
		}
		return Ticket{}, selected, fmt.Errorf("login challenge request: %w", err)
	}
	if !c.loginIssuer(ticket.Issuer, selected, reply) || ticket.Cluster != c.Cluster || ticket.SessionKey != c.Self.Public || ticket.UserKey != userKey || ticket.Username != username || !ed25519.Verify(ed25519.PublicKey(ticket.Issuer[:]), ticketBytes(ticket), ticket.Signature) {
		return Ticket{}, selected, fmt.Errorf("login challenge ticket binding/signature: %w", sfcp.ErrAdmission)
	}
	return ticket, selected, nil
}

// KeyLoginProof is the unsigned proof the user key signs for ticket.
func (c Client) KeyLoginProof(ticket Ticket) access.KeyProof {
	var session [32]byte
	if c.Self != nil {
		session = c.Self.Public
	}
	return access.KeyProof{Schema: 1, Cluster: c.Cluster, User: ticket.User, Username: ticket.Username, Credential: ticket.Credential, Challenge: ticket.Challenge, SessionKey: session, Deadline: ticket.Deadline}
}

// KeyLogin sends a signed proof for ticket to selected, the peer
// KeyLoginChallenge returned. The proof must be exactly KeyLoginProof(ticket)
// signed by ticket.UserKey; anything else is refused before sending.
func (c Client) KeyLogin(ctx context.Context, selected sfcp.Peer, ticket Ticket, proof access.KeyProof) (access.Session, error) {
	if c.Self == nil || ticket.SessionKey != c.Self.Public {
		return access.Session{}, fmt.Errorf("login ticket binding: %w", sfcp.ErrAdmission)
	}
	signature := proof.Signature
	want := c.KeyLoginProof(ticket)
	if !bytes.Equal(access.KeyProofBytes(proof), access.KeyProofBytes(want)) || !ed25519.Verify(ed25519.PublicKey(ticket.UserKey[:]), access.KeyProofBytes(want), signature) {
		return access.Session{}, fmt.Errorf("login proof binding/signature: %w", sfcp.ErrAdmission)
	}
	want.Signature = signature
	login, err := sessionlessRequest(LoginMethod, KeyLoginQuery{Ticket: ticket, Proof: want, LoginClient: LoginClientFrom(ctx)})
	if err != nil {
		return access.Session{}, err
	}
	reply, _, err := c.exchange(ctx, selected, func(conn *sfcp.Session) (Envelope, error) {
		if conn.PeerChallenge() != ticket.Challenge {
			return Envelope{}, fmt.Errorf("login connection challenge changed: %w", sfcp.ErrAdmission)
		}
		return Envelope{Body: login}, nil
	}, false)
	session, ok := replyData[access.Session](reply)
	if err != nil || !ok {
		if err == nil {
			err = sfcp.ErrFrame
		}
		return access.Session{}, fmt.Errorf("login proof request: %w", err)
	}
	if session.User != ticket.User || session.Credential != ticket.Credential || session.AccountRevision != ticket.AccountRevision || session.Issuer != ticket.Issuer || !c.loginIssuer(session.Issuer, selected, reply) {
		return access.Session{}, fmt.Errorf("login issued session account binding: %w", sfcp.ErrAdmission)
	}
	if !c.pinned(session.Issuer) {
		// The pinned node relayed the login and names the issuer from its
		// committed members; this client trusts it from now on, or not at all.
		issuer := vouchedIssuer(reply)
		if c.TrustIssuer == nil {
			return access.Session{}, &UntrustedIssuerError{Node: issuer.ID, Key: hex.EncodeToString(session.Issuer[:])}
		}
		if err := c.TrustIssuer(issuer); err != nil {
			return access.Session{}, fmt.Errorf("login issuer trust: %w", err)
		}
		c.Peers = append(slices.Clone(c.Peers), issuer)
	}
	now := time.Now().Unix()
	if err := c.verifyAt(session, now); err != nil {
		if session.IssuedAt > now && c.verifyAt(session, session.IssuedAt) == nil {
			return access.Session{}, fmt.Errorf("login issuer clock is %d seconds ahead of client: %w", session.IssuedAt-now, err)
		}
		return access.Session{}, fmt.Errorf("login issued session validation: %w", err)
	}
	return session, nil
}

// pinned reports whether key is a node this client trusts.
func (c Client) pinned(key [32]byte) bool {
	return slices.ContainsFunc(c.Peers, func(p sfcp.Peer) bool { return [32]byte(p.Key) == key })
}

// loginIssuer reports whether a login reply from selected may carry a ticket
// or session issued by key: selected itself, another pinned node, or the
// session issuer selected names after relaying the login to it.
func (c Client) loginIssuer(key [32]byte, selected sfcp.Peer, reply Reply) bool {
	if key == [32]byte(selected.Key) || c.pinned(key) {
		return true
	}
	return c.pinned([32]byte(selected.Key)) && reply.SessionIssuer != nil && reply.SessionIssuer.Key == hex.EncodeToString(key[:]) && reply.SessionIssuer.ID != "" && reply.SessionIssuer.Endpoint != ""
}

func vouchedIssuer(reply Reply) sfcp.Peer {
	key, _ := hex.DecodeString(reply.SessionIssuer.Key)
	return sfcp.Peer{ID: reply.SessionIssuer.ID, Endpoint: reply.SessionIssuer.Endpoint, Policy: sfcp.Policy{Key: sfcp.Identity(key), Respond: true}}
}

// UntrustedIssuerError: a login relayed by a trusted node was issued by a
// node this client does not trust, and nothing here can record the trust.
type UntrustedIssuerError struct {
	Node, Key string
}

func (e *UntrustedIssuerError) Error() string {
	key := e.Key
	if len(key) > 16 {
		key = key[:16]
	}
	return fmt.Sprintf("login: the session was issued by node %s (key %s...), which this client does not trust; trust that node, then log in again", e.Node, key)
}

func (e *UntrustedIssuerError) Is(target error) bool { return target == sfcp.ErrAdmission }

// keyLogin answers challenge and login on the issuer (serve; a member that
// issues no sessions relays them instead, forwardLogin).
func (s Service) keyLogin(c access.Catalog, binding userBinding, r Request, envelope Envelope) Reply {
	reply := Reply{Schema: 1, Code: "denied"}
	if !s.Policy.Issuer(s.Self.Public).Enabled {
		return Reply{Schema: 1, Code: "not-session-issuer"}
	}
	if envelope.Session != nil || len(envelope.Signature) != 0 {
		return reply
	}
	now := time.Now().Unix()
	if q, ok := paramsOf(r, ChallengeMethod); ok {
		u, ok := c.Username(q.Username)
		if !ok || !u.Enabled {
			return reply
		}
		for _, credential := range u.Credentials {
			if credential.Enabled && credential.Method == access.PrivateKey && credential.PublicKey == q.UserKey {
				t := Ticket{Schema: 1, Cluster: s.Policy.Cluster, User: u.ID, Username: u.Username, Credential: credential.ID, AccountRevision: u.Revision, SessionKey: binding.key, UserKey: q.UserKey, Challenge: binding.challenge, Issuer: s.Self.Public, IssuedAt: now, Deadline: now + 300}
				if _, err := rand.Read(t.Nonce[:]); err != nil {
					return reply
				}
				t.Signature = ed25519.Sign(s.Self.Private, ticketBytes(t))
				return sessionlessReply(t)
			}
		}
		return reply
	}
	q, ok := paramsOf(r, LoginMethod)
	if !ok {
		return reply
	}
	t, proof := q.Ticket, q.Proof
	if t.Schema != 1 || t.Cluster != s.Policy.Cluster || t.Issuer != s.Self.Public || t.SessionKey != binding.key || t.Challenge != binding.challenge || t.Nonce == ([32]byte{}) || t.IssuedAt > now || t.Deadline <= now || t.Deadline-t.IssuedAt != 300 || !ed25519.Verify(ed25519.PublicKey(s.Self.Public[:]), ticketBytes(t), t.Signature) {
		return reply
	}
	u, exists := c.User(t.User)
	if !exists || u.Revision != t.AccountRevision || proof.User != t.User || proof.Username != t.Username || proof.Credential != t.Credential || proof.SessionKey != t.SessionKey || proof.Deadline != t.Deadline || c.VerifyKeyProof(proof, s.Policy.Cluster, binding.challenge, now) != nil {
		return reply
	}
	// Private-key credentials authenticate the account; every request still
	// intersects this ceiling with CURRENT roles/membership and revocations.
	session := access.Session{Schema: 1, ID: "s" + hex.EncodeToString(t.Nonce[:16]), Cluster: s.Policy.Cluster, User: u.ID, Credential: t.Credential, AccountRevision: u.Revision, Key: t.SessionKey, Issuer: s.Self.Public, IssuerEpoch: 1, IssuedAt: t.IssuedAt, ExpiresAt: t.IssuedAt + access.MaxSessionSeconds, Scopes: fullUserScopes()}
	session.Signature = ed25519.Sign(s.Self.Private, access.SessionBytes(session))
	if c.VerifyAuthenticationSession(session, s.Policy.Cluster, s.Policy.Issuer(s.Self.Public), now) != nil {
		return reply
	}
	return sessionlessReply(session)
}
