// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

// A private-key login in three steps for a client whose user key is held
// elsewhere (the mydc-web daemon relays a browser's signatures):
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
func (c Client) KeyLoginChallenge(ctx context.Context, target mydcp.Peer, username string, userKey [32]byte) (Ticket, mydcp.Peer, error) {
	if c.Self == nil || userKey == ([32]byte{}) {
		return Ticket{}, target, mydcp.ErrAdmission
	}
	hello, err := requestBody(Request{Method: "challenge", Username: username, UserKey: userKey})
	if err != nil {
		return Ticket{}, target, err
	}
	reply, selected, err := c.loginChallenge(ctx, target, hello)
	if err != nil || reply.Ticket == nil {
		if err == nil {
			err = mydcp.ErrFrame
		}
		return Ticket{}, selected, fmt.Errorf("login challenge request: %w", err)
	}
	ticket := *reply.Ticket
	if ticket.Issuer != [32]byte(selected.Key) || ticket.Cluster != c.Cluster || ticket.SessionKey != c.Self.Public || ticket.UserKey != userKey || ticket.Username != username || !ed25519.Verify(ed25519.PublicKey(ticket.Issuer[:]), ticketBytes(ticket), ticket.Signature) {
		return Ticket{}, selected, fmt.Errorf("login challenge ticket binding/signature: %w", mydcp.ErrAdmission)
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
func (c Client) KeyLogin(ctx context.Context, selected mydcp.Peer, ticket Ticket, proof access.KeyProof) (access.Session, error) {
	if c.Self == nil || ticket.SessionKey != c.Self.Public || ticket.Issuer != [32]byte(selected.Key) {
		return access.Session{}, fmt.Errorf("login ticket binding: %w", mydcp.ErrAdmission)
	}
	signature := proof.Signature
	want := c.KeyLoginProof(ticket)
	if !bytes.Equal(access.KeyProofBytes(proof), access.KeyProofBytes(want)) || !ed25519.Verify(ed25519.PublicKey(ticket.UserKey[:]), access.KeyProofBytes(want), signature) {
		return access.Session{}, fmt.Errorf("login proof binding/signature: %w", mydcp.ErrAdmission)
	}
	want.Signature = signature
	login, err := requestBody(Request{Method: "login", Ticket: &ticket, Proof: &want})
	if err != nil {
		return access.Session{}, err
	}
	reply, _, err := c.exchange(ctx, selected, func(conn *mydcp.Session) (Envelope, error) {
		if conn.PeerChallenge() != ticket.Challenge {
			return Envelope{}, fmt.Errorf("login connection challenge changed: %w", mydcp.ErrAdmission)
		}
		return Envelope{Body: login}, nil
	}, false)
	if err != nil || reply.Session == nil {
		if err == nil {
			err = mydcp.ErrFrame
		}
		return access.Session{}, fmt.Errorf("login proof request: %w", err)
	}
	session := *reply.Session
	if session.User != ticket.User || session.Credential != ticket.Credential || session.AccountRevision != ticket.AccountRevision {
		return access.Session{}, fmt.Errorf("login issued session account binding: %w", mydcp.ErrAdmission)
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
