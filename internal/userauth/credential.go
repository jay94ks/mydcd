// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/credentials"
	"github.com/jay94ks/seafield/internal/sfcp"
)

func credentialLoginBytes(cluster, key, challenge [32]byte, body []byte) []byte {
	b := append([]byte("sfc-user-credential-login-1\x00"), cluster[:]...)
	b = append(b, key[:]...)
	b = append(b, challenge[:]...)
	digest := sha256.Sum256(body)
	return append(b, digest[:]...)
}

func fullUserScopes() []access.Scope {
	return []access.Scope{{Tenant: "*", Actions: []access.Action{access.Read, access.CallService, access.ManageNetwork, access.Deploy, access.ManageSecrets, access.ManageVolumes, access.ManageRoutes, access.ManageServices, access.ManageCD, access.ManageRegistry, access.ManageTrust, access.ManageMembers, access.ManageCluster, access.ManageCredentials, access.NodeShell}}}
}

func (s Service) credential(ctx context.Context, c access.Catalog, binding userBinding, r Request, envelope Envelope, remote string) (reply Reply) {
	denied := Reply{Schema: 1, Code: "denied"}
	if s.Credentials == nil || envelope.Session != nil {
		return denied
	}
	now := time.Now()
	if q, ok := paramsOf(r, CredentialChallengeMethod); ok {
		if len(envelope.Signature) != 0 {
			return denied
		}
		u, ok := c.Username(q.Username)
		if !ok {
			return denied
		}
		selected, err := credentials.Select(u, q.AuthMethod, q.Credential)
		if err != nil {
			return denied
		}
		// A builtin record opens only on a voter. Send the client to the
		// leader before it sends any secret; nothing private is relayed.
		if !s.Credentials.Ready(selected.VerifierRef) {
			if s.Engine != nil && !s.Engine.IsLeader() {
				if _, id := s.Engine.Leader(); id != "" {
					return Reply{Schema: 1, Code: "not-leader", Leader: string(id)}
				}
			}
			return Reply{Schema: 1, Code: "unavailable"}
		}
		t := Ticket{Schema: 1, Cluster: s.Policy.Cluster, User: u.ID, Username: u.Username, Credential: selected.ID, AccountRevision: u.Revision, SessionKey: binding.key, Challenge: binding.challenge, Issuer: s.Self.Public, IssuedAt: now.Unix(), Deadline: now.Unix() + 300, AuthMethod: q.AuthMethod, VerifierRef: selected.VerifierRef}
		if _, err = rand.Read(t.Nonce[:]); err != nil {
			return denied
		}
		t.Signature = ed25519.Sign(s.Self.Private, ticketBytes(t))
		return sessionlessReply(t)
	}
	q, ok := paramsOf(r, CredentialLoginMethod)
	defer clear(q.Secret)
	if !ok || !ed25519.Verify(ed25519.PublicKey(binding.key[:]), credentialLoginBytes(s.Policy.Cluster, binding.key, binding.challenge, envelope.Body), envelope.Signature) {
		return denied
	}
	// From here the ticket is this node's own (checked again before
	// recording), so the outcome is part of that account's login history.
	reason := "denied"
	defer func() { s.recordLogin(&q.Ticket, q.LoginClient, remote, reply, reason) }()
	t := q.Ticket
	if t.Schema != 1 || t.Cluster != s.Policy.Cluster || t.Issuer != s.Self.Public || t.SessionKey != binding.key || t.UserKey != ([32]byte{}) || t.Challenge != binding.challenge || t.Nonce == ([32]byte{}) || t.IssuedAt > now.Unix() || t.Deadline <= now.Unix() || t.Deadline-t.IssuedAt != 300 || !ed25519.Verify(ed25519.PublicKey(s.Self.Public[:]), ticketBytes(t), t.Signature) {
		return denied
	}
	u, known := c.User(t.User)
	selected, err := credentials.Select(u, t.AuthMethod, t.Credential)
	if !known || err != nil || u.Username != t.Username || u.Revision != t.AccountRevision || selected.VerifierRef != t.VerifierRef {
		return denied
	}
	if remote == "" {
		return denied
	}
	grant, err := s.Credentials.Verify(ctx, s.Policy.Cluster, u, selected, q.Secret, remote, now)
	if err != nil {
		if errors.Is(err, credentials.ErrThrottled) {
			reason = "throttled"
		}
		return denied
	}
	// Provider/KDF work can overlap credential, membership or leader changes.
	// Only the latest quorum-backed policy may issue a session after that work.
	view, err := s.authenticationView(ctx)
	if err != nil {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	p, err := s.Policy.Current(view.State)
	if err != nil {
		return denied
	}
	current, err := p.Catalog(view.State)
	if err != nil {
		return denied
	}
	live, known := current.User(u.ID)
	check, err := credentials.Select(live, t.AuthMethod, t.Credential)
	now = time.Now()
	if !known || err != nil || live.Revision != t.AccountRevision || !check.Equal(selected) || now.Unix() >= t.Deadline {
		return denied
	}
	if !s.nodeLoginAllowed(view.State, current, live.ID) {
		return denied
	}
	expires := t.IssuedAt + access.MaxSessionSeconds
	scopes := grant.Scopes
	if selected.Method == access.Password {
		scopes = fullUserScopes()
	}
	if grant.ExpiresAt != 0 && grant.ExpiresAt < expires {
		expires = grant.ExpiresAt
	}
	session := access.Session{Schema: 1, ID: "s" + hex.EncodeToString(t.Nonce[:16]), Cluster: p.Cluster, User: live.ID, Credential: grant.Credential, AccountRevision: live.Revision, Key: binding.key, Issuer: s.Self.Public, IssuerEpoch: 1, IssuedAt: t.IssuedAt, ExpiresAt: expires, Scopes: scopes}
	session.Signature = ed25519.Sign(s.Self.Private, access.SessionBytes(session))
	if current.VerifyAuthenticationSession(session, p.Cluster, p.Issuer(s.Self.Public), now.Unix()) != nil {
		return denied
	}
	return sessionlessReply(session)
}

// LoginCredential sends private material only to the already-pinned ticket
// issuer and original connection challenge. Credential proofs are never
// member-relayed/retried; only explicit pre-ticket leader refusals can retry.
// It is CredentialChallenge then CredentialLogin on the same connection.
func (c Client) LoginCredential(ctx context.Context, target sfcp.Peer, username string, method access.Method, id string, secret []byte) (access.Session, error) {
	if method != access.Password && method != access.Token || len(secret) == 0 || len(secret) > 1024 {
		return access.Session{}, sfcp.ErrAdmission
	}
	t, selected, err := c.CredentialChallenge(ctx, target, username, method, id)
	if err != nil {
		return access.Session{}, err
	}
	return c.CredentialLogin(ctx, selected, t, secret)
}

// CredentialChallenge asks for a password or token login ticket. The ticket
// is bound to selected's connection challenge and this client's session key;
// send the secret with CredentialLogin to selected before the connection is
// replaced (a new connection needs a new ticket).
func (c Client) CredentialChallenge(ctx context.Context, target sfcp.Peer, username string, method access.Method, id string) (Ticket, sfcp.Peer, error) {
	if c.Self == nil || method != access.Password && method != access.Token {
		return Ticket{}, target, sfcp.ErrAdmission
	}
	body, err := sessionlessRequest(CredentialChallengeMethod, CredentialChallengeQuery{Username: username, AuthMethod: method, Credential: id})
	if err != nil {
		return Ticket{}, target, err
	}
	reply, selected, err := c.loginChallenge(ctx, target, body)
	if err != nil {
		return Ticket{}, selected, err
	}
	t, ok := replyData[Ticket](reply)
	if !ok {
		return Ticket{}, selected, sfcp.ErrFrame
	}
	if t.Issuer != [32]byte(selected.Key) || t.Cluster != c.Cluster || t.SessionKey != c.Self.Public || t.Username != username || t.AuthMethod != method || id != "" && t.Credential != id || t.UserKey != ([32]byte{}) || !ed25519.Verify(ed25519.PublicKey(t.Issuer[:]), ticketBytes(t), t.Signature) {
		return Ticket{}, selected, sfcp.ErrAdmission
	}
	return t, selected, nil
}

// CredentialLogin sends secret for a CredentialChallenge ticket to the peer
// that issued it. The secret is never retried or relayed.
func (c Client) CredentialLogin(ctx context.Context, selected sfcp.Peer, t Ticket, secret []byte) (access.Session, error) {
	if c.Self == nil || t.AuthMethod != access.Password && t.AuthMethod != access.Token || len(secret) == 0 || len(secret) > 1024 || t.Issuer != [32]byte(selected.Key) || t.SessionKey != c.Self.Public {
		return access.Session{}, sfcp.ErrAdmission
	}
	body, err := sessionlessRequest(CredentialLoginMethod, CredentialLoginQuery{Ticket: t, Secret: secret, LoginClient: LoginClientFrom(ctx)})
	if err != nil {
		return access.Session{}, err
	}
	defer clear(body)
	reply, _, err := c.exchange(ctx, selected, func(conn *sfcp.Session) (Envelope, error) {
		if conn.PeerChallenge() != t.Challenge {
			return Envelope{}, sfcp.ErrAdmission
		}
		return Envelope{Body: body, Signature: ed25519.Sign(c.Self.Private, credentialLoginBytes(c.Cluster, c.Self.Public, t.Challenge, body))}, nil
	}, false)
	if err != nil {
		return access.Session{}, err
	}
	session, ok := replyData[access.Session](reply)
	if !ok || session.User != t.User || session.Credential != t.Credential || session.AccountRevision != t.AccountRevision || session.Issuer != t.Issuer || c.Verify(session) != nil {
		return access.Session{}, sfcp.ErrAdmission
	}
	return session, nil
}
