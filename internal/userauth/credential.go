// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/credentials"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

func credentialLoginBytes(cluster, key, challenge [32]byte, body []byte) []byte {
	b := append([]byte("mydc-user-credential-login-1\x00"), cluster[:]...)
	b = append(b, key[:]...)
	b = append(b, challenge[:]...)
	digest := sha256.Sum256(body)
	return append(b, digest[:]...)
}

func fullUserScopes() []access.Scope {
	return []access.Scope{{Tenant: "*", Actions: []access.Action{access.Read, access.CallService, access.ManageNetwork, access.Deploy, access.ManageSecrets, access.ManageVolumes, access.ManageRoutes, access.ManageServices, access.ManageCD, access.ManageRegistry, access.ManageTrust, access.ManageMembers, access.ManageCluster, access.ManageCredentials, access.NodeShell}}}
}

func (s Service) credential(ctx context.Context, c access.Catalog, binding userBinding, r Request, envelope Envelope, remote string) Reply {
	denied := Reply{Schema: 1, Code: "denied"}
	if s.Credentials == nil || envelope.Session != nil || r.Tenant != "" || r.After != "" || r.Node != "" || r.Proof != nil || r.Operation != nil || r.Enrollment != nil || r.UserKey != ([32]byte{}) {
		return denied
	}
	now := time.Now()
	if r.Method == "credential-challenge" {
		if r.Ticket != nil || len(envelope.Signature) != 0 || r.Secret != nil {
			return denied
		}
		u, ok := c.Username(r.Username)
		if !ok {
			return denied
		}
		selected, err := credentials.Select(u, r.AuthMethod, r.Credential)
		if err != nil {
			return denied
		}
		t := Ticket{Schema: 1, Cluster: s.Policy.Cluster, User: u.ID, Username: u.Username, Credential: selected.ID, AccountRevision: u.Revision, SessionKey: binding.key, Challenge: binding.challenge, Issuer: s.Self.Public, IssuedAt: now.Unix(), Deadline: now.Unix() + 300, AuthMethod: r.AuthMethod, VerifierRef: selected.VerifierRef}
		if _, err = rand.Read(t.Nonce[:]); err != nil {
			return denied
		}
		t.Signature = ed25519.Sign(s.Self.Private, ticketBytes(t))
		return Reply{Schema: 1, Code: "ok", Ticket: &t}
	}
	if r.Method != "credential-login" || r.Ticket == nil || r.AuthMethod != "" || r.Username != "" || r.Credential != "" || len(r.Secret) == 0 || len(r.Secret) > 1024 || !ed25519.Verify(ed25519.PublicKey(binding.key[:]), credentialLoginBytes(s.Policy.Cluster, binding.key, binding.challenge, envelope.Body), envelope.Signature) {
		return denied
	}
	t := *r.Ticket
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
	grant, err := s.Credentials.Verify(ctx, s.Policy.Cluster, u, selected, r.Secret, remote, now)
	if err != nil {
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
	return Reply{Schema: 1, Code: "ok", Session: &session}
}

// LoginCredential sends private material only to the already-pinned ticket
// issuer and original connection challenge. Credential proofs are never
// member-relayed/retried; only explicit pre-ticket leader refusals can retry.
// It is CredentialChallenge then CredentialLogin on the same connection.
func (c Client) LoginCredential(ctx context.Context, target mydcp.Peer, username string, method access.Method, id string, secret []byte) (access.Session, error) {
	if method != access.Password && method != access.Token || len(secret) == 0 || len(secret) > 1024 {
		return access.Session{}, mydcp.ErrAdmission
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
func (c Client) CredentialChallenge(ctx context.Context, target mydcp.Peer, username string, method access.Method, id string) (Ticket, mydcp.Peer, error) {
	if c.Self == nil || method != access.Password && method != access.Token {
		return Ticket{}, target, mydcp.ErrAdmission
	}
	body, err := requestBody(Request{Method: "credential-challenge", Username: username, AuthMethod: method, Credential: id})
	if err != nil {
		return Ticket{}, target, err
	}
	reply, selected, err := c.loginChallenge(ctx, target, body)
	if err != nil {
		return Ticket{}, selected, err
	}
	if reply.Ticket == nil {
		return Ticket{}, selected, mydcp.ErrFrame
	}
	t := *reply.Ticket
	if t.Issuer != [32]byte(selected.Key) || t.Cluster != c.Cluster || t.SessionKey != c.Self.Public || t.Username != username || t.AuthMethod != method || id != "" && t.Credential != id || t.UserKey != ([32]byte{}) || !ed25519.Verify(ed25519.PublicKey(t.Issuer[:]), ticketBytes(t), t.Signature) {
		return Ticket{}, selected, mydcp.ErrAdmission
	}
	return t, selected, nil
}

// CredentialLogin sends secret for a CredentialChallenge ticket to the peer
// that issued it. The secret is never retried or relayed.
func (c Client) CredentialLogin(ctx context.Context, selected mydcp.Peer, t Ticket, secret []byte) (access.Session, error) {
	if c.Self == nil || t.AuthMethod != access.Password && t.AuthMethod != access.Token || len(secret) == 0 || len(secret) > 1024 || t.Issuer != [32]byte(selected.Key) || t.SessionKey != c.Self.Public {
		return access.Session{}, mydcp.ErrAdmission
	}
	body, err := requestBody(Request{Method: "credential-login", Ticket: &t, Secret: secret})
	if err != nil {
		return access.Session{}, err
	}
	defer clear(body)
	reply, _, err := c.exchange(ctx, selected, func(conn *mydcp.Session) (Envelope, error) {
		if conn.PeerChallenge() != t.Challenge {
			return Envelope{}, mydcp.ErrAdmission
		}
		return Envelope{Body: body, Signature: ed25519.Sign(c.Self.Private, credentialLoginBytes(c.Cluster, c.Self.Public, t.Challenge, body))}, nil
	}, false)
	if err != nil {
		return access.Session{}, err
	}
	if reply.Session == nil || reply.Session.User != t.User || reply.Session.Credential != t.Credential || reply.Session.AccountRevision != t.AccountRevision || reply.Session.Issuer != t.Issuer || c.Verify(*reply.Session) != nil {
		return access.Session{}, mydcp.ErrAdmission
	}
	return *reply.Session, nil
}
