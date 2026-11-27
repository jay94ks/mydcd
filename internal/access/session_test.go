// SPDX-License-Identifier: Apache-2.0

package access

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"slices"
	"testing"
)

func signingKey(n byte) (public [32]byte, private ed25519.PrivateKey) {
	seed := make([]byte, 32)
	seed[0] = n
	private = ed25519.NewKeyFromSeed(seed)
	copy(public[:], private.Public().(ed25519.PublicKey))
	return
}
func signedSession(c Catalog, user, credential string, scopes []Scope) (Session, Issuer, ed25519.PrivateKey) {
	pub, private := signingKey(9)
	sessionKey, sessionPrivate := signingKey(8)
	u, _ := c.User(user)
	s := Session{Schema: 1, ID: "session-one", Cluster: key(1), User: user, Credential: credential, AccountRevision: u.Revision, Key: sessionKey, Issuer: pub, IssuerEpoch: 1, IssuedAt: 100, ExpiresAt: 200, Scopes: scopes}
	s.Signature = ed25519.Sign(private, SessionBytes(s))
	return s, Issuer{Key: pub, Epoch: 1, Enabled: true}, sessionPrivate
}
func resign(s Session) Session {
	_, k := signingKey(9)
	s.Signature = ed25519.Sign(k, SessionBytes(s))
	return s
}

func TestUserKeyProofBindsAccountClusterChallengeAndSession(t *testing.T) {
	c := enrolled(t)
	public, private := signingKey(7)
	u := user("alice", false)
	u.Credentials[0].PublicKey = public
	c = put(t, c, "admin", u)
	p := KeyProof{Schema: 1, Cluster: key(1), User: "alice", Username: "alice", Credential: "key", Challenge: key(2), SessionKey: key(3), Deadline: 150}
	p.Signature = ed25519.Sign(private, KeyProofBytes(p))
	if err := c.VerifyKeyProof(p, key(1), key(2), 100); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*KeyProof){func(p *KeyProof) { p.Username = "admin" }, func(p *KeyProof) { p.User = "admin" }, func(p *KeyProof) { p.Credential = "missing" }, func(p *KeyProof) { p.Cluster = key(4) }, func(p *KeyProof) { p.Challenge = key(4) }, func(p *KeyProof) { p.SessionKey = [32]byte{} }, func(p *KeyProof) { p.Deadline = 100 }, func(p *KeyProof) { p.Deadline = 500 }} {
		bad := p
		mutate(&bad)
		bad.Signature = ed25519.Sign(private, KeyProofBytes(bad))
		if c.VerifyKeyProof(bad, key(1), key(2), 100) == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	if c.VerifyKeyProof(p, key(1), key(4), 100) == nil {
		t.Fatal("connection replay")
	}
}

func TestSignedSessionIntersectsCurrentRolesAndCredentialScopes(t *testing.T) {
	c := tenant(t, tenant(t, enrolled(t), "first"), "second")
	c = put(t, c, "admin", user("alice", false))
	c = member(t, c, "first", "alice", Manager, true)
	s, issuer, _ := signedSession(c, "alice", "key", []Scope{{Tenant: "*", Actions: []Action{Read, Deploy, ManageCluster}}})
	if c.AuthorizeSession(s, key(1), issuer, 100, "first", Deploy, "") != nil {
		t.Fatal("valid session")
	}
	if c.AuthorizeSession(s, key(1), issuer, 100, "second", Deploy, "") == nil || c.AuthorizeSession(s, key(1), issuer, 100, "", ManageCluster, "") == nil {
		t.Fatal("scope became authority")
	}
	c = member(t, c, "first", "alice", Manager, false)
	if c.AuthorizeSession(s, key(1), issuer, 100, "first", Deploy, "") == nil {
		t.Fatal("membership revocation cached")
	}
	admin, issuer, _ := signedSession(c, "admin", "key", []Scope{{Tenant: "first", Actions: []Action{Read}}})
	if c.AuthorizeSession(admin, key(1), issuer, 100, "first", Read, "") != nil || c.AuthorizeSession(admin, key(1), issuer, 100, "second", Read, "") == nil || c.AuthorizeSession(admin, key(1), issuer, 100, "first", Deploy, "") == nil {
		t.Fatal("limited admin grant widened")
	}
	admin, issuer, _ = signedSession(c, "admin", "key", []Scope{{Tenant: "*", Actions: []Action{ManageCluster}}})
	if c.AuthorizeSession(admin, key(1), issuer, 100, "", ManageCluster, "") != nil {
		t.Fatal("global admin scope")
	}
}

func TestSessionAcceptsFullActionVocabularyWithoutWideningScopes(t *testing.T) {
	c := tenant(t, enrolled(t), "first")
	actions := []Action{Read, CallService, ManageNetwork, Deploy, ManageSecrets, ManageVolumes, ManageRoutes, ManageServices, ManageCD, ManageRegistry, ManageTrust, ManageMembers, ManageCluster, ManageCredentials}
	s, issuer, _ := signedSession(c, "admin", "key", []Scope{{Tenant: "*", Actions: actions}})
	if !ValidateScopes(s.Scopes) || c.VerifyAuthenticationSession(s, key(1), issuer, 100) != nil || c.VerifySession(s, key(1), issuer, 100) != nil {
		t.Fatal("full signed login vocabulary rejected")
	}
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Session
	if err := json.Unmarshal(raw, &decoded); err != nil || !bytes.Equal(SessionBytes(decoded), SessionBytes(s)) || !bytes.Equal(decoded.Signature, s.Signature) || c.VerifySession(decoded, key(1), issuer, 100) != nil {
		t.Fatal("full signed session JSON changed", err)
	}
	if c.AuthorizeSession(decoded, key(1), issuer, 100, "first", CallService, "") != nil {
		t.Fatal("signed service-call action rejected for manager authority")
	}
	limited := s
	limited.Scopes = []Scope{{Tenant: "*", Actions: slices.Delete(slices.Clone(actions), 1, 2)}}
	if c.VerifySession(limited, key(1), issuer, 100) == nil {
		t.Fatal("scope tampering retained original signature")
	}
	limited = resign(limited)
	if c.VerifySession(limited, key(1), issuer, 100) != nil || c.AuthorizeSession(limited, key(1), issuer, 100, "first", Read, "") != nil || c.AuthorizeSession(limited, key(1), issuer, 100, "first", CallService, "") == nil {
		t.Fatal("omitted service-call scope was granted implicitly")
	}
	for _, replacement := range []Action{Action("unknown"), Read} {
		bad := s
		bad.Scopes = []Scope{{Tenant: "*", Actions: slices.Clone(actions)}}
		bad.Scopes[0].Actions[1] = replacement
		bad = resign(bad)
		if ValidateScopes(bad.Scopes) || c.VerifySession(bad, key(1), issuer, 100) == nil {
			t.Fatal("signed unknown or duplicate action accepted", replacement)
		}
	}
	for _, action := range []Action{ManageCluster, ManageCredentials} {
		bad, _, _ := signedSession(c, "admin", "key", []Scope{{Tenant: "first", Actions: []Action{Read, action}}})
		if ValidateScopes(bad.Scopes) || c.VerifySession(bad, key(1), issuer, 100) == nil {
			t.Fatal("global action accepted in tenant scope", action)
		}
	}
}

func TestSessionExpiryIssuerAndAccountRevocation(t *testing.T) {
	c := enrolled(t)
	s, issuer, _ := signedSession(c, "admin", "key", []Scope{{Tenant: "*", Actions: []Action{Read}}})
	for _, mutate := range []func(*Session){func(s *Session) { s.Key = [32]byte{} }, func(s *Session) { s.ExpiresAt = 100 }, func(s *Session) { s.IssuedAt = 100 + MaxClockSkewSeconds + 1 }, func(s *Session) { s.ExpiresAt = 100 + MaxSessionSeconds + 1 }, func(s *Session) { s.AccountRevision++ }, func(s *Session) { s.IssuerEpoch++ }, func(s *Session) { s.Scopes[0].Actions = append(s.Scopes[0].Actions, Read) }} {
		bad, _, _ := signedSession(c, "admin", "key", []Scope{{Tenant: "*", Actions: []Action{Read}}})
		mutate(&bad)
		bad = resign(bad)
		if c.VerifySession(bad, key(1), issuer, 100) == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	if c.VerifySession(s, key(2), issuer, 100) == nil {
		t.Fatal("other cluster")
	}
	issuer.Enabled = false
	if c.VerifySession(s, key(1), issuer, 100) == nil {
		t.Fatal("issuer disabled")
	}
	issuer.Enabled = true
	u, _ := c.User("admin")
	u.Credentials = append(u.Credentials, Credential{ID: "token", Method: Token, VerifierRef: "system/opaque", Enabled: true})
	c = put(t, c, "admin", u)
	if c.VerifySession(s, key(1), issuer, 100) == nil {
		t.Fatal("account policy changed without reauth")
	}
}

func TestSessionProofCannotBeReusedOnAnotherConnectionOrRequest(t *testing.T) {
	s, _, private := signedSession(enrolled(t), "admin", "key", []Scope{{Tenant: "*", Actions: []Action{Read}}})
	body := []byte(`{"tenant":"first","action":"read","nonce":"one"}`)
	signature := ed25519.Sign(private, RequestBytes(s, key(3), body))
	if VerifyRequest(s, key(3), body, signature) != nil {
		t.Fatal("valid request")
	}
	if VerifyRequest(s, key(4), body, signature) == nil || VerifyRequest(s, key(3), append(body, ' '), signature) == nil {
		t.Fatal("request/connection substitution")
	}
	s.ID = "session-two"
	if VerifyRequest(s, key(3), body, signature) == nil {
		t.Fatal("session substitution")
	}
}

func TestIndividualLogoutSurvivesSnapshotWithoutRevokingOtherSessions(t *testing.T) {
	c := enrolled(t)
	one, issuer, _ := signedSession(c, "admin", "key", []Scope{{Tenant: "*", Actions: []Action{Read}}})
	two := one
	two.ID = "session-two"
	two = resign(two)
	n, err := c.RevokeSession("admin", "admin", one.ID, one.AccountRevision)
	if err != nil {
		t.Fatal(err)
	}
	if c.VerifySession(one, key(1), issuer, 100) != nil || n.VerifySession(one, key(1), issuer, 100) == nil || n.VerifySession(two, key(1), issuer, 100) != nil {
		t.Fatal("logout scope")
	}
	b, _ := n.Encode()
	n, err = Decode(b)
	if err != nil || n.VerifySession(one, key(1), issuer, 100) == nil {
		t.Fatal("logout lost on snapshot", err)
	}
	u, _ := n.User("admin")
	n = put(t, n, "admin", u)
	if len(n.revocations) != 0 || n.VerifySession(one, key(1), issuer, 100) == nil || n.VerifySession(two, key(1), issuer, 100) == nil {
		t.Fatal("unsafe tombstone reclamation")
	}
}

func TestAcceptedApplicationGrantPreservesCeilingAndCurrentAuthority(t *testing.T) {
	c := tenant(t, enrolled(t), "first")
	c = put(t, c, "admin", user("alice", false))
	c = member(t, c, "first", "alice", Manager, true)
	s, issuer, _ := signedSession(c, "alice", "key", []Scope{{Tenant: "first", Actions: []Action{Deploy}}})
	u, _ := c.User("alice")
	revoked, err := c.RevokeSession("alice", "alice", s.ID, u.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if revoked.AuthorizeSession(s, key(1), issuer, 101, "first", Deploy, "") == nil {
		t.Fatal("revoked session authenticated new request")
	}
	if revoked.AuthorizeAccepted(s, key(1), 100, "first", Deploy, "") != nil {
		t.Fatal("logout cancelled committed application grant")
	}
	// The accepted instant must lie in the original signed grant, never a new clock.
	if revoked.AuthorizeAccepted(s, key(1), 200, "first", Deploy, "") == nil || revoked.AuthorizeAccepted(s, key(2), 100, "first", Deploy, "") == nil {
		t.Fatal("bad original acceptance")
	}
	if revoked.AuthorizeAccepted(s, key(1), 100, "first", ManageNetwork, "") == nil || revoked.AuthorizeAccepted(s, key(1), 100, "other", Deploy, "") == nil {
		t.Fatal("accepted scope widened")
	}
	removed := member(t, revoked, "first", "alice", Manager, false)
	if removed.AuthorizeAccepted(s, key(1), 100, "first", Deploy, "") == nil {
		t.Fatal("role revocation ignored")
	}
	disabled := u
	disabled.Enabled = false
	disabled.Revision = 0
	changed, err := revoked.replaceUser(u.Revision, disabled)
	if err != nil {
		t.Fatal(err)
	}
	if changed.AuthorizeAccepted(s, key(1), 100, "first", Deploy, "") == nil {
		t.Fatal("account revocation ignored")
	}
	disabled = u
	disabled.Revision = 0
	disabled.Credentials[0].Enabled = false
	// Retain a second credential so the account keeps one authentication method.
	disabled.Credentials = append(disabled.Credentials, Credential{ID: "other", Method: PrivateKey, PublicKey: key(22), Enabled: true})
	changed, err = revoked.replaceUser(u.Revision, disabled)
	if err != nil {
		t.Fatal(err)
	}
	if changed.AuthorizeAccepted(s, key(1), 100, "first", Deploy, "") == nil {
		t.Fatal("credential revision ignored")
	}
}
