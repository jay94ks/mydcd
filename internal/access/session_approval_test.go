// SPDX-License-Identifier: Apache-2.0

package access

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"
)

func approvalFixture(t *testing.T, method Method) (Catalog, Session, Issuer, ed25519.PrivateKey) {
	t.Helper()
	public, private := signingKey(7)
	c := tenant(t, enrolled(t), "tenant")
	u := user("alice", false)
	u.Credentials[0].PublicKey = public
	u.Credentials = append(u.Credentials,
		Credential{ID: "password", Method: Password, VerifierRef: "password-backend", Enabled: true},
		Credential{ID: "token", Method: Token, VerifierRef: "token-backend", Enabled: true})
	c = put(t, c, "admin", u)
	c = member(t, c, "tenant", "alice", Manager, true)
	id := "key"
	if method != PrivateKey {
		id = string(method)
	}
	s, issuer, _ := signedSession(c, "alice", id, []Scope{{Tenant: "tenant", Actions: []Action{Read, Deploy}}})
	return c, s, issuer, private
}

func TestSessionApprovalKeepsAuthenticationCredentialAndScopeCeiling(t *testing.T) {
	for _, method := range []Method{PrivateKey, Password, Token} {
		t.Run(string(method), func(t *testing.T) {
			c, original, issuer, private := approvalFixture(t, method)
			before, _ := json.Marshal(original)
			approved, err := ApproveSession(original, private)
			if err != nil || c.VerifySessionApproval(approved) != nil || c.VerifySession(approved, original.Cluster, issuer, 110) != nil {
				t.Fatal("registered user approval was rejected", err)
			}
			if !bytes.Equal(SessionBytes(original), SessionBytes(approved)) || !bytes.Equal(original.Signature, approved.Signature) || original.Approval != nil || original.Credential != approved.Credential {
				t.Fatal("approval rewrote the issuer grant or authentication method")
			}
			if c.AuthorizeSession(approved, original.Cluster, issuer, 110, "tenant", Deploy, "") != nil || c.AuthorizeSession(approved, original.Cluster, issuer, 110, "tenant", ManageSecrets, "") == nil || c.AuthorizeSession(approved, original.Cluster, issuer, 110, "other", Deploy, "") == nil {
				t.Fatal("approval widened scopes or tenant authority")
			}
			var restored Session
			raw, _ := json.Marshal(approved)
			if err := json.Unmarshal(raw, &restored); err != nil || c.VerifySessionApproval(restored) != nil {
				t.Fatal("approval did not survive the wallet/wire JSON form", err)
			}
			legacy, _ := json.Marshal(original)
			if !bytes.Equal(legacy, before) || bytes.Contains(legacy, []byte(`"Approval"`)) {
				t.Fatal("unapproved schema-1 session bytes changed")
			}
		})
	}
}

func TestSessionApprovalRejectsIssuerRewritesAndDifferentUserKeys(t *testing.T) {
	c, original, issuer, private := approvalFixture(t, Token)
	approved, err := ApproveSession(original, private)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Session){
		func(s *Session) { s.Schema++ },
		func(s *Session) { s.ID = "another-session" },
		func(s *Session) { s.Cluster[0]++ },
		func(s *Session) { s.User = "admin" },
		func(s *Session) { s.Credential = "password" },
		func(s *Session) { s.AccountRevision++ },
		func(s *Session) { s.Key[0]++ },
		func(s *Session) { s.Issuer[0]++ },
		func(s *Session) { s.IssuerEpoch++ },
		func(s *Session) { s.IssuedAt-- },
		func(s *Session) { s.ExpiresAt++ },
		func(s *Session) { s.Scopes = []Scope{{Tenant: "*", Actions: []Action{ManageCluster}}} },
		func(s *Session) { s.Signature = bytes.Repeat([]byte{1}, 64) },
	} {
		bad := approved
		mutate(&bad)
		// A compromised issuer can re-sign the rewritten grant. That must not
		// make an unchanged independent user delegation valid for that grant.
		if bad.Issuer == issuer.Key && bytes.Equal(bad.Signature, approved.Signature) {
			bad = resign(bad)
		}
		if c.VerifySessionApproval(bad) == nil {
			t.Fatal("issuer-only rewrite reused user approval", bad.ID)
		}
	}
	for _, seed := range []byte{6, 9} { // unregistered user key and issuer key
		_, other := signingKey(seed)
		bad, err := ApproveSession(original, other)
		if err != nil || c.VerifySessionApproval(bad) == nil || c.VerifySession(bad, original.Cluster, issuer, 110) == nil {
			t.Fatal("unregistered key approval was accepted", seed, err)
		}
	}
	if c.VerifySessionApproval(original) == nil {
		t.Fatal("issuer signature alone proved user approval")
	}
	corrupt := *approved.Approval
	corrupt.Signature = bytes.Repeat([]byte{2}, 64)
	approved.Approval = &corrupt
	if c.VerifySessionApproval(approved) == nil {
		t.Fatal("corrupt approval signature accepted")
	}
}

func TestSessionApprovalRechecksRegistrationAndPreservesAcceptedTimeBoundary(t *testing.T) {
	c, s, issuer, private := approvalFixture(t, Password)
	s, err := ApproveSession(s, private)
	if err != nil {
		t.Fatal(err)
	}
	if c.VerifySession(s, s.Cluster, issuer, s.ExpiresAt) == nil || c.AuthorizeAccepted(s, s.Cluster, 110, "tenant", Deploy, "") != nil {
		t.Fatal("current expiry and committed grant were confused")
	}
	u, _ := c.User("alice")
	u.Credentials[0].Enabled = false // password remains a valid login method
	expected := u.Revision
	u.Revision = 0
	n, err := c.PutUser("admin", expected, u)
	if err != nil || n.VerifySessionApproval(s) == nil || n.AuthorizeAccepted(s, s.Cluster, 110, "tenant", Deploy, "") == nil {
		t.Fatal("credential/account revocation was cached", err)
	}
	if c.VerifySessionApproval(s) != nil {
		t.Fatal("immutable original catalog changed")
	}
	if _, err := ApproveSession(s, ed25519.PrivateKey{1}); err == nil {
		t.Fatal("invalid signer accepted")
	}
	s = resign(s)
	s.Signature[0] ^= 1
	if _, err := ApproveSession(s, private); err == nil {
		t.Fatal("client approved an invalid issuer grant")
	}
}
