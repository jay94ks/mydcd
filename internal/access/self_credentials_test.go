// SPDX-License-Identifier: Apache-2.0

package access

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
)

func selfAddition(t *testing.T, c Catalog, who string) (CredentialAddition, ed25519.PrivateKey) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{99}, 32))
	u, _ := c.User(who)
	v := CredentialAddition{User: who, Credential: CredentialKey{ID: "browser", Method: PrivateKey, PublicKey: [32]byte(key.Public().(ed25519.PublicKey))}, Label: "browser only", Challenge: [32]byte{9}}
	v.Proof = ed25519.Sign(key, CredentialAdditionBytes([32]byte{1}, u.Revision, v))
	return v, key
}

func TestSelfCredentialsOwnAccountProofCASAndFieldPreservation(t *testing.T) {
	c := put(t, enrolled(t), "admin", user("alice", false))
	u, _ := c.User("alice")
	u.Credentials = append(u.Credentials, Credential{ID: "password", Method: Password, VerifierRef: "private-backend-reference", Enabled: true})
	c = put(t, c, "admin", u)
	u, _ = c.User("alice")
	v, key := selfAddition(t, c, "alice")
	defer clear(key)
	for _, mutate := range []func(*CredentialAddition){
		func(v *CredentialAddition) { v.Proof = nil }, func(v *CredentialAddition) { v.User = "admin" },
		func(v *CredentialAddition) { v.Label = "other" }, func(v *CredentialAddition) { v.Credential.PublicKey = [32]byte{8} },
		func(v *CredentialAddition) { v.Challenge = [32]byte{} }, func(v *CredentialAddition) { v.Credential.Method = Password },
	} {
		bad := v
		mutate(&bad)
		if _, err := c.AddCredential("alice", [32]byte{1}, u.Revision, bad); err == nil {
			t.Fatal("modified proof/input accepted")
		}
	}
	if _, err := c.AddCredential("alice", [32]byte{2}, u.Revision, v); err == nil {
		t.Fatal("proof crossed clusters")
	}
	if _, err := c.AddCredential("alice", [32]byte{1}, u.Revision+1, v); !errors.Is(err, ErrConflict) {
		t.Fatal("stale CAS", err)
	}
	n, err := c.AddCredential("alice", [32]byte{1}, u.Revision, v)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := n.User("alice")
	if got.Revision <= u.Revision || got.SystemAdmin || !got.Enabled || got.Username != u.Username || len(got.Credentials) != 3 || !got.Credentials[1].Equal(u.Credentials[1]) || got.Credentials[2].Label != v.Label {
		t.Fatal("self edit replaced account/other credential", got)
	}
	if _, err = n.AddCredential("alice", [32]byte{1}, u.Revision, v); !errors.Is(err, ErrConflict) {
		t.Fatal("proof replay", err)
	}
	duplicate := v
	duplicate.Credential.ID = "another"
	duplicate.Proof = ed25519.Sign(key, CredentialAdditionBytes([32]byte{1}, got.Revision, duplicate))
	if _, err = n.AddCredential("alice", [32]byte{1}, got.Revision, duplicate); err == nil {
		t.Fatal("duplicate registered key")
	}
	disabled, err := n.DisableCredential("alice", got.Revision, CredentialDisable{User: "alice", Credential: "browser"})
	if err != nil {
		t.Fatal(err)
	}
	after, _ := disabled.User("alice")
	if after.Credentials[2].Enabled || after.Revision <= got.Revision || after.SystemAdmin {
		t.Fatal("disable did not preserve account")
	}
	if _, err = n.DisableCredential("alice", got.Revision, CredentialDisable{User: "admin", Credential: "key"}); err == nil {
		t.Fatal("cross-account disable")
	}
	if _, err = c.DisableCredential("admin", 1, CredentialDisable{User: "admin", Credential: "key"}); err == nil {
		t.Fatal("last authentication removed")
	}
	encoded, _ := disabled.Encode()
	restored, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	back, _ := restored.Encode()
	if !bytes.Equal(encoded, back) {
		t.Fatal("credential label/projection changed after restore")
	}
	raw, _ := json.Marshal(PublicUserOf(after))
	if bytes.Contains(raw, []byte("VerifierRef")) || bytes.Contains(raw, []byte("private-backend")) {
		t.Fatal("self metadata exposes protected refs")
	}
}

func TestSelfCredentialsNeedExplicitScopeAndKeepIndependentAdminKey(t *testing.T) {
	c := put(t, enrolled(t), "admin", user("alice", false))
	for _, scopes := range [][]Scope{{{Tenant: "*", Actions: []Action{Read}}}, {{Tenant: "*", Actions: []Action{ManageCluster}}}, {{Tenant: "*", Actions: []Action{ManageCredentials}}}} {
		s, issuer, _ := signedSession(c, "alice", "key", scopes)
		err := c.AuthorizeCredentialManagement(s, key(1), issuer, 100, "alice")
		if (err == nil) != (scopes[0].Actions[0] == ManageCredentials) {
			t.Fatal("self scope ceiling", err)
		}
		if c.AuthorizeCredentialManagement(s, key(1), issuer, 100, "admin") == nil {
			t.Fatal("self scope changed another account")
		}
	}
	if ValidateScopes([]Scope{{Tenant: "first", Actions: []Action{ManageCredentials}}}) {
		t.Fatal("tenant-scoped credential escalation")
	}
	admin, _ := c.User("admin")
	admin.Credentials = append(admin.Credentials, Credential{ID: "password", Method: Password, VerifierRef: "private", Enabled: true})
	c = put(t, c, "admin", admin)
	var err error
	c, err = c.SetNodeCLI("admin", 0, true)
	if err != nil {
		t.Fatal(err)
	}
	admin, _ = c.User("admin")
	if _, err = c.DisableCredential("admin", admin.Revision, CredentialDisable{User: "admin", Credential: "key"}); err == nil {
		t.Fatal("last independent admin key removed")
	}
}

// Frozen wire vector includes multibyte UTF-8 and an HTML-escaped JSON byte;
// browser proof bytes must remain independent of JSON string escaping.
func TestSelfCredentialProofFrozenBrowserVector(t *testing.T) {
	change := CredentialAddition{User: "alice", Credential: CredentialKey{ID: "browser", Method: PrivateKey, PublicKey: [32]byte{2}}, Label: "브라우저<", Challenge: [32]byte{3}}
	const expected = "6d7964632d73656c662d63726564656e7469616c2d6164646974696f6e2d3100010000000000000000000000000000000000000000000000000000000000000007000000000000000500000000000000616c696365070000000000000062726f777365720b00000000000000707269766174652d6b65790d00000000000000ebb88ceb9dbcec9ab0eca0803c02000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000"
	if got := hex.EncodeToString(CredentialAdditionBytes([32]byte{1}, 7, change)); got != expected {
		t.Fatal("credential proof wire vector changed")
	}
}
