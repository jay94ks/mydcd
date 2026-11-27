// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/identity"
)

func TestProtectedPasswordBindsOriginalUserMethodReferenceAndEncoding(t *testing.T) {
	cluster := [32]byte{31}
	ref := "vault/system/system/credentials/alice/password@1"
	password := []byte("private-only-password")
	m, err := NewPassword(cluster, "alice", "password", ref, password, bytes.Repeat([]byte{8}, 16), identity.PasswordCost{Memory: 8 * 1024, Iterations: 1, Threads: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Destroy()
	raw, err := m.ProtectedBytes()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	restored, err := Restore(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Destroy()
	credential := access.Credential{ID: "password", Method: access.Password, VerifierRef: ref, Enabled: true}
	grant, err := restored.Verify(cluster, "alice", credential, password, 10)
	if err != nil || grant.Credential != "password" || grant.ExpiresAt != 0 || grant.Scopes != nil {
		t.Fatal(grant, err)
	}
	clear(raw)
	if _, err := restored.Verify(cluster, "alice", credential, password, 10); err != nil {
		t.Fatal("restored material aliases input", err)
	}
	for _, change := range []func(*access.Credential){func(c *access.Credential) { c.ID = "other" }, func(c *access.Credential) { c.Method = access.Token }, func(c *access.Credential) { c.VerifierRef = ref[:len(ref)-1] + "2" }, func(c *access.Credential) { c.Enabled = false }, func(c *access.Credential) { c.PublicKey = [32]byte{1} }} {
		copy := credential
		change(&copy)
		if _, err := m.Verify(cluster, "alice", copy, password, 10); err == nil {
			t.Fatal("swapped binding accepted")
		}
	}
	for _, input := range []struct {
		cluster  [32]byte
		user     string
		password []byte
		now      int64
	}{{[32]byte{32}, "alice", password, 10}, {cluster, "bob", password, 10}, {cluster, "alice", []byte("wrong"), 10}, {cluster, "alice", password, -1}} {
		if _, err := m.Verify(input.cluster, input.user, credential, input.password, input.now); err == nil {
			t.Fatal("foreign/invalid authentication")
		}
	}
	if _, err := json.Marshal(m); err == nil || fmt.Sprintf("%#v", m) != "[redacted credential material]" {
		t.Fatal("private material leaked to ordinary encoding")
	}
	encoded, _ := m.ProtectedBytes()
	defer clear(encoded)
	for _, bad := range [][]byte{append(bytes.Clone(encoded), ' '), []byte(`{}`), bytes.Replace(encoded, []byte(`"Schema":1`), []byte(`"Schema":1,"Schema":1`), 1), bytes.Replace(encoded, []byte(`"Schema":1`), []byte(`"Schema":2`), 1)} {
		if _, err := Restore(bad); err == nil {
			t.Fatal("noncanonical/unknown private encoding")
		}
	}
}

func TestProtectedTokenExpiryScopesAndPrivateCopies(t *testing.T) {
	cluster := [32]byte{32}
	ref := "vault/system/system/credentials/alice/robot@7"
	token := []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{17}, 32)))
	scopes := []access.Scope{{Tenant: "first", Actions: []access.Action{access.Read}}}
	m, err := NewToken(cluster, "alice", "robot", ref, token, 500, scopes)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Destroy()
	scopes[0].Actions[0] = access.ManageCluster
	credential := access.Credential{ID: "robot", Method: access.Token, VerifierRef: ref, Enabled: true}
	g, err := m.Verify(cluster, "alice", credential, token, 499)
	if err != nil || g.ExpiresAt != 500 || g.Scopes[0].Actions[0] != access.Read {
		t.Fatal("scope widened/alias", g, err)
	}
	g.Scopes[0].Actions[0] = access.ManageCluster
	g, err = m.Verify(cluster, "alice", credential, token, 499)
	if err != nil || g.Scopes[0].Actions[0] != access.Read {
		t.Fatal("grant aliases private scopes", err)
	}
	for _, now := range []int64{500, 501} {
		if _, err := m.Verify(cluster, "alice", credential, token, now); err == nil {
			t.Fatal("expired token")
		}
	}
	wrong := bytes.Clone(token)
	wrong[0] = 'z'
	for _, input := range [][]byte{wrong, []byte("weak"), append(bytes.Clone(token), '=')} {
		if _, err := m.Verify(cluster, "alice", credential, input, 10); err == nil {
			t.Fatal("invalid token")
		}
	}
	if _, err := NewToken(cluster, "alice", "robot", ref, token, 500, []access.Scope{{Tenant: "first", Actions: []access.Action{access.ManageCluster}}}); err == nil {
		t.Fatal("tenant token acquired cluster scope")
	}
	if _, err := NewToken(cluster, "alice", "robot", ref, token, 500, nil); err == nil {
		t.Fatal("implicit unlimited token scope")
	}
	raw, _ := m.ProtectedBytes()
	defer clear(raw)
	if bytes.Contains(raw, token) {
		t.Fatal("raw token was persisted")
	}
	restored, err := Restore(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Destroy()
	if _, err := restored.Verify(cluster, "alice", credential, token, 10); err != nil {
		t.Fatal(err)
	}
}

func TestProtectedReferenceAndAmbiguousCredentialSelection(t *testing.T) {
	valid := "vault/system/system/credentials/alice/password@1"
	ref, err := Reference(valid)
	if err != nil || ref.Profile != "system" || ref.Revision != 1 || ref.Keys[0] != "credential" {
		t.Fatal(ref, err)
	}
	for _, bad := range []string{"system/latest", "vault/system/a@0", "vault/system/a@01", "vault/system/a@latest", "vault/system/../a@1", "vault/system/a//b@1", "vault/system/a%2fb@1", "vault/system/a@2147483648", "vault/system/a@1@2", "vault/system//a@1"} {
		if _, err := Reference(bad); err == nil {
			t.Fatal("noncanonical/provider escape", bad)
		}
	}
	u := access.User{ID: "alice", Enabled: true, Credentials: []access.Credential{{ID: "first", Method: access.Password, VerifierRef: valid, Enabled: true}, {ID: "second", Method: access.Password, VerifierRef: valid, Enabled: true}}}
	if _, err := Select(u, access.Password, ""); err == nil {
		t.Fatal("ambiguous credential selected implicitly")
	}
	if c, err := Select(u, access.Password, "second"); err != nil || c.ID != "second" {
		t.Fatal(c, err)
	}
	u.Credentials[1].Enabled = false
	if c, err := Select(u, access.Password, ""); err != nil || c.ID != "first" {
		t.Fatal(c, err)
	}
	u.Enabled = false
	if _, err := Select(u, access.Password, "first"); err == nil {
		t.Fatal("disabled account")
	}
}
