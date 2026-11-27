// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/wallet"
)

// A saved login that has only run out of time says so, instead of the
// generic private-state error a damaged record gets.
func TestExpiredSavedLoginSaysLogInAgain(t *testing.T) {
	home := t.TempDir()
	password := []byte("wallet storage fixture password")
	disk, err := wallet.OpenDisk(home, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := disk.Init(password); err != nil {
		t.Fatal(err)
	}
	_ = disk.Close()
	issuer, _ := identity.Ephemeral()
	self, _ := identity.Ephemeral()
	defer clear(issuer.Private)
	defer clear(self.Private)
	c := Client{Cluster: [32]byte{42}, Self: self, Peers: []sfcp.Peer{{ID: "node", Endpoint: "127.0.0.1:7443", Policy: sfcp.Policy{Key: sfcp.Identity(issuer.Public), Respond: true}}}}
	store, err := OpenCredentials(home, password)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	now := time.Now().Unix()
	s := access.Session{Schema: 1, ID: "session-a", Cluster: c.Cluster, User: "user-a", Credential: "key", AccountRevision: 1, Key: self.Public, Issuer: issuer.Public, IssuerEpoch: 1, IssuedAt: now, ExpiresAt: now + 1, Scopes: []access.Scope{{Tenant: "*", Actions: []access.Action{access.Read}}}}
	s.Signature = ed25519.Sign(issuer.Private, access.SessionBytes(s))
	if err := store.activate(c, "alice", s); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Until(time.Unix(s.ExpiresAt, 0)) + 100*time.Millisecond)
	if _, err := store.Load(c, "alice"); !errors.Is(err, ErrSessionExpired) {
		t.Fatal("expired login without its message", err)
	}
}
