// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/wallet"
)

// These cases cover real encrypted storage/selection, not remote login. The
// signed grants are fixtures. Actual CLI/daemon login is a separate U0 boundary.
func TestU0SavedWalletAccountsCoexistAndRequireExplicitUser(t *testing.T) {
	home := t.TempDir()
	password := []byte("wallet storage fixture password")
	disk, err := wallet.OpenDisk(home, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := disk.Init(password); err != nil {
		t.Fatal(err)
	}
	if err := disk.Close(); err != nil {
		t.Fatal(err)
	}
	issuer, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	alice, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	bob, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(issuer.Private)
	defer clear(alice.Private)
	defer clear(bob.Private)
	c := Client{Cluster: [32]byte{42}, Peers: []sfcp.Peer{{ID: "node", Endpoint: "127.0.0.1:7443", Policy: sfcp.Policy{Key: sfcp.Identity(issuer.Public), Respond: true}}}}
	store, err := OpenCredentials(home, password)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	if _, err := store.Load(c, ""); !errors.Is(err, ErrLoginRequired) {
		t.Fatal("empty wallet silently selected a user", err)
	}
	makeSession := func(self *identity.Identity, user, id string) access.Session {
		now := time.Now().Unix()
		s := access.Session{Schema: 1, ID: id, Cluster: c.Cluster, User: user, Credential: "key", AccountRevision: 1, Key: self.Public, Issuer: issuer.Public, IssuerEpoch: 1, IssuedAt: now, ExpiresAt: now + 3600, Scopes: []access.Scope{{Tenant: "*", Actions: []access.Action{access.Read}}}}
		s.Signature = ed25519.Sign(issuer.Private, access.SessionBytes(s))
		return s
	}
	c.Self = alice
	a := makeSession(alice, "stable-user-a", "session-a")
	if err := store.activate(c, "alice", a); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load(c, "")
	if err != nil || loaded.Username != "alice" || loaded.Session.User != "stable-user-a" || loaded.Self.Public != alice.Public {
		t.Fatal("single account", err)
	}
	clear(loaded.Self.Private)
	c.Self = bob
	b := makeSession(bob, "stable-user-b", "session-b")
	if err := store.activate(c, "bob", b); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(c, ""); !errors.Is(err, ErrUserRequired) {
		t.Fatal("most recent login became an implicit default", err)
	}
	if _, err := store.Load(c, "missing"); !errors.Is(err, ErrLoginRequired) {
		t.Fatal("unknown --user fell back", err)
	}
	for _, username := range []string{"alice", "bob"} {
		loaded, err := store.Load(c, username)
		if err != nil || loaded.Username != username {
			t.Fatal(username, err)
		}
		clear(loaded.Self.Private)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenCredentials(home, password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(c, ""); !errors.Is(err, ErrUserRequired) {
		t.Fatal("reopen reset ambiguous accounts", err)
	}
	raw, err := os.ReadFile(filepath.Join(home, ".sfc", "wallet.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("stable-user-a")) || bytes.Contains(raw, []byte("alice")) || bytes.Contains(raw, alice.Private.Seed()) {
		t.Fatal("login credential was not encrypted")
	}
	if _, err := os.Stat(filepath.Join(home, ".sfc", "sessions")); !os.IsNotExist(err) {
		t.Fatal("new login created a plaintext session file", err)
	}
}
