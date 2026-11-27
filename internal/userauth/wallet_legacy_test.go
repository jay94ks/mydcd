// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/wallet"
)

// Native storage migration boundary for U0's final batch. Grants/signatures are
// fixture data, not evidence of live login. No host network or daemon is used.
func TestU0LegacyWalletReadbackPreservesOriginalAndSettlesOnce(t *testing.T) {
	home := t.TempDir()
	c, original, raw := migrationFixture(t)
	defer clear(original.Seed[:])
	defer clear(raw)
	root, err := profileRoot(home, c, true)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := writePrivate(root, "session.json", original); err != nil {
		t.Fatal(err)
	}
	password := []byte("U0 original signer migration password")
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
	store, err := OpenCredentials(home, password)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.Load(c, ""); !errors.Is(err, ErrLegacyAccountUnbound) {
		t.Fatal("unverified original username became implicit account", err)
	}
	var reference walletSessionRecord
	if err := readPrivate(root, "session.json", &reference); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reference.Session, original.Session) || !reflect.DeepEqual(reference.Pending, original.Pending) || reference.Profile != original.Profile || reference.Tenant != original.Tenant {
		t.Fatal("migration changed original session/tenant/intent")
	}
	metadata, err := root.ReadFile("session.json")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(metadata)
	if bytes.Contains(metadata, []byte(`"Seed"`)) {
		t.Fatal("plaintext seed survived migration")
	}
	entry, err := store.disk.ReadBack(reference.WalletKey, password)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(entry.Seed[:])
	if entry.Seed != original.Seed {
		t.Fatal("actual installed wallet replaced signer")
	}
	before, err := store.migrateLegacy(c)
	if err != nil {
		t.Fatal(err)
	}
	// Formatting and a different local name for the SAME key cannot resurrect
	// an old pending request after its wallet settlement.
	alias := entry
	defer clear(alias.Seed[:])
	alias.Name = "retained-original-alias"
	if _, err := store.disk.Put(alias); err != nil {
		t.Fatal(err)
	}
	if err := store.disk.Save(password); err != nil {
		t.Fatal(err)
	}
	reference.WalletKey = alias.Name
	if err := writePrivate(root, "session.json", reference); err != nil {
		t.Fatal(err)
	}
	after, err := store.migrateLegacy(c)
	if err != nil || before.id != after.id {
		t.Fatal("alias altered original intent identity", err)
	}
	issuer := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	defer clear(issuer)
	makeLogin := func(username, id string) (Client, access.Session) {
		t.Helper()
		client := c
		client.Self, err = identity.Ephemeral()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { clear(client.Self.Private) })
		now := time.Now().Unix()
		session := original.Session
		session.ID, session.User, session.Key = id, username, client.Self.Public
		session.IssuedAt, session.ExpiresAt = now, now+3600
		session.Signature = ed25519.Sign(issuer, access.SessionBytes(session))
		return client, session
	}
	bob, bobSession := makeLogin("bob", "new-bob-session")
	if err := store.activate(bob, "bob", bobSession); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(c, ""); !errors.Is(err, ErrUserRequired) {
		t.Fatal("unknown original login was hidden by new sole account", err)
	}
	alice, aliceSession := makeLogin("alice", "new-alice-session")
	alice.Username = "alice-login"
	if err := store.activate(alice, alice.Username, aliceSession); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load(alice, alice.Username)
	if err != nil {
		t.Fatal(err)
	}
	clear(loaded.Self.Private)
	if !sameSession(loaded.Session, aliceSession) || loaded.Pending == nil || !bytes.Equal(control.OperationBytes(*loaded.Pending), control.OperationBytes(*original.Pending)) || !bytes.Equal(loaded.Pending.Signature, original.Pending.Signature) {
		t.Fatal("new login erased or re-signed old Unknown operation")
	}
	if err := store.settleLogout(alice, *original.Pending, state.Result{Index: 42, Code: state.Applied}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenCredentials(home, password)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	loaded, err = store.Load(alice, alice.Username)
	if err != nil {
		t.Fatal(err)
	}
	clear(loaded.Self.Private)
	if loaded.Pending != nil || !sameSession(loaded.Session, aliceSession) {
		t.Fatal("old source reattached settled logout or erased new session")
	}
	if _, err := store.Load(c, ""); !errors.Is(err, ErrUserRequired) {
		t.Fatal("settlement silently selected one of two users", err)
	}
}

func TestU0LegacyWalletSourceLockAndForeignCandidatePreserveOrigin(t *testing.T) {
	home := t.TempDir()
	c, original, raw := migrationFixture(t)
	defer clear(original.Seed[:])
	defer clear(raw)
	root, err := profileRoot(home, c, true)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := writePrivate(root, "session.json", original); err != nil {
		t.Fatal(err)
	}
	password := []byte("U0 source CAS collision password")
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
	store, err := OpenCredentials(home, password)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	unlock, err := lockProfile(root)
	if err != nil {
		t.Fatal(err)
	}
	_, migrateErr := store.migrateLegacy(c)
	unlock()
	if migrateErr == nil {
		t.Fatal("migration ignored original writer's lock")
	}
	foreign := []byte("foreign candidate must remain")
	f, err := root.OpenFile("session.json.pending", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(foreign); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.migrateLegacy(c); err == nil {
		t.Fatal("migration replaced foreign candidate")
	}
	unchanged, err := root.ReadFile("session.json")
	defer clear(unchanged)
	if err != nil || !bytes.Equal(unchanged, raw) {
		t.Fatal("failed publication changed original", err)
	}
	got, err := root.ReadFile("session.json.pending")
	if err != nil || !bytes.Equal(got, foreign) {
		t.Fatal("foreign candidate removed", err)
	}
	var decoded privateRecord
	if json.Unmarshal(unchanged, &decoded) != nil || decoded.Seed != original.Seed {
		t.Fatal("source key lost")
	}
	clear(decoded.Seed[:])
}
