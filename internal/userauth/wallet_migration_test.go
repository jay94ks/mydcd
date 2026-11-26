// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/wallet"
)

func migrationFixture(t *testing.T) (Client, privateRecord, []byte) {
	t.Helper()
	issuer := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	defer clear(issuer)
	seed := [32]byte{6}
	key := ed25519.NewKeyFromSeed(seed[:])
	defer clear(key)
	var pub, issuerPub [32]byte
	copy(pub[:], key[32:])
	copy(issuerPub[:], issuer[32:])
	c := Client{Cluster: [32]byte{1}, Self: &identity.Identity{Public: pub}, Peers: []mydcp.Peer{{ID: "node-a", Endpoint: "127.0.0.1:7443", Policy: mydcp.Policy{Key: mydcp.Identity(issuerPub)}}}}
	s := access.Session{Schema: 1, ID: "session-original", Cluster: c.Cluster, User: "alice", Credential: "key", AccountRevision: 1, Key: pub, Issuer: issuerPub, IssuerEpoch: 1, IssuedAt: 100, ExpiresAt: 200, Scopes: []access.Scope{{Tenant: "tenant-a", Actions: []access.Action{access.Read}}}}
	s.Signature = ed25519.Sign(issuer, access.SessionBytes(s))
	payload, _ := json.Marshal(control.SessionRevocation{User: s.User, Session: s.ID})
	pending := control.UserOperation{Schema: 1, Session: s, At: 150, Epoch: 2, RequestID: "original-logout", RootRevision: 17, Change: control.Change{Schema: 1, Action: "revoke-session", Principal: s.User, Payload: payload}}
	pending.Signature = ed25519.Sign(key, control.OperationBytes(pending))
	if pending.VerifyOriginal(c.Cluster) != nil {
		t.Fatal("bad original request fixture")
	}
	r := privateRecord{Schema: 1, Profile: c.Profile(), Session: s, Seed: seed, Tenant: "tenant-a", Pending: &pending}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return c, r, raw
}
func TestSessionWalletMigrationPreservesOriginalSignerAndUnknownIntent(t *testing.T) {
	c, original, raw := migrationFixture(t)
	defer clear(original.Seed[:])
	defer clear(raw)
	migration, err := PlanSessionMigration(c, raw)
	if err != nil {
		t.Fatal(err)
	}
	defer migration.Close()
	entry := migration.Entry()
	defer clear(entry.Seed[:])
	if entry.Seed != original.Seed || entry.Public() != original.Session.Key || migration.ExpectedSource() != sha256.Sum256(raw) {
		t.Fatal("original signer replaced")
	}
	// Interrupted wallet write/readback cannot publish a reference.
	for _, wrong := range []wallet.Entry{{}, {Name: entry.Name, Seed: [32]byte{99}}, {Name: "other", Seed: entry.Seed}} {
		if b, err := migration.CommitRecord(raw, wrong); err == nil || b != nil {
			t.Fatal("unverified wallet key published")
		}
	}
	if b, err := migration.CommitRecord(append(bytes.Clone(raw), ' '), entry); err == nil || b != nil {
		t.Fatal("source CAS silently rebased")
	}
	metadata, err := migration.CommitRecord(raw, entry)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(metadata)
	var fields map[string]json.RawMessage
	if json.Unmarshal(metadata, &fields) != nil {
		t.Fatal("metadata")
	}
	if _, ok := fields["Seed"]; ok {
		t.Fatal("plaintext seed retained")
	}
	var record walletSessionRecord
	if strict(metadata, &record) != nil {
		t.Fatal("noncanonical reference")
	}
	if !reflect.DeepEqual(record.Session, original.Session) || !reflect.DeepEqual(record.Pending, original.Pending) || record.Tenant != original.Tenant || record.Profile != original.Profile {
		t.Fatal("origin/Unknown request changed")
	}
	before, err := original.Pending.Command()
	if err != nil {
		t.Fatal(err)
	}
	after, err := record.Pending.Command()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("request actor/id/CAS/signature changed")
	}
	name, pub, err := SessionWalletReference(c, metadata)
	if err != nil || name != entry.Name || pub != entry.Public() {
		t.Fatal(name, err)
	}
	if _, err := PlanSessionMigration(c, metadata); err == nil {
		t.Fatal("reference treated as new plaintext seed")
	}
	if _, err := json.Marshal(migration); err == nil || fmt.Sprintf("%+v", migration) != "[redacted session migration]" {
		t.Fatal("migration leaks seed")
	}
	migration.Close()
	if b, err := migration.CommitRecord(raw, entry); err == nil || b != nil {
		t.Fatal("closed migration reused")
	}
}
func TestSessionMigrationRejectsWrongProfileOrTamperedOriginal(t *testing.T) {
	c, r, raw := migrationFixture(t)
	defer clear(r.Seed[:])
	defer clear(raw)
	wrong := c
	wrong.Cluster[0] ^= 1
	if _, err := PlanSessionMigration(wrong, raw); err == nil {
		t.Fatal("another cluster adopted original session")
	}
	for _, mut := range []func(*privateRecord){
		func(r *privateRecord) { r.Seed[0]++ },
		func(r *privateRecord) { r.Session.User = "bob" },
		func(r *privateRecord) { r.Pending.RootRevision++ },
		func(r *privateRecord) { r.Pending.RequestID = "new-id" },
		func(r *privateRecord) { r.Profile[0]++ },
	} {
		var changed privateRecord
		if json.Unmarshal(raw, &changed) != nil {
			t.Fatal("fixture")
		}
		mut(&changed)
		bad, _ := json.Marshal(changed)
		_, err := PlanSessionMigration(c, bad)
		clear(changed.Seed[:])
		clear(bad)
		if err == nil {
			t.Fatal("tampered record migrated")
		}
	}
}
