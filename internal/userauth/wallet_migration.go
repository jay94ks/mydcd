// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cliprofile"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/wallet"
)

// walletSessionRecord replaces only the plaintext seed in the original private
// session schema. Session/Pending retain their original signed bytes/IDs/CAS.
// Decoding this reference alone never supplies current user authorization.
type walletSessionRecord struct {
	Schema    uint8
	Profile   [32]byte
	Session   access.Session
	WalletKey string
	Tenant    string
	Pending   *control.UserOperation `json:",omitempty"`
}

type SessionMigration struct {
	source   [32]byte
	entry    wallet.Entry
	metadata []byte
}

func (SessionMigration) MarshalJSON() ([]byte, error) { return nil, ErrPrivateState }
func (SessionMigration) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[redacted session migration]")
}
func (m *SessionMigration) Close() {
	clear(m.entry.Seed[:])
	m.entry = wallet.Entry{}
	clear(m.metadata)
	m.metadata = nil
}
func (m SessionMigration) Entry() wallet.Entry      { return m.entry }
func (m SessionMigration) ExpectedSource() [32]byte { return m.source }

// originalSessionRecord checks only immutable provenance at the original issue
// time. Expiry/revocation never licenses dropping the original recovery record;
// current authorization remains the responsibility of the normal user handler.
func originalSessionMetadata(c Client, profile [32]byte, session access.Session, tenant string, pending *control.UserOperation) error {
	if profile != c.Profile() || !safeID(session.User) || tenant != "" && !safeID(tenant) || session.IssuedAt < 0 || c.verifyAt(session, session.IssuedAt) != nil {
		return ErrPrivateState
	}
	if pending != nil && (pending.Session.User != session.User || !pending.SelfLogout() || pending.VerifyOriginal(c.Cluster) != nil) {
		return ErrPrivateState
	}
	return nil
}
func originalSessionRecord(c Client, r privateRecord) error {
	if r.Schema != 1 {
		return ErrPrivateState
	}
	private := ed25519.NewKeyFromSeed(r.Seed[:])
	defer clear(private)
	var public [32]byte
	copy(public[:], private[32:])
	c.Self = &identity.Identity{Private: private, Public: public}
	return originalSessionMetadata(c, r.Profile, r.Session, r.Tenant, r.Pending)
}

// PlanSessionMigration is deterministic and does not write the wallet or source
// file. The real adapter must hold its private locks, durably store Entry, read
// it back through the encrypted wallet, then CAS-replace the exact source.
func PlanSessionMigration(c Client, raw []byte) (SessionMigration, error) {
	var r privateRecord
	defer clear(r.Seed[:])
	if len(raw) == 0 || len(raw) > 65536 || strict(raw, &r) != nil || originalSessionRecord(c, r) != nil {
		return SessionMigration{}, ErrPrivateState
	}
	entry := wallet.Entry{Seed: r.Seed}
	public := entry.Public()
	entry.Name = "session-" + hex.EncodeToString(public[:])
	replacement := walletSessionRecord{Schema: r.Schema, Profile: r.Profile, Session: r.Session, WalletKey: entry.Name, Tenant: r.Tenant, Pending: r.Pending}
	metadata, err := json.Marshal(replacement)
	if err != nil || len(metadata) > 65536 {
		clear(entry.Seed[:])
		clear(metadata)
		return SessionMigration{}, ErrPrivateState
	}
	return SessionMigration{source: sha256.Sum256(raw), entry: entry, metadata: metadata}, nil
}

// CommitRecord returns only reference metadata, after exact original-source CAS
// and the same named private key read-back. It never changes session/user/tenant,
// request ID/signature/CAS, nor copies a newer operation into the old record.
func (m SessionMigration) CommitRecord(original []byte, readback wallet.Entry) ([]byte, error) {
	if len(m.metadata) == 0 || m.entry.Name == "" || sha256.Sum256(original) != m.source || readback.Name != m.entry.Name || subtle.ConstantTimeCompare(readback.Seed[:], m.entry.Seed[:]) != 1 {
		return nil, ErrPrivateState
	}
	return bytes.Clone(m.metadata), nil
}

// SessionWalletReference validates reference metadata for the exact original
// profile. It does not load a key, create TLS identity, or authenticate a request.
func SessionWalletReference(c Client, raw []byte) (string, [32]byte, error) {
	var r walletSessionRecord
	if len(raw) == 0 || len(raw) > 65536 || strict(raw, &r) != nil || r.Schema != 1 || !cliprofile.ValidKeyName(r.WalletKey) {
		return "", [32]byte{}, ErrPrivateState
	}
	// This key is public metadata, not proof of possession. Reuse the existing
	// original-time signature/profile checks; normal login/dispatch still proves
	// the wallet key and checks CURRENT authorization.
	c.Self = &identity.Identity{Public: r.Session.Key}
	if originalSessionMetadata(c, r.Profile, r.Session, r.Tenant, r.Pending) != nil {
		return "", [32]byte{}, ErrPrivateState
	}
	return r.WalletKey, r.Session.Key, nil
}
