// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cliprofile"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/wallet"
)

// CredentialStore owns an unlocked, encrypted wallet transaction lifetime.
// Login grants/account metadata are encrypted alongside the original proof
// keys. No latest-account pointer or implicit account default is persisted.
type CredentialStore struct {
	disk     *wallet.Disk
	password []byte
	ready    bool
	home     string
}

func (*CredentialStore) MarshalJSON() ([]byte, error) { return nil, ErrPrivateState }
func (*CredentialStore) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[redacted login wallet]")
}

func OpenCredentials(home string, password []byte) (*CredentialStore, error) {
	d, err := wallet.OpenDisk(home, false)
	if err != nil {
		return nil, err
	}
	if err := d.Unlock(password); err != nil {
		_ = d.Close()
		return nil, err
	}
	return &CredentialStore{disk: d, password: bytes.Clone(password), ready: true, home: home}, nil
}

func (s *CredentialStore) Close() error {
	if s == nil {
		return nil
	}
	clear(s.password)
	s.password = nil
	s.ready = false
	if s.disk == nil {
		return nil
	}
	err := s.disk.Close()
	s.disk = nil
	return err
}

type loginCredential struct {
	Schema            uint8
	Cluster, Profile  [32]byte
	Username          string
	Session           access.Session
	WalletKey, Tenant string
	Pending           *control.UserOperation `json:",omitempty"`
	Closed            bool                   `json:",omitempty"`
	Legacy            [32]byte               `json:",omitempty"`
}

func loginRecordName(cluster, profile [32]byte, username string) string {
	b := append([]byte("mydc-wallet-login-1\x00"), cluster[:]...)
	b = append(b, profile[:]...)
	b = append(b, username...)
	digest := sha256.Sum256(b)
	return "login-" + hex.EncodeToString(digest[:])
}

func sessionProofName(key [32]byte) string { return "session-" + hex.EncodeToString(key[:]) }

func decodeLogin(c Client, name string, raw []byte) (loginCredential, bool, error) {
	var r loginCredential
	if len(raw) > wallet.MaxRecordBytes || strict(raw, &r) != nil || r.Schema != 1 || r.Cluster == [32]byte{} || r.Profile == [32]byte{} || !cliprofile.ValidUsername(r.Username) || name != loginRecordName(r.Cluster, r.Profile, r.Username) || r.WalletKey != sessionProofName(r.Session.Key) || r.Closed && r.Pending != nil {
		return loginCredential{}, false, ErrPrivateState
	}
	if r.Cluster != c.Cluster || r.Profile != c.Profile() {
		return r, false, nil
	}
	original := c
	original.Self = &identity.Identity{Public: r.Session.Key}
	if originalSessionMetadata(original, r.Profile, r.Session, r.Tenant, r.Pending) != nil {
		return loginCredential{}, false, ErrPrivateState
	}
	return r, true, nil
}

func (s *CredentialStore) Accounts(c Client) ([]Account, error) {
	if s == nil || !s.ready || s.disk == nil {
		return nil, wallet.ErrWallet
	}
	names, err := s.disk.RecordNames()
	if err != nil {
		return nil, err
	}
	accounts := []Account{}
	for _, name := range names {
		raw, err := s.disk.Record(name)
		if err != nil {
			return nil, err
		}
		r, match, err := decodeLogin(c, name, raw)
		clear(raw)
		if err != nil {
			return nil, err
		}
		if match && !r.Closed {
			accounts = append(accounts, Account{Cluster: r.Cluster, Profile: r.Profile, Username: r.Username})
		}
	}
	return accounts, nil
}

func (s *CredentialStore) Load(c Client, username string) (Stored, error) {
	legacy, err := s.migrateLegacy(c)
	if err != nil {
		return Stored{}, err
	}
	accounts, err := s.Accounts(c)
	if err != nil {
		return Stored{}, err
	}
	if username == "" && legacy != nil {
		known, err := s.legacyKnown(c, legacy)
		if err != nil {
			return Stored{}, err
		}
		if !known {
			if len(accounts) == 0 {
				return Stored{}, ErrLegacyAccountUnbound
			}
			return Stored{}, fmt.Errorf("%w (a retained original login is also present)", ErrUserRequired)
		}
	}
	account, err := SelectAccount(accounts, c.Cluster, c.Profile(), username)
	if err != nil {
		return Stored{}, err
	}
	raw, err := s.disk.Record(loginRecordName(account.Cluster, account.Profile, account.Username))
	if err != nil {
		return Stored{}, err
	}
	defer clear(raw)
	r, match, err := decodeLogin(c, loginRecordName(account.Cluster, account.Profile, account.Username), raw)
	if err != nil || !match {
		return Stored{}, ErrPrivateState
	}
	beforeLegacy := r.Legacy
	if err := mergeLegacy(&r, legacy); err != nil {
		return Stored{}, err
	}
	if r.Legacy != beforeLegacy {
		owner := c
		owner.Username = r.Username
		if err := s.writeRecord(owner, raw, r); err != nil {
			return Stored{}, err
		}
	}
	entry, err := s.disk.Get(r.WalletKey)
	if err != nil {
		return Stored{}, err
	}
	defer clear(entry.Seed[:])
	if entry.Public() != r.Session.Key {
		return Stored{}, ErrPrivateState
	}
	self, err := identity.FromSeed(entry.Seed[:])
	if err != nil {
		return Stored{}, err
	}
	c.Self = self
	valid := c.Verify(r.Session) == nil
	if r.Pending != nil {
		if sameSession(r.Pending.Session, r.Session) {
			valid = c.verifyAt(r.Session, r.Pending.At) == nil
		}
		valid = valid && r.Pending.Session.User == r.Session.User && r.Pending.SelfLogout() && r.Pending.VerifyOriginal(c.Cluster) == nil
	}
	if !valid {
		expired := r.Pending == nil && c.expired(r.Session)
		clear(self.Private)
		if expired {
			return Stored{}, ErrSessionExpired
		}
		return Stored{}, ErrPrivateState
	}
	return Stored{Username: r.Username, Session: r.Session, Tenant: r.Tenant, Self: self, Pending: r.Pending}, nil
}

// LoginPrivate/PasswordOrToken store only a successful protocol login's account,
// issued session and proof key. Input passwords/tokens are not needed afterwards
// and are not used to silently repeat authentication on expiry or disconnect.
func (s *CredentialStore) LoginPrivate(ctx context.Context, c Client, peer mydcp.Peer, username string, key ed25519.PrivateKey) (access.Session, error) {
	if s == nil || !s.ready || !cliprofile.ValidUsername(username) {
		return access.Session{}, ErrPrivateState
	}
	if _, err := s.migrateLegacy(c); err != nil {
		return access.Session{}, err
	}
	session, err := c.Login(ctx, peer, username, key)
	if err != nil {
		return access.Session{}, err
	}
	if err := s.activate(c, username, session); err != nil {
		return access.Session{}, err
	}
	return session, nil
}

func (s *CredentialStore) PasswordOrToken(ctx context.Context, c Client, peer mydcp.Peer, username string, method access.Method, credential string, secret []byte) (access.Session, error) {
	return s.passwordOrToken(ctx, c, peer, username, method, credential, secret, nil)
}

// PasswordOrTokenApproved retains the password/token authentication backend and
// its scope ceiling, adding a delegation by an explicitly selected user key.
// The approval key is not retained in the login record or used as a fallback
// authentication method. The cluster checks its current account registration.
func (s *CredentialStore) PasswordOrTokenApproved(ctx context.Context, c Client, peer mydcp.Peer, username string, method access.Method, credential string, secret []byte, key ed25519.PrivateKey) (access.Session, error) {
	if len(key) != ed25519.PrivateKeySize {
		return access.Session{}, ErrPrivateState
	}
	return s.passwordOrToken(ctx, c, peer, username, method, credential, secret, key)
}

func (s *CredentialStore) passwordOrToken(ctx context.Context, c Client, peer mydcp.Peer, username string, method access.Method, credential string, secret []byte, key ed25519.PrivateKey) (access.Session, error) {
	if s == nil || !s.ready || !cliprofile.ValidUsername(username) {
		return access.Session{}, ErrPrivateState
	}
	if _, err := s.migrateLegacy(c); err != nil {
		return access.Session{}, err
	}
	session, err := c.LoginCredential(ctx, peer, username, method, credential, secret)
	if err != nil {
		return access.Session{}, err
	}
	if key != nil {
		session, err = access.ApproveSession(session, key)
		if err != nil {
			return access.Session{}, err
		}
	}
	if err := s.activate(c, username, session); err != nil {
		return access.Session{}, err
	}
	return session, nil
}

func (s *CredentialStore) activate(c Client, username string, session access.Session) error {
	return s.activateAt(c, username, session, time.Now().Unix())
}

// Historical import is used only after a current same-user authentication has
// been checked by preserveOriginalLegacy. This does not authorize an old grant.
func (s *CredentialStore) activateAt(c Client, username string, session access.Session, at int64) error {
	if s == nil || !s.ready || c.Self == nil || len(c.Self.Private) != ed25519.PrivateKeySize || c.verifyAt(session, at) != nil || !safeID(session.User) || !cliprofile.ValidUsername(username) {
		return ErrPrivateState
	}
	legacy, err := s.migrateLegacy(c)
	if err != nil {
		return err
	}
	name := loginRecordName(c.Cluster, c.Profile(), username)
	r := loginCredential{Schema: 1, Cluster: c.Cluster, Profile: c.Profile(), Username: username, Session: session, WalletKey: sessionProofName(session.Key)}
	var expected *[32]byte
	previous, err := s.disk.Record(name)
	defer clear(previous)
	if err == nil {
		old, match, err := decodeLogin(c, name, previous)
		if err != nil || !match {
			return ErrPrivateState
		}
		if old.Pending != nil {
			if old.Session.User != session.User || sameSession(old.Session, session) {
				return ErrPrivateState
			}
			r.Pending = old.Pending
		}
		r.Tenant = old.Tenant
		if old.Session.User == session.User {
			r.Legacy = old.Legacy
		}
		digest := sha256.Sum256(previous)
		expected = &digest
	} else if !errors.Is(err, wallet.ErrMissing) {
		return err
	}
	if err := mergeLegacy(&r, legacy); err != nil {
		return err
	}
	entry := wallet.Entry{Name: r.WalletKey}
	seed := c.Self.Private.Seed()
	defer clear(seed)
	copy(entry.Seed[:], seed)
	defer clear(entry.Seed[:])
	if entry.Public() != session.Key {
		return ErrPrivateState
	}
	changed, err := s.disk.Put(entry)
	if err != nil {
		return err
	}
	confirmed := false
	defer func() {
		if changed && !confirmed {
			s.ready = false
		}
	}()
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	defer clear(raw)
	if err := s.disk.PutRecord(name, raw, expected); err != nil {
		return err
	}
	changed = true
	if err := s.disk.Save(s.password); err != nil {
		s.ready = false
		return err
	}
	readback, err := s.disk.ReadBackRecord(name, s.password)
	defer clear(readback)
	if err != nil {
		s.ready = false
		return err
	}
	if !bytes.Equal(raw, readback) {
		s.ready = false
		return ErrPrivateState
	}
	key, err := s.disk.Get(r.WalletKey)
	defer clear(key.Seed[:])
	if err != nil || key.Public() != session.Key || !bytes.Equal(key.Seed[:], entry.Seed[:]) {
		s.ready = false
		return ErrPrivateState
	}
	confirmed = true
	return nil
}
