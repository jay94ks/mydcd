// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"path"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/localstore"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

var ErrLegacyAccountUnbound = errors.New("original login retained in wallet; its username must be verified before selecting an account")

type legacyLogin struct {
	record walletSessionRecord
	id     [32]byte
}

// migrateLegacy consumes the SAME immutable migration plan as the early core.
// The wallet lock is already held; the original session lock is acquired next.
// No source seed is removed until real encrypted readback and exact source CAS.
func (s *CredentialStore) migrateLegacy(c Client) (*legacyLogin, error) {
	if s == nil || !s.ready {
		return nil, ErrPrivateState
	}
	root, err := localstore.Open(s.home, false)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	profile := c.Profile()
	base := path.Join("sessions", hex.EncodeToString(c.Cluster[:]), "profiles", hex.EncodeToString(profile[:]))
	name := path.Join(base, "session.json")
	probe, err := root.Read(name, 65536)
	clear(probe)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	lock, err := root.Lock(path.Join(base, "session.lock"))
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	raw, err := root.Read(name, 65536)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	var fields map[string]json.RawMessage
	defer func() {
		for _, value := range fields {
			clear(value)
		}
	}()
	// Inspect only the discriminator here. A map marshals in key order, whereas
	// the source writer marshals a struct in field order. Both branches below
	// still require the exact canonical typed record before any key/file change.
	if json.Unmarshal(raw, &fields) != nil {
		return nil, ErrPrivateState
	}
	var reference walletSessionRecord
	if _, exists := fields["WalletKey"]; exists {
		keyName, public, err := SessionWalletReference(c, raw)
		if err != nil {
			return nil, err
		}
		key, err := s.disk.Get(keyName)
		defer clear(key.Seed[:])
		if err != nil || key.Public() != public {
			return nil, ErrPrivateState
		}
		if strict(raw, &reference) != nil {
			return nil, ErrPrivateState
		}
	} else {
		plan, err := PlanSessionMigration(c, raw)
		if err != nil {
			return nil, err
		}
		defer plan.Close()
		entry := plan.Entry()
		defer clear(entry.Seed[:])
		changed, err := s.disk.Put(entry)
		if err != nil {
			return nil, err
		}
		if changed {
			if err := s.disk.Save(s.password); err != nil {
				s.ready = false
				return nil, err
			}
		}
		readback, err := s.disk.ReadBack(entry.Name, s.password)
		defer clear(readback.Seed[:])
		if err != nil {
			s.ready = false
			return nil, err
		}
		current, err := root.Read(name, 65536)
		defer clear(current)
		if err != nil {
			return nil, err
		}
		metadata, err := plan.CommitRecord(current, readback)
		defer clear(metadata)
		if err != nil {
			return nil, err
		}
		if err := lock.Check(); err != nil {
			return nil, err
		}
		if err := root.ReplaceFile(name, metadata, plan.ExpectedSource()); err != nil {
			return nil, err
		}
		if strict(metadata, &reference) != nil {
			return nil, ErrPrivateState
		}
	}
	// The stable ID excludes the removed seed and the local key alias, and
	// survives source formatting. Renaming an alias does not create a new intent.
	// A completed wallet settlement cannot re-import the same old Pending on the
	// next login merely because its original reference remains retained on disk.
	canonical, err := json.Marshal(struct {
		Profile [32]byte
		Session access.Session
		Tenant  string
		Pending *control.UserOperation
	}{reference.Profile, reference.Session, reference.Tenant, reference.Pending})
	if err != nil {
		return nil, err
	}
	defer clear(canonical)
	return &legacyLogin{record: reference, id: sha256.Sum256(canonical)}, nil
}

func (s *CredentialStore) legacyKnown(c Client, legacy *legacyLogin) (bool, error) {
	if legacy == nil {
		return true, nil
	}
	names, err := s.disk.RecordNames()
	if err != nil {
		return false, err
	}
	for _, name := range names {
		raw, err := s.disk.Record(name)
		if err != nil {
			return false, err
		}
		r, match, err := decodeLogin(c, name, raw)
		clear(raw)
		if err != nil {
			return false, err
		}
		if match && r.Session.User == legacy.record.Session.User && r.Legacy == legacy.id {
			return true, nil
		}
	}
	return false, nil
}

func mergeLegacy(r *loginCredential, legacy *legacyLogin) error {
	if legacy == nil || r.Session.User != legacy.record.Session.User || r.Legacy == legacy.id {
		return nil
	}
	if legacy.record.Pending != nil {
		if r.Pending != nil && (!bytes.Equal(control.OperationBytes(*r.Pending), control.OperationBytes(*legacy.record.Pending)) || !bytes.Equal(r.Pending.Signature, legacy.record.Pending.Signature)) {
			return ErrPrivateState
		}
		r.Pending = legacy.record.Pending
	}
	if r.Tenant == "" {
		r.Tenant = legacy.record.Tenant
	}
	r.Legacy = legacy.id
	return nil
}

// ImportLegacy verifies the sole original login's username through the actual
// pinned user handler. It is used only when there are no named wallet accounts
// and --user was omitted. An explicit missing user NEVER triggers this query.
// Expired/revoked sessions need explicit login; they are not refreshed/replayed.
func (s *CredentialStore) ImportLegacy(ctx context.Context, c Client, peer mydcp.Peer) (Stored, error) {
	legacy, err := s.migrateLegacy(c)
	if err != nil {
		return Stored{}, err
	}
	if legacy == nil {
		return Stored{}, ErrLoginRequired
	}
	accounts, err := s.Accounts(c)
	if err != nil {
		return Stored{}, err
	}
	if len(accounts) != 0 {
		return Stored{}, ErrUserRequired
	}
	entry, err := s.disk.Get(legacy.record.WalletKey)
	if err != nil {
		return Stored{}, err
	}
	defer clear(entry.Seed[:])
	c.Self, err = identity.FromSeed(entry.Seed[:])
	if err != nil {
		return Stored{}, err
	}
	defer clear(c.Self.Private)
	if c.Verify(legacy.record.Session) != nil {
		return Stored{}, ErrLoginRequired
	}
	c.Mesh, err = mydcp.NewTransport(c.Self, c.Cluster, func(key mydcp.Identity) (mydcp.Peer, bool) {
		for _, candidate := range c.Peers {
			if candidate.Key == key {
				return candidate, true
			}
		}
		return mydcp.Peer{}, false
	})
	if err != nil {
		return Stored{}, err
	}
	defer c.Mesh.Close()
	reply, err := c.Query(ctx, peer, legacy.record.Session, "whoami", "")
	if err != nil {
		return Stored{}, err
	}
	if reply.User == nil || reply.User.ID != legacy.record.Session.User {
		return Stored{}, ErrPrivateState
	}
	if err := s.activate(c, reply.User.Username, legacy.record.Session); err != nil {
		return Stored{}, err
	}
	return s.Load(c, reply.User.Username)
}
