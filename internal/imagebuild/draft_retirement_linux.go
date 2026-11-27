// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/jay94ks/seafield/internal/nodestorage"
	"github.com/jay94ks/seafield/internal/reconcile"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/sys/unix"
)

// A configuration revision alone does not end editable data. Only deletion or
// a newer data Generation fences this original lifetime against further use.
type DraftRetirementGrant struct {
	Scope                       DraftScope
	ContextRevision, Generation uint64
	Deleted                     bool
	Index, Epoch                uint64
}

func (g DraftRetirementGrant) Valid() bool {
	return g.Scope.Validate() == nil && g.ContextRevision >= g.Scope.ContextRevision && g.Generation <= g.ContextRevision && g.Generation >= g.Scope.Data().Generation && (g.Deleted || g.Generation > g.Scope.Data().Generation) && g.Index > 0 && g.Epoch > 0
}

type DraftRetirement struct {
	Schema  uint8
	Grant   DraftRetirementGrant
	Root    NativeRootHold
	Removed bool
}

var draftRetirementKey = []byte("retirement")

func (r DraftRetirement) valid(binding draftBinding) bool {
	return r.Schema == 1 && r.Grant.Valid() && r.Grant.Scope == binding.Identity.Scope && r.Root.Lease.Token > 0 && r.Root.Lease.Generation == r.Grant.Scope.Root.Generation && r.Root.validate(r.Grant.Scope.Root.Generation) == nil && r.Removed == r.Root.Returning
}

func (r DraftRetirement) accepts(g DraftRetirementGrant) bool {
	return g.Valid() && r.Grant.Scope == g.Scope && g.Index >= r.Grant.Index && g.Epoch >= r.Grant.Epoch && g.ContextRevision >= r.Grant.ContextRevision && g.Generation >= r.Grant.Generation
}

func readDraftRetirement(parent *bolt.Bucket, binding draftBinding) (DraftRetirement, bool, error) {
	var r DraftRetirement
	if parent == nil || parent.Bucket([]byte(binding.Namespace)) == nil {
		return r, false, ErrStorage
	}
	raw := parent.Bucket([]byte(binding.Namespace)).Get(draftRetirementKey)
	if raw == nil {
		return r, false, nil
	}
	if len(raw) > 16<<10 || json.Unmarshal(raw, &r) != nil || !r.valid(binding) {
		return r, false, ErrStorage
	}
	return r, true, nil
}

func DraftRetirementState(db Transactions, scope DraftScope) (DraftRetirement, bool, error) {
	var r DraftRetirement
	if db == nil || scope.Validate() != nil {
		return r, false, ErrInvalid
	}
	found := false
	err := db.View(func(tx *bolt.Tx) error {
		parent := draftParent(tx, scope.Root)
		binding, exists, err := resolveDraftBinding(parent, scope)
		if err != nil || !exists {
			return err
		}
		r, found, err = readDraftRetirement(parent, binding)
		return err
	})
	return r, found, err
}

// StoredDraftLifetimes discovers original anchors without opening files or
// selecting a new consumer after configuration changes. Completed tombstones
// are retained in the DB and skipped by subsequent finite collection passes.
func StoredDraftLifetimes(db Transactions, root nodestorage.Reference, tenant, context string, choose func(DraftScope, *DraftRetirement) (bool, error), limit int) ([]DraftScope, error) {
	if db == nil || root.Validate() != nil || choose == nil || limit < 1 || limit > 16 {
		return nil, ErrInvalid
	}
	var scopes []DraftScope
	err := db.View(func(tx *bolt.Tx) error {
		parent := draftParent(tx, root)
		if parent == nil {
			return nil
		}
		cursor := parent.Cursor()
		for key, raw := cursor.Seek([]byte("draft-")); key != nil && strings.HasPrefix(string(key), "draft-"); key, raw = cursor.Next() {
			if raw != nil {
				return ErrStorage
			}
			bucket := parent.Bucket(key)
			var identity draftIdentity
			if bucket == nil {
				return ErrStorage
			}
			if raw := bucket.Get([]byte("identity")); len(raw) > 16<<10 || json.Unmarshal(raw, &identity) != nil || identity.Scope.Validate() != nil || identity.Scope.Root != root {
				return ErrStorage
			}
			if identity.Scope.Tenant != tenant || identity.Scope.Context != context {
				continue
			}
			binding, found, err := resolveDraftBinding(parent, identity.Scope)
			if err != nil || !found || binding.Namespace != string(key) || binding.Identity != identity {
				return ErrStorage
			}
			retirement, started, err := readDraftRetirement(parent, binding)
			if err != nil {
				return err
			}
			var original *DraftRetirement
			if started {
				if retirement.Root.Returned {
					continue
				}
				original = &retirement
			}
			selected, err := choose(identity.Scope, original)
			if err != nil {
				return err
			}
			if selected {
				scopes = append(scopes, identity.Scope)
				if len(scopes) == limit {
					break
				}
			}
		}
		return nil
	})
	return scopes, err
}

func saveDraftRetirement(db Transactions, binding draftBinding, before *DraftRetirement, next DraftRetirement) error {
	if !next.valid(binding) {
		return ErrStorage
	}
	raw, err := json.Marshal(next)
	if err != nil || len(raw) > 16<<10 {
		return ErrStorage
	}
	return db.Update(func(tx *bolt.Tx) error {
		parent := draftParent(tx, binding.Identity.Scope.Root)
		current, found, err := resolveDraftBinding(parent, binding.Identity.Scope)
		if err != nil || !found || current != binding {
			return ErrStorage
		}
		old, started, err := readDraftRetirement(parent, binding)
		if err != nil {
			return err
		}
		if before == nil && started || before != nil && (!started || old != *before) {
			return ErrConflict
		}
		return parent.Bucket([]byte(binding.Namespace)).Put(draftRetirementKey, raw)
	})
}

// A prepared source may already have an independent archive pin or a header
// written before rename. Do not destroy its original inode through recursive
// namespace deletion; first settle that archive through its own native path.
func draftArchivesTransferred(parent *bolt.Bucket, binding draftBinding) error {
	if parent == nil || parent.Bucket([]byte(binding.Namespace)) == nil {
		return ErrStorage
	}
	cursor := parent.Bucket([]byte(binding.Namespace)).Cursor()
	for key, raw := cursor.Seek([]byte("freeze-")); key != nil && bytes.HasPrefix(key, []byte("freeze-")); key, raw = cursor.Next() {
		var freeze nativeDraftFreeze
		if len(raw) > 16<<10 || json.Unmarshal(raw, &freeze) != nil || !freeze.valid() || freeze.Plan.Scope.Data() != binding.Data || !bytes.Equal(key, freezeKey(freeze.Plan)) {
			return ErrStorage
		}
		if freeze.Scope == nil {
			continue
		}
		bucket := parent.Bucket([]byte(scopeName(*freeze.Scope)))
		if bucket == nil {
			return ErrUsed
		}
		var header localUpload
		data := bucket.Get(spoolHeader)
		if len(data) > 16<<10 || json.Unmarshal(data, &header) != nil {
			return ErrStorage
		}
		if header.Scope != *freeze.Scope || header.Generated == nil || *header.Generated != freeze.Plan.Digest() || header.Device != freeze.Device || header.Inode != freeze.Inode || header.Invalid {
			return ErrUsed
		}
		settled := header.Deleted && header.Unpublished != nil && header.Unpublished.valid(header) && header.Unpublished.Returning
		if !settled && (header.Seal == nil || header.Seal.Scope != freeze.Scope.Hash() || header.Seal.ZIP != freeze.Scope.Digest) {
			return ErrUsed
		}
	}
	return nil
}

// RetireDraft closes one obsolete private directory, not its metadata or any
// archive already adopted into the sibling Spool namespace. Caller holds the
// Runtime owner gate and the ORIGINAL RootManager pin through descriptor Close.
func (s *Spool) RetireDraft(ctx context.Context, g DraftRetirementGrant, lease reconcile.Lease) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !g.Valid() || g.Scope.Root != s.root || s.dir == nil || lease.Token == 0 || lease.Generation != s.root.Generation {
		return ErrInvalid
	}
	if s.readers[g.Scope.Data().Digest()] != 0 {
		return ErrUsed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var binding draftBinding
	var r DraftRetirement
	started := false
	err := s.db.View(func(tx *bolt.Tx) error {
		parent := draftParent(tx, s.root)
		var found bool
		var err error
		binding, found, err = resolveDraftBinding(parent, g.Scope)
		if err != nil || !found || binding.Identity.Scope != g.Scope {
			return ErrStorage
		}
		r, started, err = readDraftRetirement(parent, binding)
		if err == nil && !started {
			err = draftArchivesTransferred(parent, binding)
		}
		return err
	})
	if err != nil {
		return err
	}
	if started {
		if !r.accepts(g) || r.Root.Lease != lease {
			return ErrConflict
		}
		if r.Removed {
			return nil
		}
	}
	file, stat, openErr := openNativeDirectory(int(s.dir.Fd()), binding.Namespace)
	exists := openErr == nil
	if exists {
		closeErr := file.Close()
		if closeErr != nil || uint64(stat.Dev) != binding.Identity.Device || stat.Ino != binding.Identity.Inode || stat.Uid != uint32(os.Geteuid()) || stat.Mode&07777 != 0700 {
			return ErrStorage
		}
	} else if !errors.Is(openErr, unix.ENOENT) || !started {
		return ErrStorage
	}
	if !started {
		r = DraftRetirement{Schema: 1, Grant: g, Root: NativeRootHold{Lease: lease}}
		if err := saveDraftRetirement(s.db, binding, nil, r); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if exists {
		confined, err := os.OpenRoot(fmt.Sprintf("/proc/self/fd/%d", s.dir.Fd()))
		if err != nil {
			return err
		}
		err = confined.RemoveAll(binding.Namespace)
		closeErr := confined.Close()
		if err != nil || closeErr != nil {
			return errors.Join(err, closeErr)
		}
	}
	if err := s.dir.Sync(); err != nil {
		return err
	}
	next := r
	next.Removed, next.Root.Returning = true, true
	return saveDraftRetirement(s.db, binding, &r, next)
}

// FinishDraftRetirement records the original Return acknowledgement without
// reopening a retired data path or allocating a replacement lease/draft.
func FinishDraftRetirement(db Transactions, scope DraftScope, lease reconcile.Lease) error {
	var binding draftBinding
	var r DraftRetirement
	if db == nil || scope.Validate() != nil {
		return ErrInvalid
	}
	err := db.View(func(tx *bolt.Tx) error {
		parent := draftParent(tx, scope.Root)
		var found bool
		var err error
		binding, found, err = resolveDraftBinding(parent, scope)
		if err != nil || !found {
			return ErrStorage
		}
		r, found, err = readDraftRetirement(parent, binding)
		if err != nil || !found || !r.Removed || !r.Root.Returning || r.Root.Lease != lease {
			return ErrConflict
		}
		return nil
	})
	if err != nil || r.Root.Returned {
		return err
	}
	next := r
	next.Root.Returned = true
	return saveDraftRetirement(db, binding, &r, next)
}
