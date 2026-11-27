// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"

	"github.com/jay94ks/seafield/internal/nodestorage"
	"github.com/jay94ks/seafield/internal/reconcile"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/sys/unix"
)

// Discovery reads existing evidence only. The callback is a pure shared-state
// fence. A per-context cursor prevents completed/protected rows starving later
// original artifacts, without an independent cleanup journal or DB.
func StoredGeneratedArtifacts(db Transactions, root nodestorage.Reference, tenant, context, after string, choose func(GeneratedArtifact) (bool, error), limit int) ([]GeneratedArtifact, string, error) {
	if db == nil || root.Validate() != nil || choose == nil || limit < 1 || limit > 16 {
		return nil, "", ErrInvalid
	}
	var out []GeneratedArtifact
	next := ""
	full := false
	err := db.View(func(tx *bolt.Tx) error {
		parent := draftParent(tx, root)
		if parent == nil {
			return nil
		}
		consider := func(position string, a GeneratedArtifact) error {
			if full || position <= after || a.Scope.Tenant != tenant || a.Scope.Context != context {
				return nil
			}
			if !a.Valid() || a.Scope.Root != root {
				return ErrStorage
			}
			if bucket := parent.Bucket([]byte(scopeName(a.Scope))); bucket != nil {
				var h localUpload
				data := bucket.Get(spoolHeader)
				if len(data) > 16<<10 || json.Unmarshal(data, &h) != nil || h.Scope != a.Scope {
					return ErrStorage
				}
				if h.Unpublished != nil {
					if !h.Unpublished.valid(h) || h.Unpublished.Artifact != a.Digest() {
						return ErrStorage
					}
					if h.Unpublished.Returned {
						return nil
					}
				}
			}
			selected, err := choose(a)
			if err != nil {
				return err
			}
			if !selected {
				return nil
			}
			out = append(out, a)
			if len(out) == limit {
				full, next = true, position
			}
			return nil
		}
		return parent.ForEach(func(key, raw []byte) error {
			if full {
				return nil
			}
			switch {
			case raw != nil && strings.HasPrefix(string(key), "git-"):
				var h nativeGitSave
				if len(raw) > 16<<10 || json.Unmarshal(raw, &h) != nil || !h.valid() || !bytes.Equal(key, gitSaveKey(h.Plan)) || h.Plan.Root != root {
					return ErrStorage
				}
				if h.Scope != nil {
					return consider(string(key), GeneratedArtifact{Scope: *h.Scope, Git: &h.Plan})
				}
			case raw == nil && strings.HasPrefix(string(key), "draft-"):
				bucket := parent.Bucket(key)
				var identity draftIdentity
				if bucket == nil {
					return ErrStorage
				}
				data := bucket.Get([]byte("identity"))
				if len(data) > 16<<10 || json.Unmarshal(data, &identity) != nil || identity.Scope.Validate() != nil || identity.Scope.Root != root {
					return ErrStorage
				}
				if identity.Scope.Tenant != tenant || identity.Scope.Context != context {
					return nil
				}
				binding, found, err := resolveDraftBinding(parent, identity.Scope)
				if err != nil || !found || binding.Namespace != string(key) || binding.Identity != identity {
					return ErrStorage
				}
				cursor := bucket.Cursor()
				for k, v := cursor.Seek([]byte("freeze-")); !full && k != nil && bytes.HasPrefix(k, []byte("freeze-")); k, v = cursor.Next() {
					var h nativeDraftFreeze
					if len(v) > 16<<10 || json.Unmarshal(v, &h) != nil || !h.valid() || !bytes.Equal(k, freezeKey(h.Plan)) || h.Plan.Scope.Data() != binding.Data {
						return ErrStorage
					}
					if h.Scope != nil {
						if err := consider(string(key)+"/"+string(k), GeneratedArtifact{Scope: *h.Scope, Draft: &h.Plan}); err != nil {
							return err
						}
					}
				}
			}
			return nil
		})
	})
	return out, next, err
}

func GeneratedArchiveState(db Transactions, a GeneratedArtifact) (*GeneratedArchiveRetirement, error) {
	if db == nil || !a.Valid() {
		return nil, ErrInvalid
	}
	var r *GeneratedArchiveRetirement
	err := db.View(func(tx *bolt.Tx) error {
		parent := draftParent(tx, a.Scope.Root)
		if parent == nil {
			return nil
		}
		bucket := parent.Bucket([]byte(scopeName(a.Scope)))
		if bucket == nil {
			return nil
		}
		var h localUpload
		data := bucket.Get(spoolHeader)
		if len(data) > 16<<10 || json.Unmarshal(data, &h) != nil || h.Scope != a.Scope {
			return ErrStorage
		}
		if h.Unpublished != nil && (!h.Unpublished.valid(h) || h.Unpublished.Artifact != a.Digest()) {
			return ErrStorage
		}
		if h.Unpublished != nil {
			original, _, err := generatedSourceIn(parent, a)
			if err != nil || !generatedIdentity(h, original) {
				return ErrStorage
			}
		}
		r = h.Unpublished
		return nil
	})
	return r, err
}

func generatedSourceIn(parent *bolt.Bucket, a GeneratedArtifact) (original nativeGeneratedArchive, binding *draftBinding, err error) {
	if parent == nil {
		return original, nil, ErrStorage
	}
	if a.Git != nil {
		var h nativeGitSave
		data := parent.Get(gitSaveKey(*a.Git))
		if len(data) > 16<<10 || json.Unmarshal(data, &h) != nil || !h.valid() || h.Plan != *a.Git || h.Scope == nil || *h.Scope != a.Scope {
			return original, nil, ErrStorage
		}
		original = nativeGeneratedArchive{Scope: a.Scope, Plan: a.PlanDigest(), Device: h.Device, Inode: h.Inode}
	} else {
		b, found, err := resolveDraftBinding(parent, a.Draft.Scope)
		if err != nil || !found {
			return original, nil, ErrStorage
		}
		var h nativeDraftFreeze
		data := parent.Bucket([]byte(b.Namespace)).Get(freezeKey(*a.Draft))
		if len(data) > 16<<10 || json.Unmarshal(data, &h) != nil || !h.valid() || h.Plan != *a.Draft || h.Scope == nil || *h.Scope != a.Scope {
			return original, nil, ErrStorage
		}
		binding = &b
		original = nativeGeneratedArchive{Scope: a.Scope, Plan: a.PlanDigest(), Device: h.Device, Inode: h.Inode}
	}
	return original, binding, nil
}

func (s *Spool) generatedSource(a GeneratedArtifact) (nativeGeneratedArchive, *draftBinding, error) {
	var original nativeGeneratedArchive
	var binding *draftBinding
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		original, binding, err = generatedSourceIn(draftParent(tx, a.Scope.Root), a)
		return err
	})
	return original, binding, err
}

func generatedIdentity(h localUpload, o nativeGeneratedArchive) bool {
	return h.Scope == o.Scope && h.Generated != nil && *h.Generated == o.Plan && h.Device == o.Device && h.Inode == o.Inode
}

func putGeneratedRetirement(db Transactions, before *localUpload, next localUpload) error {
	if next.Unpublished == nil || !next.Unpublished.valid(next) {
		return ErrStorage
	}
	raw, _ := json.Marshal(next)
	if len(raw) > 16<<10 {
		return ErrStorage
	}
	return db.Update(func(tx *bolt.Tx) error {
		parent := draftParent(tx, next.Scope.Root)
		if parent == nil {
			return ErrStorage
		}
		bucket := parent.Bucket([]byte(scopeName(next.Scope)))
		if before == nil {
			if bucket != nil {
				return ErrConflict
			}
			var err error
			bucket, err = parent.CreateBucket([]byte(scopeName(next.Scope)))
			if err != nil {
				return err
			}
		} else {
			if bucket == nil {
				return ErrStorage
			}
			var current localUpload
			data := bucket.Get(spoolHeader)
			if len(data) > 16<<10 || json.Unmarshal(data, &current) != nil {
				return ErrStorage
			}
			x, _ := json.Marshal(before)
			y, _ := json.Marshal(current)
			if !bytes.Equal(x, y) {
				return ErrConflict
			}
		}
		return bucket.Put(spoolHeader, raw)
	})
}

// Validate a source/destination before the retirement intent. A missing file
// after our original deleting intent is handled solely by existing Reclaim.
func (s *Spool) generatedLocation(h localUpload, a GeneratedArtifact, binding *draftBinding) (int, string, *os.File, error) {
	name := ""
	if a.Git != nil {
		name = gitSaveName(*a.Git)
	} else {
		name = freezeName(*a.Draft)
	}
	var st unix.Stat_t
	err := unix.Fstatat(int(s.dir.Fd()), scopeName(a.Scope)+".zip", &st, unix.AT_SYMLINK_NOFOLLOW)
	check := func(st unix.Stat_t) bool {
		return st.Mode&unix.S_IFMT == unix.S_IFREG && st.Nlink == 1 && st.Uid == uint32(os.Geteuid()) && st.Mode&07777 == 0600 && st.Ino == h.Inode && uint64(st.Dev) == h.Device && st.Size == a.Scope.Length
	}
	if err == nil {
		if !check(st) {
			return 0, "", nil, ErrStorage
		}
		if binding != nil {
			file, stat, err := openNativeDirectory(int(s.dir.Fd()), binding.Namespace)
			if errors.Is(err, unix.ENOENT) {
				r, started, cause := DraftRetirementState(s.db, binding.Identity.Scope)
				if cause != nil || !started || !r.Removed {
					return 0, "", nil, ErrStorage
				}
			} else if err != nil {
				return 0, "", nil, ErrStorage
			} else {
				if uint64(stat.Dev) != binding.Identity.Device || stat.Ino != binding.Identity.Inode || stat.Uid != uint32(os.Geteuid()) || stat.Mode&07777 != 0700 {
					_ = file.Close()
					return 0, "", nil, ErrStorage
				}
				return int(file.Fd()), name, file, nil
			}
		}
		return int(s.dir.Fd()), name, nil, nil
	}
	if !errors.Is(err, unix.ENOENT) {
		return 0, "", nil, ErrStorage
	}
	if h.Unpublished != nil && (h.Deleting || h.Deleted) {
		return int(s.dir.Fd()), name, nil, nil
	}
	fd := int(s.dir.Fd())
	var owned *os.File
	if binding != nil {
		file, stat, err := openNativeDirectory(fd, binding.Namespace)
		if err != nil {
			return 0, "", nil, ErrStorage
		}
		if uint64(stat.Dev) != binding.Identity.Device || stat.Ino != binding.Identity.Inode || stat.Uid != uint32(os.Geteuid()) || stat.Mode&07777 != 0700 {
			_ = file.Close()
			return 0, "", nil, ErrStorage
		}
		owned, fd = file, int(file.Fd())
	}
	if err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil || !check(st) {
		if owned != nil {
			_ = owned.Close()
		}
		return 0, "", nil, ErrStorage
	}
	return fd, name, owned, nil
}

// The Runtime gate and current grant fence prevent an original publish while
// this adapter reuses the existing inode-placement/deletion core. No seal,
// fake upload/part receipt, new root pin or user operation is constructed.
func (s *Spool) ReclaimGenerated(ctx context.Context, g GeneratedArchiveGrant, lease reconcile.Lease) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := g.Artifact
	if !g.Valid() || s.check(a.Scope) != nil || lease.Token == 0 && lease != (reconcile.Lease{}) || lease.Token != 0 && lease.Generation != s.root.Generation {
		return ErrInvalid
	}
	if s.readers[a.Scope.Hash()] != 0 || a.Draft != nil && s.readers[a.Draft.Scope.Data().Digest()] != 0 {
		return ErrUsed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	o, binding, err := s.generatedSource(a)
	if err != nil {
		return err
	}
	var h localUpload
	var before *localUpload
	exists := false
	if err := s.db.View(func(tx *bolt.Tx) error { exists = s.bucket(tx, a.Scope) != nil; return nil }); err != nil {
		return err
	}
	if exists {
		h, err = s.header(a.Scope)
		if err != nil || !generatedIdentity(h, o) {
			return ErrStorage
		}
		old := h
		before = &old
		if h.Unpublished == nil && lease.Token == 0 {
			return ErrStorage
		}
	} else {
		h = localUpload{Scope: a.Scope, Device: o.Device, Inode: o.Inode, Generated: &o.Plan}
	}
	if r := h.Unpublished; r != nil {
		if !r.valid(h) || r.Artifact != a.Digest() || r.Lease != lease || g.Index < r.Index || g.Epoch < r.Epoch || g.ContextRevision < r.ContextRevision || g.PolicyRevision < r.PolicyRevision {
			return ErrConflict
		}
		if r.Returning {
			return nil
		}
	}
	fd, name, owned, err := s.generatedLocation(h, a, binding)
	if err != nil {
		return err
	}
	if owned != nil {
		defer func() { err = errors.Join(err, owned.Close()) }()
	}
	if h.Unpublished == nil {
		h.Unpublished = &GeneratedArchiveRetirement{Artifact: a.Digest(), ContextRevision: g.ContextRevision, PolicyRevision: g.PolicyRevision, Deleted: g.Deleted, Index: g.Index, Epoch: g.Epoch, Lease: lease, Borrowed: lease.Token != 0}
		if err := putGeneratedRetirement(s.db, before, h); err != nil {
			return err
		}
	}
	if !h.Deleting && !h.Deleted {
		file, err := s.placeGeneratedArchive(h, fd, name)
		if err != nil {
			return err
		}
		info, statErr := file.Stat()
		closeErr := file.Close()
		if statErr != nil || closeErr != nil || info.Size() != a.Scope.Length {
			return ErrStorage
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.reclaim(Upload{Scope: a.Scope, Revision: 1, Closed: true}, false); err != nil {
		return err
	}
	h, err = s.header(a.Scope)
	if err != nil {
		return err
	}
	next := h
	r := *h.Unpublished
	r.Returning = true
	next.Unpublished = &r
	return putGeneratedRetirement(s.db, &h, next)
}

func FinishGeneratedRetirement(db Transactions, a GeneratedArtifact, lease reconcile.Lease) error {
	if db == nil || !a.Valid() {
		return ErrInvalid
	}
	var h localUpload
	if err := db.View(func(tx *bolt.Tx) error {
		parent := draftParent(tx, a.Scope.Root)
		if parent == nil || parent.Bucket([]byte(scopeName(a.Scope))) == nil {
			return ErrStorage
		}
		data := parent.Bucket([]byte(scopeName(a.Scope))).Get(spoolHeader)
		if len(data) > 16<<10 || json.Unmarshal(data, &h) != nil || h.Unpublished == nil || !h.Unpublished.valid(h) || h.Unpublished.Artifact != a.Digest() || !h.Unpublished.Returning || h.Unpublished.Lease != lease {
			return ErrConflict
		}
		original, _, err := generatedSourceIn(parent, a)
		if err != nil || !generatedIdentity(h, original) {
			return ErrStorage
		}
		return nil
	}); err != nil {
		return err
	}
	if h.Unpublished.Returned {
		return nil
	}
	next := h
	r := *h.Unpublished
	r.Returned = true
	next.Unpublished = &r
	return putGeneratedRetirement(db, &h, next)
}
