// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"

	"github.com/jay94ks/mydcd/internal/nodestorage"
	"github.com/jay94ks/mydcd/internal/reconcile"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/sys/unix"
)

type GitStageGrant struct {
	Plan                            GitSavePlan
	ContextRevision, PolicyRevision uint64
	Deleted                         bool
	Index, Epoch                    uint64
}

func (g GitStageGrant) Valid() bool {
	return g.Plan.Validate() == nil && g.ContextRevision >= g.Plan.ContextRevision && g.PolicyRevision >= g.Plan.PolicyRevision && g.Index > 0 && g.Epoch > 0
}
func (g GitStageGrant) Obsolete() bool {
	return g.Deleted || g.ContextRevision > g.Plan.ContextRevision || g.PolicyRevision > g.Plan.PolicyRevision
}

type GitStageRetirement struct {
	Grant                GitStageGrant
	Root                 NativeRootHold
	Transferred, Removed bool
}

func (r GitStageRetirement) valid(h nativeGitSave) bool {
	return r.Grant.Valid() && r.Grant.Plan == h.Plan && (r.Transferred && h.Scope != nil && h.Inode != 0 || !r.Transferred && r.Grant.Obsolete()) && r.Root.Lease.Token != 0 && r.Root.Lease.Generation == h.Plan.Root.Generation && r.Root.validate(h.Plan.Root.Generation) == nil && r.Removed == r.Root.Returning
}

// GitStageState reads original evidence without creating native storage or a
// replacement root pin. Scope is the independent archive, not its stage lease.
func GitStageState(db Transactions, plan GitSavePlan) (*UploadScope, *GitStageRetirement, bool, error) {
	if db == nil || plan.Validate() != nil {
		return nil, nil, false, ErrInvalid
	}
	h, found, err := readGitSave(db, plan)
	return h.Scope, h.Retirement, found, err
}

func StoredGitStages(db Transactions, root nodestorage.Reference, tenant, context string, obsolete func(GitSavePlan) (bool, error), limit int) ([]GitSavePlan, error) {
	if db == nil || root.Validate() != nil || obsolete == nil || limit < 1 || limit > 16 {
		return nil, ErrInvalid
	}
	var plans []GitSavePlan
	err := db.View(func(tx *bolt.Tx) error {
		parent := draftParent(tx, root)
		if parent == nil {
			return nil
		}
		cursor := parent.Cursor()
		for key, raw := cursor.Seek([]byte("git-")); key != nil && bytes.HasPrefix(key, []byte("git-")); key, raw = cursor.Next() {
			var h nativeGitSave
			if len(raw) > 16<<10 || json.Unmarshal(raw, &h) != nil || !h.valid() || h.Plan.Root != root || !bytes.Equal(key, gitSaveKey(h.Plan)) {
				return ErrStorage
			}
			if h.Plan.Tenant != tenant || h.Plan.Context != context || h.Retirement != nil && h.Retirement.Root.Returned {
				continue
			}
			selected := h.Retirement != nil
			if !selected {
				var err error
				selected, err = obsolete(h.Plan)
				if err != nil {
					return err
				}
			}
			if !selected && h.Scope != nil {
				bucket := parent.Bucket([]byte(scopeName(*h.Scope)))
				if bucket != nil {
					var header localUpload
					data := bucket.Get(spoolHeader)
					if len(data) > 16<<10 || json.Unmarshal(data, &header) != nil || header.Scope != *h.Scope {
						return ErrStorage
					}
					selected = header.Seal != nil
				}
			}
			if !selected {
				continue
			}
			plans = append(plans, h.Plan)
			if len(plans) == limit {
				break
			}
		}
		return nil
	})
	return plans, err
}

func updateGitRetirement(db Transactions, before, next nativeGitSave) error {
	if !before.valid() || !next.valid() || before.Plan != next.Plan {
		return ErrStorage
	}
	expected, _ := json.Marshal(before)
	raw, _ := json.Marshal(next)
	if len(raw) > 16<<10 {
		return ErrStorage
	}
	return db.Update(func(tx *bolt.Tx) error {
		parent := draftParent(tx, next.Plan.Root)
		if parent == nil {
			return ErrStorage
		}
		var current nativeGitSave
		stored := parent.Get(gitSaveKey(next.Plan))
		if len(stored) > 16<<10 || json.Unmarshal(stored, &current) != nil || !current.valid() {
			return ErrStorage
		}
		canonical, _ := json.Marshal(current)
		if !bytes.Equal(canonical, expected) {
			return ErrConflict
		}
		return parent.Put(gitSaveKey(next.Plan), raw)
	})
}

// RetireGitStage preserves adopted archives and all original native metadata.
// The owner holds the same editor gate and original stage pin through Close.
func (s *Spool) RetireGitStage(ctx context.Context, g GitStageGrant, lease reconcile.Lease) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !g.Valid() || g.Plan.Root != s.root || s.dir == nil || lease.Token == 0 || lease.Generation != s.root.Generation {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	h, found, err := s.loadGitSave(g.Plan)
	if err != nil || !found {
		return errors.Join(ErrStorage, err)
	}
	if h.Retirement != nil {
		r := h.Retirement
		if r.Root.Lease != lease || g.Index < r.Grant.Index || g.Epoch < r.Grant.Epoch || g.ContextRevision < r.Grant.ContextRevision || g.PolicyRevision < r.Grant.PolicyRevision {
			return ErrConflict
		}
		if r.Removed {
			return nil
		}
	}
	var st unix.Stat_t
	statErr := unix.Fstatat(int(s.dir.Fd()), gitSaveName(g.Plan), &st, unix.AT_SYMLINK_NOFOLLOW)
	exists := statErr == nil
	if statErr != nil && !errors.Is(statErr, unix.ENOENT) {
		return ErrStorage
	}
	transferred := false
	if h.Scope != nil {
		header, headerErr := s.header(*h.Scope)
		if headerErr == nil {
			// A header alone precedes rename. Only the original sealed archive
			// (or its completed native deletion) proves independent ownership.
			if header.Generated == nil || *header.Generated != g.Plan.Digest() || header.Device != h.Device || header.Inode != h.Inode || header.Invalid || exists {
				return ErrUsed
			}
			settled := header.Deleted && header.Unpublished != nil && header.Unpublished.valid(header) && header.Unpublished.Returning
			if !settled && (header.Seal == nil || header.Seal.Schema != 1 || header.Seal.Scope != h.Scope.Hash() || header.Seal.ZIP != h.Scope.Digest || header.Seal.Tree != g.Plan.Tree || header.Seal.Entries == 0 || header.Seal.Entries > MaxTreeEntries || header.Seal.ExpandedBytes < 0 || header.Seal.ExpandedBytes > h.Scope.ExpandedLimit) {
				return ErrUsed
			}
			if !header.Deleted {
				file, err := s.file(header, false)
				if err != nil {
					return err
				}
				info, statErr := file.Stat()
				closeErr := file.Close()
				if statErr != nil || closeErr != nil || info.Size() != h.Scope.Length {
					return ErrStorage
				}
			}
			transferred = true
		} else {
			// Missing and malformed headers are distinct. Never discard an
			// ambiguous generated archive from a failed header decode.
			missing := false
			err := s.db.View(func(tx *bolt.Tx) error { missing = s.bucket(tx, *h.Scope) == nil; return nil })
			if err != nil || !missing {
				return ErrStorage
			}
			return ErrUsed // prepared source must settle its independent archive first
		}
	}
	if !transferred && !g.Obsolete() {
		return reconcile.ErrPending
	}
	if h.Retirement != nil && h.Retirement.Transferred != transferred {
		return ErrStorage
	}
	next := h
	if exists {
		if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) || st.Mode&07777 != 0600 || st.Size < 0 || st.Size > MaxZIPBytes || h.Inode != 0 && (st.Ino != h.Inode || uint64(st.Dev) != h.Device) || h.Inode == 0 && st.Size != 0 {
			return ErrStorage
		}
		if h.Inode == 0 {
			next.Device, next.Inode = uint64(st.Dev), st.Ino
		}
	} else if !transferred && h.Inode != 0 && h.Retirement == nil {
		return ErrStorage
	}
	if h.Retirement == nil {
		next.Retirement = &GitStageRetirement{Grant: g, Root: NativeRootHold{Lease: lease}, Transferred: transferred}
		if err := updateGitRetirement(s.db, h, next); err != nil {
			return err
		}
		h = next
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if exists {
		if err := unix.Unlinkat(int(s.dir.Fd()), gitSaveName(g.Plan), 0); err != nil {
			return err
		}
	}
	if err := s.dir.Sync(); err != nil {
		return err
	}
	next = h
	r := *h.Retirement
	r.Removed, r.Root.Returning = true, true
	next.Retirement = &r
	return updateGitRetirement(s.db, h, next)
}

func FinishGitStageRetirement(db Transactions, plan GitSavePlan, lease reconcile.Lease) error {
	if db == nil || plan.Validate() != nil {
		return ErrInvalid
	}
	h, found, err := readGitSave(db, plan)
	if err != nil || !found {
		return errors.Join(ErrStorage, err)
	}
	if h.Retirement == nil || !h.Retirement.Removed || h.Retirement.Root.Lease != lease {
		return ErrConflict
	}
	if h.Retirement.Root.Returned {
		return nil
	}
	next := h
	r := *h.Retirement
	r.Root.Returned = true
	next.Retirement = &r
	return updateGitRetirement(db, h, next)
}
