// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/jay94ks/mydcd/internal/reconcile"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/sys/unix"
)

type nativeGitSave struct {
	Plan          GitSavePlan
	Device, Inode uint64
	Scope         *UploadScope        `json:",omitempty"`
	Retirement    *GitStageRetirement `json:",omitempty"`
}

func (h nativeGitSave) valid() bool {
	return h.Plan.Validate() == nil && (h.Device == 0) == (h.Inode == 0) && (h.Scope == nil || h.Scope.Validate() == nil && *h.Scope == h.Plan.ArchiveScope(h.Scope.Length, h.Scope.Digest) && h.Inode != 0) && (h.Retirement == nil || h.Retirement.valid(h))
}

func gitSaveKey(plan GitSavePlan) []byte {
	h := digestJSON("mydc-imagebuild-git-local-id-1", struct{ Tenant, ID string }{plan.Tenant, plan.ID})
	return []byte("git-" + hex.EncodeToString(h[:]))
}
func gitSaveName(plan GitSavePlan) string {
	h := plan.Digest()
	return "git-" + hex.EncodeToString(h[:]) + ".zip"
}

// GitSaveExists is a metadata-only admission lookup. It never creates an
// intent or treats a different plan under the same original ID as a miss.
func (s *Spool) GitSaveExists(plan GitSavePlan) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if plan.Validate() != nil || plan.Root != s.root || s.dir == nil {
		return false, ErrInvalid
	}
	_, found, err := s.loadGitSave(plan)
	return found, err
}
func (s *Spool) loadGitSave(plan GitSavePlan) (nativeGitSave, bool, error) {
	return readGitSave(s.db, plan)
}

// GitSaveRecorded does not create a root/spool. Runtime uses it to distinguish
// a new fetch from a retained artifact whose original pin must still exist.
func GitSaveRecorded(db Transactions, plan GitSavePlan) (bool, error) {
	if db == nil || plan.Validate() != nil {
		return false, ErrInvalid
	}
	_, found, err := readGitSave(db, plan)
	return found, err
}
func readGitSave(db Transactions, plan GitSavePlan) (nativeGitSave, bool, error) {
	var h nativeGitSave
	found := false
	err := db.View(func(tx *bolt.Tx) error {
		parent := draftParent(tx, plan.Root)
		if parent == nil {
			return nil
		}
		raw := parent.Get(gitSaveKey(plan))
		found = raw != nil
		if found && (len(raw) > 16<<10 || json.Unmarshal(raw, &h) != nil || !h.valid() || h.Plan != plan) {
			return ErrConflict
		}
		return nil
	})
	return h, found, err
}
func (s *Spool) saveGit(h nativeGitSave) error {
	if !h.valid() {
		return ErrStorage
	}
	raw, _ := json.Marshal(h)
	return s.db.Update(func(tx *bolt.Tx) error {
		parent := draftParent(tx, h.Plan.Root)
		if parent == nil {
			return ErrStorage
		}
		return parent.Put(gitSaveKey(h.Plan), raw)
	})
}
func (s *Spool) gitSaveFile(h nativeGitSave) (*os.File, error) {
	fd, err := unix.Openat2(int(s.dir.Fd()), gitSaveName(h.Plan), &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "imagebuild-git-original")
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || h.Inode == 0 || st.Ino != h.Inode || uint64(st.Dev) != h.Device || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) || st.Mode&0777 != 0600 || st.Size <= 0 || st.Size > MaxZIPBytes {
		_ = file.Close()
		return nil, ErrStorage
	}
	return file, nil
}
func savedGitTree(ctx context.Context, file *os.File, plan GitSavePlan) (UploadScope, Tree, error) {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > MaxZIPBytes {
		return UploadScope{}, Tree{}, ErrStorage
	}
	hash, err := fileDigest(ctx, file, info.Size())
	if err != nil {
		return UploadScope{}, Tree{}, err
	}
	tree, err := InspectZIP(ctx, file, info.Size(), plan.Dockerfile, plan.ExpandedLimit)
	if err != nil {
		return UploadScope{}, Tree{}, err
	}
	if tree.Digest() != plan.Tree {
		return UploadScope{}, Tree{}, ErrDigest
	}
	return plan.ArchiveScope(info.Size(), hash), tree, nil
}

// PrepareGit writes an authenticated exact-commit archive once. The callback
// is never invoked for a retained intent, even after a partial write. A full
// original can recover its missing completion through the same ZIP/tree core.
func (s *Spool) PrepareGit(ctx context.Context, plan GitSavePlan, write func(io.Writer) (Tree, error)) (UploadScope, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if plan.Validate() != nil || plan.Root != s.root || s.dir == nil {
		return UploadScope{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return UploadScope{}, err
	}
	h, found, err := s.loadGitSave(plan)
	if err != nil {
		return UploadScope{}, err
	}
	if found && h.Retirement != nil && !h.Retirement.Transferred {
		return UploadScope{}, ErrUsed
	}
	if !found {
		if write == nil {
			return UploadScope{}, ErrInvalid
		}
		h = nativeGitSave{Plan: plan}
		if err = s.saveGit(h); err != nil {
			return UploadScope{}, err
		}
		fd, cause := unix.Openat2(int(s.dir.Fd()), gitSaveName(plan), &unix.OpenHow{Flags: unix.O_CREAT | unix.O_EXCL | unix.O_RDWR | unix.O_CLOEXEC, Mode: 0600, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
		if cause != nil {
			return UploadScope{}, ErrStorage
		}
		file := os.NewFile(uintptr(fd), "imagebuild-git-write")
		defer file.Close()
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) || st.Mode&0777 != 0600 {
			return UploadScope{}, ErrStorage
		}
		h.Device, h.Inode = uint64(st.Dev), st.Ino
		if unix.Fsync(int(s.dir.Fd())) != nil {
			return UploadScope{}, ErrStorage
		}
		if err = s.saveGit(h); err != nil {
			return UploadScope{}, err
		}
		tree, cause := write(file)
		if cause != nil {
			return UploadScope{}, cause
		}
		if tree.Digest() != plan.Tree {
			return UploadScope{}, ErrDigest
		}
		if file.Sync() != nil || unix.Fsync(int(s.dir.Fd())) != nil {
			return UploadScope{}, ErrStorage
		}
	}
	file, err := s.gitSaveFile(h)
	if errors.Is(err, unix.ENOENT) && h.Scope != nil {
		imported, cause := s.header(*h.Scope)
		original := nativeGeneratedArchive{Scope: *h.Scope, Plan: plan.Digest(), Device: h.Device, Inode: h.Inode}
		if cause != nil || !matchesGeneratedArchive(imported, original) {
			return UploadScope{}, ErrStorage
		}
		file, err = s.file(imported, false)
	}
	if err != nil {
		return UploadScope{}, errors.Join(reconcile.ErrPending, err)
	}
	defer file.Close()
	scope, _, err := savedGitTree(ctx, file, plan)
	if err != nil {
		return UploadScope{}, errors.Join(reconcile.ErrPending, err)
	}
	if h.Scope != nil && *h.Scope != scope {
		return UploadScope{}, ErrStorage
	}
	if file.Sync() != nil || unix.Fsync(int(s.dir.Fd())) != nil {
		return UploadScope{}, ErrStorage
	}
	h.Scope = &scope
	if err = s.saveGit(h); err != nil {
		return UploadScope{}, err
	}
	return scope, nil
}

// AdoptGit requires the caller's original staging and archive RootManager
// pins, just like draft freeze. It returns owner evidence, not a Raft commit.
func (s *Spool) AdoptGit(ctx context.Context, plan GitSavePlan, key ed25519.PrivateKey) (SavedGit, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if plan.Validate() != nil || plan.Root != s.root || s.dir == nil {
		return SavedGit{}, ErrInvalid
	}
	h, found, err := s.loadGitSave(plan)
	if err != nil || !found || h.Scope == nil || h.Retirement != nil && !h.Retirement.Transferred || !signingKey(*h.Scope, key) {
		return SavedGit{}, ErrStorage
	}
	original := nativeGeneratedArchive{Scope: *h.Scope, Plan: plan.Digest(), Device: h.Device, Inode: h.Inode}
	fact, err := s.adoptGeneratedArchive(ctx, original, int(s.dir.Fd()), gitSaveName(plan), key, func(ctx context.Context, file *os.File) (Tree, error) {
		actual, tree, err := savedGitTree(ctx, file, plan)
		if err != nil {
			return Tree{}, err
		}
		if actual != original.Scope {
			return Tree{}, ErrDigest
		}
		return tree, nil
	})
	if err != nil {
		return SavedGit{}, err
	}
	out := SavedGit{Schema: 1, Plan: plan, Scope: *h.Scope, Fact: fact}
	out.Signature = ed25519.Sign(key, SavedGitBytes(out))
	return out, nil
}
