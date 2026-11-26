// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/sys/unix"
)

type nativeGeneratedArchive struct {
	Scope         UploadScope
	Plan          [32]byte
	Device, Inode uint64
}

func matchesGeneratedArchive(h localUpload, original nativeGeneratedArchive) bool {
	return h.Scope == original.Scope && h.Generated != nil && *h.Generated == original.Plan && h.Device == original.Device && h.Inode == original.Inode && !h.Invalid && !h.Deleted && !h.Deleting && h.Unpublished == nil
}

func matchesGenerated(h localUpload, original nativeDraftFreeze, plan DraftFreezePlan) bool {
	return original.Scope != nil && matchesGeneratedArchive(h, nativeGeneratedArchive{Scope: *original.Scope, Plan: plan.Digest(), Device: original.Device, Inode: original.Inode})
}

// adoptGenerated is called under the existing Spool gate after the source and
// archive RootManager dependencies have been retained. Its write-ahead header
// identifies the ONE original inode even when rename's response is lost.
func (s *Spool) adoptGenerated(ctx context.Context, original nativeDraftFreeze, sourceFD int, sourceName string, key ed25519.PrivateKey) (SealReceipt, error) {
	if original.Scope == nil || s.check(*original.Scope) != nil || original.Plan.Validate() != nil || *original.Scope != original.Plan.ArchiveScope(original.Scope.Length, original.Scope.Digest) || original.Inode == 0 || sourceFD < 0 || sourceName != freezeName(original.Plan) || !signingKey(*original.Scope, key) {
		return SealReceipt{}, ErrInvalid
	}
	archive := nativeGeneratedArchive{Scope: *original.Scope, Plan: original.Plan.Digest(), Device: original.Device, Inode: original.Inode}
	return s.adoptGeneratedArchive(ctx, archive, sourceFD, sourceName, key, func(ctx context.Context, file *os.File) (Tree, error) {
		actual, tree, err := frozenDraftTree(ctx, file, original.Plan)
		if err != nil {
			return Tree{}, err
		}
		if actual != archive.Scope {
			return Tree{}, ErrDigest
		}
		return tree, nil
	})
}

// Draft and Git wrappers keep their own source proof; this single adapter
// owns the original inode/rename/seal path for both generated archive kinds.
func (s *Spool) adoptGeneratedArchive(ctx context.Context, original nativeGeneratedArchive, sourceFD int, sourceName string, key ed25519.PrivateKey, check func(context.Context, *os.File) (Tree, error)) (SealReceipt, error) {
	if s.check(original.Scope) != nil || original.Plan == ([32]byte{}) || original.Inode == 0 || original.Device == 0 || sourceFD < 0 || !ContextPath(sourceName) || !signingKey(original.Scope, key) || check == nil {
		return SealReceipt{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return SealReceipt{}, err
	}
	scope := original.Scope
	var h localUpload
	err := s.db.Update(func(tx *bolt.Tx) error {
		parent := tx.Bucket(spoolBucket)
		if parent == nil {
			return ErrStorage
		}
		parent = parent.Bucket(s.key)
		if parent == nil {
			return ErrStorage
		}
		b := parent.Bucket([]byte(scopeName(scope)))
		if b != nil {
			if json.Unmarshal(b.Get(spoolHeader), &h) != nil || !matchesGeneratedArchive(h, original) {
				return ErrStorage
			}
			return nil
		}
		var err error
		b, err = parent.CreateBucket([]byte(scopeName(scope)))
		if err != nil {
			return err
		}
		digest := original.Plan
		h = localUpload{Scope: scope, Device: original.Device, Inode: original.Inode, Generated: &digest}
		raw, _ := json.Marshal(h)
		return b.Put(spoolHeader, raw)
	})
	if err != nil {
		return SealReceipt{}, err
	}
	file, err := s.placeGeneratedArchive(h, sourceFD, sourceName)
	if err != nil {
		return SealReceipt{}, err
	}
	defer file.Close()
	tree, err := check(ctx, file)
	if err != nil {
		return SealReceipt{}, err
	}
	if file.Sync() != nil {
		return SealReceipt{}, ErrStorage
	}
	// A generated archive is already complete. No fabricated per-part receipt
	// or Raft slot is created; all consumers use the same real sealed bytes.
	h.Received = scope.Parts()
	return s.persistSeal(h, tree, key)
}

// placeGeneratedArchive moves only the original prepared inode. Adoption and
// fenced unpublished cleanup share its header/rename/fsync/file checks.
func (s *Spool) placeGeneratedArchive(h localUpload, sourceFD int, sourceName string) (*os.File, error) {
	scope := h.Scope
	destination := scopeName(scope) + ".zip"
	var st unix.Stat_t
	err := unix.Fstatat(int(s.dir.Fd()), destination, &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		fd, cause := unix.Openat2(sourceFD, sourceName, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
		if cause != nil {
			return nil, ErrStorage
		}
		file := os.NewFile(uintptr(fd), "imagebuild-generated-archive")
		cause = unix.Fstat(fd, &st)
		_ = file.Close()
		if cause != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) || st.Mode&0777 != 0600 || uint64(st.Dev) != h.Device || st.Ino != h.Inode || st.Size != scope.Length {
			return nil, ErrStorage
		}
		if cause = unix.Renameat2(sourceFD, sourceName, int(s.dir.Fd()), destination, unix.RENAME_NOREPLACE); cause != nil {
			return nil, ErrStorage
		}
	} else if err != nil {
		return nil, ErrStorage
	}
	if unix.Fsync(sourceFD) != nil || unix.Fsync(int(s.dir.Fd())) != nil {
		return nil, ErrStorage
	}
	file, err := s.file(h, false)
	if err != nil {
		return nil, err
	}
	return file, nil
}
