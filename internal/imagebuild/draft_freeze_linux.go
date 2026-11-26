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

type nativeDraftFreeze struct {
	Plan          DraftFreezePlan
	Device, Inode uint64
	Scope         *UploadScope `json:",omitempty"`
	Removing      bool         `json:",omitempty"`
	Removed       bool         `json:",omitempty"`
}

func (h nativeDraftFreeze) valid() bool {
	return h.Plan.Validate() == nil && (h.Device == 0) == (h.Inode == 0) && (h.Scope == nil || h.Scope.Validate() == nil && *h.Scope == h.Plan.ArchiveScope(h.Scope.Length, h.Scope.Digest) && h.Inode != 0) && (!h.Removed || h.Removing) && (!h.Removing || h.Scope == nil)
}

func freezeKey(plan DraftFreezePlan) []byte { return []byte("freeze-" + plan.ID) }
func freezeName(plan DraftFreezePlan) string {
	h := plan.Digest()
	return "freeze-" + hex.EncodeToString(h[:]) + ".zip"
}
func (d *DraftStore) loadFreeze(plan DraftFreezePlan) (nativeDraftFreeze, bool, error) {
	var h nativeDraftFreeze
	found := false
	err := d.spool.db.View(func(tx *bolt.Tx) error {
		b := d.bucket(tx)
		if b == nil {
			return ErrStorage
		}
		raw := b.Get(freezeKey(plan))
		found = raw != nil
		if found && (len(raw) > 16<<10 || json.Unmarshal(raw, &h) != nil || h.Plan != plan || !h.valid()) {
			return ErrConflict
		}
		return nil
	})
	return h, found, err
}
func (d *DraftStore) saveFreeze(h nativeDraftFreeze) error {
	if !h.valid() || h.Plan.Scope.Data() != d.scope.Data() {
		return ErrStorage
	}
	raw, _ := json.Marshal(h)
	return d.spool.db.Update(func(tx *bolt.Tx) error {
		b := d.bucket(tx)
		if b == nil {
			return ErrStorage
		}
		return b.Put(freezeKey(h.Plan), raw)
	})
}
func (d *DraftStore) freezeFile(h nativeDraftFreeze) (*os.File, error) {
	fd, err := unix.Openat2(int(d.dir.Fd()), freezeName(h.Plan), &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "imagebuild-draft-freeze")
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || h.Inode == 0 || st.Ino != h.Inode || uint64(st.Dev) != h.Device || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) || st.Mode&0777 != 0600 || st.Size <= 0 || st.Size > MaxZIPBytes {
		_ = file.Close()
		return nil, ErrStorage
	}
	return file, nil
}

func frozenDraftTree(ctx context.Context, file *os.File, plan DraftFreezePlan) (UploadScope, Tree, error) {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > MaxZIPBytes {
		return UploadScope{}, Tree{}, ErrStorage
	}
	digest, err := fileDigest(ctx, file, info.Size())
	if err != nil {
		return UploadScope{}, Tree{}, err
	}
	tree, err := InspectZIP(ctx, file, info.Size(), plan.Scope.Dockerfile, plan.Scope.ExpandedLimit)
	if err != nil {
		return UploadScope{}, Tree{}, err
	}
	draft := Draft{Scope: plan.Scope, Revision: plan.Revision, Entries: tree.Entries}
	if draft.Validate() != nil || draft.Digest() != plan.Draft {
		return UploadScope{}, Tree{}, ErrDigest
	}
	return plan.ArchiveScope(info.Size(), digest), tree, nil
}

// PrepareFreeze creates one original archive. A complete file survives a lost
// completion record through ZIP/tree/read-back; a partial original is retained
// as pending and is never truncated/rebuilt under the same freeze ID.
func (d *DraftStore) PrepareFreeze(ctx context.Context, plan DraftFreezePlan) (UploadScope, error) {
	d.spool.mu.Lock()
	defer d.spool.mu.Unlock()
	if plan.Validate() != nil || plan.Scope.Data() != d.scope.Data() || d.dir == nil || d.spool.dir == nil {
		return UploadScope{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return UploadScope{}, err
	}
	h, found, err := d.loadFreeze(plan)
	if err != nil {
		return UploadScope{}, err
	}
	if found && h.Removing {
		return UploadScope{}, ErrUsed
	}
	if !found {
		if plan.Scope != d.scope {
			return UploadScope{}, ErrConflict
		}
		draft, err := d.state()
		if err != nil {
			return UploadScope{}, err
		}
		if draft.Revision != plan.Revision || draft.Digest() != plan.Draft {
			return UploadScope{}, ErrConflict
		}
		if draft.Validate() != nil {
			return UploadScope{}, ErrInvalid
		}
		validDockerfile := false
		for _, entry := range draft.Entries {
			if entry.Path == plan.Scope.Dockerfile && !entry.Directory {
				validDockerfile = true
			}
		}
		if !validDockerfile {
			return UploadScope{}, ErrInvalid
		}
		h = nativeDraftFreeze{Plan: plan}
		if err = d.saveFreeze(h); err != nil {
			return UploadScope{}, err
		}
		fd, err := unix.Openat2(int(d.dir.Fd()), freezeName(plan), &unix.OpenHow{Flags: unix.O_CREAT | unix.O_EXCL | unix.O_RDWR | unix.O_CLOEXEC, Mode: 0600, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
		if err != nil {
			return UploadScope{}, ErrStorage
		}
		file := os.NewFile(uintptr(fd), "imagebuild-draft-freeze")
		defer file.Close()
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) || st.Mode&0777 != 0600 {
			return UploadScope{}, ErrStorage
		}
		h.Device, h.Inode = uint64(st.Dev), st.Ino
		if err = d.saveFreeze(h); err != nil {
			return UploadScope{}, err
		}
		_, err = draft.WriteZIP(ctx, file, func(entry Entry) (io.ReadCloser, error) {
			blob, err := d.blob(entry)
			if err != nil || !blob.Done {
				return nil, ErrStorage
			}
			return d.openBlob(blob)
		})
		if err != nil {
			return UploadScope{}, err
		}
		if file.Sync() != nil || unix.Fsync(int(d.dir.Fd())) != nil {
			return UploadScope{}, ErrStorage
		}
	}
	file, err := d.freezeFile(h)
	if err != nil {
		if errors.Is(err, unix.ENOENT) && h.Scope != nil {
			// Adoption may already have moved the original inode. Never create
			// another file because its source pathname has disappeared.
			imported, cause := d.spool.header(*h.Scope)
			if cause != nil || !matchesGenerated(imported, h, plan) {
				return UploadScope{}, ErrStorage
			}
			file, err = d.spool.file(imported, false)
		}
		if err != nil {
			return UploadScope{}, errors.Join(reconcile.ErrPending, err)
		}
	}
	defer file.Close()
	scope, _, err := frozenDraftTree(ctx, file, plan)
	if err != nil {
		return UploadScope{}, errors.Join(reconcile.ErrPending, err)
	}
	if h.Scope != nil && *h.Scope != scope {
		return UploadScope{}, ErrStorage
	}
	if file.Sync() != nil || unix.Fsync(int(d.dir.Fd())) != nil {
		return UploadScope{}, ErrStorage
	}
	h.Scope = &scope
	if err = d.saveFreeze(h); err != nil {
		return UploadScope{}, err
	}
	return scope, nil
}

// AdoptFreeze requires the caller to retain both the draft pin and the
// archive's RootManager pin. It hands the SAME inode to the existing Spool.
func (d *DraftStore) AdoptFreeze(ctx context.Context, plan DraftFreezePlan, key ed25519.PrivateKey) (FrozenDraft, error) {
	d.spool.mu.Lock()
	defer d.spool.mu.Unlock()
	if plan.Validate() != nil || plan.Scope.Data() != d.scope.Data() || d.dir == nil || d.spool.dir == nil {
		return FrozenDraft{}, ErrInvalid
	}
	h, found, err := d.loadFreeze(plan)
	if err != nil || !found || h.Removing || h.Scope == nil || !signingKey(*h.Scope, key) {
		return FrozenDraft{}, ErrStorage
	}
	fact, err := d.spool.adoptGenerated(ctx, h, int(d.dir.Fd()), freezeName(plan), key)
	if err != nil {
		return FrozenDraft{}, err
	}
	result := FrozenDraft{Schema: 1, Plan: plan, Scope: *h.Scope, Fact: fact}
	result.Signature = ed25519.Sign(key, FrozenDraftBytes(result))
	return result, nil
}
