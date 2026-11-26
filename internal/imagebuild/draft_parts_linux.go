// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/jay94ks/mydcd/internal/reconcile"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/sys/unix"
)

func draftFilePartKey(digest [32]byte, index uint32) []byte {
	return append(append(draftBlobKey(digest), '/'), partKey(index)...)
}

// fileIntent pins the same edit ID before any file write, including partial
// uploads. Its final result is written by the existing DraftStore.Edit core.
func (d *DraftStore) fileIntent(edit DraftEdit, create bool) (*DraftEditResult, error) {
	if edit.Validate() != nil || edit.Kind != "put" {
		return nil, ErrInvalid
	}
	if d.dir == nil || d.spool.dir == nil {
		return nil, ErrStorage
	}
	var record draftEditRecord
	found := false
	err := d.spool.db.View(func(tx *bolt.Tx) error {
		b := d.bucket(tx)
		if b == nil {
			return ErrStorage
		}
		raw := b.Get([]byte("edit-" + edit.ID))
		found = raw != nil
		if found && (len(raw) > maxDraftEditRecordBytes || json.Unmarshal(raw, &record) != nil || !record.matches(edit)) {
			return ErrConflict
		}
		return nil
	})
	if err == nil && found && record.Abandoned {
		return nil, ErrConflict // Original CAS was fenced before body collection.
	}
	if err != nil || found {
		return record.Result, err
	}
	if !create {
		return nil, ErrDraftMissing
	}
	draft, err := d.state()
	if err != nil {
		return nil, err
	}
	if _, err := draft.Edit(edit); err != nil {
		return nil, err // Do not reserve bytes for an edit that cannot commit.
	}
	if err := d.guardDraftBlobGC(edit); err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(draftEditRecord{Edit: edit.Digest(), Input: &edit})
	err = d.spool.db.Update(func(tx *bolt.Tx) error {
		b := d.bucket(tx)
		if b == nil || b.Get([]byte("edit-"+edit.ID)) != nil {
			return ErrConflict
		}
		return b.Put([]byte("edit-"+edit.ID), raw)
	})
	return nil, err
}

func (d *DraftStore) openMultipartBlob(blob draftBlob) (*os.File, error) {
	fd, err := unix.Openat2(int(d.dir.Fd()), string(draftBlobKey(blob.Digest)), &unix.OpenHow{Flags: unix.O_RDWR | unix.O_NONBLOCK | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return nil, ErrStorage
	}
	file := os.NewFile(uintptr(fd), "imagebuild-draft-part")
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || !blob.Created || uint64(st.Dev) != blob.Device || st.Ino != blob.Inode || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size < 0 || st.Size > blob.Bytes || st.Uid != uint32(os.Geteuid()) || st.Mode&0777 != 0600 || st.Nlink != 1 {
		_ = file.Close()
		return nil, ErrStorage
	}
	return file, nil
}

func (d *DraftStore) multipartBlob(entry Entry) (draftBlob, error) {
	found := false
	err := d.spool.db.View(func(tx *bolt.Tx) error {
		b := d.bucket(tx)
		if b == nil {
			return ErrStorage
		}
		found = b.Get(draftBlobKey(entry.Digest)) != nil
		return nil
	})
	if err != nil {
		return draftBlob{}, err
	}
	if found {
		blob, err := d.blob(entry)
		if err != nil || !blob.Created || !blob.Multipart && !blob.Done {
			return draftBlob{}, errors.Join(reconcile.ErrPending, err)
		}
		return blob, nil
	}
	blob := draftBlob{Digest: entry.Digest, Bytes: entry.Bytes, Multipart: true}
	if err := d.saveBlob(blob); err != nil {
		return draftBlob{}, err
	}
	fd, err := unix.Openat2(int(d.dir.Fd()), string(draftBlobKey(blob.Digest)), &unix.OpenHow{Flags: unix.O_CREAT | unix.O_EXCL | unix.O_RDWR | unix.O_CLOEXEC, Mode: 0600, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return draftBlob{}, ErrStorage
	}
	file := os.NewFile(uintptr(fd), "imagebuild-draft-file")
	defer file.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) || st.Mode&0777 != 0600 {
		return draftBlob{}, ErrStorage
	}
	blob.Device, blob.Inode, blob.Created = uint64(st.Dev), st.Ino, true
	if unix.Fsync(int(d.dir.Fd())) != nil {
		return draftBlob{}, ErrStorage
	}
	return blob, d.saveBlob(blob)
}

func (d *DraftStore) StageFilePart(ctx context.Context, edit DraftEdit, index uint32, data []byte) (DraftFileProgress, error) {
	d.spool.mu.Lock()
	defer d.spool.mu.Unlock()
	if len(data) == 0 || len(data) != DraftFilePartLength(edit, index) {
		return DraftFileProgress{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return DraftFileProgress{}, err
	}
	original, err := d.fileIntent(edit, true)
	if err != nil {
		return DraftFileProgress{}, err
	}
	var blob draftBlob
	if original != nil {
		blob, err = d.blob(*edit.File) // Never recreate bytes of a completed edit.
		if err == nil && !blob.Done {
			err = ErrStorage
		}
	} else {
		blob, err = d.multipartBlob(*edit.File)
	}
	if err != nil {
		return DraftFileProgress{}, err
	}
	file, err := d.openMultipartBlob(blob)
	if err != nil {
		return DraftFileProgress{}, err
	}
	defer file.Close()
	digest := sha256.Sum256(data)
	var part localPart
	key := draftFilePartKey(blob.Digest, index)
	err = d.spool.db.View(func(tx *bolt.Tx) error {
		b := d.bucket(tx)
		if b == nil {
			return ErrStorage
		}
		raw := b.Get(key)
		if raw != nil && (len(raw) > 1024 || json.Unmarshal(raw, &part) != nil || part.Digest != digest) {
			return ErrConflict
		}
		return nil
	})
	if err != nil {
		return DraftFileProgress{}, err
	}
	offset := int64(index) * PartBytes
	if part.Stored || blob.Done {
		actual := make([]byte, len(data))
		n, err := file.ReadAt(actual, offset)
		if err != nil || n != len(actual) || !bytes.Equal(actual, data) {
			return DraftFileProgress{}, ErrDigest
		}
	} else {
		if blob.Received >= draftFileParts(edit) {
			return DraftFileProgress{}, ErrStorage
		}
		if part.Digest == ([32]byte{}) {
			part.Digest = digest
			raw, _ := json.Marshal(part)
			if err := d.spool.db.Update(func(tx *bolt.Tx) error {
				b := d.bucket(tx)
				if b == nil {
					return ErrStorage
				}
				return b.Put(key, raw)
			}); err != nil {
				return DraftFileProgress{}, err
			}
		}
		// A pending slot can be repaired only with the same immutable bytes.
		// No other slot, file length, edit ID or expected revision is changed.
		if n, err := file.WriteAt(data, offset); err != nil || n != len(data) {
			return DraftFileProgress{}, ErrStorage
		}
		if file.Sync() != nil {
			return DraftFileProgress{}, ErrStorage
		}
		part.Stored = true
		blob.Received++
		raw, _ := json.Marshal(part)
		header, _ := json.Marshal(blob)
		if err := d.spool.db.Update(func(tx *bolt.Tx) error {
			b := d.bucket(tx)
			if b == nil {
				return ErrStorage
			}
			if err := b.Put(key, raw); err != nil {
				return err
			}
			return b.Put(draftBlobKey(blob.Digest), header)
		}); err != nil {
			return DraftFileProgress{}, err
		}
	}
	if !blob.Done && blob.Received == draftFileParts(edit) {
		if _, err := file.Seek(0, io.SeekStart); err != nil || verifyDraftBlob(ctx, file, blob) != nil {
			return DraftFileProgress{}, ErrDigest
		}
		blob.Done = true
		if err := d.saveBlob(blob); err != nil {
			return DraftFileProgress{}, err
		}
	}
	progress := DraftFileProgress{Edit: edit.Digest(), Parts: draftFileParts(edit), Received: blob.Received, Complete: blob.Done, Part: &DraftFilePart{Index: index, Length: uint32(len(data)), Digest: digest}}
	if blob.Done {
		progress.Received = progress.Parts
	}
	return progress, nil
}

func (d *DraftStore) FileStatus(ctx context.Context, edit DraftEdit, offset uint32) (DraftFileProgress, error) {
	d.spool.mu.Lock()
	defer d.spool.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return DraftFileProgress{}, err
	}
	if _, err := d.fileIntent(edit, false); err != nil {
		return DraftFileProgress{}, err
	}
	if offset > draftFileParts(edit) {
		return DraftFileProgress{}, ErrInvalid
	}
	blob, err := d.blob(*edit.File)
	if err != nil {
		return DraftFileProgress{}, err
	}
	progress := DraftFileProgress{Edit: edit.Digest(), Parts: draftFileParts(edit), Received: blob.Received, Complete: blob.Done, Offset: offset}
	if blob.Done {
		progress.Received = progress.Parts
		return progress, nil
	}
	err = d.spool.db.View(func(tx *bolt.Tx) error {
		b := d.bucket(tx)
		if b == nil {
			return ErrStorage
		}
		for i := offset; i < progress.Parts; i++ {
			var part localPart
			raw := b.Get(draftFilePartKey(blob.Digest, i))
			if raw != nil && (len(raw) > 1024 || json.Unmarshal(raw, &part) != nil || part.Digest == ([32]byte{})) {
				return ErrStorage
			}
			if !part.Stored {
				progress.Missing = append(progress.Missing, i)
			}
			if len(progress.Missing) == 256 {
				if i+1 < progress.Parts {
					progress.Next = i + 1
				}
				break
			}
		}
		return nil
	})
	return progress, err
}

func (d *DraftStore) CommitFile(ctx context.Context, edit DraftEdit) (DraftEditResult, error) {
	if err := ctx.Err(); err != nil {
		return DraftEditResult{}, err
	}
	// Edit takes the gate itself, verifies original bytes again, and commits
	// its original receipt and revision atomically. No second edit algorithm.
	d.spool.mu.Lock()
	original, err := d.fileIntent(edit, false)
	if err == nil && original == nil {
		var current Draft
		current, err = d.state()
		if err == nil {
			_, err = current.Edit(edit)
		}
	}
	if err == nil && original == nil {
		var blob draftBlob
		blob, err = d.blob(*edit.File)
		if err == nil && !blob.Done {
			if !blob.Multipart || blob.Received != draftFileParts(edit) {
				err = reconcile.ErrPending
			} else {
				var file *os.File
				file, err = d.openBlob(blob)
				if err == nil {
					err = verifyDraftBlob(ctx, file, blob)
					if err == nil {
						err = file.Sync()
					}
					closeErr := file.Close()
					if err == nil {
						err = closeErr
					}
				}
				if err == nil {
					blob.Done = true
					err = d.saveBlob(blob)
				}
			}
		}
	}
	d.spool.mu.Unlock()
	if err != nil {
		return DraftEditResult{}, err
	}
	if original != nil {
		return *original, nil
	}
	return d.Edit(ctx, edit, nil)
}
