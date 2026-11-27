// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/jay94ks/seafield/internal/reconcile"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/sys/unix"
)

// DraftStore borrows the existing Spool/observations DB and its RootManager
// pin. Close this descriptor before closing the Spool or returning that pin.
// Runtime admission is the caller's responsibility; no method grants access.
type DraftStore struct {
	spool *Spool
	dir   *os.File
	scope DraftScope
	key   []byte
}

var ErrDraftMissing = errors.New("original build draft not initialized")

type draftIdentity struct {
	Scope         DraftScope
	Device, Inode uint64
}
type DraftEditResult struct {
	Edit, Draft [32]byte
	Revision    uint64
}
type draftEditRecord struct {
	Edit      [32]byte
	Result    *DraftEditResult `json:",omitempty"`
	Input     *DraftEdit       `json:",omitempty"`
	Abandoned bool             `json:",omitempty"`
}

const maxDraftEditRecordBytes = 16 << 10

func (r draftEditRecord) matches(edit DraftEdit) bool {
	return r.Edit == edit.Digest() && (r.Input == nil || r.Input.Validate() == nil && r.Input.Digest() == r.Edit) && (r.Result == nil || r.Result.Edit == r.Edit && r.Result.Revision == edit.Expected+1 && r.Result.Draft != ([32]byte{})) && (!r.Abandoned || r.Input != nil && r.Result == nil)
}

type draftBlob struct {
	Digest        [32]byte
	Bytes         int64
	Device, Inode uint64
	Created, Done bool
	Multipart     bool   `json:",omitempty"`
	Received      uint32 `json:",omitempty"`
}

func OpenDraftStore(spool *Spool, scope DraftScope, create bool) (*DraftStore, error) {
	if spool == nil || scope.Validate() != nil || spool.root != scope.Root {
		return nil, ErrInvalid
	}
	spool.mu.Lock()
	defer spool.mu.Unlock()
	if spool.dir == nil {
		return nil, ErrStorage
	}
	digest := scope.Data().Digest()
	var binding draftBinding
	var found bool
	err := spool.db.View(func(tx *bolt.Tx) error {
		var err error
		binding, found, err = resolveDraftBinding(draftParent(tx, scope.Root), scope)
		if err == nil && found {
			_, retiring, cause := readDraftRetirement(draftParent(tx, scope.Root), binding)
			if cause != nil {
				return cause
			}
			if retiring {
				return ErrUsed
			}
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	name := draftDataName(scope.Data())
	if found {
		name = binding.Namespace
	}
	created := false
	if create && !found {
		if err = unix.Mkdirat(int(spool.dir.Fd()), name, 0700); err != nil {
			return nil, ErrStorage
		}
		created = true
	}
	fd, err := unix.Openat2(int(spool.dir.Fd()), name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		if !found && !create && errors.Is(err, unix.ENOENT) {
			return nil, ErrDraftMissing
		}
		return nil, ErrStorage
	}
	dir := os.NewFile(uintptr(fd), name)
	store := &DraftStore{spool: spool, dir: dir, scope: scope, key: []byte(name)}
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0777 != 0700 {
		_ = dir.Close()
		return nil, ErrStorage
	}
	if found && (uint64(stat.Dev) != binding.Identity.Device || stat.Ino != binding.Identity.Inode) {
		_ = dir.Close()
		return nil, ErrStorage
	}
	if !found {
		binding = draftBinding{Data: scope.Data(), Namespace: name, Identity: draftIdentity{scope, uint64(stat.Dev), stat.Ino}}
	}
	identity, _ := json.Marshal(binding.Identity)
	if created {
		if unix.Fsync(int(spool.dir.Fd())) != nil {
			_ = dir.Close()
			return nil, ErrStorage
		}
		err = spool.db.Update(func(tx *bolt.Tx) error {
			parent := store.parent(tx)
			if parent == nil || parent.Bucket(store.key) != nil {
				return ErrStorage
			}
			b, err := parent.CreateBucket(store.key)
			if err != nil {
				return err
			}
			if err = b.Put([]byte("identity"), identity); err != nil {
				return err
			}
			draft, err := NewDraft(scope)
			if err != nil {
				return err
			}
			raw, _ := json.Marshal(draft)
			if err = b.Put([]byte("state"), raw); err != nil {
				return err
			}
			return saveDraftBinding(parent, binding)
		})
	} else {
		err = spool.db.View(func(tx *bolt.Tx) error {
			b := store.bucket(tx)
			if b == nil || !bytes.Equal(b.Get([]byte("identity")), identity) {
				return ErrStorage // Missing evidence never initializes an old directory.
			}
			return nil
		})
		if err == nil && create {
			err = spool.db.Update(func(tx *bolt.Tx) error { return saveDraftBinding(store.parent(tx), binding) })
		}
	}
	if err != nil {
		_ = dir.Close()
		return nil, ErrStorage
	}
	// Use the existing Spool borrow gate, including its refusal to close while
	// a native reader/store still depends on the original root descriptor.
	spool.readers[digest]++
	return store, nil
}

func (d *DraftStore) parent(tx *bolt.Tx) *bolt.Bucket {
	b := tx.Bucket(spoolBucket)
	if b != nil {
		b = b.Bucket(d.spool.key)
	}
	return b
}
func (d *DraftStore) bucket(tx *bolt.Tx) *bolt.Bucket {
	b := d.parent(tx)
	if b != nil {
		b = b.Bucket(d.key)
	}
	return b
}
func (d *DraftStore) readState() (Draft, []byte, error) {
	var draft Draft
	var original []byte
	if d.dir == nil || d.spool.dir == nil {
		return draft, nil, ErrStorage
	}
	err := d.spool.db.View(func(tx *bolt.Tx) error {
		b := d.bucket(tx)
		if b == nil {
			return ErrStorage
		}
		raw := b.Get([]byte("state"))
		if len(raw) > MaxDraftMetadataBytes || json.Unmarshal(raw, &draft) != nil || draft.Scope.Data() != d.scope.Data() || draft.shape() != nil {
			return ErrStorage
		}
		original = bytes.Clone(raw)
		return nil
	})
	if err == nil {
		draft.Scope = d.scope
		if draft.shape() != nil {
			return Draft{}, nil, ErrStorage
		}
	}
	return draft, original, err
}
func (d *DraftStore) state() (Draft, error) { draft, _, err := d.readState(); return draft, err }
func (d *DraftStore) Read() (Draft, error) {
	d.spool.mu.Lock()
	defer d.spool.mu.Unlock()
	return d.state()
}
func draftBlobKey(hash [32]byte) []byte { return []byte("blob-" + hex.EncodeToString(hash[:])) }

func validDraftBlob(blob draftBlob) bool {
	parts := uint32((blob.Bytes + PartBytes - 1) / PartBytes)
	return blob.Digest != ([32]byte{}) && blob.Bytes >= 0 && blob.Bytes <= MaxZIPBytes && (!blob.Done || blob.Created) && (!blob.Created || blob.Inode != 0) && (blob.Multipart || blob.Received == 0) && (!blob.Multipart || blob.Received <= parts && (!blob.Done || blob.Received == parts))
}
func (d *DraftStore) blob(entry Entry) (draftBlob, error) {
	var blob draftBlob
	err := d.spool.db.View(func(tx *bolt.Tx) error {
		b := d.bucket(tx)
		if b == nil || len(b.Get(draftBlobKey(entry.Digest))) > 1024 || json.Unmarshal(b.Get(draftBlobKey(entry.Digest)), &blob) != nil || blob.Digest != entry.Digest || blob.Bytes != entry.Bytes || !validDraftBlob(blob) {
			return ErrStorage
		}
		return nil
	})
	return blob, err
}
func (d *DraftStore) saveBlob(blob draftBlob) error {
	raw, _ := json.Marshal(blob)
	return d.spool.db.Update(func(tx *bolt.Tx) error {
		b := d.bucket(tx)
		if b == nil {
			return ErrStorage
		}
		return b.Put(draftBlobKey(blob.Digest), raw)
	})
}
func (d *DraftStore) openBlob(blob draftBlob) (*os.File, error) {
	return d.openDraftBlob(blob, false)
}

// Partial bodies can be inspected for collection using their original inode,
// but are never accepted as complete source input by openBlob.
func (d *DraftStore) openDraftBlob(blob draftBlob, partial bool) (*os.File, error) {
	fd, err := unix.Openat2(int(d.dir.Fd()), string(draftBlobKey(blob.Digest)), &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return nil, errors.Join(ErrStorage, err)
	}
	file := os.NewFile(uintptr(fd), "imagebuild-draft-file")
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || !blob.Created || uint64(stat.Dev) != blob.Device || stat.Ino != blob.Inode || stat.Size < 0 || stat.Size > blob.Bytes || !partial && stat.Size != blob.Bytes || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0777 != 0600 || stat.Nlink != 1 {
		_ = file.Close()
		return nil, ErrStorage
	}
	return file, nil
}
func verifyDraftBlob(ctx context.Context, file *os.File, blob draftBlob) error {
	hash := sha256.New()
	n, err := io.CopyBuffer(hash, io.LimitReader(contextReader{ctx, file}, blob.Bytes+1), make([]byte, PartBytes))
	if err != nil || n != blob.Bytes || !bytes.Equal(hash.Sum(nil), blob.Digest[:]) {
		return ErrDigest
	}
	return nil
}

// putFile journals allocation before O_EXCL creation, and records the original
// inode before writing. Interrupted writes are never overwritten. A complete
// original may be adopted only after length/hash/fsync read-back.
func (d *DraftStore) putFile(ctx context.Context, entry Entry, body io.Reader) error {
	var blob draftBlob
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
		return err
	}
	if found {
		blob, err = d.blob(entry)
		if err != nil {
			return err
		}
		if blob.Multipart && !blob.Done {
			return reconcile.ErrPending
		}
		file, err := d.openBlob(blob)
		if err != nil {
			return errors.Join(reconcile.ErrPending, err)
		}
		defer file.Close()
		if err = verifyDraftBlob(ctx, file, blob); err != nil {
			return errors.Join(reconcile.ErrPending, err)
		}
		if err = file.Sync(); err != nil || unix.Fsync(int(d.dir.Fd())) != nil {
			return ErrStorage
		}
		blob.Done = true
		return d.saveBlob(blob)
	}
	if body == nil {
		return ErrInvalid
	}
	blob = draftBlob{Digest: entry.Digest, Bytes: entry.Bytes}
	if err = d.saveBlob(blob); err != nil {
		return err
	}
	fd, err := unix.Openat2(int(d.dir.Fd()), string(draftBlobKey(blob.Digest)), &unix.OpenHow{Flags: unix.O_CREAT | unix.O_EXCL | unix.O_WRONLY | unix.O_CLOEXEC, Mode: 0600, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return ErrStorage
	}
	file := os.NewFile(uintptr(fd), "imagebuild-draft-put")
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0777 != 0600 {
		return ErrStorage
	}
	blob.Device, blob.Inode, blob.Created = uint64(stat.Dev), stat.Ino, true
	if err = d.saveBlob(blob); err != nil {
		return err
	}
	hash := sha256.New()
	n, err := io.CopyBuffer(io.MultiWriter(file, hash), io.LimitReader(contextReader{ctx, body}, entry.Bytes+1), make([]byte, PartBytes))
	if err != nil || n != entry.Bytes || !bytes.Equal(hash.Sum(nil), entry.Digest[:]) {
		return ErrDigest
	}
	if file.Sync() != nil || unix.Fsync(int(d.dir.Fd())) != nil {
		return ErrStorage
	}
	if err = file.Close(); err != nil {
		return ErrStorage
	}
	blob.Done = true
	return d.saveBlob(blob)
}

func (d *DraftStore) Edit(ctx context.Context, edit DraftEdit, body io.Reader) (DraftEditResult, error) {
	d.spool.mu.Lock()
	defer d.spool.mu.Unlock()
	if edit.Validate() != nil {
		return DraftEditResult{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return DraftEditResult{}, err
	}
	before, originalState, err := d.readState()
	if err != nil {
		return DraftEditResult{}, err
	}
	key := []byte("edit-" + edit.ID)
	var original draftEditRecord
	var originalIntent []byte
	found := false
	err = d.spool.db.View(func(tx *bolt.Tx) error {
		b := d.bucket(tx)
		if b == nil {
			return ErrStorage
		}
		raw := b.Get(key)
		found = raw != nil
		if found && (len(raw) > maxDraftEditRecordBytes || json.Unmarshal(raw, &original) != nil || !original.matches(edit)) {
			return ErrConflict
		}
		originalIntent = bytes.Clone(raw)
		return nil
	})
	if err != nil {
		return DraftEditResult{}, err
	}
	if found && original.Abandoned {
		return DraftEditResult{}, ErrConflict
	}
	if found && original.Result != nil {
		return *original.Result, nil
	}
	after, err := before.Edit(edit)
	if err != nil {
		return DraftEditResult{}, err
	}
	if edit.Kind != "put" && body != nil {
		return DraftEditResult{}, ErrInvalid
	}
	if err := d.guardDraftBlobGC(edit); err != nil {
		return DraftEditResult{}, err
	}
	intent, _ := json.Marshal(draftEditRecord{Edit: edit.Digest(), Input: &edit})
	if found {
		intent = originalIntent // Preserve legacy pending records and their CAS.
	}
	if !found {
		err = d.spool.db.Update(func(tx *bolt.Tx) error {
			b := d.bucket(tx)
			if b == nil || b.Get(key) != nil {
				return ErrConflict
			}
			return b.Put(key, intent)
		})
		if err != nil {
			return DraftEditResult{}, err
		}
	}
	if edit.Kind == "put" {
		if err = d.putFile(ctx, *edit.File, body); err != nil {
			return DraftEditResult{}, err
		}
	}
	if err = ctx.Err(); err != nil {
		return DraftEditResult{}, err
	}
	result := DraftEditResult{Edit: edit.Digest(), Draft: after.Digest(), Revision: after.Revision}
	raw, _ := json.Marshal(after)
	receipt, _ := json.Marshal(draftEditRecord{Edit: edit.Digest(), Result: &result})
	err = d.spool.db.Update(func(tx *bolt.Tx) error {
		b := d.bucket(tx)
		if b == nil {
			return ErrStorage
		}
		if !bytes.Equal(b.Get([]byte("state")), originalState) || !bytes.Equal(b.Get(key), intent) {
			return ErrConflict
		}
		if err := b.Put(key, receipt); err != nil {
			return err
		}
		return b.Put([]byte("state"), raw)
	})
	return result, err
}

// Freeze holds the same native gate as edits, so every file is read from one
// revision. The returned tree is not a published version or a signed receipt.
func (d *DraftStore) Freeze(ctx context.Context, expected uint64, out io.Writer) (Draft, Tree, error) {
	d.spool.mu.Lock()
	defer d.spool.mu.Unlock()
	draft, err := d.state()
	if err != nil {
		return Draft{}, Tree{}, err
	}
	if draft.Revision != expected {
		return Draft{}, Tree{}, ErrConflict
	}
	tree, err := draft.WriteZIP(ctx, out, func(entry Entry) (io.ReadCloser, error) {
		blob, err := d.blob(entry)
		if err != nil || !blob.Done {
			return nil, ErrStorage
		}
		return d.openBlob(blob)
	})
	return draft, tree, err
}

func (d *DraftStore) Close() error {
	d.spool.mu.Lock()
	defer d.spool.mu.Unlock()
	if d.dir == nil {
		return nil
	}
	err := d.dir.Close()
	d.dir = nil
	if err == nil {
		digest := d.scope.Data().Digest()
		d.spool.readers[digest]--
		if d.spool.readers[digest] == 0 {
			delete(d.spool.readers, digest)
		}
	}
	return err
}
