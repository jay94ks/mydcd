// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/jay94ks/seafield/internal/nodestorage"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/sys/unix"
)

var spoolBucket = []byte("imagebuild-spools-1")
var spoolHeader = []byte("header")

// Spool borrows the node's observations DB and a registered root descriptor.
// It never owns the DB or returns the caller's RootManager pin. The caller must
// hold that pin through Close (including any open artifact readers).
type Spool struct {
	mu      sync.Mutex
	db      Transactions
	dir     *os.File
	root    nodestorage.Reference
	key     []byte
	readers map[[32]byte]int
}

// Transactions borrows synchronous transactions from the node's existing DB;
// neither Spool nor its caller gains ownership of that DB's lifetime.
type Transactions interface {
	View(func(*bolt.Tx) error) error
	Update(func(*bolt.Tx) error) error
}

type localUpload struct {
	Scope                      UploadScope
	Device, Inode              uint64
	Received                   uint32
	Invalid, Deleting, Deleted bool
	Seal                       *SealReceipt                `json:",omitempty"` // unsigned native evidence, signed at reply
	Generated                  *[32]byte                   `json:",omitempty"`
	Unpublished                *GeneratedArchiveRetirement `json:",omitempty"`
}
type localPart struct {
	Digest [32]byte
	Stored bool
}

// OpenSpool creates only a private child of the already pinned descriptor.
// Resolve flags prohibit symlink/mount escapes; names inside this directory
// are fixed SHA-256 scope identifiers, never paths supplied by a tenant.
func OpenSpool(rootFD int, root nodestorage.Reference, db Transactions) (*Spool, error) {
	return openSpool(rootFD, root, db, true)
}

// OpenExistingSpool does not create directories/buckets or rewrite identity.
// Read-only queries cannot initialize missing evidence as a fresh artifact.
func OpenExistingSpool(rootFD int, root nodestorage.Reference, db Transactions) (*Spool, error) {
	return openSpool(rootFD, root, db, false)
}
func openSpool(rootFD int, root nodestorage.Reference, db Transactions, create bool) (*Spool, error) {
	if rootFD < 0 || root.Validate() != nil || db == nil {
		return nil, ErrInvalid
	}
	if create {
		if err := unix.Mkdirat(rootFD, ".sfc-imagebuild", 0700); err != nil && !errors.Is(err, unix.EEXIST) {
			return nil, ErrStorage
		}
	}
	fd, err := unix.Openat2(rootFD, ".sfc-imagebuild", &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return nil, ErrStorage
	}
	dir := os.NewFile(uintptr(fd), "imagebuild-spool")
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0777 != 0700 {
		_ = dir.Close()
		return nil, ErrStorage
	}
	hash := root.Digest()
	spool := &Spool{db: db, dir: dir, root: root, key: []byte(hex.EncodeToString(hash[:])), readers: map[[32]byte]int{}}
	identity := struct {
		Root          nodestorage.Reference
		Device, Inode uint64
	}{root, uint64(stat.Dev), stat.Ino}
	raw, _ := json.Marshal(identity)
	var recorded bool
	err = db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(spoolBucket)
		if bucket != nil {
			bucket = bucket.Bucket(spool.key)
		}
		if bucket == nil || bucket.Get([]byte("identity")) == nil {
			if create {
				return nil
			}
			return ErrStorage
		}
		if string(bucket.Get([]byte("identity"))) != string(raw) {
			return ErrStorage
		}
		recorded = true
		return nil
	})
	if err == nil && !recorded {
		// The private directory must be durable before its identity is first
		// committed. An already committed matching identity needs no rewrite.
		if err := unix.Fsync(rootFD); err != nil {
			_ = dir.Close()
			return nil, ErrStorage
		}
		err = db.Update(func(tx *bolt.Tx) error {
			bucket, err := tx.CreateBucketIfNotExists(spoolBucket)
			if err != nil {
				return err
			}
			bucket, err = bucket.CreateBucketIfNotExists(spool.key)
			if err != nil {
				return err
			}
			// Protect against changing the private subdirectory inode between
			// restarts. RootManager separately protects the registered root identity.
			if before := bucket.Get([]byte("identity")); before != nil {
				if string(before) != string(raw) {
					return ErrStorage
				}
				return nil
			}
			return bucket.Put([]byte("identity"), raw)
		})
	}
	if err != nil {
		_ = dir.Close()
		return nil, ErrStorage
	}
	return spool, nil
}

func scopeName(s UploadScope) string { hash := s.Hash(); return hex.EncodeToString(hash[:]) }
func partKey(index uint32) []byte {
	key := []byte{'p', 0, 0, 0, 0}
	binary.BigEndian.PutUint32(key[1:], index)
	return key
}
func (s *Spool) bucket(tx *bolt.Tx, scope UploadScope) *bolt.Bucket {
	b := tx.Bucket(spoolBucket)
	if b == nil {
		return nil
	}
	b = b.Bucket(s.key)
	if b == nil {
		return nil
	}
	return b.Bucket([]byte(scopeName(scope)))
}
func (s *Spool) header(scope UploadScope) (localUpload, error) {
	var h localUpload
	err := s.db.View(func(tx *bolt.Tx) error {
		b := s.bucket(tx, scope)
		if b == nil {
			return ErrStorage
		}
		var err error
		h, err = decodeSpoolHeader(b.Get(spoolHeader), scope)
		return err
	})
	if err != nil {
		return localUpload{}, ErrStorage
	}
	return h, nil
}
func decodeSpoolHeader(raw []byte, scope UploadScope) (localUpload, error) {
	var h localUpload
	if json.Unmarshal(raw, &h) != nil || h.Scope != scope || h.Received > scope.Parts() || (h.Device == 0) != (h.Inode == 0) || h.Inode == 0 && (h.Received != 0 || h.Seal != nil) || h.Generated != nil && (*h.Generated == ([32]byte{}) || h.Inode == 0 || h.Received != 0 && h.Received != scope.Parts()) || h.Unpublished != nil && !h.Unpublished.valid(h) {
		return localUpload{}, ErrStorage
	}
	return h, nil
}
func (s *Spool) save(h localUpload) error {
	raw, _ := json.Marshal(h)
	return s.db.Update(func(tx *bolt.Tx) error {
		b := s.bucket(tx, h.Scope)
		if b == nil {
			return ErrStorage
		}
		return b.Put(spoolHeader, raw)
	})
}
func (s *Spool) check(scope UploadScope) error {
	if s == nil || s.dir == nil || scope.Validate() != nil || scope.Root != s.root {
		return ErrStorage
	}
	return nil
}
func (s *Spool) file(h localUpload, write bool) (*os.File, error) {
	if h.Deleted || h.Deleting || write && h.Seal != nil {
		return nil, ErrStorage
	}
	flags := uint64(unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW)
	if write {
		flags = unix.O_RDWR | unix.O_CLOEXEC | unix.O_NOFOLLOW
	}
	fd, err := unix.Openat2(int(s.dir.Fd()), scopeName(h.Scope)+".zip", &unix.OpenHow{Flags: flags, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return nil, ErrStorage
	}
	file := os.NewFile(uintptr(fd), "imagebuild-artifact")
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0777 != 0600 || uint64(stat.Dev) != h.Device || stat.Ino != h.Inode || stat.Size < 0 || stat.Size > h.Scope.Length {
		_ = file.Close()
		return nil, ErrStorage
	}
	return file, nil
}

// Begin follows the committed shared scope. A crash after the creation intent
// may adopt only an empty, private, regular original filename. Once an inode is
// recorded, a missing/replaced file never becomes a fresh empty upload.
func (s *Spool) Begin(ctx context.Context, scope UploadScope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.check(scope) != nil {
		return ErrStorage
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var h localUpload
	var recorded bool
	err := s.db.View(func(tx *bolt.Tx) error {
		b := s.bucket(tx, scope)
		if b == nil || b.Get(spoolHeader) == nil {
			return nil
		}
		var err error
		h, err = decodeSpoolHeader(b.Get(spoolHeader), scope)
		recorded = err == nil
		return err
	})
	if err == nil && !recorded {
		err = s.db.Update(func(tx *bolt.Tx) error {
			parent := tx.Bucket(spoolBucket)
			if parent != nil {
				parent = parent.Bucket(s.key)
			}
			if parent == nil {
				return ErrStorage
			}
			b, err := parent.CreateBucketIfNotExists([]byte(scopeName(scope)))
			if err != nil {
				return err
			}
			// A concurrent initializer may have committed after our View.
			if before := b.Get(spoolHeader); before != nil {
				h, err = decodeSpoolHeader(before, scope)
				return err
			}
			h.Scope = scope
			raw, _ := json.Marshal(h)
			return b.Put(spoolHeader, raw)
		})
	}
	if h.Invalid && err == nil {
		return ErrDigest
	}
	if err != nil || h.Deleted || h.Deleting || h.Generated != nil {
		return ErrStorage
	}
	if h.Inode != 0 {
		file, err := s.file(h, false)
		if err != nil {
			return err
		}
		return file.Close()
	}
	name := scopeName(scope) + ".zip"
	fd, err := unix.Openat(int(s.dir.Fd()), name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if errors.Is(err, unix.EEXIST) {
		fd, err = unix.Openat2(int(s.dir.Fd()), name, &unix.OpenHow{Flags: unix.O_RDWR | unix.O_CLOEXEC | unix.O_NOFOLLOW, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	}
	if err != nil {
		return ErrStorage
	}
	file := os.NewFile(uintptr(fd), "imagebuild-upload")
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Size != 0 || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0777 != 0600 || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) {
		return ErrStorage
	}
	if file.Sync() != nil || s.dir.Sync() != nil {
		return ErrStorage
	}
	h.Device, h.Inode = uint64(stat.Dev), stat.Ino
	return s.save(h)
}

func signingKey(scope UploadScope, key ed25519.PrivateKey) bool {
	return len(key) == ed25519.PrivateKeySize && string(key.Public().(ed25519.PublicKey)) == string(scope.Root.Key[:])
}
func signPart(scope UploadScope, index uint32, digest [32]byte, key ed25519.PrivateKey) PartReceipt {
	r := PartReceipt{Schema: 1, Scope: scope.Hash(), Index: index, Length: uint32(scope.PartLength(index)), Digest: digest}
	r.Signature = ed25519.Sign(key, PartReceiptBytes(r))
	return r
}
func fileDigest(ctx context.Context, f *os.File, length int64) ([32]byte, error) {
	hash := sha256.New()
	count, err := io.CopyBuffer(hash, contextReader{ctx, io.NewSectionReader(f, 0, length)}, make([]byte, 32<<10))
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	if err != nil || count != length {
		if err := ctx.Err(); err != nil {
			return [32]byte{}, err
		}
		return [32]byte{}, ErrStorage
	}
	return digest, nil
}

// Put stores unordered, fixed-offset parts. Native intent precedes WriteAt and
// fsync; native completion precedes the signed receipt. A pending part can only
// be recovered with the exact same bytes, never overwritten by a new payload.
func (s *Spool) Put(ctx context.Context, scope UploadScope, index uint32, data []byte, key ed25519.PrivateKey) (PartReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.check(scope) != nil || scope.PartLength(index) == 0 || len(data) != scope.PartLength(index) || !signingKey(scope, key) {
		return PartReceipt{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return PartReceipt{}, err
	}
	h, err := s.header(scope)
	if err != nil || h.Deleted || h.Deleting || h.Generated != nil {
		return PartReceipt{}, ErrStorage
	}
	if h.Invalid {
		return PartReceipt{}, ErrDigest
	}
	digest := sha256.Sum256(data)
	var part localPart
	err = s.db.Update(func(tx *bolt.Tx) error {
		b := s.bucket(tx, scope)
		if b == nil {
			return ErrStorage
		}
		if raw := b.Get(partKey(index)); raw != nil {
			if json.Unmarshal(raw, &part) != nil {
				return ErrStorage
			}
			if part.Digest != digest {
				return ErrConflict
			}
			return nil
		}
		if h.Seal != nil {
			return ErrConflict
		}
		part.Digest = digest
		raw, _ := json.Marshal(part)
		return b.Put(partKey(index), raw)
	})
	if err != nil {
		return PartReceipt{}, err
	}
	if part.Stored {
		return s.readStoredPart(ctx, scope, index, digest, h, key)
	}
	file, err := s.file(h, !part.Stored)
	if err != nil {
		return PartReceipt{}, err
	}
	defer file.Close()
	offset := int64(index) * scope.PartSize()
	if n, err := file.WriteAt(data, offset); err != nil || n != len(data) {
		return PartReceipt{}, ErrStorage
	}
	if err := file.Sync(); err != nil {
		return PartReceipt{}, ErrStorage
	}
	if h.Received+1 == scope.Parts() {
		actual, err := fileDigest(ctx, file, scope.Length)
		if err != nil {
			return PartReceipt{}, err
		}
		if actual != scope.Digest {
			h.Invalid = true
			if err := s.save(h); err != nil {
				return PartReceipt{}, ErrStorage
			}
			return PartReceipt{}, ErrDigest
		}
	}
	part.Stored = true
	h.Received++
	err = s.db.Update(func(tx *bolt.Tx) error {
		b := s.bucket(tx, scope)
		if b == nil {
			return ErrStorage
		}
		raw, _ := json.Marshal(part)
		if err := b.Put(partKey(index), raw); err != nil {
			return err
		}
		raw, _ = json.Marshal(h)
		return b.Put(spoolHeader, raw)
	})
	if err != nil {
		return PartReceipt{}, ErrStorage
	}
	return signPart(scope, index, digest, key), nil
}

// RecoverPart only rechecks a completed original slot. A shared confirmation
// cannot authorize recreating a lost local header, file, pending part or pin.
func (s *Spool) RecoverPart(ctx context.Context, scope UploadScope, index uint32, digest [32]byte, key ed25519.PrivateKey) (PartReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.check(scope) != nil || scope.PartLength(index) == 0 || digest == ([32]byte{}) || !signingKey(scope, key) {
		return PartReceipt{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return PartReceipt{}, err
	}
	h, err := s.header(scope)
	if err != nil || h.Deleted || h.Deleting || h.Generated != nil || h.Invalid {
		return PartReceipt{}, ErrStorage
	}
	err = s.db.View(func(tx *bolt.Tx) error {
		var part localPart
		b := s.bucket(tx, scope)
		if b == nil || json.Unmarshal(b.Get(partKey(index)), &part) != nil || !part.Stored {
			return ErrStorage
		}
		if part.Digest != digest {
			return ErrConflict
		}
		return nil
	})
	if err != nil {
		return PartReceipt{}, err
	}
	return s.readStoredPart(ctx, scope, index, digest, h, key)
}

func (s *Spool) readStoredPart(ctx context.Context, scope UploadScope, index uint32, digest [32]byte, h localUpload, key ed25519.PrivateKey) (PartReceipt, error) {
	if err := ctx.Err(); err != nil {
		return PartReceipt{}, err
	}
	file, err := s.file(h, false)
	if err != nil {
		return PartReceipt{}, err
	}
	defer file.Close()
	actual := make([]byte, scope.PartLength(index))
	if n, err := file.ReadAt(actual, int64(index)*scope.PartSize()); err != nil || n != len(actual) || sha256.Sum256(actual) != digest {
		return PartReceipt{}, ErrStorage
	}
	if err := ctx.Err(); err != nil {
		return PartReceipt{}, err
	}
	return signPart(scope, index, digest, key), nil
}

// Seal reuses the same ZIP validator as admission/build consumers. Only the
// tree fingerprint/count/size enter a signed receipt; the large tree stays
// native and is reconstructed from the immutable original artifact.
func (s *Spool) Seal(ctx context.Context, scope UploadScope, key ed25519.PrivateKey) (SealReceipt, Tree, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.check(scope) != nil || !signingKey(scope, key) {
		return SealReceipt{}, Tree{}, ErrInvalid
	}
	h, err := s.header(scope)
	if err != nil || h.Invalid || h.Received != scope.Parts() {
		return SealReceipt{}, Tree{}, ErrConflict
	}
	file, err := s.file(h, false)
	if err != nil {
		return SealReceipt{}, Tree{}, err
	}
	defer file.Close()
	digest, err := fileDigest(ctx, file, scope.Length)
	if err != nil {
		return SealReceipt{}, Tree{}, err
	}
	if digest != scope.Digest {
		return SealReceipt{}, Tree{}, ErrDigest
	}
	tree, err := InspectZIP(ctx, file, scope.Length, scope.Dockerfile, scope.ExpandedLimit)
	if err != nil {
		return SealReceipt{}, Tree{}, err
	}
	receipt, err := s.persistSeal(h, tree, key)
	return receipt, tree, err
}

func (s *Spool) persistSeal(h localUpload, tree Tree, key ed25519.PrivateKey) (SealReceipt, error) {
	scope := h.Scope
	if !signingKey(scope, key) || h.Invalid || h.Deleted || h.Deleting || h.Received != scope.Parts() || len(tree.Entries) == 0 || len(tree.Entries) > MaxTreeEntries || tree.Bytes < 0 || tree.Bytes > scope.ExpandedLimit {
		return SealReceipt{}, ErrStorage
	}
	receipt := SealReceipt{Schema: 1, Scope: scope.Hash(), ZIP: scope.Digest, Tree: tree.Digest(), Entries: uint32(len(tree.Entries)), ExpandedBytes: tree.Bytes}
	if h.Seal != nil {
		// Signature is deliberately nil in persisted evidence. Compare its
		// exact signing bytes so no slice comparability is assumed.
		if string(SealReceiptBytes(*h.Seal)) != string(SealReceiptBytes(receipt)) {
			return SealReceipt{}, ErrStorage
		}
	}
	h.Seal = &receipt
	if err := s.save(h); err != nil {
		return SealReceipt{}, ErrStorage
	}
	receipt.Signature = ed25519.Sign(key, SealReceiptBytes(receipt))
	return receipt, nil
}

type artifactReader struct {
	*io.SectionReader
	file  *os.File
	spool *Spool
	scope [32]byte
	once  sync.Once
	err   error
	ctx   context.Context
}

func (r *artifactReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.SectionReader.Read(p)
}
func (r *artifactReader) ReadAt(p []byte, offset int64) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.SectionReader.ReadAt(p, offset)
}

func (r *artifactReader) Close() error {
	r.once.Do(func() {
		r.err = r.file.Close()
		r.spool.mu.Lock()
		r.spool.readers[r.scope]--
		if r.spool.readers[r.scope] == 0 {
			delete(r.spool.readers, r.scope)
		}
		r.spool.mu.Unlock()
	})
	return r.err
}
func (s *Spool) Open(ctx context.Context, scope UploadScope, receipt SealReceipt) (io.ReadCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.check(scope) != nil || !receipt.Valid(scope) {
		return nil, ErrInvalid
	}
	h, err := s.header(scope)
	if err != nil || h.Invalid || h.Unpublished != nil || h.Seal == nil || string(SealReceiptBytes(*h.Seal)) != string(SealReceiptBytes(receipt)) {
		return nil, ErrStorage
	}
	file, err := s.file(h, false)
	if err != nil {
		return nil, err
	}
	digest, err := fileDigest(ctx, file, scope.Length)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if digest != receipt.ZIP {
		_ = file.Close()
		return nil, ErrDigest
	}
	s.readers[scope.Hash()]++
	return &artifactReader{SectionReader: io.NewSectionReader(file, 0, scope.Length), file: file, spool: s, scope: scope.Hash(), ctx: ctx}, nil
}

// CheckSeal reopens the recorded inode without reading the full ZIP. Immutable
// in-memory projections still require this original artifact to be retained.
func (s *Spool) CheckSeal(scope UploadScope, receipt SealReceipt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.check(scope) != nil || !receipt.Valid(scope) {
		return ErrInvalid
	}
	h, err := s.header(scope)
	if err != nil || h.Invalid || h.Unpublished != nil || h.Seal == nil || string(SealReceiptBytes(*h.Seal)) != string(SealReceiptBytes(receipt)) {
		return ErrStorage
	}
	file, err := s.file(h, false)
	if err != nil {
		return err
	}
	info, statErr := file.Stat()
	closeErr := file.Close()
	if statErr != nil || info.Size() != scope.Length || closeErr != nil {
		return ErrStorage
	}
	return nil
}

func (s *Spool) Inspect(ctx context.Context, scope UploadScope, receipt SealReceipt) (Tree, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.check(scope) != nil || !receipt.Valid(scope) {
		return Tree{}, ErrInvalid
	}
	h, err := s.header(scope)
	if err != nil || h.Invalid || h.Unpublished != nil || h.Seal == nil || string(SealReceiptBytes(*h.Seal)) != string(SealReceiptBytes(receipt)) {
		return Tree{}, ErrStorage
	}
	file, err := s.file(h, false)
	if err != nil {
		return Tree{}, err
	}
	defer file.Close()
	digest, err := fileDigest(ctx, file, scope.Length)
	if err != nil {
		return Tree{}, err
	}
	if digest != scope.Digest {
		return Tree{}, ErrDigest
	}
	tree, err := InspectZIP(ctx, file, scope.Length, scope.Dockerfile, scope.ExpandedLimit)
	if err != nil {
		return Tree{}, err
	}
	if tree.Digest() != receipt.Tree || tree.Bytes != receipt.ExpandedBytes || uint32(len(tree.Entries)) != receipt.Entries {
		return Tree{}, ErrDigest
	}
	return tree, nil
}

// Reclaim requires a committed close/consume and the caller's current shared
// context-version/job reference check under its admission fence. It preserves
// an original deletion intent across crashes and never reinitializes its ID.
func (s *Spool) Reclaim(upload Upload, referenced bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reclaim(upload, referenced)
}

func (s *Spool) reclaim(upload Upload, referenced bool) error {
	if upload.Validate() != nil || !upload.Closed || s.check(upload.Scope) != nil {
		return ErrInvalid
	}
	if referenced || s.readers[upload.Scope.Hash()] != 0 {
		return ErrUsed
	}
	// A held parent pin can precede Begin's native creation intent. Under the
	// caller's closed shared scope/gate, a healthy DB with no scope bucket and
	// no original filename proves this adapter never started creating bytes.
	// Existing malformed buckets or unexpected files are never initialized.
	missing := false
	if err := s.db.View(func(tx *bolt.Tx) error { missing = s.bucket(tx, upload.Scope) == nil; return nil }); err != nil {
		return ErrStorage
	}
	if missing {
		var stat unix.Stat_t
		if err := unix.Fstatat(int(s.dir.Fd()), scopeName(upload.Scope)+".zip", &stat, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
			return ErrStorage
		}
		return s.db.Update(func(tx *bolt.Tx) error {
			parent := tx.Bucket(spoolBucket).Bucket(s.key)
			b, err := parent.CreateBucket([]byte(scopeName(upload.Scope)))
			if err != nil {
				return err
			}
			raw, _ := json.Marshal(localUpload{Scope: upload.Scope, Deleted: true})
			return b.Put(spoolHeader, raw)
		})
	}
	h, err := s.header(upload.Scope)
	if err != nil {
		return err
	}
	if h.Deleted {
		return nil
	}
	if h.Inode == 0 {
		// Recover only a zero-byte creation intent: no successful part was
		// possible before attachment. Do not create a file just to reclaim it.
		var stat unix.Stat_t
		err := unix.Fstatat(int(s.dir.Fd()), scopeName(upload.Scope)+".zip", &stat, unix.AT_SYMLINK_NOFOLLOW)
		if errors.Is(err, unix.ENOENT) {
			h.Deleted = true
			return s.save(h)
		}
		if err != nil || stat.Size != 0 || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0777 != 0600 || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) {
			return ErrStorage
		}
		h.Device, h.Inode = uint64(stat.Dev), stat.Ino
		if err := s.save(h); err != nil {
			return ErrStorage
		}
	}
	if !h.Deleting {
		file, err := s.file(h, false)
		if err != nil {
			return err
		}
		if err := file.Close(); err != nil {
			return ErrStorage
		}
		h.Deleting = true
		if err := s.save(h); err != nil {
			return ErrStorage
		}
	}
	// Even recovery only unlinks the same original inode. A replacement is
	// never removed. Absence is acceptable solely after our durable intent;
	// this API makes no physical reclaimed-byte claim for that ambiguous case.
	name := scopeName(upload.Scope) + ".zip"
	var stat unix.Stat_t
	err = unix.Fstatat(int(s.dir.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		if uint64(stat.Dev) != h.Device || stat.Ino != h.Inode || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 {
			return ErrStorage
		}
		if err := unix.Unlinkat(int(s.dir.Fd()), name, 0); err != nil {
			return ErrStorage
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return ErrStorage
	}
	if err := s.dir.Sync(); err != nil {
		return ErrStorage
	}
	h.Deleted, h.Deleting = true, false
	return s.db.Update(func(tx *bolt.Tx) error {
		b := s.bucket(tx, upload.Scope)
		if b == nil {
			return ErrStorage
		}
		// Keep the tombstone; remove bounded per-part metadata only after bytes
		// are actually gone and the parent directory has been synchronized.
		cursor := b.Cursor()
		for key, _ := cursor.Seek([]byte{'p'}); key != nil && len(key) == 5 && key[0] == 'p'; key, _ = cursor.Next() {
			if err := cursor.Delete(); err != nil {
				return err
			}
		}
		raw, _ := json.Marshal(h)
		return b.Put(spoolHeader, raw)
	})
}
func (s *Spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.readers) != 0 {
		return ErrUsed
	}
	if s.dir == nil {
		return nil
	}
	err := s.dir.Close()
	if err != nil {
		return fmt.Errorf("%w: close", ErrStorage)
	}
	s.dir = nil
	return nil
}

// ReclaimEvidence is available only after the original native tombstone and
// directory sync. It is not inferred from a missing filename or closed socket.
func (s *Spool) ReclaimEvidence(scope UploadScope) ([32]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.check(scope) != nil {
		return [32]byte{}, ErrStorage
	}
	header, err := s.header(scope)
	if err != nil || !header.Deleted || header.Deleting || s.readers[scope.Hash()] != 0 {
		return [32]byte{}, ErrStorage
	}
	return digestJSON("sfc-imagebuild-native-reclaim-1", header), nil
}
