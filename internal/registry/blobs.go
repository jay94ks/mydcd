// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	oci "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/jay94ks/seafield/internal/storage"
	"golang.org/x/sys/unix"
)

var ErrReaders = errors.New("registry streams have not closed")

type BlobLimits struct {
	BlobBytes, TotalBytes int64
	Records               int
}

func (l BlobLimits) valid() bool {
	return l.BlobBytes > 0 && l.BlobBytes < math.MaxInt64 && l.TotalBytes >= l.BlobBytes && l.Records > 0 && l.Records <= 65536
}

// Blobs owns files in one registry's already-authorized Volume root. Metadata
// and its DB are borrowed; none of these types acquire a shared Volume writer.
// The serving owner must close request bodies/join HTTP before closing Blobs.
type Blobs struct {
	scope                    Scope
	metadataLimits           MetadataLimits
	mu                       sync.Mutex
	root                     *os.Root
	lock                     *storage.Lock
	db                       *storage.DB
	limits                   BlobLimits
	uploads                  map[string]uploadRecord
	blobs                    map[string]blobRecord
	used                     int64
	readers                  int
	failed, draining, closed bool
	closeErr                 error
}

var (
	_ oci.UploadStore     = (*Blobs)(nil)
	_ oci.BlobHandler     = (*Blobs)(nil)
	_ oci.BlobStatHandler = (*Blobs)(nil)
)

const (
	uploadPrefix = "registry/upload/"
	blobPrefix   = "registry/blob/"
)

type uploadRecord struct {
	Schema          uint8
	Repo, ID, Phase string
	Offset          int64
	Digest          string
}
type blobRecord struct {
	Schema       uint8
	Repo, Digest string
	Size         int64
	Origin       string
	Unpublished  bool `json:",omitempty"` // completed upload awaiting a manifest publication
	Retired      bool `json:",omitempty"` // positive prior manifest retirement; false protects an unpublished push
}

func privateFile(info os.FileInfo, directory bool) bool {
	if info == nil {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Geteuid()) && info.Mode().Perm()&0077 == 0 && (directory && info.IsDir() || !directory && info.Mode().IsRegular())
}

func openBlobs(ctx context.Context, path string, metadata *Metadata, limits BlobLimits) (*Blobs, error) {
	if ctx == nil || ctx.Err() != nil || metadata == nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || !limits.valid() {
		return nil, ErrStorage
	}
	metadata.mu.Lock()
	defer metadata.mu.Unlock()
	if metadata.enter(ctx) != nil {
		return nil, ErrStorage
	}
	owner, _ := json.Marshal(metadata.scope)
	stored, err := metadata.db.GetBounded("registry/blob-root", 4096)
	fresh := errors.Is(err, storage.ErrMissing)
	if !fresh && (err != nil || string(stored) != string(owner)) {
		return nil, ErrStorage
	}
	if fresh {
		for _, prefix := range []string{uploadPrefix, blobPrefix} {
			rows, e := metadata.db.SizesBounded(prefix, 1, 4096)
			if e != nil || len(rows) != 0 {
				return nil, ErrStorage
			}
		}
		if err := os.MkdirAll(path, 0700); err != nil {
			return nil, ErrStorage
		}
	}
	info, err := os.Lstat(path)
	if err != nil || !privateFile(info, true) {
		return nil, ErrStorage
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil || canonical != path {
		return nil, ErrStorage
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, ErrStorage
	}
	b := &Blobs{scope: metadata.scope, metadataLimits: metadata.limits, root: root, db: metadata.db, limits: limits, uploads: map[string]uploadRecord{}, blobs: map[string]blobRecord{}}
	ok := false
	defer func() {
		if !ok {
			_ = b.Close()
		}
	}()
	b.lock, err = storage.LockRoot(path)
	if err != nil {
		return nil, ErrStorage
	}
	for _, dir := range []string{"uploads", "blobs"} {
		st, e := root.Lstat(dir)
		if os.IsNotExist(e) && fresh {
			if root.Mkdir(dir, 0700) != nil {
				return nil, ErrStorage
			}
			st, e = root.Lstat(dir)
		}
		if e != nil || !privateFile(st, true) {
			return nil, ErrStorage
		}
	}
	if fresh {
		for _, prefix := range []string{uploadPrefix, blobPrefix} {
			rows, e := b.db.SizesBounded(prefix, 1, 4096)
			if e != nil || len(rows) != 0 {
				return nil, ErrStorage
			}
		}
		for _, dir := range []string{"uploads", "blobs"} {
			names, e := b.names(dir)
			if e != nil || len(names) != 0 {
				return nil, ErrStorage
			}
		}
		if b.syncDir(".") != nil || b.db.Write(map[string][]byte{"registry/blob-root": owner}) != nil {
			return nil, ErrStorage
		}
	}
	if err = b.recover(ctx); err != nil {
		return nil, err
	}
	ok = true
	return b, nil
}

func (b *Blobs) enter(ctx context.Context, admit bool) error {
	if ctx == nil || ctx.Err() != nil || b.closed || b.failed || admit && b.draining {
		return ErrStorage
	}
	return nil
}
func (b *Blobs) syncDir(dir string) error {
	f, err := b.root.Open(dir)
	if err != nil {
		return ErrStorage
	}
	err = f.Sync()
	other := f.Close()
	if err != nil || other != nil {
		return ErrStorage
	}
	return nil
}
func (b *Blobs) names(dir string) ([]string, error) {
	f, err := b.root.Open(dir)
	if err != nil {
		return nil, ErrStorage
	}
	defer f.Close()
	limit := b.limits.Records
	if dir == "." {
		limit += 3
	}
	names, err := f.Readdirnames(limit + 1)
	if err != nil && !errors.Is(err, io.EOF) || len(names) > limit {
		return nil, ErrStorage
	}
	return names, nil
}
func validUploadID(id string) bool {
	raw, err := hex.DecodeString(id)
	return err == nil && len(raw) == 16 && hex.EncodeToString(raw) == id
}
func blobPath(digest string) (string, error) {
	h, err := v1.NewHash(digest)
	if err != nil || h.Algorithm != "sha256" {
		return "", ErrStorage
	}
	return "blobs/" + h.Hex, nil
}
func blobKey(repo, digest string) (string, error) {
	id, err := repoID(repo)
	if err != nil {
		return "", err
	}
	if _, err = blobPath(digest); err != nil {
		return "", err
	}
	return blobPrefix + id + "/" + digest, nil
}

func (b *Blobs) open(rel string, flags int) (*os.File, error) {
	info, err := b.root.Lstat(rel)
	if err != nil || !privateFile(info, false) {
		return nil, ErrStorage
	}
	f, err := b.root.OpenFile(rel, flags|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, ErrStorage
	}
	actual, err := f.Stat()
	if err != nil || !os.SameFile(info, actual) || !privateFile(actual, false) {
		_ = f.Close()
		return nil, ErrStorage
	}
	return f, nil
}
func (b *Blobs) writeUpload(u uploadRecord) error {
	raw, _ := json.Marshal(u)
	if err := b.db.Write(map[string][]byte{uploadPrefix + u.ID: raw}); err != nil {
		b.failed = true
		return ErrStorage
	}
	b.uploads[u.ID] = u
	return nil
}

func (b *Blobs) lookup(repo, id string) (uploadRecord, error) {
	if _, err := repoID(repo); err != nil || !validUploadID(id) {
		return uploadRecord{}, ErrStorage
	}
	u, ok := b.uploads[id]
	if !ok || u.Repo != repo || u.Phase == "canceled" {
		return uploadRecord{}, oci.ErrNotFound
	}
	return u, nil
}
func uploadView(u uploadRecord) oci.Upload {
	v := oci.Upload{ID: u.ID, Offset: u.Offset}
	if u.Phase == "complete" {
		v.Digest = u.Digest
	}
	return v
}

func (b *Blobs) Status(ctx context.Context, repo, id string) (oci.Upload, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.enter(ctx, false) != nil {
		return oci.Upload{}, ErrStorage
	}
	u, err := b.lookup(repo, id)
	if err != nil {
		return oci.Upload{}, err
	}
	return uploadView(u), nil
}

func (b *Blobs) blob(repo string, h v1.Hash) (blobRecord, string, error) {
	key, err := blobKey(repo, h.String())
	if err != nil {
		return blobRecord{}, "", err
	}
	v, ok := b.blobs[key]
	if !ok {
		return blobRecord{}, "", oci.ErrNotFound
	}
	path, _ := blobPath(v.Digest)
	return v, path, nil
}
func (b *Blobs) Stat(ctx context.Context, repo string, h v1.Hash) (int64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.enter(ctx, true) != nil {
		return 0, ErrStorage
	}
	v, path, err := b.blob(repo, h)
	if err != nil {
		return 0, err
	}
	f, err := b.open(path, os.O_RDONLY)
	if err != nil {
		return 0, err
	}
	st, err := f.Stat()
	closed := f.Close()
	if err != nil || closed != nil || st.Size() != v.Size {
		return 0, ErrStorage
	}
	return v.Size, nil
}

type contextReader struct {
	ctx context.Context
	io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.Reader.Read(p)
	if e := r.ctx.Err(); e != nil {
		return n, e
	}
	return n, err
}

func hashFile(ctx context.Context, f *os.File, size int64, digest string) error {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return ErrStorage
	}
	h := sha256.New()
	n, err := io.CopyBuffer(h, io.LimitReader(contextReader{ctx, f}, size+1), make([]byte, 32<<10))
	if err != nil || n != size {
		return ErrStorage
	}
	if "sha256:"+hex.EncodeToString(h.Sum(nil)) != digest {
		return oci.ErrDigestMismatch
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return ErrStorage
	}
	return nil
}

func (b *Blobs) Get(ctx context.Context, repo string, h v1.Hash) (io.ReadCloser, error) {
	return b.GetFrom(ctx, repo, h, 0)
}

// GetFrom is Get starting offset bytes in, for a reader that resumes an
// interrupted copy. The whole stored file is still checked against its
// digest first; the reader checks the digest of everything it received.
// offset may equal the size (nothing left to read).
func (b *Blobs) GetFrom(ctx context.Context, repo string, h v1.Hash, offset int64) (io.ReadCloser, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.enter(ctx, true) != nil {
		return nil, ErrStorage
	}
	v, path, err := b.blob(repo, h)
	if err != nil {
		return nil, err
	}
	f, err := b.open(path, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	if offset < 0 || offset > v.Size {
		_ = f.Close()
		return nil, ErrOffset
	}
	if err = hashFile(ctx, f, v.Size, v.Digest); err != nil {
		_ = f.Close()
		return nil, err
	}
	if _, err = f.Seek(offset, io.SeekStart); err != nil {
		_ = f.Close()
		return nil, ErrStorage
	}
	b.readers++
	return &blobReader{file: f, owner: b}, nil
}

type blobReader struct {
	file  *os.File
	owner *Blobs
	once  sync.Once
	err   error
}

func (r *blobReader) Read(p []byte) (int, error)              { return r.file.Read(p) }
func (r *blobReader) ReadAt(p []byte, off int64) (int, error) { return r.file.ReadAt(p, off) }
func (r *blobReader) Close() error {
	r.once.Do(func() {
		r.err = r.file.Close()
		r.owner.mu.Lock()
		defer r.owner.mu.Unlock()
		if r.err == nil {
			r.owner.readers--
		} else {
			r.owner.failed = true
		}
	})
	return r.err
}
func (b *Blobs) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return b.closeErr
	}
	b.draining = true
	if b.readers != 0 {
		return ErrReaders
	}
	var err error
	if b.root != nil {
		err = b.root.Close()
	}
	if b.lock != nil {
		err = errors.Join(err, b.lock.Close())
	}
	b.closeErr = err
	b.closed = true
	return err
}
