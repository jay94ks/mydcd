// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"

	oci "github.com/google/go-containerregistry/pkg/registry"
)

func (b *Blobs) Begin(ctx context.Context, repo string) (oci.Upload, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.enter(ctx, true) != nil {
		return oci.Upload{}, ErrStorage
	}
	if _, err := repoID(repo); err != nil {
		return oci.Upload{}, err
	}
	if len(b.uploads)+len(b.blobs) >= b.limits.Records {
		return oci.Upload{}, ErrStorage
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return oci.Upload{}, ErrStorage
	}
	id := hex.EncodeToString(nonce[:])
	if _, exists := b.uploads[id]; exists {
		return oci.Upload{}, ErrStorage
	}
	u := uploadRecord{Schema: 1, Repo: repo, ID: id, Phase: "creating"}
	if err := b.writeUpload(u); err != nil {
		return oci.Upload{}, err
	}
	if err := b.createUpload(u); err != nil {
		b.failed = true
		return oci.Upload{}, err
	}
	u.Phase = "active"
	if err := b.writeUpload(u); err != nil {
		return oci.Upload{}, err
	}
	return uploadView(u), nil
}

func (b *Blobs) createUpload(u uploadRecord) error {
	path := "uploads/" + u.ID
	f, err := b.root.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if os.IsExist(err) {
		f, err = b.open(path, os.O_RDWR)
	}
	if err != nil {
		return ErrStorage
	}
	st, err := f.Stat()
	if err != nil || st.Size() != 0 {
		_ = f.Close()
		return ErrStorage
	}
	err = f.Sync()
	closed := f.Close()
	if err != nil || closed != nil || b.syncDir("uploads") != nil {
		return ErrStorage
	}
	return nil
}

func (b *Blobs) Append(ctx context.Context, repo, id string, offset, length int64, body io.Reader) (result oci.Upload, resultErr error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.enter(ctx, true) != nil || body == nil || length < -1 {
		return oci.Upload{}, ErrStorage
	}
	u, err := b.lookup(repo, id)
	if err != nil {
		return oci.Upload{}, err
	}
	if u.Phase != "active" || offset != u.Offset {
		return uploadView(u), oci.ErrUploadOffset
	}
	remaining := min(b.limits.BlobBytes-u.Offset, b.limits.TotalBytes-b.used)
	if remaining < 0 || length > remaining {
		return uploadView(u), ErrStorage
	}
	f, err := b.open("uploads/"+id, os.O_RDWR)
	if err != nil {
		return uploadView(u), err
	}
	defer func() {
		if f.Close() != nil {
			b.failed = true
			result = oci.Upload{}
			resultErr = ErrStorage
		}
	}()
	st, err := f.Stat()
	if err != nil || st.Size() != u.Offset {
		return uploadView(u), ErrStorage
	}
	if _, err = f.Seek(u.Offset, io.SeekStart); err != nil {
		return uploadView(u), ErrStorage
	}
	limit := remaining
	if length >= 0 {
		limit = length
	}
	// Never write beyond the declared/quota bound. Probe one further byte in
	// memory to distinguish an exact body from an oversized one.
	input := contextReader{ctx, body}
	n, copyErr := io.CopyBuffer(f, io.LimitReader(input, limit), make([]byte, 32<<10))
	if copyErr == nil && n == limit {
		var extra [1]byte
		count, end := input.Read(extra[:])
		if count != 0 || !errors.Is(end, io.EOF) {
			copyErr = ErrStorage
		}
	}
	if copyErr != nil || n > limit || length >= 0 && n != length || ctx.Err() != nil {
		if f.Truncate(u.Offset) != nil || f.Sync() != nil {
			b.failed = true
		}
		return uploadView(u), ErrStorage
	}
	if n == 0 {
		return uploadView(u), nil
	}
	if err = f.Sync(); err != nil {
		b.failed = true
		return uploadView(u), ErrStorage
	}
	// The old offset remains authoritative if this DB write is uncertain.
	u.Offset += n
	if err = b.writeUpload(u); err != nil {
		return oci.Upload{}, err
	}
	b.used += n
	return uploadView(u), nil
}

func (b *Blobs) Commit(ctx context.Context, repo, id, digest string) (oci.Upload, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.enter(ctx, true) != nil {
		return oci.Upload{}, ErrStorage
	}
	path, err := blobPath(digest)
	if err != nil {
		return oci.Upload{}, err
	}
	u, err := b.lookup(repo, id)
	if err != nil {
		return oci.Upload{}, err
	}
	if u.Phase == "complete" {
		if u.Digest != digest {
			return uploadView(u), oci.ErrDigestMismatch
		}
		return uploadView(u), nil
	}
	if u.Phase != "active" {
		return uploadView(u), oci.ErrUploadOffset
	}
	key, _ := blobKey(repo, digest)
	if _, ok := b.blobs[key]; !ok && len(b.uploads)+len(b.blobs) >= b.limits.Records {
		return uploadView(u), ErrStorage
	}
	f, err := b.open("uploads/"+id, os.O_RDONLY)
	if err != nil {
		return uploadView(u), err
	}
	err = hashFile(ctx, f, u.Offset, digest)
	closed := f.Close()
	if err != nil {
		return uploadView(u), err
	}
	if closed != nil || ctx.Err() != nil {
		return uploadView(u), ErrStorage
	}
	u.Phase, u.Digest = "publishing", digest
	if err = b.writeUpload(u); err != nil {
		return oci.Upload{}, err
	}
	// The same publishing intent is resumable even after the rename happened.
	if err = b.publish(ctx, u, path, true); err != nil {
		b.failed = true
		return oci.Upload{}, err
	}
	if err = b.countBytes(); err != nil {
		b.failed = true
		return oci.Upload{}, err
	}
	return uploadView(b.uploads[id]), nil
}

func (b *Blobs) publish(ctx context.Context, u uploadRecord, path string, sourceVerified bool) error {
	if ctx.Err() != nil {
		return ErrStorage
	}
	st, err := b.root.Lstat(path)
	if err == nil {
		if !privateFile(st, false) || st.Size() != u.Offset {
			return ErrStorage
		}
		f, e := b.open(path, os.O_RDONLY)
		if e != nil {
			return e
		}
		e = hashFile(ctx, f, u.Offset, u.Digest)
		closed := f.Close()
		if e != nil || closed != nil {
			return ErrStorage
		}
		if _, e = b.root.Lstat("uploads/" + u.ID); e == nil {
			if e = b.verifyPublicationSource(ctx, u, sourceVerified); e != nil {
				return e
			}
			if b.root.Remove("uploads/"+u.ID) != nil {
				return ErrStorage
			}
		} else if !os.IsNotExist(e) {
			return ErrStorage
		}
	} else if os.IsNotExist(err) {
		if e := b.verifyPublicationSource(ctx, u, sourceVerified); e != nil {
			return e
		}
		if b.root.Rename("uploads/"+u.ID, path) != nil {
			return ErrStorage
		}
	} else {
		return ErrStorage
	}
	if b.syncDir("blobs") != nil || b.syncDir("uploads") != nil {
		return ErrStorage
	}
	u.Phase = "complete"
	v := blobRecord{Schema: 1, Repo: u.Repo, Digest: u.Digest, Size: u.Offset, Origin: u.ID, Unpublished: true}
	key, _ := blobKey(v.Repo, v.Digest)
	if old, exists := b.blobs[key]; exists {
		origin, ok := b.uploads[old.Origin]
		if old.Schema != 1 || old.Repo != v.Repo || old.Digest != v.Digest || old.Size != v.Size || !ok || origin.Phase != "complete" || origin.Repo != old.Repo || origin.Digest != old.Digest || origin.Offset != old.Size {
			return ErrStorage
		}
		v = old
		v.Unpublished = true
		v.Retired = false // a new completed upload may precede a new manifest request
	}
	uRaw, _ := json.Marshal(u)
	vRaw, _ := json.Marshal(v)
	if err = b.db.Write(map[string][]byte{uploadPrefix + u.ID: uRaw, key: vRaw}); err != nil {
		b.failed = true
		return ErrStorage
	}
	b.uploads[u.ID], b.blobs[key] = u, v
	return nil
}

func (b *Blobs) verifyPublicationSource(ctx context.Context, u uploadRecord, verified bool) error {
	f, err := b.open("uploads/"+u.ID, os.O_RDONLY)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err == nil && st.Size() != u.Offset {
		err = ErrStorage
	}
	if err == nil && !verified {
		err = hashFile(ctx, f, u.Offset, u.Digest)
	}
	closed := f.Close()
	if err != nil || closed != nil {
		return ErrStorage
	}
	return nil
}

func (b *Blobs) Cancel(ctx context.Context, repo, id string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.enter(ctx, true) != nil {
		return ErrStorage
	}
	// An original canceled ID is an idempotent lookup, never a new upload.
	if old, ok := b.uploads[id]; ok && old.Repo == repo && old.Phase == "canceled" {
		return nil
	}
	u, err := b.lookup(repo, id)
	if err != nil {
		return err
	}
	if u.Phase != "active" && u.Phase != "creating" {
		return oci.ErrUploadOffset
	}
	u.Phase = "canceling"
	if err = b.writeUpload(u); err != nil {
		return err
	}
	if err = b.cancelUpload(u); err != nil {
		b.failed = true
		return err
	}
	if err = b.countBytes(); err != nil {
		b.failed = true
		return err
	}
	return nil
}
func (b *Blobs) cancelUpload(u uploadRecord) error {
	path := "uploads/" + u.ID
	st, err := b.root.Lstat(path)
	if err == nil {
		if !privateFile(st, false) || b.root.Remove(path) != nil {
			return ErrStorage
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrStorage
	}
	if b.syncDir("uploads") != nil {
		return ErrStorage
	}
	u.Phase = "canceled"
	return b.writeUpload(u)
}
