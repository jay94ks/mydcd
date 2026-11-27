// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	bolt "go.etcd.io/bbolt"
	"hash"
	"io"
	"io/fs"
	"os"

	"github.com/jay94ks/seafield/internal/reconcile"
)

// OpenFile borrows the retained original inode and seal; it never extracts the
// ZIP or opens a user path. The caller selects Entry from the inspected tree.
func (s *Spool) OpenFile(scope UploadScope, seal SealReceipt, entry Entry) (*FileReader, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.check(scope) != nil || !seal.Valid(scope) || !validContentEntry(entry) || entry.Directory {
		return nil, ErrInvalid
	}
	h, err := s.header(scope)
	if err != nil || h.Invalid || h.Unpublished != nil || h.Seal == nil || string(SealReceiptBytes(*h.Seal)) != string(SealReceiptBytes(seal)) {
		return nil, ErrStorage
	}
	file, err := s.file(h, false)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = file.Close()
		}
	}()
	z, err := zip.NewReader(file, scope.Length)
	if err != nil || len(z.File) == 0 || len(z.File) > MaxTreeEntries {
		return nil, ErrDigest
	}
	var selected *zip.File
	for _, candidate := range z.File {
		if candidate.Name != entry.Path {
			continue
		}
		mode := candidate.Mode()
		if selected != nil || !mode.IsRegular() || mode&(fs.ModeSymlink|fs.ModeDevice|fs.ModeNamedPipe|fs.ModeSocket|fs.ModeIrregular|fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) != 0 || candidate.ExternalAttrs&0x400 != 0 || unsafeZIPExtra(candidate.Extra) || candidate.UncompressedSize64 != uint64(entry.Bytes) || (mode.Perm()&0111 != 0) != entry.Executable {
			return nil, ErrDigest
		}
		selected = candidate
	}
	if selected == nil {
		return nil, ErrDigest
	}
	ok = true
	return &FileReader{file: file, zipped: selected, entry: entry}, nil
}

// FileReader keeps one decompressor and incremental digest for sequential
// pages. It owns no root dependency: the runtime keeps its recorded artifact
// pin and closes this reader under the same admission/GC gate before return.
// At most the most recent bounded page is retained. Arbitrary offsets reopen
// and skip the prefix; following Next consumes each expanded byte only once.
type FileReader struct {
	file     *os.File
	zipped   *zip.File
	body     io.ReadCloser
	entry    Entry
	position uint64
	digest   hash.Hash
	last     *FilePage
}

func (r *FileReader) Close() error {
	if r == nil {
		return nil
	}
	var err error
	if r.body != nil {
		err = r.body.Close()
		r.body = nil
	}
	if r.file != nil {
		closeErr := r.file.Close()
		r.file = nil
		if err == nil {
			err = closeErr
		}
	}
	r.last = nil
	return err
}
func (r *FileReader) Read(ctx context.Context, offset uint64) (FilePage, error) {
	if r == nil || r.file == nil || offset > uint64(r.entry.Bytes) {
		return FilePage{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return FilePage{}, err
	}
	if r.last != nil && r.last.Offset == offset {
		out := *r.last
		out.Data = bytes.Clone(out.Data)
		return out, nil
	}
	if r.body == nil || offset != r.position {
		if r.body != nil {
			_ = r.body.Close()
			r.body = nil
		}
		body, err := r.zipped.Open()
		if err != nil {
			return FilePage{}, err
		}
		r.body = body
		r.position = 0
		r.digest = sha256.New()
		r.last = nil
	}
	fail := func(err error) (FilePage, error) {
		if r.body != nil {
			_ = r.body.Close()
			r.body = nil
		}
		r.last = nil
		return FilePage{}, err
	}
	source := io.TeeReader(contextReader{ctx, r.body}, r.digest)
	if offset > r.position {
		n, err := io.CopyBuffer(io.Discard, io.LimitReader(source, int64(offset-r.position)), make([]byte, PartBytes))
		if err != nil {
			return fail(err)
		}
		r.position += uint64(n)
		if r.position != offset {
			return fail(ErrDigest)
		}
	}
	out := FilePage{Entry: r.entry, Offset: offset, Total: uint64(r.entry.Bytes)}
	end := min(out.Total, offset+PartBytes)
	out.Data = make([]byte, end-offset)
	if _, err := io.ReadFull(source, out.Data); err != nil {
		return fail(err)
	}
	r.position = end
	if end < out.Total {
		out.Next = end
	} else {
		var extra [1]byte
		n, err := source.Read(extra[:])
		if n != 0 || err != io.EOF || !bytes.Equal(r.digest.Sum(nil), r.entry.Digest[:]) {
			if ctx.Err() != nil {
				return fail(ctx.Err())
			}
			return fail(ErrDigest)
		}
		if err := r.body.Close(); err != nil {
			r.body = nil
			return fail(err)
		}
		r.body = nil
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	cached := out
	cached.Data = bytes.Clone(out.Data)
	r.last = &cached
	return out, nil
}

// ReadFile holds the same native gate as edits and reclamation. Both the tree
// revision and its digest must still equal the original client snapshot.
func (d *DraftStore) ReadFile(ctx context.Context, revision uint64, digest [32]byte, path string, offset uint32) (FilePage, error) {
	d.spool.mu.Lock()
	defer d.spool.mu.Unlock()
	if revision == 0 || digest == ([32]byte{}) || !ContextPath(path) {
		return FilePage{}, ErrInvalid
	}
	draft, err := d.state()
	if err != nil {
		return FilePage{}, err
	}
	if draft.Revision != revision || draft.Digest() != digest {
		return FilePage{}, ErrConflict
	}
	for _, entry := range draft.Entries {
		if entry.Path != path {
			continue
		}
		if entry.Directory {
			return FilePage{}, ErrInvalid
		}
		blob, err := d.blob(entry)
		if err != nil {
			return FilePage{}, err
		}
		if !blob.Done {
			return FilePage{}, reconcile.ErrPending
		}
		file, err := d.openBlob(blob)
		if err != nil {
			return FilePage{}, err
		}
		out, err := readAtFilePage(ctx, entry, uint64(offset), file)
		closeErr := file.Close()
		if err != nil {
			return FilePage{}, err
		}
		if closeErr != nil {
			return FilePage{}, ErrStorage
		}
		return out, nil
	}
	// A multipart put is intentionally absent from the committed tree until
	// sealing. Never expose its partial bytes under a current tree snapshot.
	err = d.spool.db.View(func(tx *bolt.Tx) error {
		b := d.bucket(tx)
		if b == nil {
			return ErrStorage
		}
		cursor := b.Cursor()
		for key, raw := cursor.Seek([]byte("edit-")); bytes.HasPrefix(key, []byte("edit-")); key, raw = cursor.Next() {
			if err := ctx.Err(); err != nil {
				return err
			}
			var record draftEditRecord
			if len(raw) > maxDraftEditRecordBytes || json.Unmarshal(raw, &record) != nil || record.Edit == ([32]byte{}) {
				return ErrStorage
			}
			if record.Result != nil || record.Abandoned {
				continue
			}
			if record.Input == nil {
				return reconcile.ErrPending
			}
			if !record.matches(*record.Input) || string(key) != "edit-"+record.Input.ID {
				return ErrStorage
			}
			if record.Input.Kind == "put" && record.Input.Path == path && record.Input.Expected == draft.Revision {
				return reconcile.ErrPending
			}
		}
		return ErrInvalid
	})
	return FilePage{}, err
}
