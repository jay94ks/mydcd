// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"encoding/hex"
	"os"
	"sort"

	"github.com/jay94ks/mydcd/internal/schema"
)

func (b *Blobs) validUpload(u uploadRecord) bool {
	if u.Schema != 1 || !validUploadID(u.ID) || u.Offset < 0 || u.Offset > b.limits.BlobBytes {
		return false
	}
	if _, err := repoID(u.Repo); err != nil {
		return false
	}
	switch u.Phase {
	case "creating":
		return u.Offset == 0 && u.Digest == ""
	case "active", "canceling", "canceled":
		return u.Digest == ""
	case "publishing", "complete":
		_, err := blobPath(u.Digest)
		return err == nil
	default:
		return false
	}
}

func (b *Blobs) recover(ctx context.Context) error {
	if err := b.recoverGC(ctx); err != nil {
		return err
	}
	uRows, err := b.db.ScanBounded(uploadPrefix, b.limits.Records, b.limits.Records*2048)
	if err != nil {
		return ErrStorage
	}
	vRows, err := b.db.ScanBounded(blobPrefix, b.limits.Records, b.limits.Records*2048)
	if err != nil || len(uRows)+len(vRows) > b.limits.Records {
		return ErrStorage
	}
	for key, raw := range uRows {
		u, e := schema.Decode[uploadRecord](raw)
		if e != nil || !b.validUpload(u) || key != uploadPrefix+u.ID {
			return ErrStorage
		}
		b.uploads[u.ID] = u
	}
	objects := map[string]int64{}
	for key, raw := range vRows {
		v, e := schema.Decode[blobRecord](raw)
		expected, kerr := blobKey(v.Repo, v.Digest)
		if e != nil || kerr != nil || v.Schema != 1 || v.Size < 0 || v.Size > b.limits.BlobBytes || key != expected || !validUploadID(v.Origin) {
			return ErrStorage
		}
		origin, ok := b.uploads[v.Origin]
		if !ok || origin.Phase != "complete" || origin.Repo != v.Repo || origin.Digest != v.Digest || origin.Offset != v.Size {
			return ErrStorage
		}
		if n, ok := objects[v.Digest]; ok && n != v.Size {
			return ErrStorage
		}
		objects[v.Digest] = v.Size
		b.blobs[key] = v
	}
	for _, u := range b.uploads {
		if u.Phase == "complete" {
			key, _ := blobKey(u.Repo, u.Digest)
			v, exists := b.blobs[key]
			if !exists || v.Size != u.Offset {
				return ErrStorage
			}
		}
		if u.Phase == "publishing" {
			if n, ok := objects[u.Digest]; ok && n != u.Offset {
				return ErrStorage
			}
			objects[u.Digest] = u.Offset
		}
	}
	// Refuse unowned files rather than adopting or removing an unknown write.
	rootNames, err := b.names(".")
	if err != nil {
		return err
	}
	for _, name := range rootNames {
		if name != "uploads" && name != "blobs" && name != "node.lock" {
			return ErrStorage
		}
	}
	names, err := b.names("uploads")
	if err != nil {
		return err
	}
	for _, id := range names {
		u, exists := b.uploads[id]
		if !exists || u.Phase == "complete" || u.Phase == "canceled" {
			return ErrStorage
		}
		st, e := b.root.Lstat("uploads/" + id)
		if e != nil || !privateFile(st, false) {
			return ErrStorage
		}
	}
	names, err = b.names("blobs")
	if err != nil {
		return err
	}
	for _, id := range names {
		raw, e := hex.DecodeString(id)
		size, exists := objects["sha256:"+id]
		if e != nil || len(raw) != 32 || hex.EncodeToString(raw) != id || !exists {
			return ErrStorage
		}
		st, e := b.root.Lstat("blobs/" + id)
		if e != nil || !privateFile(st, false) || st.Size() != size {
			return ErrStorage
		}
	}
	ids := make([]string, 0, len(b.uploads))
	for id := range b.uploads {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if ctx.Err() != nil {
			return ErrStorage
		}
		u := b.uploads[id]
		switch u.Phase {
		case "creating":
			if err = b.createUpload(u); err != nil {
				return err
			}
			u.Phase = "active"
			if err = b.writeUpload(u); err != nil {
				return err
			}
		case "active":
			f, e := b.open("uploads/"+id, os.O_RDWR)
			if e != nil {
				return e
			}
			st, e := f.Stat()
			if e == nil && st.Size() < u.Offset {
				e = ErrStorage
			}
			if e == nil && st.Size() > u.Offset {
				e = f.Truncate(u.Offset)
				if e == nil {
					e = f.Sync()
				}
			}
			closed := f.Close()
			if e != nil || closed != nil {
				return ErrStorage
			}
		case "publishing":
			path, _ := blobPath(u.Digest)
			if err = b.publish(ctx, u, path, false); err != nil {
				return err
			}
		case "canceling":
			if err = b.cancelUpload(u); err != nil {
				return err
			}
		}
	}
	// All committed objects must exist, including a zero-length object. A
	// missing blob is corruption, never a new registry or ordinary cache miss.
	for _, v := range b.blobs {
		path, _ := blobPath(v.Digest)
		st, e := b.root.Lstat(path)
		if e != nil || !privateFile(st, false) || st.Size() != v.Size {
			return ErrStorage
		}
	}
	return b.countBytes()
}

func (b *Blobs) countBytes() error {
	var used int64
	for _, dir := range []string{"uploads", "blobs"} {
		names, err := b.names(dir)
		if err != nil {
			return err
		}
		for _, name := range names {
			st, e := b.root.Lstat(dir + "/" + name)
			if e != nil || !privateFile(st, false) || st.Size() < 0 || st.Size() > b.limits.TotalBytes-used {
				return ErrStorage
			}
			used += st.Size()
		}
	}
	b.used = used
	return nil
}
