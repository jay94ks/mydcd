// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/sys/unix"
)

// CollectUnpreparedFreezes reclaims original incomplete ZIPs fenced by a newer
// committed configuration. The caller holds its owner/root gate and supplies
// the monotonic shared-state check. Prepared/adopted archives are not collected.
func (d *DraftStore) CollectUnpreparedFreezes(ctx context.Context, obsolete func(DraftFreezePlan) (bool, error), limit int) (int, error) {
	d.spool.mu.Lock()
	defer d.spool.mu.Unlock()
	if obsolete == nil || limit < 1 || limit > 16 || d.dir == nil || d.spool.dir == nil {
		return 0, ErrInvalid
	}
	if d.spool.readers[d.scope.Data().Digest()] != 1 {
		return 0, ErrUsed
	}
	if _, err := d.state(); err != nil {
		return 0, err
	}
	var candidates []nativeDraftFreeze
	err := d.spool.db.View(func(tx *bolt.Tx) error {
		b := d.bucket(tx)
		if b == nil {
			return ErrStorage
		}
		cursor := b.Cursor()
		for key, raw := cursor.Seek([]byte("freeze-")); key != nil && bytes.HasPrefix(key, []byte("freeze-")); key, raw = cursor.Next() {
			if err := ctx.Err(); err != nil {
				return err
			}
			var freeze nativeDraftFreeze
			if len(raw) > 16<<10 || json.Unmarshal(raw, &freeze) != nil || !freeze.valid() || freeze.Plan.Scope.Data() != d.scope.Data() || !bytes.Equal(key, freezeKey(freeze.Plan)) {
				return ErrStorage
			}
			if freeze.Scope != nil || freeze.Removed {
				continue
			}
			allowed := freeze.Removing
			if !allowed {
				var err error
				allowed, err = obsolete(freeze.Plan)
				if err != nil {
					return err
				}
			}
			if allowed {
				candidates = append(candidates, freeze)
				if len(candidates) == limit {
					break
				}
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, freeze := range candidates {
		if err := ctx.Err(); err != nil {
			return removed, err
		}
		if err := d.removeUnpreparedFreeze(freeze); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

func (d *DraftStore) removeUnpreparedFreeze(h nativeDraftFreeze) error {
	// Adoption always persists Scope before the archive header. If such a
	// header exists despite a partial source record, preserve the contradiction.
	if err := d.spool.db.View(func(tx *bolt.Tx) error {
		parent := d.parent(tx)
		if parent == nil {
			return ErrStorage
		}
		return parent.ForEach(func(key, raw []byte) error {
			if raw != nil || len(key) != 64 {
				return nil
			}
			bucket := parent.Bucket(key)
			if bucket == nil {
				return ErrStorage
			}
			var upload localUpload
			header := bucket.Get(spoolHeader)
			if len(header) > 16<<10 || json.Unmarshal(header, &upload) != nil || upload.Scope.Validate() != nil || upload.Scope.Root != d.scope.Root || string(key) != scopeName(upload.Scope) {
				return ErrStorage
			}
			if upload.Generated != nil && *upload.Generated == h.Plan.Digest() {
				return ErrUsed
			}
			return nil
		})
	}); err != nil {
		return err
	}
	name := freezeName(h.Plan)
	var st unix.Stat_t
	err := unix.Fstatat(int(d.dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) || st.Mode&07777 != 0600 || st.Size < 0 || st.Size > MaxZIPBytes || h.Inode != 0 && (st.Ino != h.Inode || uint64(st.Dev) != h.Device) || h.Inode == 0 && st.Size != 0 {
			return ErrStorage
		}
		if h.Inode == 0 {
			h.Device, h.Inode = uint64(st.Dev), st.Ino
		}
	} else if !errors.Is(err, unix.ENOENT) || h.Inode != 0 && !h.Removing {
		return ErrStorage
	}
	if !h.Removing {
		h.Removing = true
		if err := d.saveFreeze(h); err != nil {
			return err
		}
	}
	if err == nil {
		if err := unix.Unlinkat(int(d.dir.Fd()), name, 0); err != nil {
			return err
		}
	}
	if err := d.dir.Sync(); err != nil {
		return err
	}
	h.Removed = true
	return d.saveFreeze(h)
}
