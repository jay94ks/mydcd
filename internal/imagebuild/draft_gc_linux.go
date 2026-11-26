// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/jay94ks/mydcd/internal/reconcile"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/sys/unix"
)

func draftBlobGCKey(hash [32]byte) []byte { return append([]byte("gc-"), draftBlobKey(hash)...) }

// A new pending edit must not pin a body whose original deletion is already
// unsettled. Otherwise that new reference would prevent GC from finishing,
// while the missing body would prevent the edit from committing.
func (d *DraftStore) guardDraftBlobGC(edit DraftEdit) error {
	if edit.Kind != "put" {
		return nil
	}
	return d.spool.db.View(func(tx *bolt.Tx) error {
		b := d.bucket(tx)
		if b == nil {
			return ErrStorage
		}
		if b.Get(draftBlobGCKey(edit.File.Digest)) != nil {
			return reconcile.ErrPending
		}
		return nil
	})
}

// CollectUnused reclaims unreferenced editor bodies, including interrupted
// writes whose edit CAS was superseded, not an entire draft lifetime. The
// caller retains the original root pin and owner gate.
// Readers/edits/freezes in this Spool use the same mutex for their whole I/O.
func (d *DraftStore) CollectUnused(ctx context.Context, limit int) (int, error) {
	d.spool.mu.Lock()
	defer d.spool.mu.Unlock()
	if limit < 1 || limit > 16 {
		return 0, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	draft, err := d.state()
	if err != nil {
		return 0, err
	}
	live := make(map[[32]byte]bool, len(draft.Entries))
	for _, entry := range draft.Entries {
		if !entry.Directory {
			live[entry.Digest] = true
		}
	}
	var candidates []draftBlob
	superseded := make(map[[32]byte][]DraftEdit)
	keepAll := false
	err = d.spool.db.View(func(tx *bolt.Tx) error {
		b := d.bucket(tx)
		if b == nil {
			return ErrStorage
		}
		protect := func(k, raw []byte) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			switch {
			case strings.HasPrefix(string(k), "edit-"):
				var record draftEditRecord
				if len(raw) > maxDraftEditRecordBytes || json.Unmarshal(raw, &record) != nil || record.Edit == ([32]byte{}) || record.Abandoned && record.Input == nil || record.Input != nil && (!record.matches(*record.Input) || string(k) != "edit-"+record.Input.ID) {
					return ErrStorage
				}
				if record.Result != nil {
					if record.Result.Edit != record.Edit || record.Result.Revision < 2 || record.Result.Draft == ([32]byte{}) {
						return ErrStorage
					}
				} else if record.Input == nil {
					keepAll = true // A legacy pending digest cannot identify its file.
				} else if record.Input.Expected > draft.Revision {
					return ErrStorage
				} else if record.Abandoned && record.Input.Expected == draft.Revision {
					return ErrStorage
				} else if record.Input.Kind == "put" && record.Input.Expected == draft.Revision {
					live[record.Input.File.Digest] = true
				} else if record.Input.Kind == "put" {
					superseded[record.Input.File.Digest] = append(superseded[record.Input.File.Digest], *record.Input)
				}
				// An older expected revision can never commit. Its original
				// intent remains, but no longer retains source bytes forever.
			case strings.HasPrefix(string(k), "freeze-"):
				var freeze nativeDraftFreeze
				if len(raw) > 16<<10 || json.Unmarshal(raw, &freeze) != nil || !freeze.valid() || freeze.Plan.Scope.Data() != d.scope.Data() || string(k) != string(freezeKey(freeze.Plan)) {
					return ErrStorage
				}
				if freeze.Scope == nil && !freeze.Removed {
					keepAll = true // Preserve inputs of an unfinished original freeze.
				}
			}
			return nil
		}
		cursor := b.Cursor()
		for _, prefix := range [][]byte{[]byte("edit-"), []byte("freeze-")} {
			for key, raw := cursor.Seek(prefix); key != nil && bytes.HasPrefix(key, prefix); key, raw = cursor.Next() {
				if err := protect(key, raw); err != nil {
					return err
				}
			}
		}
		if keepAll {
			return nil
		}
		for key, raw := cursor.Seek([]byte("blob-")); key != nil && bytes.HasPrefix(key, []byte("blob-")); {
			if err := ctx.Err(); err != nil {
				return err
			}
			if len(key) != len("blob-")+64 {
				key, raw = cursor.Next()
				continue // Orphan slots remain evidence, never guessed as bodies.
			}
			var blob draftBlob
			if len(raw) > 1024 || json.Unmarshal(raw, &blob) != nil || !validDraftBlob(blob) || !bytes.Equal(key, draftBlobKey(blob.Digest)) {
				return ErrStorage
			}
			if blob.Created && !live[blob.Digest] {
				candidates = append(candidates, blob)
				if len(candidates) == limit {
					break
				}
			}
			// Skip this header's fixed part-slot range without reading every
			// chunk on each maintenance pass. No source bytes are read for GC.
			key, raw = cursor.Seek(append(bytes.Clone(key), 255))
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	completed := 0
	for _, blob := range candidates {
		if err := ctx.Err(); err != nil {
			return completed, err
		}
		if err := d.reclaimDraftBlob(blob, superseded[blob.Digest]); err != nil {
			return completed, err
		}
		completed++
	}
	return completed, nil
}

func (d *DraftStore) reclaimDraftBlob(blob draftBlob, superseded []DraftEdit) error {
	key := draftBlobKey(blob.Digest)
	gcKey := draftBlobGCKey(blob.Digest)
	header, _ := json.Marshal(blob)
	found := false
	if err := d.spool.db.View(func(tx *bolt.Tx) error {
		b := d.bucket(tx)
		if b == nil || !bytes.Equal(b.Get(key), header) {
			return ErrStorage
		}
		raw := b.Get(gcKey)
		found = raw != nil
		var original draftBlob
		if found && (len(raw) > 1024 || json.Unmarshal(raw, &original) != nil || original != blob) {
			return ErrStorage
		}
		if found {
			for _, edit := range superseded {
				var record draftEditRecord
				raw := b.Get([]byte("edit-" + edit.ID))
				if len(raw) > maxDraftEditRecordBytes || json.Unmarshal(raw, &record) != nil || !record.matches(edit) || !record.Abandoned {
					return ErrStorage
				}
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if !found {
		file, err := d.openDraftBlob(blob, !blob.Done)
		if err != nil {
			return err // Missing original bytes before intent are not GC success.
		}
		if err := file.Close(); err != nil {
			return err
		}
		if err := d.spool.db.Update(func(tx *bolt.Tx) error {
			b := d.bucket(tx)
			if b == nil || !bytes.Equal(b.Get(key), header) || b.Get(gcKey) != nil {
				return ErrConflict
			}
			// Fence only the impossible original edits, atomically with the
			// deletion intent. Preserve their input/digest and never fabricate
			// a successful edit result. Multipart retries read this small record
			// instead of decoding the entire draft tree for every chunk.
			for _, edit := range superseded {
				editKey := []byte("edit-" + edit.ID)
				var record draftEditRecord
				if raw := b.Get(editKey); len(raw) > maxDraftEditRecordBytes || json.Unmarshal(raw, &record) != nil || !record.matches(edit) || record.Input == nil || record.Result != nil {
					return ErrStorage
				}
				record.Abandoned = true
				raw, _ := json.Marshal(record)
				if err := b.Put(editKey, raw); err != nil {
					return err
				}
			}
			return b.Put(gcKey, header)
		}); err != nil {
			return err
		}
	}
	file, err := d.openDraftBlob(blob, !blob.Done)
	if err == nil {
		if err = file.Close(); err != nil {
			return err
		}
		if err = unix.Unlinkat(int(d.dir.Fd()), string(key), 0); err != nil {
			return ErrStorage
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return err
	}
	if unix.Fsync(int(d.dir.Fd())) != nil {
		return ErrStorage
	}
	return d.spool.db.Update(func(tx *bolt.Tx) error {
		b := d.bucket(tx)
		if b == nil || !bytes.Equal(b.Get(key), header) || !bytes.Equal(b.Get(gcKey), header) {
			return ErrStorage
		}
		if err := b.Delete(key); err != nil {
			return err
		}
		prefix := append(bytes.Clone(key), '/')
		cursor := b.Cursor()
		for k, _ := cursor.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = cursor.Next() {
			if err := cursor.Delete(); err != nil {
				return err
			}
		}
		return b.Delete(gcKey)
	})
}
