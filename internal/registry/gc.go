// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/storage"
)

var ErrUploadsInProgress = errors.New("registry uploads in progress")

type GCRequest struct{ Operation, Authority string }

func (q GCRequest) Valid() bool { return validImageActionScope(q.Operation, q.Authority) }

type GCBlob struct {
	Digest  string
	Size    int64
	Dropped bool
}
type GCReceipt struct {
	Schema          uint8
	Scope           Scope
	Request         GCRequest
	State           string
	At, CompletedAt uint64
	Sequence        uint64
	ReclaimedBytes  int64
	Protected       uint64
	Blobs           []GCBlob
}

func (r GCReceipt) Valid() bool {
	if r.Schema != 1 || !r.Scope.valid() || !r.Request.Valid() || r.At == 0 || r.Sequence == 0 || len(r.Blobs) > 65536 || r.Protected > 65536 || r.State != "deleting" && r.State != "done" {
		return false
	}
	last := ""
	var reclaimed, total int64
	for _, blob := range r.Blobs {
		if _, err := blobPath(blob.Digest); err != nil || blob.Digest <= last || blob.Size < 0 || blob.Size > (1<<63-1)-total {
			return false
		}
		total += blob.Size
		if blob.Dropped {
			reclaimed += blob.Size
		}
		last = blob.Digest
		if r.State == "done" && !blob.Dropped {
			return false
		}
	}
	return r.ReclaimedBytes == reclaimed && (r.State == "done") == (r.CompletedAt > 0)
}

// GarbageCollect is an explicit original native operation, not implicit app
// teardown. It joins requests, refuses unfinished uploads/open readers, retains
// unpublished push objects and rechecks shared image references before intent.
func (s *Store) GarbageCollect(ctx context.Context, q GCRequest, guard func(context.Context, []string) error) (GCReceipt, error) {
	if !q.Valid() || guard == nil {
		return GCReceipt{}, ErrStorage
	}
	release, err := s.gate.acquire(ctx, true)
	if err != nil {
		return GCReceipt{}, err
	}
	defer release()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.Metadata == nil || s.Blobs == nil {
		return GCReceipt{}, ErrStorage
	}
	m, b := s.Metadata, s.Blobs
	m.mu.Lock()
	defer m.mu.Unlock()
	b.mu.Lock()
	defer b.mu.Unlock()
	if m.enter(ctx) != nil || b.enter(ctx, true) != nil {
		return GCReceipt{}, ErrStorage
	}
	receipt, err := s.beginGC(ctx, q, guard)
	if err != nil {
		return GCReceipt{}, err
	}
	if receipt.State == "done" {
		return receipt, nil
	}
	receipt, err = b.finishGC(ctx, receipt)
	if err != nil {
		m.failed = true
		b.failed = true
		return GCReceipt{}, err
	}
	if err = b.countBytes(); err != nil {
		m.failed = true
		b.failed = true
		return GCReceipt{}, err
	}
	return receipt, nil
}

// Caller owns Store/Metadata/Blobs locks and the exclusive request gate. The
// detach and exact physical deletion intent share a DB transaction. Tests may
// cut here; recovery resumes this same function's persisted original intent.
func (s *Store) beginGC(ctx context.Context, q GCRequest, guard func(context.Context, []string) error) (GCReceipt, error) {
	m, b := s.Metadata, s.Blobs
	key := actionReceiptKey(gcPrefix, q.Operation)
	raw, err := s.db.GetBounded(key, 16<<20)
	if err == nil {
		r, e := schema.Decode[GCReceipt](raw)
		if e != nil || !r.Valid() || r.Scope != m.scope || r.Request != q {
			return GCReceipt{}, ErrStorage
		}
		return r, nil
	}
	if !errors.Is(err, storage.ErrMissing) {
		return GCReceipt{}, err
	}
	if b.readers != 0 {
		return GCReceipt{}, ErrReaders
	}
	for _, upload := range b.uploads {
		if upload.Phase != "complete" && upload.Phase != "canceled" {
			return GCReceipt{}, ErrUploadsInProgress
		}
	}
	live, err := m.liveBlobReferences(ctx, b)
	if err != nil {
		return GCReceipt{}, err
	}
	groups := map[string][]string{}
	sizes := map[string]int64{}
	for key, blob := range b.blobs {
		groups[blob.Digest] = append(groups[blob.Digest], key)
		if size, ok := sizes[blob.Digest]; ok && size != blob.Size {
			return GCReceipt{}, ErrStorage
		}
		sizes[blob.Digest] = blob.Size
	}
	candidates := map[string]bool{}
	prior, err := s.db.ScanBounded(gcPrefix, m.limits.Records, m.limits.TotalBytes)
	if err != nil {
		return GCReceipt{}, ErrStorage
	}
	var sequence uint64
	for _, raw := range prior {
		previous, err := schema.Decode[GCReceipt](raw)
		if err != nil || !previous.Valid() || previous.Scope != m.scope {
			return GCReceipt{}, ErrStorage
		}
		sequence = max(sequence, previous.Sequence)
	}
	if sequence == ^uint64(0) {
		return GCReceipt{}, ErrStorage
	}
	receipt := GCReceipt{Schema: 1, Scope: m.scope, Request: q, State: "deleting", At: uint64(time.Now().UnixMilli()), Sequence: sequence + 1}
	for digest, keys := range groups {
		eligible := true
		for _, key := range keys {
			if live[key] {
				eligible = false
				break
			}
		}
		if eligible {
			candidates[digest] = true
			receipt.Blobs = append(receipt.Blobs, GCBlob{Digest: digest, Size: sizes[digest]})
		} else {
			receipt.Protected++
		}
	}
	slices.SortFunc(receipt.Blobs, func(a, b GCBlob) int { return strings.Compare(a.Digest, b.Digest) })
	// Match retired graphs with exact deletion receipts for shared reference
	// checks. Unpublished/legacy orphan bytes require their original completed
	// upload proof and closed push leases below, never a guessed file adoption.
	rows, err := s.db.ScanBounded(imageDeletePrefix, m.limits.Records, m.limits.TotalBytes)
	if err != nil {
		return GCReceipt{}, ErrStorage
	}
	witnessed := map[string]bool{}
	images := map[string]bool{}
	for _, raw := range rows {
		r, err := schema.Decode[ImageDeleteReceipt](raw)
		if err != nil || !r.Valid() || r.Scope != m.scope {
			return GCReceipt{}, ErrStorage
		}
		for _, blob := range r.Blobs {
			if candidates[blob.Digest] {
				key, _ := blobKey(r.Request.Repository, blob.Digest)
				if value, ok := b.blobs[key]; ok {
					if value.Size != blob.Size {
						return GCReceipt{}, ErrStorage
					}
					witnessed[key] = true
					images[r.Request.Authority+"/"+r.Request.Repository+"@"+r.Request.ExpectedDigest] = true
				}
			}
		}
	}
	refs := []string{}
	for ref := range images {
		refs = append(refs, ref)
	}
	slices.Sort(refs)
	for digest := range candidates {
		for _, key := range groups[digest] {
			blob := b.blobs[key]
			origin, exists := b.uploads[blob.Origin]
			if !exists || !b.validUpload(origin) || origin.Phase != "complete" || origin.Repo != blob.Repo || origin.Digest != blob.Digest || origin.Offset != blob.Size {
				return GCReceipt{}, ErrStorage
			}
			if blob.Retired && !witnessed[key] {
				return GCReceipt{}, ErrStorage
			}
		}
	}
	if err = guard(ctx, refs); err != nil {
		return GCReceipt{}, err
	}
	changes := map[string][]byte{}
	for digest := range candidates {
		for _, key := range groups[digest] {
			changes[key] = nil
		}
	}
	for id, upload := range b.uploads {
		if upload.Phase == "complete" && candidates[upload.Digest] {
			changes[uploadPrefix+id] = nil
		}
	}
	until, err := s.beginPushFence(q.Operation, time.Now().Unix())
	if err != nil {
		return GCReceipt{}, err
	}
	if until > time.Now().Unix() {
		return GCReceipt{}, ErrPushLeaseActive
	}
	raw, _ = json.Marshal(receipt)
	// Reserve the final acknowledgement before detaching references. Empty GC
	// and large byte counters must not grow the receipt past its recovery budget.
	final := receipt
	final.Blobs = slices.Clone(receipt.Blobs)
	final.State = "done"
	final.CompletedAt = ^uint64(0)
	for i := range final.Blobs {
		final.Blobs[i].Dropped = true
		final.ReclaimedBytes += final.Blobs[i].Size
	}
	finalRaw, _ := json.Marshal(final)
	changes[key] = finalRaw
	if !receipt.Valid() || !final.Valid() || len(finalRaw) > 16<<20 {
		return GCReceipt{}, ErrStorage
	}
	if err := s.maintenanceBudget(changes); err != nil {
		return GCReceipt{}, err
	}
	changes[key] = raw
	if ctx.Err() != nil {
		return GCReceipt{}, ctx.Err()
	}
	if err = s.db.Write(changes); err != nil {
		m.failed = true
		b.failed = true
		return GCReceipt{}, ErrStorage
	}
	for key := range changes {
		if strings.HasPrefix(key, blobPrefix) {
			delete(b.blobs, key)
		}
		if strings.HasPrefix(key, uploadPrefix) {
			delete(b.uploads, strings.TrimPrefix(key, uploadPrefix))
		}
	}
	return receipt, nil
}

func (m *Metadata) liveBlobReferences(ctx context.Context, b *Blobs) (map[string]bool, error) {
	repos, err := m.repositories(ctx)
	if err != nil {
		return nil, err
	}
	live := map[string]bool{}
	for _, repo := range repos {
		refs, err := m.manifestReferences(ctx, repo)
		if err != nil {
			return nil, err
		}
		for _, ref := range refs {
			if !strings.HasPrefix(ref, "sha256:") {
				continue
			}
			data, err := m.getManifest(ctx, repo, ref)
			if err != nil {
				return nil, err
			}
			blobs, err := directManifestBlobs(data)
			if err != nil {
				return nil, err
			}
			for _, blob := range blobs {
				key, _ := blobKey(repo, blob.Digest)
				v, exists := b.blobs[key]
				if !exists || v.Size != blob.Size {
					return nil, ErrStorage
				}
				live[key] = true
			}
		}
	}
	return live, nil
}

func (b *Blobs) finishGC(ctx context.Context, r GCReceipt) (GCReceipt, error) {
	if !r.Valid() || r.Scope != b.scope {
		return GCReceipt{}, ErrStorage
	}
	if r.State == "done" {
		return r, nil
	}
	key := actionReceiptKey(gcPrefix, r.Request.Operation)
	cleared, err := clearPushFence(b.db, b.scope, r.Request.Operation, b.metadataLimits.TotalBytes)
	if err != nil {
		return GCReceipt{}, ErrStorage
	} // prove the original fence before any unlink
	for i, blob := range r.Blobs {
		if ctx.Err() != nil {
			return GCReceipt{}, ctx.Err()
		}
		path, _ := blobPath(blob.Digest)
		info, err := b.root.Lstat(path)
		if blob.Dropped {
			if !os.IsNotExist(err) {
				return GCReceipt{}, ErrStorage
			}
			continue
		}
		if err == nil {
			if !privateFile(info, false) || info.Size() != blob.Size {
				return GCReceipt{}, ErrStorage
			}
			if err = b.root.Remove(path); err != nil {
				return GCReceipt{}, ErrStorage
			}
		} else if !os.IsNotExist(err) {
			return GCReceipt{}, ErrStorage
		}
		// Missing bytes are accepted only because this original detach intent was
		// already committed; an ordinary missing live blob remains corruption.
		if err = b.syncDir("blobs"); err != nil {
			return GCReceipt{}, err
		}
		r.Blobs[i].Dropped = true
		r.ReclaimedBytes += blob.Size
		raw, _ := json.Marshal(r)
		if err = b.db.Write(map[string][]byte{key: raw}); err != nil {
			return GCReceipt{}, ErrStorage
		}
	}
	r.State = "done"
	r.CompletedAt = uint64(time.Now().UnixMilli())
	raw, _ := json.Marshal(r)
	if !r.Valid() || b.db.Write(map[string][]byte{key: raw, pushStateKey: cleared}) != nil {
		return GCReceipt{}, ErrStorage
	}
	return r, nil
}

func (m *Metadata) validateMaintenanceReceipts() error {
	sequences := map[uint64]bool{}
	maintenance := false
	for _, prefix := range []string{imageDeletePrefix, gcPrefix} {
		rows, err := m.db.ScanBounded(prefix, m.limits.Records, m.limits.TotalBytes)
		if err != nil {
			return ErrStorage
		}
		for key, raw := range rows {
			maintenance = true
			if prefix == imageDeletePrefix {
				r, err := schema.Decode[ImageDeleteReceipt](raw)
				if err != nil || !r.Valid() || r.Scope != m.scope || key != imageDeleteReceiptKey(r.Request) {
					return ErrStorage
				}
			} else {
				r, err := schema.Decode[GCReceipt](raw)
				if err != nil || !r.Valid() || r.Scope != m.scope || key != actionReceiptKey(prefix, r.Request.Operation) {
					return ErrStorage
				}
				if sequences[r.Sequence] {
					return ErrStorage
				}
				sequences[r.Sequence] = true
			}
		}
	}
	rows, err := m.db.SizesBounded(pushPrefix, 1, m.limits.TotalBytes)
	if err != nil {
		return ErrStorage
	}
	for key := range rows {
		if key != pushStateKey {
			return ErrStorage
		}
	}
	_, err = m.pushState()
	if maintenance && err != nil || err != nil && !errors.Is(err, storage.ErrMissing) {
		return ErrStorage
	}
	return nil
}
func (b *Blobs) recoverGC(ctx context.Context) error {
	rows, err := b.db.ScanBounded(gcPrefix, b.metadataLimits.Records, b.metadataLimits.TotalBytes)
	if err != nil {
		return ErrStorage
	}
	pending := []GCReceipt{}
	digests := map[string]bool{}
	for key, raw := range rows {
		r, err := schema.Decode[GCReceipt](raw)
		if err != nil || !r.Valid() || r.Scope != b.scope || key != actionReceiptKey(gcPrefix, r.Request.Operation) {
			return ErrStorage
		}
		if r.State == "done" {
			continue
		}
		for _, blob := range r.Blobs {
			if blob.Size > b.limits.BlobBytes || digests[blob.Digest] {
				return ErrStorage
			}
			digests[blob.Digest] = true
		}
		pending = append(pending, r)
	}
	if len(pending) == 0 {
		return nil
	}
	if len(pending) > 1 {
		return ErrStorage
	} // one Store owns one persisted write fence
	// A detached candidate cannot simultaneously have a live/re-published DB
	// reference. Recovery must refuse that contradiction rather than unlink it.
	blobs, err := b.db.ScanBounded(blobPrefix, b.limits.Records, b.limits.Records*2048)
	if err != nil {
		return ErrStorage
	}
	for _, raw := range blobs {
		v, err := schema.Decode[blobRecord](raw)
		if err != nil || digests[v.Digest] {
			return ErrStorage
		}
	}
	uploads, err := b.db.ScanBounded(uploadPrefix, b.limits.Records, b.limits.Records*2048)
	if err != nil {
		return ErrStorage
	}
	for _, raw := range uploads {
		u, err := schema.Decode[uploadRecord](raw)
		if err != nil || u.Phase != "complete" && u.Phase != "canceled" || digests[u.Digest] {
			return ErrStorage
		}
	}
	slices.SortFunc(pending, func(a, b GCReceipt) int { return strings.Compare(a.Request.Operation, b.Request.Operation) })
	for _, r := range pending {
		if _, err = b.finishGC(ctx, r); err != nil {
			return err
		}
	}
	return nil
}

// LatestGC reads the original local receipts. It is observation, not proof of
// current free disk space or permission to submit another collection operation.
func (m *Metadata) LatestGC(ctx context.Context) (GCReceipt, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.enter(ctx) != nil {
		return GCReceipt{}, false, ErrStorage
	}
	rows, err := m.db.ScanBounded(gcPrefix, m.limits.Records, m.limits.TotalBytes)
	if err != nil {
		return GCReceipt{}, false, ErrStorage
	}
	var latest GCReceipt
	found := false
	for _, raw := range rows {
		r, err := schema.Decode[GCReceipt](raw)
		if err != nil || !r.Valid() || r.Scope != m.scope {
			return GCReceipt{}, false, ErrStorage
		}
		if r.State == "done" && (!found || r.Sequence > latest.Sequence) {
			latest = r
			found = true
		}
	}
	return latest, found, nil
}
