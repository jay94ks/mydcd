// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"errors"

	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/storage"
)

// Original native facts are read only from this exact healthy owner DB. A
// failed/uncertain writer must close/reopen its original Store first; cached
// in-memory acknowledgement is not substituted for durability.
func (s *Store) DeleteReceipt(ctx context.Context, q ImageDelete) (ImageDeleteReceipt, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || !q.Valid() {
		return ImageDeleteReceipt{}, false, ErrStorage
	}
	s.Metadata.mu.Lock()
	defer s.Metadata.mu.Unlock()
	if s.Metadata.enter(ctx) != nil {
		return ImageDeleteReceipt{}, false, ErrStorage
	}
	raw, err := s.db.GetBounded(imageDeleteReceiptKey(q), 1<<20)
	if errors.Is(err, storage.ErrMissing) {
		return ImageDeleteReceipt{}, false, nil
	}
	if err != nil {
		return ImageDeleteReceipt{}, false, err
	}
	r, err := schema.Decode[ImageDeleteReceipt](raw)
	if err != nil || !r.Valid() || r.Scope != s.Metadata.scope || r.Request != q {
		return ImageDeleteReceipt{}, false, ErrStorage
	}
	return r, true, nil
}
func (s *Store) GCReceipt(ctx context.Context, q GCRequest) (GCReceipt, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || !q.Valid() {
		return GCReceipt{}, false, ErrStorage
	}
	s.Metadata.mu.Lock()
	defer s.Metadata.mu.Unlock()
	if s.Metadata.enter(ctx) != nil {
		return GCReceipt{}, false, ErrStorage
	}
	raw, err := s.db.GetBounded(actionReceiptKey(gcPrefix, q.Operation), 16<<20)
	if errors.Is(err, storage.ErrMissing) {
		return GCReceipt{}, false, nil
	}
	if err != nil {
		return GCReceipt{}, false, err
	}
	r, err := schema.Decode[GCReceipt](raw)
	if err != nil || !r.Valid() || r.Scope != s.Metadata.scope || r.Request != q {
		return GCReceipt{}, false, ErrStorage
	}
	return r, true, nil
}
