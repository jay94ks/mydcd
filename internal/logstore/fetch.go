// SPDX-License-Identifier: Apache-2.0

package logstore

import (
	"context"
	"errors"
)

// Bulk is the engine's answer to one purpose 33 bulk request.
type Bulk struct {
	Count       int
	First, Last uint64
	Body        []byte // records in the segment record encoding
}

// Engine is the engine side the fetcher needs (purpose 33 and 34 over the
// engine session).
type Engine interface {
	Bulk(ctx context.Context, container string, after uint64, maxBytes int) (Bulk, error)
	Ack(ctx context.Context, container string, upto uint64) error
}

// BulkBytes is how much one fetch asks for.
const BulkBytes = 4 << 20

// Fetch takes everything the engine holds for container id after what the
// store already has, stores it and acks it, until the engine answers an
// empty bulk. It is what a seafield.logs event (or a rescan after an engine
// boot change) runs. The ack follows the store write, so a crash in between
// fetches the same records again and Append skips them.
func (s *Store) Fetch(ctx context.Context, e Engine, id string, meta Meta) (int, error) {
	total := 0
	after := s.Last(id)
	for {
		b, err := e.Bulk(ctx, id, after, BulkBytes)
		if err != nil {
			return total, err
		}
		if b.Count == 0 {
			// Nothing after `after`: the engine may still hold records the
			// store already has (an ack lost to a crash).
			if after > 0 {
				err = e.Ack(ctx, id, after)
			}
			return total, err
		}
		recs, err := Decode(b.Body)
		if err != nil {
			return total, err
		}
		if len(recs) != b.Count {
			return total, errors.New("logstore: bulk count does not match its body")
		}
		last, err := s.Append(id, meta, recs)
		if err != nil {
			return total, err
		}
		if err := e.Ack(ctx, id, last); err != nil {
			return total, err
		}
		total += len(recs)
		after = last
	}
}
