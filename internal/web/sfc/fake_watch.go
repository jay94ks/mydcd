// SPDX-License-Identifier: Apache-2.0

package sfc

import "context"

// WatchChanges in the fake reports where it starts and then nothing: the
// fake keeps no change feed yet, so screens over it fall back to reading.
func (c *fakeConn) WatchChanges(ctx context.Context, from uint64, each func(ChangeBatch) error) (uint64, error) {
	const m = "change-watch"
	if _, err := c.lockSession(ctx, m); err != nil {
		return from, err
	}
	c.unlock()
	index := max(from, 1)
	if err := each(ChangeBatch{Index: index, Resync: from != 0}); err != nil {
		return from, err
	}
	<-ctx.Done()
	return index, ctx.Err()
}
