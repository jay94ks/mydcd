// SPDX-License-Identifier: Apache-2.0

package nodestorage

import (
	"context"
	"errors"

	"golang.org/x/sys/unix"
)

// Space reads the exact original directory's filesystem. It makes no recursive
// scan, reservation or filesystem quota promise. Failure is never zero usage.
func (m *RootManager) Space(ctx context.Context, root Root) (Space, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, err := m.fact(ctx, root)
	if err != nil {
		return Space{}, err
	}
	h, err := OpenDirectory(f.Root.Path)
	if err != nil {
		return Space{}, err
	}
	defer h.Close()
	dir := h.Identity()
	if !dir.MatchesOriginal(f.Directory) {
		return Space{}, ErrStorage
	}
	var fs unix.Statfs_t
	if err = unix.Fstatfs(h.FD(), &fs); err != nil {
		return Space{}, err
	}
	if fs.Type != unix.EXT4_SUPER_MAGIC || fs.Bsize <= 0 || fs.Blocks == 0 || fs.Bfree > fs.Blocks || fs.Bavail > fs.Bfree {
		return Space{}, ErrStorage
	}
	unit := uint64(fs.Bsize)
	if fs.Blocks > ^uint64(0)/unit {
		return Space{}, ErrStorage
	}
	if err = ctx.Err(); err != nil {
		return Space{}, errors.Join(ErrStorage, err)
	}
	return Space{Root: f.Root, Directory: dir, Total: fs.Blocks * unit, Free: fs.Bfree * unit, Available: fs.Bavail * unit}, nil
}
