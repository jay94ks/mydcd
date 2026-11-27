// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"context"
	"errors"
	"io"
	"math"
	"os"
	"path"
	"syscall"

	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/moby/moby/client"
)

var ErrVolumeUsage = errors.New("volume usage scan incomplete or unsupported")
var ErrUsageLimit = errors.New("volume usage scan budget exceeded")

// UsageLimits bounds work and memory, not the volume's disk quota. Directory
// reads are batched independently of Entries, including when a directory is huge.
type UsageLimits struct {
	Entries uint64
	Depth   int
}

func (l UsageLimits) valid() bool {
	return l.Entries > 0 && l.Entries <= 1_000_000 && l.Depth > 0 && l.Depth <= 128
}

// Usage is a best-effort live observation of the exact original materialization.
// Files/Directories/bytes count unique inodes; Entries includes hardlink names
// and the root. Filesystem capacity is shared with other filesystem users.
// No host paths or filenames are included. This is never a consistent backup.
type Usage struct {
	Schema                                    uint8
	Scope                                     Scope
	Owner                                     Owner
	Generation                                uint64
	QuotaMode                                 string
	Snapshot                                  bool
	Entries, Files, Directories               uint64
	LogicalBytes, AllocatedBytes              uint64
	FilesystemBytes, FilesystemAvailableBytes uint64
}

// Matches validates the public response binding at the authenticated boundary.
// It cannot prove that the peer actually scanned a filesystem.
func (u Usage) Matches(r NativeReady) bool {
	return r.Verify() == nil && u.Schema == 1 && u.Scope == r.Spec.Scope && u.Owner == r.Owner && u.Generation == r.Generation && u.QuotaMode == "observe" && !u.Snapshot && u.Entries > 0 && u.Entries <= 1_000_000 && u.Directories > 0 && u.Files <= u.Entries && u.Directories <= u.Entries-u.Files && u.AllocatedBytes%512 == 0 && u.FilesystemBytes > 0 && u.FilesystemAvailableBytes <= u.FilesystemBytes
}

type inode struct{ device, number uint64 }
type usageScan struct {
	limits UsageLimits
	device uint64
	seen   map[inode]bool
	value  Usage
}

func usageAdd(a, b uint64) (uint64, error) {
	if b > math.MaxUint64-a {
		return 0, ErrVolumeUsage
	}
	return a + b, nil
}

func (s *usageScan) account(info os.FileInfo) error {
	if s.value.Entries >= s.limits.Entries {
		return ErrUsageLimit
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(st.Dev) != s.device || st.Size < 0 || st.Blocks < 0 || uint64(st.Blocks) > math.MaxUint64/512 || !info.Mode().IsRegular() && !info.IsDir() {
		return ErrVolumeUsage
	}
	s.value.Entries++
	key := inode{uint64(st.Dev), uint64(st.Ino)}
	if s.seen[key] {
		return nil
	}
	s.seen[key] = true
	allocated, err := usageAdd(s.value.AllocatedBytes, uint64(st.Blocks)*512)
	if err != nil {
		return err
	}
	s.value.AllocatedBytes = allocated
	if info.IsDir() {
		s.value.Directories++
		return nil
	}
	s.value.Files++
	s.value.LogicalBytes, err = usageAdd(s.value.LogicalBytes, uint64(st.Size))
	return err
}

func (s *usageScan) directory(ctx context.Context, root *os.Root, rel string, depth int, expected os.FileInfo) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if depth > s.limits.Depth {
		return ErrUsageLimit
	}
	f, err := root.OpenFile(rel, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return ErrVolumeUsage
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !os.SameFile(expected, info) {
		return ErrVolumeUsage
	}
	if err = s.account(info); err != nil {
		return err
	}
	for {
		entries, err := f.ReadDir(64)
		if err != nil && !errors.Is(err, io.EOF) {
			return ErrVolumeUsage
		}
		for _, entry := range entries {
			if e := ctx.Err(); e != nil {
				return e
			}
			name := path.Join(rel, entry.Name())
			observed, e := root.Lstat(name)
			if e != nil {
				return ErrVolumeUsage
			}
			if observed.IsDir() {
				if e = s.directory(ctx, root, name, depth+1, observed); e != nil {
					return e
				}
			} else if e = s.account(observed); e != nil {
				return e
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
	}
}

func scanUsage(ctx context.Context, directory string, limits UsageLimits) (Usage, error) {
	if !limits.valid() {
		return Usage{}, ErrUsageLimit
	}
	before, err := os.Lstat(directory)
	if err != nil || !before.IsDir() {
		return Usage{}, ErrVolumeUsage
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return Usage{}, ErrVolumeUsage
	}
	defer root.Close()
	f, err := root.Open(".")
	if err != nil {
		return Usage{}, ErrVolumeUsage
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !os.SameFile(before, info) {
		return Usage{}, ErrVolumeUsage
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	var filesystem syscall.Statfs_t
	if !ok || syscall.Fstatfs(int(f.Fd()), &filesystem) != nil || filesystem.Bsize <= 0 || filesystem.Blocks > math.MaxUint64/uint64(filesystem.Bsize) || filesystem.Bavail > filesystem.Blocks {
		return Usage{}, ErrVolumeUsage
	}
	s := usageScan{limits: limits, device: uint64(st.Dev), seen: map[inode]bool{}}
	if err = s.directory(ctx, root, ".", 0, info); err != nil {
		return Usage{}, err
	}
	after, err := os.Lstat(directory)
	if err != nil || !os.SameFile(before, after) {
		return Usage{}, ErrVolumeUsage
	}
	s.value.Schema, s.value.QuotaMode = 1, "observe"
	s.value.FilesystemBytes = filesystem.Blocks * uint64(filesystem.Bsize)
	s.value.FilesystemAvailableBytes = filesystem.Bavail * uint64(filesystem.Bsize)
	return s.value, nil
}

// Usage reads only an original, converged local volume. The declaration guard
// serializes Desired/DeleteDesired against the scan. Pending effects are not
// observed as empty volumes; concurrent workload writes are not fenced by this
// method. The caller must enforce current user/tenant read authorization before
// publishing this node-local observation over SFCP.
func (m *NativeManager) Usage(ctx context.Context, key string, limits UsageLimits) (Usage, error) {
	if fixedNativeKey(key) {
		if m.fixed == nil {
			return Usage{}, ErrNativeVolume
		}
		return m.fixed.Usage(ctx, key, limits)
	}
	guard := m.declaration(key)
	guard.Lock()
	defer guard.Unlock()
	r, err := m.journal.Read(key)
	if err != nil || r.State.Pending != nil || r.State.Stopped || !r.State.Applied.Present || r.State.Applied != r.State.Desired.Resource {
		return Usage{}, ErrNativeVolume
	}
	spec, id, err := m.driver.parameters(key, reconcile.Operation{Kind: reconcile.Apply, Target: r.State.Applied})
	if err != nil {
		return Usage{}, ErrNativeVolume
	}
	got, err := m.driver.engine.API.VolumeInspect(ctx, id.Name, client.VolumeInspectOptions{})
	if err != nil || !matchNative(got.Volume, id) || nativeDirectory(got.Volume, spec, false) != nil {
		return Usage{}, ErrNativeVolume
	}
	value, err := scanUsage(ctx, got.Volume.Mountpoint, limits)
	if err != nil {
		return Usage{}, err
	}
	after, err := m.driver.engine.API.VolumeInspect(ctx, id.Name, client.VolumeInspectOptions{})
	if err != nil || !matchNative(after.Volume, id) || after.Volume.Mountpoint != got.Volume.Mountpoint || nativeDirectory(after.Volume, spec, false) != nil {
		return Usage{}, ErrNativeVolume
	}
	value.Scope, value.Owner = spec.Scope, Owner{Node: spec.Node, Key: spec.NodeKey, Native: id.Name}
	value.Generation = r.State.Applied.Generation
	return value, nil
}
