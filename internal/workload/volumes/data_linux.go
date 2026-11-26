// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"strconv"
	"syscall"

	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/moby/moby/client"
	"golang.org/x/sys/unix"
)

// OpenWriterData is the native filesystem boundary for embedded services.
// It requires the original shared writable consumer and a positively recorded
// local A3 lease. Neither argument authenticates a shared grant: the service
// must obtain its current MYDCP permit and sync the SAME Gate checkpoint before
// starting, then close/join every data user before Return or shared Release.
// Closing this root closes only descriptors; it never returns any reference.
func (m *NativeManager) OpenWriterData(ctx context.Context, ready NativeReady, consumer Consumer, lease NativeLease) (*os.Root, error) {
	if !consumer.Writable {
		return nil, ErrNativeVolume
	}
	return m.OpenConsumerData(ctx, ready, consumer, lease)
}

// OpenConsumerData is used only after current shared consumer admission.
func (m *NativeManager) OpenConsumerData(ctx context.Context, ready NativeReady, consumer Consumer, lease NativeLease) (*os.Root, error) {
	if ready.Verify() != nil || !validConsumer(consumer, ready.Spec.Scope) || consumer.Owner != ready.Owner || lease.Key != NativeKey(ready.Spec) || lease.Scope != ready.Spec.Scope || lease.Owner != ready.Owner || lease.Consumer != DataConsumerID(consumer) || lease.Pin.Generation != ready.Generation || lease.Pin.Token == 0 {
		return nil, ErrNativeVolume
	}
	row, err := m.View(lease.Key)
	if err != nil || row.Consumers[lease.Consumer] != lease.Pin || row.State.Pending != nil || !row.State.Applied.Present || row.State.Applied != row.State.Desired.Resource || row.State.Applied.Generation != ready.Generation {
		return nil, errors.Join(ErrNativeVolume, err)
	}
	if ready.Fixed != nil {
		if m.fixed == nil {
			return nil, ErrNativeVolume
		}
		digest := NativeBindingDigest(ready)
		if _, _, err = m.MountSource(lease.Key, ready.Spec.Scope, ready.Owner, ready.Generation, hex.EncodeToString(digest[:])); err != nil {
			return nil, err
		}
		_, h, err := m.fixed.BindSource(ctx, lease)
		if err != nil {
			return nil, err
		}
		defer h.Close()
		return pinnedDataRoot(h.FD())
	}
	guard := m.declaration(lease.Key)
	guard.Lock()
	defer guard.Unlock()
	spec, id, err := m.driver.parameters(lease.Key, reconcile.Operation{Kind: reconcile.Apply, Target: row.State.Applied})
	if err != nil || spec != ready.Spec {
		return nil, errors.Join(ErrNativeVolume, err)
	}
	got, err := m.driver.engine.API.VolumeInspect(ctx, id.Name, client.VolumeInspectOptions{})
	if err != nil || !matchNative(got.Volume, id) || nativeDirectory(got.Volume, spec, false) != nil {
		return nil, errors.Join(ErrNativeVolume, err)
	}
	before, err := os.Lstat(got.Volume.Mountpoint)
	if err != nil || !before.IsDir() {
		return nil, errors.Join(ErrNativeVolume, err)
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, got.Volume.Mountpoint, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	original, ok := before.Sys().(*syscall.Stat_t)
	if err = unix.Fstat(fd, &st); err != nil || !ok || st.Dev != original.Dev || st.Ino != original.Ino || st.Uid != spec.UID || st.Gid != spec.GID || st.Mode&07777 != spec.Mode {
		return nil, errors.Join(ErrNativeVolume, err)
	}
	root, err := pinnedDataRoot(fd)
	if err != nil {
		return nil, err
	}
	// Re-observe original labels/mountpoint and the intact lease after open;
	// a failed SDK response is not an empty/new data directory.
	after, err := m.driver.engine.API.VolumeInspect(ctx, id.Name, client.VolumeInspectOptions{})
	current, readErr := m.journal.Read(lease.Key)
	last, statErr := os.Lstat(got.Volume.Mountpoint)
	if err != nil || readErr != nil || statErr != nil || !os.SameFile(before, last) || !matchNative(after.Volume, id) || after.Volume.Mountpoint != got.Volume.Mountpoint || current.Consumers[lease.Consumer] != lease.Pin || current.State.Applied != row.State.Applied || current.State.Desired.Resource != row.State.Desired.Resource {
		_ = root.Close()
		return nil, errors.Join(ErrNativeVolume, err, readErr, statErr)
	}
	return root, nil
}

func DataConsumerID(c Consumer) string {
	if !identifier(c.ID) || c.Generation == 0 {
		return ""
	}
	return "data/" + c.ID + "/" + strconv.FormatUint(c.Generation, 10)
}

func pinnedDataRoot(fd int) (*os.Root, error) {
	// A trusted, live local descriptor, not a user path or a persisted Docker
	// /proc/PID/fd configuration. os.Root keeps its own anchor after this call.
	return os.OpenRoot("/proc/self/fd/" + strconv.Itoa(fd))
}
