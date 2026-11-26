// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/moby/moby/client"
)

// ColdAuthority must obtain fresh authenticated quorum authorization for the
// exact registered job/consumer, before and after native work. Local snapshots
// or a successful scan are not authorization. The callback must not reenter the
// same native declaration. Runtime/job integration supplies this boundary.
type ColdAuthority func(context.Context, NativeReady, Consumer) error

// PrepareRestoreCold observes the exact empty inactive target before stopping
// an app source. Space is a fresh observation; RestoreCold checks it again.
func (m *NativeManager) PrepareRestoreCold(ctx context.Context, ready NativeReady, c Consumer, authorize ColdAuthority, o ArchiveOptions) (err error) {
	if authorize == nil {
		return ErrNativeVolume
	}
	if err = authorize(ctx, ready, c); err != nil {
		return err
	}
	guard := m.declaration(NativeKey(ready.Spec))
	guard.Lock()
	defer guard.Unlock()
	root, err := m.coldRoot(ctx, ready, c, o, true, false)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	f, err := root.Open(".")
	if err != nil {
		return err
	}
	names, e := f.Readdirnames(1)
	if !errors.Is(e, io.EOF) || len(names) != 0 {
		err = ErrArchive
	} else {
		err = coldSpace(f, o.MaxBytes+uint64(o.MaxEntries)*8192)
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	return authorize(ctx, ready, c)
}

func (m *NativeManager) coldRoot(ctx context.Context, ready NativeReady, c Consumer, o ArchiveOptions, write, recoverOwn bool) (*os.Root, error) {
	if ready.Verify() != nil || !validConsumer(c, ready.Spec.Scope) || c.Owner != ready.Owner || c.Writable != write || o.UID != ready.Spec.UID || o.GID != ready.Spec.GID || o.RootMode != ready.Spec.Mode || !o.valid() {
		return nil, ErrNativeVolume
	}
	key := NativeKey(ready.Spec)
	r, err := m.journal.Read(key)
	raw, _ := json.Marshal(ready.Spec)
	if err != nil || r.State.Pending != nil || !r.State.Applied.Present || r.State.Applied != r.State.Desired.Resource || r.State.Applied.Generation != ready.Generation || r.State.Applied.Spec != string(raw) {
		return nil, ErrNativeVolume
	}
	if write && len(r.Consumers) != 0 {
		// An interrupted original restore may retain THIS exact local pin.
		// No other native consumer is allowed on the inactive target.
		pin, ok := r.Consumers[coldPinName(c)]
		if !recoverOwn || len(r.Consumers) != 1 || !ok || pin.Generation != ready.Generation {
			return nil, ErrNativeVolume
		}
	}
	_, id, err := m.driver.parameters(key, reconcile.Operation{Kind: reconcile.Apply, Target: r.State.Applied})
	if err != nil || id.Name != ready.Owner.Native {
		return nil, ErrNativeVolume
	}
	got, err := m.driver.engine.API.VolumeInspect(ctx, id.Name, client.VolumeInspectOptions{})
	if err != nil || !matchNative(got.Volume, id) || nativeDirectory(got.Volume, ready.Spec, false) != nil {
		return nil, ErrNativeVolume
	}
	// Even a stopped container still referencing this volume is not a closed
	// mount: it can be started again. The shared cold consumer also blocks new
	// writer admission/Start/Recover through the current authority.
	containers, err := m.driver.engine.API.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: client.Filters{}.Add("volume", id.Name)})
	if err != nil || len(containers.Items) != 0 {
		return nil, ErrNativeVolume
	}
	before, err := os.Lstat(got.Volume.Mountpoint)
	if err != nil || !before.IsDir() {
		return nil, ErrNativeVolume
	}
	root, err := os.OpenRoot(got.Volume.Mountpoint)
	if err != nil {
		return nil, ErrNativeVolume
	}
	current, err := root.Stat(".")
	if err != nil || !os.SameFile(before, current) {
		_ = root.Close()
		return nil, ErrNativeVolume
	}
	return root, nil
}

func coldFile(file *os.File, empty bool) (*syscall.Stat_t, error) {
	if file == nil {
		return nil, ErrArchive
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return nil, ErrArchive
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) || empty && st.Size != 0 {
		return nil, ErrArchive
	}
	offset, err := file.Seek(0, io.SeekCurrent)
	if err != nil || empty && offset != 0 {
		return nil, ErrArchive
	}
	return st, nil
}
func coldSpace(file *os.File, bytes uint64) error {
	var space syscall.Statfs_t
	if syscall.Fstatfs(int(file.Fd()), &space) != nil || space.Bsize <= 0 {
		return ErrArchive
	}
	if bytes/uint64(space.Bsize) >= space.Bavail {
		return errors.Join(ErrArchive, syscall.ENOSPC)
	}
	return nil
}
func coldPinName(c Consumer) string { return fmt.Sprintf("cold/%s/%d", c.ID, c.Generation) }

// CloseCold is called by the exclusive durable job owner after its copy worker
// has stopped (including recovery in a new process). The declaration lock also
// waits for a live local ExportCold. It returns only the exact original local
// reader token; shared authorization and the signed closure remain the job
// controller's responsibility. A missing token is an idempotent local return,
// never proof that an archive/copy was not executed.
func (m *NativeManager) CloseCold(ctx context.Context, ready NativeReady, c Consumer, o ArchiveOptions) error {
	return m.closeCold(ctx, ready, c, o, false)
}

// CloseRestoreCold settles only the original inactive writable restore pin
// after its exclusive job worker has stopped. It never removes target data.
func (m *NativeManager) CloseRestoreCold(ctx context.Context, ready NativeReady, c Consumer, o ArchiveOptions) error {
	return m.closeCold(ctx, ready, c, o, true)
}
func (m *NativeManager) closeCold(ctx context.Context, ready NativeReady, c Consumer, o ArchiveOptions, write bool) error {
	guard := m.declaration(NativeKey(ready.Spec))
	guard.Lock()
	defer guard.Unlock()
	root, err := m.coldRoot(ctx, ready, c, o, write, true)
	if err != nil {
		return err
	}
	if err = root.Close(); err != nil {
		return err
	}
	r, err := m.journal.Read(NativeKey(ready.Spec))
	if err != nil {
		return err
	}
	pin, exists := r.Consumers[coldPinName(c)]
	if !exists {
		return nil
	}
	if pin.Generation != ready.Generation {
		return ErrNativeVolume
	}
	return m.Return(NativeLease{Key: NativeKey(ready.Spec), Consumer: coldPinName(c), Owner: ready.Owner, Scope: ready.Spec.Scope, Pin: pin})
}

// VerifyRestoreCold is read-only recovery for the EXACT original target. A
// matching reconstructed archive proves the requested file tree/metadata is
// already present, even if its completion reply was lost. A mismatch remains
// Unknown: it never truncates/recreates/recopies a partial target. The shared
// staging authority must still exclude app Start and require current quorum.
func (m *NativeManager) VerifyRestoreCold(ctx context.Context, ready NativeReady, c Consumer, authorize ColdAuthority, receipt ArchiveReceipt, o ArchiveOptions) (err error) {
	if authorize == nil || !receipt.valid(o) {
		return ErrNativeVolume
	}
	if err = authorize(ctx, ready, c); err != nil {
		return err
	}
	guard := m.declaration(NativeKey(ready.Spec))
	guard.Lock()
	defer guard.Unlock()
	root, err := m.coldRoot(ctx, ready, c, o, true, true)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	pin, err := m.journal.Borrow(NativeKey(ready.Spec), coldPinName(c), ready.Generation)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, m.Return(NativeLease{Key: NativeKey(ready.Spec), Consumer: coldPinName(c), Owner: ready.Owner, Scope: ready.Spec.Scope, Pin: pin}))
	}()
	entries, err := planArchive(ctx, root, o)
	if err != nil {
		return err
	}
	got, err := WriteArchive(ctx, root, io.Discard, o)
	if err != nil {
		return err
	}
	if got != receipt {
		return ErrArchive
	}
	// A readable match alone does not prove durability after an interrupted
	// sync. Flush the unchanged original files, then child directories/root.
	// No data/metadata is rewritten; archiveFile rejects identity/stat changes.
	for i := len(entries) - 1; i >= 0; i-- {
		if err = ctx.Err(); err != nil {
			return err
		}
		file, e := archiveFile(root, entries[i])
		if e != nil {
			return e
		}
		e = errors.Join(m.archiveIO.sync(file), file.Close())
		if e != nil {
			return archiveError(e)
		}
	}
	return authorize(ctx, ready, c)
}

// ExportCold copies only a currently authorized readonly consumer's unmounted
// original materialization into a fresh private regular artifact file. File
// sync precedes success; its owner must also durably publish the directory/job
// receipt before releasing shared references or advertising a usable backup.
func (m *NativeManager) ExportCold(ctx context.Context, ready NativeReady, c Consumer, authorize ColdAuthority, out *os.File, o ArchiveOptions) (result ArchiveReceipt, err error) {
	if authorize == nil {
		return result, ErrNativeVolume
	}
	if _, err = coldFile(out, true); err != nil {
		return result, err
	}
	if err = coldSpace(out, o.MaxBytes); err != nil {
		return result, err
	}
	if err = authorize(ctx, ready, c); err != nil {
		return result, err
	}
	guard := m.declaration(NativeKey(ready.Spec))
	guard.Lock()
	defer guard.Unlock()
	root, err := m.coldRoot(ctx, ready, c, o, false, false)
	if err != nil {
		return result, err
	}
	// Borrow the existing A3 journal directly after resolving the exact ready
	// identity. No container/backup-specific lease algorithm is introduced.
	pin, err := m.journal.Borrow(NativeKey(ready.Spec), coldPinName(c), ready.Generation)
	if err != nil {
		_ = root.Close()
		return result, err
	}
	lease := NativeLease{Key: NativeKey(ready.Spec), Consumer: coldPinName(c), Owner: ready.Owner, Scope: ready.Spec.Scope, Pin: pin}
	defer func() {
		if e := m.Return(lease); e != nil {
			result = ArchiveReceipt{}
			err = errors.Join(err, e)
		}
	}()
	defer root.Close()
	result, err = WriteArchive(ctx, root, out, o)
	if err != nil {
		return ArchiveReceipt{}, err
	}
	if err = out.Sync(); err != nil {
		return ArchiveReceipt{}, archiveError(err)
	}
	if _, err = coldFile(out, false); err != nil {
		return ArchiveReceipt{}, err
	}
	if err = authorize(ctx, ready, c); err != nil {
		return ArchiveReceipt{}, err
	}
	return result, nil
}

// RestoreCold writes only an exclusive writable consumer's empty, inactive
// staging materialization. An error preserves that same partial staging and
// original shared consumer; its controller must not publish Ready or silently
// overwrite/reset it. This never writes into the original source volume.
func (m *NativeManager) RestoreCold(ctx context.Context, ready NativeReady, c Consumer, authorize ColdAuthority, in *os.File, receipt ArchiveReceipt, o ArchiveOptions) (err error) {
	if authorize == nil || !receipt.valid(o) {
		return ErrNativeVolume
	}
	if _, err = coldFile(in, false); err != nil {
		return err
	}
	if err = authorize(ctx, ready, c); err != nil {
		return err
	}
	guard := m.declaration(NativeKey(ready.Spec))
	guard.Lock()
	defer guard.Unlock()
	root, err := m.coldRoot(ctx, ready, c, o, true, false)
	if err != nil {
		return err
	}
	pin, err := m.journal.Borrow(NativeKey(ready.Spec), coldPinName(c), ready.Generation)
	if err != nil {
		_ = root.Close()
		return err
	}
	lease := NativeLease{Key: NativeKey(ready.Spec), Consumer: coldPinName(c), Owner: ready.Owner, Scope: ready.Spec.Scope, Pin: pin}
	defer func() { err = errors.Join(err, m.Return(lease)) }()
	defer root.Close()
	directory, err := root.Open(".")
	if err != nil {
		return ErrArchive
	}
	// Space for logical file bytes plus per-entry block/metadata allowance is
	// observed, never claimed as an enforced filesystem quota or reservation.
	need := receipt.DataBytes + uint64(receipt.Entries)*8192
	err = coldSpace(directory, need)
	_ = directory.Close()
	if err != nil {
		return err
	}
	if err = restoreArchive(ctx, root, in, receipt, o, m.archiveIO); err != nil {
		return err
	}
	return authorize(ctx, ready, c)
}

// CheckColdReleased observes the exact named staging pin after positive restore
// verification. Other pins may belong to the now-running target and are kept.
// No cold-root open, native mutation, reference return, or data scan occurs.
func (m *NativeManager) CheckColdReleased(ready NativeReady, c Consumer) error {
	if ready.Verify() != nil || !validConsumer(c, ready.Spec.Scope) || c.Owner != ready.Owner {
		return ErrNativeVolume
	}
	guard := m.declaration(NativeKey(ready.Spec))
	guard.Lock()
	defer guard.Unlock()
	row, err := m.journal.Read(NativeKey(ready.Spec))
	raw, e := json.Marshal(ready.Spec)
	if err != nil || e != nil || row.State.Pending != nil || !row.State.Applied.Present || row.State.Applied != row.State.Desired.Resource || row.State.Applied.Generation != ready.Generation || row.State.Applied.Spec != string(raw) {
		return ErrNativeVolume
	}
	if _, found := row.Consumers[coldPinName(c)]; found {
		return reconcile.ErrLease
	}
	return nil
}
