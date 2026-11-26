// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/moby/moby/client"
	"golang.org/x/sys/unix"
)

// DataDirectory is a node-local held native directory for an embedded consumer.
// It creates no container/mount and grants no shared writer. Return the original
// native lease only after this handle and all of its consumer I/O have closed.
type DataDirectory struct {
	Root     *os.Root
	path     string
	info     os.FileInfo
	hold     io.Closer
	closed   bool
	closeErr error
}

func (d *DataDirectory) Path() string { return d.path }
func (d *DataDirectory) Check() error {
	if d == nil || d.Root == nil {
		return ErrNativeVolume
	}
	current, err := os.Lstat(d.path)
	if err != nil || !os.SameFile(current, d.info) {
		return ErrNativeVolume
	}
	f, err := d.Root.Open(".")
	if err != nil {
		return err
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil || !os.SameFile(actual, d.info) {
		return ErrNativeVolume
	}
	return nil
}
func (d *DataDirectory) Close() error {
	if d.closed {
		return d.closeErr
	}
	d.closed = true
	var err error
	if d.Root != nil {
		err = d.Root.Close()
		d.Root = nil
	}
	if d.hold != nil {
		err = errors.Join(err, d.hold.Close())
		d.hold = nil
	}
	d.closeErr = err
	return err
}

// OpenDataDirectory consumes only a lease already present in the native
// journal and checks the exact native owner. A caller-supplied path is never
// accepted. Fixed data keeps its existing bound inode/root policy checks.
func (m *NativeManager) OpenDataDirectory(ctx context.Context, l NativeLease) (result *DataDirectory, err error) {
	row, err := m.View(l.Key)
	if err != nil || row.Consumers[l.Consumer] != l.Pin {
		return nil, ErrNativeVolume
	}
	owner, scope, err := m.Owner(ctx, l.Key)
	if err != nil || owner != l.Owner || scope != l.Scope {
		return nil, ErrNativeVolume
	}
	var path string
	var held io.Closer
	var fixedStat *unix.Stat_t
	if fixedNativeKey(l.Key) {
		if m.fixed == nil {
			return nil, ErrNativeVolume
		}
		p, h, e := m.fixed.BindSource(ctx, l)
		if e != nil {
			return nil, e
		}
		path, held = p, h
		st := &unix.Stat_t{}
		if e = unix.Fstat(h.FD(), st); e != nil {
			_ = h.Close()
			return nil, e
		}
		fixedStat = st
	} else {
		got, e := m.driver.engine.API.VolumeInspect(ctx, owner.Native, client.VolumeInspectOptions{})
		if e != nil {
			return nil, e
		}
		spec, id, e := m.driver.parameters(l.Key, reconcile.Operation{Kind: reconcile.Apply, Target: row.State.Applied})
		if e != nil || spec.Scope != scope || !matchNative(got.Volume, id) {
			return nil, ErrNativeVolume
		}
		path = got.Volume.Mountpoint
	}
	ok := false
	defer func() {
		if !ok && held != nil {
			_ = held.Close()
		}
	}()
	canonical, e := filepath.EvalSymlinks(path)
	if e != nil || canonical != path {
		return nil, ErrNativeVolume
	}
	info, e := os.Lstat(path)
	if e != nil || !info.IsDir() {
		return nil, ErrNativeVolume
	}
	if fixedStat != nil {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Dev != uint64(fixedStat.Dev) || st.Ino != fixedStat.Ino {
			return nil, ErrNativeVolume
		}
	}
	root, e := os.OpenRoot(path)
	if e != nil {
		return nil, e
	}
	d := &DataDirectory{Root: root, path: path, info: info, hold: held}
	if e = d.Check(); e != nil {
		_ = root.Close()
		return nil, e
	}
	ok = true
	return d, nil
}
