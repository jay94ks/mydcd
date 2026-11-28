// SPDX-License-Identifier: Apache-2.0

package diskfs

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/jay94ks/seafield/internal/schema"
)

type diskNode struct {
	fs.Inode
	d *Disk
}

var (
	_ = (fs.NodeGetattrer)((*diskNode)(nil))
	_ = (fs.NodeSetattrer)((*diskNode)(nil))
	_ = (fs.NodeOpener)((*diskNode)(nil))
	_ = (fs.NodeReader)((*diskNode)(nil))
	_ = (fs.NodeWriter)((*diskNode)(nil))
	_ = (fs.NodeFsyncer)((*diskNode)(nil))
	_ = (fs.NodeFlusher)((*diskNode)(nil))
)

func (n *diskNode) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	out.Mode = syscall.S_IFREG | 0o600
	out.Size = n.d.Size()
	out.Blocks = (n.d.Size() + 511) / 512
	return 0
}

// Setattr accepts what the loop driver and tools send but never resizes.
func (n *diskNode) Setattr(ctx context.Context, fh fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if size, ok := in.GetSize(); ok && size != n.d.Size() {
		return syscall.EPERM
	}
	return n.Getattr(ctx, fh, out)
}

func (n *diskNode) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	return nil, 0, 0
}

func (n *diskNode) Read(ctx context.Context, fh fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	size := int64(n.d.Size())
	if off >= size {
		return fuse.ReadResultData(nil), 0
	}
	dest = dest[:min(int64(len(dest)), size-off)]
	if _, err := n.d.ReadAt(dest, off); err != nil {
		return nil, syscall.EIO
	}
	return fuse.ReadResultData(dest), 0
}

func (n *diskNode) Write(ctx context.Context, fh fs.FileHandle, data []byte, off int64) (uint32, syscall.Errno) {
	if off < 0 || uint64(off)+uint64(len(data)) > n.d.Size() {
		return 0, syscall.ENOSPC
	}
	if _, err := n.d.WriteAt(data, off); err != nil {
		return 0, syscall.EIO
	}
	return uint32(len(data)), 0
}

func (n *diskNode) Fsync(ctx context.Context, fh fs.FileHandle, flags uint32) syscall.Errno {
	if n.d.Sync() != nil {
		return syscall.EIO
	}
	return 0
}

func (n *diskNode) Flush(ctx context.Context, fh fs.FileHandle) syscall.Errno {
	return n.Fsync(ctx, fh, 0)
}

// Paths of one bundle's run directory.
func MountDir(bundle string) string   { return filepath.Join(RunDir, bundle, "mnt") }
func DiskFile(bundle string) string   { return filepath.Join(MountDir(bundle), "disk") }
func StatusFile(bundle string) string { return filepath.Join(RunDir, bundle, "status.json") }

// Mount serves d at dir (file "disk"). The caller unmounts the server.
func Mount(dir string, d *Disk) (*fuse.Server, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	root := &fs.Inode{}
	opts := &fs.Options{
		FirstAutomaticIno: 1,
		OnAdd: func(ctx context.Context) {
			n := root.EmbeddedInode()
			n.AddChild("disk", n.NewPersistentInode(ctx, &diskNode{d: d}, fs.StableAttr{Mode: syscall.S_IFREG}), false)
		},
		MountOptions: fuse.MountOptions{FsName: "sfc-diskfs", Name: "sfcdiskfs", MaxWrite: 1 << 20, DisableXAttrs: true, DirectMount: os.Geteuid() == 0},
	}
	return fs.Mount(dir, root, opts)
}

// Serve is `sfcd diskfs serve SPEC`: it opens the bundle, mounts it,
// resyncs mirror copies that are back, keeps status.json current and
// unmounts on SIGTERM.
func Serve(specPath string) error {
	raw, err := os.ReadFile(specPath)
	if err != nil {
		return err
	}
	spec, err := schema.Decode[Spec](raw)
	if err != nil || !spec.Valid() {
		return errors.New("diskfs: invalid spec file")
	}
	d, err := Open(spec)
	if err != nil {
		writeStatus(spec.Bundle, Status{Bundle: spec.Bundle, State: "missing"})
		return err
	}
	defer d.Close()
	server, err := Mount(MountDir(spec.Bundle), d)
	if err != nil {
		return err
	}
	stop := make(chan struct{})
	go d.Resync(stop)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	writeStatus(spec.Bundle, d.Status())
	done := make(chan struct{})
	go func() { server.Wait(); close(done) }()
	for {
		select {
		case <-signals:
			close(stop)
			_ = d.Sync()
			err := server.Unmount()
			_ = os.Remove(StatusFile(spec.Bundle))
			return err
		case <-done:
			close(stop)
			_ = d.Sync()
			_ = os.Remove(StatusFile(spec.Bundle))
			return nil
		case <-d.changed:
		case <-tick.C:
		}
		writeStatus(spec.Bundle, d.Status())
	}
}

func writeStatus(bundle string, s Status) {
	raw, _ := json.Marshal(s)
	path := StatusFile(bundle)
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	tmp := path + ".tmp"
	if os.WriteFile(tmp, raw, 0o600) == nil {
		_ = os.Rename(tmp, path)
	}
}

// ReadStatus reads a bundle's status.json; ok is false when none is there.
func ReadStatus(bundle string) (Status, bool) {
	raw, err := os.ReadFile(StatusFile(bundle))
	if err != nil {
		return Status{}, false
	}
	s, err := schema.Decode[Status](raw)
	return s, err == nil && s.Bundle == bundle
}
