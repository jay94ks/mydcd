// SPDX-License-Identifier: Apache-2.0

// Package mount is the mount front-end: it serves a shared Volume's Ops as
// a FUSE file system that a container gets as an ordinary directory.
package mount

import (
	"context"
	"sync"
	"syscall"
	"time"

	"github.com/jay94ks/seafield/internal/volumeshare"
	"github.com/jay94ks/seafield/internal/volumeshare/fuse"
)

// Options tunes caching. A writer that is the only writer of the Volume
// may cache long; readers and shared writers keep it short so changes made
// on other servers show up (close-to-open).
type Options struct {
	Session  uint64 // lock and open-file scope on the home
	EntryTTL time.Duration
	AttrTTL  time.Duration
	// KeepCache keeps page cache across opens (only safe for the only writer).
	KeepCache bool
	// DirectIO bypasses the page cache (shared writers, no shared mmap).
	DirectIO bool
	// ReadDirBatch is how many rows one home call returns.
	ReadDirBatch int
	// Nodes, when set, records every change of the node table (under the
	// table lock, in order) so a restarted server can resume the mount.
	Nodes Nodes
	// Restore is the node table a resumed mount starts from.
	Restore []Node
}

// Node is one kernel node ID the mount answers for.
type Node struct {
	ID, Ino, Refs uint64
	Handle        volumeshare.Handle
}

// Nodes keeps the node table outside the process (remote's memfd log).
type Nodes interface {
	Put(Node)
	Drop(id uint64)
}

// FS adapts Ops to fuse.FileSystem.
type FS struct {
	fuse.Unsupported
	ops volumeshare.Ops
	o   Options

	mu    sync.Mutex
	next  uint64
	nodes map[uint64]*node // FUSE node ID → node
	byIno map[uint64]uint64
}

type node struct {
	handle volumeshare.Handle
	ino    uint64
	refs   uint64
}

// New serves ops. The root is FUSE node 1.
func New(ops volumeshare.Ops, o Options) *FS {
	if o.ReadDirBatch <= 0 {
		o.ReadDirBatch = 256
	}
	f := &FS{ops: ops, o: o, next: fuse.RootID + 1, nodes: map[uint64]*node{}, byIno: map[uint64]uint64{}}
	f.nodes[fuse.RootID] = &node{handle: ops.Root(), refs: 1}
	for _, n := range o.Restore {
		if n.ID <= fuse.RootID || n.Refs == 0 {
			continue
		}
		f.nodes[n.ID] = &node{handle: n.Handle, ino: n.Ino, refs: n.Refs}
		f.byIno[n.Ino] = n.ID
		if n.ID >= f.next {
			f.next = n.ID + 1
		}
	}
	return f
}

func (f *FS) handle(id uint64) (volumeshare.Handle, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if n := f.nodes[id]; n != nil {
		return n.handle, nil
	}
	return nil, syscall.ESTALE
}

func attr(a volumeshare.Attr) fuse.Attr {
	return fuse.Attr{Ino: a.Ino, Size: a.Size, Blocks: a.Blocks, Atime: a.Atime, Mtime: a.Mtime, Ctime: a.Ctime, Mode: a.Mode, Nlink: a.Nlink, UID: a.UID, GID: a.GID, Rdev: a.Rdev, Blksize: a.Blksize}
}

// remember adds one kernel lookup reference for e and returns its node ID.
func (f *FS) remember(e volumeshare.Entry) fuse.Entry {
	f.mu.Lock()
	id, ok := f.byIno[e.Attr.Ino]
	if ok {
		n := f.nodes[id]
		n.refs++
		n.handle = e.Handle
	} else {
		id = f.next
		f.next++
		f.nodes[id] = &node{handle: e.Handle, ino: e.Attr.Ino, refs: 1}
		f.byIno[e.Attr.Ino] = id
	}
	if f.o.Nodes != nil {
		n := f.nodes[id]
		f.o.Nodes.Put(Node{ID: id, Ino: n.ino, Refs: n.refs, Handle: n.handle})
	}
	f.mu.Unlock()
	return fuse.Entry{Node: id, Generation: 1, EntryValid: f.o.EntryTTL, AttrValid: f.o.AttrTTL, Attr: attr(e.Attr)}
}

func (f *FS) Forget(id, n uint64) {
	if id == fuse.RootID {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	x := f.nodes[id]
	if x == nil {
		return
	}
	if x.refs <= n {
		delete(f.nodes, id)
		delete(f.byIno, x.ino)
		if f.o.Nodes != nil {
			f.o.Nodes.Drop(id)
		}
		return
	}
	x.refs -= n
	if f.o.Nodes != nil {
		f.o.Nodes.Put(Node{ID: id, Ino: x.ino, Refs: x.refs, Handle: x.handle})
	}
}

func who(c fuse.Caller) volumeshare.Caller { return volumeshare.Caller{UID: c.UID, GID: c.GID} }

func (f *FS) Lookup(ctx context.Context, _ fuse.Caller, parent uint64, name string) (fuse.Entry, error) {
	h, err := f.handle(parent)
	if err != nil {
		return fuse.Entry{}, err
	}
	e, err := f.ops.Lookup(ctx, h, name)
	if err != nil {
		return fuse.Entry{}, err
	}
	return f.remember(e), nil
}

func (f *FS) GetAttr(ctx context.Context, _ fuse.Caller, id, _ uint64, _ bool) (fuse.AttrReply, error) {
	h, err := f.handle(id)
	if err != nil {
		return fuse.AttrReply{}, err
	}
	a, err := f.ops.GetAttr(ctx, h)
	if err != nil {
		return fuse.AttrReply{}, err
	}
	return fuse.AttrReply{Attr: attr(a), Valid: f.o.AttrTTL}, nil
}

func (f *FS) SetAttr(ctx context.Context, c fuse.Caller, id uint64, in fuse.SetAttrIn) (fuse.AttrReply, error) {
	h, err := f.handle(id)
	if err != nil {
		return fuse.AttrReply{}, err
	}
	a, err := f.ops.SetAttr(ctx, who(c), h, volumeshare.SetAttr{Valid: in.Valid, Size: in.Size, Mode: in.Mode, UID: in.UID, GID: in.GID, Atime: in.Atime, Mtime: in.Mtime, File: volumeshare.FileID(in.FH)})
	if err != nil {
		return fuse.AttrReply{}, err
	}
	return fuse.AttrReply{Attr: attr(a), Valid: f.o.AttrTTL}, nil
}

func (f *FS) Readlink(ctx context.Context, _ fuse.Caller, id uint64) (string, error) {
	h, err := f.handle(id)
	if err != nil {
		return "", err
	}
	return f.ops.Readlink(ctx, h)
}

func (f *FS) Symlink(ctx context.Context, c fuse.Caller, parent uint64, name, target string) (fuse.Entry, error) {
	h, err := f.handle(parent)
	if err != nil {
		return fuse.Entry{}, err
	}
	e, err := f.ops.Symlink(ctx, who(c), h, name, target)
	if err != nil {
		return fuse.Entry{}, err
	}
	return f.remember(e), nil
}

func (f *FS) Mkdir(ctx context.Context, c fuse.Caller, parent uint64, name string, mode, umask uint32) (fuse.Entry, error) {
	h, err := f.handle(parent)
	if err != nil {
		return fuse.Entry{}, err
	}
	e, err := f.ops.Mkdir(ctx, who(c), h, name, mode&^umask)
	if err != nil {
		return fuse.Entry{}, err
	}
	return f.remember(e), nil
}

func (f *FS) Unlink(ctx context.Context, _ fuse.Caller, parent uint64, name string) error {
	h, err := f.handle(parent)
	if err != nil {
		return err
	}
	return f.ops.Unlink(ctx, h, name)
}

func (f *FS) Rmdir(ctx context.Context, _ fuse.Caller, parent uint64, name string) error {
	h, err := f.handle(parent)
	if err != nil {
		return err
	}
	return f.ops.Rmdir(ctx, h, name)
}

func (f *FS) Rename(ctx context.Context, _ fuse.Caller, parent uint64, name string, newParent uint64, newName string, flags uint32) error {
	h, err := f.handle(parent)
	if err != nil {
		return err
	}
	nh, err := f.handle(newParent)
	if err != nil {
		return err
	}
	return f.ops.Rename(ctx, h, name, nh, newName, flags)
}

func (f *FS) Link(ctx context.Context, _ fuse.Caller, id, newParent uint64, newName string) (fuse.Entry, error) {
	h, err := f.handle(id)
	if err != nil {
		return fuse.Entry{}, err
	}
	nh, err := f.handle(newParent)
	if err != nil {
		return fuse.Entry{}, err
	}
	e, err := f.ops.Link(ctx, h, nh, newName)
	if err != nil {
		return fuse.Entry{}, err
	}
	return f.remember(e), nil
}

func (f *FS) openFlags() uint32 {
	var fl uint32
	if f.o.KeepCache {
		fl |= fuse.OpenKeepCache
	}
	if f.o.DirectIO {
		fl |= fuse.OpenDirectIO
	}
	return fl
}

func (f *FS) Open(ctx context.Context, _ fuse.Caller, id uint64, flags uint32) (fuse.OpenReply, error) {
	h, err := f.handle(id)
	if err != nil {
		return fuse.OpenReply{}, err
	}
	fid, err := f.ops.Open(ctx, f.o.Session, h, flags)
	if err != nil {
		return fuse.OpenReply{}, err
	}
	return fuse.OpenReply{FH: uint64(fid), Flags: f.openFlags()}, nil
}

func (f *FS) Create(ctx context.Context, c fuse.Caller, parent uint64, name string, flags, mode, umask uint32) (fuse.Entry, fuse.OpenReply, error) {
	h, err := f.handle(parent)
	if err != nil {
		return fuse.Entry{}, fuse.OpenReply{}, err
	}
	e, fid, err := f.ops.Create(ctx, f.o.Session, who(c), h, name, flags, mode&^umask)
	if err != nil {
		return fuse.Entry{}, fuse.OpenReply{}, err
	}
	return f.remember(e), fuse.OpenReply{FH: uint64(fid), Flags: f.openFlags()}, nil
}

func (f *FS) Read(ctx context.Context, _ fuse.Caller, _, fh, off uint64, size uint32) ([]byte, error) {
	return f.ops.Read(ctx, volumeshare.FileID(fh), off, size)
}

func (f *FS) Write(ctx context.Context, _ fuse.Caller, _, fh, off uint64, data []byte) (uint32, error) {
	return f.ops.Write(ctx, volumeshare.FileID(fh), off, data)
}

// Flush is a close(2) of one descriptor: POSIX locks of that owner end.
func (f *FS) Flush(ctx context.Context, _ fuse.Caller, _, fh, owner uint64) error {
	return f.ops.SetLk(ctx, volumeshare.FileID(fh), owner, volumeshare.Lock{Start: 0, End: ^uint64(0), Type: syscall.F_UNLCK}, false, false)
}

func (f *FS) Release(_, fh uint64, _ uint32, owner uint64, flock bool) {
	if flock {
		_ = f.ops.ReleaseOwner(volumeshare.FileID(fh), owner)
	}
	_ = f.ops.Close(volumeshare.FileID(fh))
}

func (f *FS) Fsync(ctx context.Context, _ fuse.Caller, _, fh uint64, datasync bool) error {
	return f.ops.Fsync(ctx, volumeshare.FileID(fh), datasync)
}

func (f *FS) OpenDir(ctx context.Context, _ fuse.Caller, id uint64, _ uint32) (fuse.OpenReply, error) {
	if _, err := f.handle(id); err != nil {
		return fuse.OpenReply{}, err
	}
	return fuse.OpenReply{}, nil
}

func (f *FS) ReleaseDir(uint64, uint64) {}

func (f *FS) FsyncDir(context.Context, fuse.Caller, uint64, uint64, bool) error { return nil }

// Directory offsets: 1 is after ".", 2 after "..", and a home cookie c is
// c+3, so small cookies (tmpfs starts at 2) never collide with the dots.
func (f *FS) ReadDir(ctx context.Context, _ fuse.Caller, id, _, off uint64) ([]fuse.DirEntry, error) {
	h, err := f.handle(id)
	if err != nil {
		return nil, err
	}
	var out []fuse.DirEntry
	if off == 0 {
		out = append(out, fuse.DirEntry{Ino: 1, Off: 1, Type: syscall.DT_DIR, Name: "."})
	}
	if off <= 1 {
		out = append(out, fuse.DirEntry{Ino: 1, Off: 2, Type: syscall.DT_DIR, Name: ".."})
	}
	var cookie uint64
	if off >= 3 {
		cookie = off - 3
	}
	rows, err := f.ops.ReadDir(ctx, h, cookie, f.o.ReadDirBatch)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		out = append(out, fuse.DirEntry{Ino: r.Ino, Off: r.Cookie + 3, Type: r.Type, Name: r.Name})
	}
	return out, nil
}

func (f *FS) StatFs(ctx context.Context, _ fuse.Caller, _ uint64) (fuse.StatFs, error) {
	s, err := f.ops.StatFs(ctx)
	if err != nil {
		return fuse.StatFs{}, err
	}
	return fuse.StatFs{Blocks: s.Blocks, Bfree: s.Bfree, Bavail: s.Bavail, Files: s.Files, Ffree: s.Ffree, Bsize: s.Bsize, Namelen: s.Namelen, Frsize: s.Frsize}, nil
}

func (f *FS) GetLk(ctx context.Context, _ fuse.Caller, _, fh, owner uint64, l fuse.Lock, flock bool) (fuse.Lock, error) {
	got, err := f.ops.GetLk(ctx, volumeshare.FileID(fh), owner, volumeshare.Lock{Start: l.Start, End: l.End, Type: l.Type, PID: l.PID}, flock)
	if err != nil {
		return fuse.Lock{}, err
	}
	return fuse.Lock{Start: got.Start, End: got.End, Type: got.Type, PID: got.PID}, nil
}

func (f *FS) SetLk(ctx context.Context, _ fuse.Caller, _, fh, owner uint64, l fuse.Lock, wait, flock bool) error {
	return f.ops.SetLk(ctx, volumeshare.FileID(fh), owner, volumeshare.Lock{Start: l.Start, End: l.End, Type: l.Type, PID: l.PID}, wait, flock)
}

var _ fuse.FileSystem = (*FS)(nil)
