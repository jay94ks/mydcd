// SPDX-License-Identifier: Apache-2.0

package fuse

import (
	"context"
	"sort"
	"sync"
	"syscall"
	"time"
)

// memFS is a small in-memory FileSystem for driver tests.
type memFS struct {
	Unsupported
	mu     sync.Mutex
	nodes  map[uint64]*memNode
	next   uint64
	locks  []memLock
	wake   chan struct{}
	forgot map[uint64]uint64
}

type memNode struct {
	ino      uint64
	mode     uint32
	data     []byte
	target   string
	children map[string]uint64
	nlink    uint32
	mtime    time.Time
}

type memLock struct {
	node, owner uint64
	start, end  uint64
	write       bool
	flock       bool
}

func newMemFS() *memFS {
	now := time.Now()
	return &memFS{
		nodes:  map[uint64]*memNode{RootID: {ino: RootID, mode: syscall.S_IFDIR | 0o777, children: map[string]uint64{}, nlink: 2, mtime: now}},
		next:   RootID + 1,
		wake:   make(chan struct{}),
		forgot: map[uint64]uint64{},
	}
}

func (f *memFS) attr(n *memNode) Attr {
	return Attr{Ino: n.ino, Size: uint64(len(n.data)) + uint64(len(n.target)), Blocks: (uint64(len(n.data)) + 511) / 512, Mode: n.mode, Nlink: n.nlink, Atime: n.mtime, Mtime: n.mtime, Ctime: n.mtime, Blksize: 4096}
}

func (f *memFS) entry(n *memNode) Entry {
	return Entry{Node: n.ino, Generation: 1, EntryValid: time.Second, AttrValid: time.Second, Attr: f.attr(n)}
}

func (f *memFS) dir(id uint64) (*memNode, error) {
	n := f.nodes[id]
	if n == nil {
		return nil, syscall.ENOENT
	}
	if n.mode&syscall.S_IFMT != syscall.S_IFDIR {
		return nil, syscall.ENOTDIR
	}
	return n, nil
}

func (f *memFS) add(parent uint64, name string, mode uint32) (*memNode, error) {
	p, err := f.dir(parent)
	if err != nil {
		return nil, err
	}
	if _, ok := p.children[name]; ok {
		return nil, syscall.EEXIST
	}
	n := &memNode{ino: f.next, mode: mode, nlink: 1, mtime: time.Now()}
	if mode&syscall.S_IFMT == syscall.S_IFDIR {
		n.children = map[string]uint64{}
		n.nlink = 2
	}
	f.next++
	f.nodes[n.ino] = n
	p.children[name] = n.ino
	return n, nil
}

func (f *memFS) Lookup(_ context.Context, _ Caller, parent uint64, name string) (Entry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, err := f.dir(parent)
	if err != nil {
		return Entry{}, err
	}
	id, ok := p.children[name]
	if !ok {
		return Entry{}, syscall.ENOENT
	}
	return f.entry(f.nodes[id]), nil
}

func (f *memFS) Forget(node, n uint64) {
	f.mu.Lock()
	f.forgot[node] += n
	f.mu.Unlock()
}

func (f *memFS) GetAttr(_ context.Context, _ Caller, node, _ uint64, _ bool) (AttrReply, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := f.nodes[node]
	if n == nil {
		return AttrReply{}, syscall.ENOENT
	}
	return AttrReply{Attr: f.attr(n), Valid: time.Second}, nil
}

func (f *memFS) SetAttr(_ context.Context, _ Caller, node uint64, in SetAttrIn) (AttrReply, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := f.nodes[node]
	if n == nil {
		return AttrReply{}, syscall.ENOENT
	}
	if in.Valid&SetSize != 0 {
		if in.Size <= uint64(len(n.data)) {
			n.data = n.data[:in.Size]
		} else {
			n.data = append(n.data, make([]byte, in.Size-uint64(len(n.data)))...)
		}
	}
	if in.Valid&SetMode != 0 {
		n.mode = n.mode&syscall.S_IFMT | in.Mode&^syscall.S_IFMT
	}
	n.mtime = time.Now()
	return AttrReply{Attr: f.attr(n), Valid: time.Second}, nil
}

func (f *memFS) Readlink(_ context.Context, _ Caller, node uint64) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := f.nodes[node]
	if n == nil || n.mode&syscall.S_IFMT != syscall.S_IFLNK {
		return "", syscall.EINVAL
	}
	return n.target, nil
}

func (f *memFS) Symlink(_ context.Context, _ Caller, parent uint64, name, target string) (Entry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, err := f.add(parent, name, syscall.S_IFLNK|0o777)
	if err != nil {
		return Entry{}, err
	}
	n.target = target
	return f.entry(n), nil
}

func (f *memFS) Mkdir(_ context.Context, _ Caller, parent uint64, name string, mode, umask uint32) (Entry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, err := f.add(parent, name, syscall.S_IFDIR|mode&^umask&0o7777)
	if err != nil {
		return Entry{}, err
	}
	return f.entry(n), nil
}

func (f *memFS) remove(parent uint64, name string, dir bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, err := f.dir(parent)
	if err != nil {
		return err
	}
	id, ok := p.children[name]
	if !ok {
		return syscall.ENOENT
	}
	n := f.nodes[id]
	isDir := n.mode&syscall.S_IFMT == syscall.S_IFDIR
	switch {
	case dir && !isDir:
		return syscall.ENOTDIR
	case !dir && isDir:
		return syscall.EISDIR
	case dir && len(n.children) > 0:
		return syscall.ENOTEMPTY
	}
	delete(p.children, name)
	n.nlink--
	return nil
}

func (f *memFS) Unlink(_ context.Context, _ Caller, parent uint64, name string) error {
	return f.remove(parent, name, false)
}
func (f *memFS) Rmdir(_ context.Context, _ Caller, parent uint64, name string) error {
	return f.remove(parent, name, true)
}

func (f *memFS) Rename(_ context.Context, _ Caller, parent uint64, name string, newParent uint64, newName string, flags uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if flags != 0 {
		return syscall.EINVAL
	}
	p, err := f.dir(parent)
	if err != nil {
		return err
	}
	q, err := f.dir(newParent)
	if err != nil {
		return err
	}
	id, ok := p.children[name]
	if !ok {
		return syscall.ENOENT
	}
	delete(p.children, name)
	q.children[newName] = id
	return nil
}

func (f *memFS) Open(_ context.Context, _ Caller, node uint64, flags uint32) (OpenReply, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := f.nodes[node]
	if n == nil {
		return OpenReply{}, syscall.ENOENT
	}
	if flags&syscall.O_TRUNC != 0 {
		n.data = nil
	}
	return OpenReply{FH: node}, nil
}

func (f *memFS) Create(_ context.Context, _ Caller, parent uint64, name string, _, mode, umask uint32) (Entry, OpenReply, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, err := f.add(parent, name, syscall.S_IFREG|mode&^umask&0o7777)
	if err != nil {
		return Entry{}, OpenReply{}, err
	}
	return f.entry(n), OpenReply{FH: n.ino}, nil
}

func (f *memFS) Read(_ context.Context, _ Caller, node, _, off uint64, size uint32) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := f.nodes[node]
	if n == nil {
		return nil, syscall.EBADF
	}
	if off >= uint64(len(n.data)) {
		return nil, nil
	}
	end := min(off+uint64(size), uint64(len(n.data)))
	return append([]byte(nil), n.data[off:end]...), nil
}

func (f *memFS) Write(_ context.Context, _ Caller, node, _, off uint64, data []byte) (uint32, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := f.nodes[node]
	if n == nil {
		return 0, syscall.EBADF
	}
	if end := off + uint64(len(data)); end > uint64(len(n.data)) {
		n.data = append(n.data, make([]byte, end-uint64(len(n.data)))...)
	}
	copy(n.data[off:], data)
	n.mtime = time.Now()
	return uint32(len(data)), nil
}

func (f *memFS) Flush(context.Context, Caller, uint64, uint64, uint64) error { return nil }

func (f *memFS) Release(node, _ uint64, _ uint32, owner uint64, flock bool) {
	if flock {
		f.mu.Lock()
		f.unlock(node, owner, true, 0, ^uint64(0))
		f.mu.Unlock()
	}
}

func (f *memFS) Fsync(context.Context, Caller, uint64, uint64, bool) error { return nil }

func (f *memFS) OpenDir(_ context.Context, _ Caller, node uint64, _ uint32) (OpenReply, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := f.dir(node); err != nil {
		return OpenReply{}, err
	}
	return OpenReply{FH: node}, nil
}

func (f *memFS) ReadDir(_ context.Context, _ Caller, node, _, off uint64) ([]DirEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, err := f.dir(node)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(d.children))
	for name := range d.children {
		names = append(names, name)
	}
	sort.Strings(names)
	all := []DirEntry{{Ino: node, Type: syscall.DT_DIR, Name: "."}, {Ino: RootID, Type: syscall.DT_DIR, Name: ".."}}
	for _, name := range names {
		n := f.nodes[d.children[name]]
		all = append(all, DirEntry{Ino: n.ino, Type: (n.mode & syscall.S_IFMT) >> 12, Name: name})
	}
	for i := range all {
		all[i].Off = uint64(i + 1)
	}
	if off >= uint64(len(all)) {
		return nil, nil
	}
	return all[off:], nil
}

func (f *memFS) StatFs(context.Context, Caller, uint64) (StatFs, error) {
	return StatFs{Blocks: 1000, Bfree: 500, Bavail: 400, Files: 100, Ffree: 50, Bsize: 4096, Namelen: 255, Frsize: 4096}, nil
}

func (f *memFS) conflict(node, owner uint64, l Lock, flock bool) *memLock {
	for i := range f.locks {
		h := &f.locks[i]
		if h.node == node && h.owner != owner && h.flock == flock && h.start <= l.End && l.Start <= h.end && (h.write || l.Type == syscall.F_WRLCK) {
			return h
		}
	}
	return nil
}

func (f *memFS) unlock(node, owner uint64, flock bool, start, end uint64) {
	kept := f.locks[:0]
	for _, h := range f.locks {
		if !(h.node == node && h.owner == owner && h.flock == flock && h.start <= end && start <= h.end) {
			kept = append(kept, h)
		}
	}
	f.locks = kept
	close(f.wake)
	f.wake = make(chan struct{})
}

func (f *memFS) GetLk(_ context.Context, _ Caller, node, _, owner uint64, l Lock, flock bool) (Lock, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if h := f.conflict(node, owner, l, flock); h != nil {
		t := uint32(syscall.F_RDLCK)
		if h.write {
			t = syscall.F_WRLCK
		}
		return Lock{Start: h.start, End: h.end, Type: t}, nil
	}
	return Lock{Type: syscall.F_UNLCK}, nil
}

func (f *memFS) SetLk(ctx context.Context, _ Caller, node, _, owner uint64, l Lock, wait, flock bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if flock {
		l.Start, l.End = 0, ^uint64(0)
	}
	if l.Type == syscall.F_UNLCK {
		f.unlock(node, owner, flock, l.Start, l.End)
		return nil
	}
	for f.conflict(node, owner, l, flock) != nil {
		if !wait {
			return syscall.EAGAIN
		}
		w := f.wake
		f.mu.Unlock()
		select {
		case <-w:
		case <-ctx.Done():
			f.mu.Lock()
			return syscall.EINTR
		}
		f.mu.Lock()
	}
	if flock {
		f.unlock(node, owner, true, 0, ^uint64(0))
	}
	f.locks = append(f.locks, memLock{node: node, owner: owner, start: l.Start, end: l.End, write: l.Type == syscall.F_WRLCK, flock: flock})
	return nil
}
