// SPDX-License-Identifier: Apache-2.0

package fuse

import (
	"context"
	"syscall"
	"time"
)

// Attr is struct fuse_attr. Mode carries the file type bits (S_IFREG …).
type Attr struct {
	Ino                 uint64
	Size, Blocks        uint64
	Atime, Mtime, Ctime time.Time
	Mode, Nlink         uint32
	UID, GID, Rdev      uint32
	Blksize             uint32
}

// AttrReply is an attribute answer and how long the kernel may cache it.
type AttrReply struct {
	Attr  Attr
	Valid time.Duration
}

// Entry is a lookup answer: the node the kernel will refer to from now on.
// Every Entry returned adds one lookup reference that a later Forget drops.
type Entry struct {
	Node, Generation      uint64
	EntryValid, AttrValid time.Duration
	Attr                  Attr
}

// DirEntry is one readdir answer. Off is the cookie of the entry that
// follows it; the kernel passes it back as the next offset.
type DirEntry struct {
	Ino  uint64
	Off  uint64
	Type uint32 // DT_* value
	Name string
}

// StatFs is struct fuse_kstatfs.
type StatFs struct {
	Blocks, Bfree, Bavail  uint64
	Files, Ffree           uint64
	Bsize, Namelen, Frsize uint32
}

// Lock is struct fuse_file_lock. Type is F_RDLCK, F_WRLCK or F_UNLCK.
type Lock struct {
	Start, End uint64
	Type, PID  uint32
}

// SetAttrIn is the SETATTR request; Valid says which fields apply.
type SetAttrIn struct {
	Valid               uint32
	FH                  uint64
	Size                uint64
	LockOwner           uint64
	Atime, Mtime, Ctime time.Time
	Mode, UID, GID      uint32
}

// Caller is who issued the request on the mounting host.
type Caller struct {
	UID, GID, PID uint32
}

// OpenReply is the answer to Open, Create and OpenDir.
type OpenReply struct {
	FH    uint64
	Flags uint32 // OpenDirectIO, OpenKeepCache
}

// FileSystem serves one mount. Methods may run concurrently. A returned
// error that is a syscall.Errno reaches the caller as that errno; any other
// error becomes EIO. ctx is cancelled when the kernel interrupts the request.
//
// Release, ReleaseDir and Forget have no caller left to answer and must not
// fail silently on transient errors: the implementation owns retrying them.
type FileSystem interface {
	Lookup(ctx context.Context, c Caller, parent uint64, name string) (Entry, error)
	Forget(node, n uint64)
	GetAttr(ctx context.Context, c Caller, node uint64, fh uint64, hasFH bool) (AttrReply, error)
	SetAttr(ctx context.Context, c Caller, node uint64, in SetAttrIn) (AttrReply, error)
	Readlink(ctx context.Context, c Caller, node uint64) (string, error)
	Symlink(ctx context.Context, c Caller, parent uint64, name, target string) (Entry, error)
	Mkdir(ctx context.Context, c Caller, parent uint64, name string, mode, umask uint32) (Entry, error)
	Unlink(ctx context.Context, c Caller, parent uint64, name string) error
	Rmdir(ctx context.Context, c Caller, parent uint64, name string) error
	Rename(ctx context.Context, c Caller, parent uint64, name string, newParent uint64, newName string, flags uint32) error
	Link(ctx context.Context, c Caller, node, newParent uint64, newName string) (Entry, error)
	Open(ctx context.Context, c Caller, node uint64, flags uint32) (OpenReply, error)
	Create(ctx context.Context, c Caller, parent uint64, name string, flags, mode, umask uint32) (Entry, OpenReply, error)
	// Read returns at most size bytes; fewer means end of file.
	Read(ctx context.Context, c Caller, node, fh, off uint64, size uint32) ([]byte, error)
	Write(ctx context.Context, c Caller, node, fh, off uint64, data []byte) (uint32, error)
	Flush(ctx context.Context, c Caller, node, fh, lockOwner uint64) error
	Release(node, fh uint64, flags uint32, lockOwner uint64, flock bool)
	Fsync(ctx context.Context, c Caller, node, fh uint64, datasync bool) error
	OpenDir(ctx context.Context, c Caller, node uint64, flags uint32) (OpenReply, error)
	// ReadDir returns entries starting at the cookie off (0 = start). The
	// driver packs as many as fit; it asks again from the last one's Off.
	ReadDir(ctx context.Context, c Caller, node, fh, off uint64) ([]DirEntry, error)
	ReleaseDir(node, fh uint64)
	FsyncDir(ctx context.Context, c Caller, node, fh uint64, datasync bool) error
	StatFs(ctx context.Context, c Caller, node uint64) (StatFs, error)
	GetLk(ctx context.Context, c Caller, node, fh, owner uint64, l Lock, flock bool) (Lock, error)
	// SetLk takes or releases a lock. wait means block until granted (or ctx
	// is cancelled, then return EINTR). flock selects flock(2) semantics.
	SetLk(ctx context.Context, c Caller, node, fh, owner uint64, l Lock, wait, flock bool) error
}

// Unsupported answers ENOSYS for every operation. Embed it to implement
// only part of FileSystem.
type Unsupported struct{}

func (Unsupported) Lookup(context.Context, Caller, uint64, string) (Entry, error) {
	return Entry{}, syscall.ENOSYS
}
func (Unsupported) Forget(uint64, uint64) {}
func (Unsupported) GetAttr(context.Context, Caller, uint64, uint64, bool) (AttrReply, error) {
	return AttrReply{}, syscall.ENOSYS
}
func (Unsupported) SetAttr(context.Context, Caller, uint64, SetAttrIn) (AttrReply, error) {
	return AttrReply{}, syscall.ENOSYS
}
func (Unsupported) Readlink(context.Context, Caller, uint64) (string, error) {
	return "", syscall.ENOSYS
}
func (Unsupported) Symlink(context.Context, Caller, uint64, string, string) (Entry, error) {
	return Entry{}, syscall.ENOSYS
}
func (Unsupported) Mkdir(context.Context, Caller, uint64, string, uint32, uint32) (Entry, error) {
	return Entry{}, syscall.ENOSYS
}
func (Unsupported) Unlink(context.Context, Caller, uint64, string) error { return syscall.ENOSYS }
func (Unsupported) Rmdir(context.Context, Caller, uint64, string) error  { return syscall.ENOSYS }
func (Unsupported) Rename(context.Context, Caller, uint64, string, uint64, string, uint32) error {
	return syscall.ENOSYS
}
func (Unsupported) Link(context.Context, Caller, uint64, uint64, string) (Entry, error) {
	return Entry{}, syscall.ENOSYS
}
func (Unsupported) Open(context.Context, Caller, uint64, uint32) (OpenReply, error) {
	return OpenReply{}, syscall.ENOSYS
}
func (Unsupported) Create(context.Context, Caller, uint64, string, uint32, uint32, uint32) (Entry, OpenReply, error) {
	return Entry{}, OpenReply{}, syscall.ENOSYS
}
func (Unsupported) Read(context.Context, Caller, uint64, uint64, uint64, uint32) ([]byte, error) {
	return nil, syscall.ENOSYS
}
func (Unsupported) Write(context.Context, Caller, uint64, uint64, uint64, []byte) (uint32, error) {
	return 0, syscall.ENOSYS
}
func (Unsupported) Flush(context.Context, Caller, uint64, uint64, uint64) error {
	return syscall.ENOSYS
}
func (Unsupported) Release(uint64, uint64, uint32, uint64, bool)              {}
func (Unsupported) Fsync(context.Context, Caller, uint64, uint64, bool) error { return syscall.ENOSYS }
func (Unsupported) OpenDir(context.Context, Caller, uint64, uint32) (OpenReply, error) {
	return OpenReply{}, syscall.ENOSYS
}
func (Unsupported) ReadDir(context.Context, Caller, uint64, uint64, uint64) ([]DirEntry, error) {
	return nil, syscall.ENOSYS
}
func (Unsupported) ReleaseDir(uint64, uint64) {}
func (Unsupported) FsyncDir(context.Context, Caller, uint64, uint64, bool) error {
	return syscall.ENOSYS
}
func (Unsupported) StatFs(context.Context, Caller, uint64) (StatFs, error) {
	return StatFs{}, syscall.ENOSYS
}
func (Unsupported) GetLk(context.Context, Caller, uint64, uint64, uint64, Lock, bool) (Lock, error) {
	return Lock{}, syscall.ENOSYS
}
func (Unsupported) SetLk(context.Context, Caller, uint64, uint64, uint64, Lock, bool, bool) error {
	return syscall.ENOSYS
}

func split(t time.Time) (uint64, uint32) {
	if t.IsZero() {
		return 0, 0
	}
	return uint64(t.Unix()), uint32(t.Nanosecond())
}

func seconds(d time.Duration) (uint64, uint32) {
	if d <= 0 {
		return 0, 0
	}
	return uint64(d / time.Second), uint32(d % time.Second)
}

func unixTime(s uint64, n uint32) time.Time {
	return time.Unix(int64(s), int64(n))
}
