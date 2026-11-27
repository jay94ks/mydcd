// SPDX-License-Identifier: Apache-2.0

// Package volumeshare shares one Volume between servers. The data stays in
// one place (the home); every other server reaches it through Ops. The home
// side implements Ops on its local directory (back/localroot); a consuming
// server implements Ops over SFCP VolumeFS; front-ends (front/mount, later
// S3 and SFTP) turn Ops into what a container or a user sees.
package volumeshare

import (
	"context"
	"time"
)

// Handle names one file or directory inside a Volume. It is opaque to the
// caller and stays valid across a home restart. The home only accepts
// handles it issued for this Volume.
type Handle []byte

// FileID is an open file on the home.
type FileID uint64

// Attr is what stat reports. Mode carries the type bits (S_IFREG …).
type Attr struct {
	Ino                 uint64
	Size, Blocks        uint64
	Atime, Mtime, Ctime time.Time
	Mode, Nlink         uint32
	UID, GID, Rdev      uint32
	Blksize             uint32
}

// Entry is a child found or created in a directory.
type Entry struct {
	Handle Handle
	Attr   Attr
}

// DirEntry is one directory listing row. Cookie resumes the listing after
// this row.
type DirEntry struct {
	Name   string
	Ino    uint64
	Type   uint32 // DT_* value
	Cookie uint64
}

// SetAttr changes the fields whose bit is set in Valid (fuse.Set* bits).
type SetAttr struct {
	Valid          uint32
	Size           uint64
	Mode, UID, GID uint32
	Atime, Mtime   time.Time
	File           FileID // with fuse.SetFH: truncate through this open file
}

// Lock is a byte-range or whole-file lock request.
type Lock struct {
	Start, End uint64 // End is inclusive; ^0 means to end of file
	Type       uint32 // F_RDLCK, F_WRLCK, F_UNLCK
	PID        uint32
}

// Caller is the identity a change is made for: new files get this owner.
type Caller struct{ UID, GID uint32 }

// StatFs is the home file system's space.
type StatFs struct {
	Blocks, Bfree, Bavail  uint64
	Files, Ffree           uint64
	Bsize, Namelen, Frsize uint32
}

// Ops is one Volume as the home serves it. Errors that are syscall.Errno
// reach the application as that errno.
//
// Lock owners are scoped by the caller's session: Release(session) drops
// every lock and open file of that session, which is what the home does
// when a consuming server goes away.
type Ops interface {
	Root() Handle
	Lookup(ctx context.Context, dir Handle, name string) (Entry, error)
	GetAttr(ctx context.Context, h Handle) (Attr, error)
	SetAttr(ctx context.Context, c Caller, h Handle, in SetAttr) (Attr, error)
	Readlink(ctx context.Context, h Handle) (string, error)
	Symlink(ctx context.Context, c Caller, dir Handle, name, target string) (Entry, error)
	Mkdir(ctx context.Context, c Caller, dir Handle, name string, mode uint32) (Entry, error)
	Unlink(ctx context.Context, dir Handle, name string) error
	Rmdir(ctx context.Context, dir Handle, name string) error
	Rename(ctx context.Context, dir Handle, name string, newDir Handle, newName string, flags uint32) error
	Link(ctx context.Context, h, dir Handle, name string) (Entry, error)
	ReadDir(ctx context.Context, dir Handle, cookie uint64, max int) ([]DirEntry, error)
	StatFs(ctx context.Context) (StatFs, error)

	Open(ctx context.Context, session uint64, h Handle, flags uint32) (FileID, error)
	Create(ctx context.Context, session uint64, c Caller, dir Handle, name string, flags, mode uint32) (Entry, FileID, error)
	Read(ctx context.Context, f FileID, off uint64, size uint32) ([]byte, error)
	Write(ctx context.Context, f FileID, off uint64, data []byte) (uint32, error)
	Fsync(ctx context.Context, f FileID, datasync bool) error
	Close(f FileID) error

	// GetLk reports a conflicting lock (Type F_UNLCK when none).
	GetLk(ctx context.Context, f FileID, owner uint64, l Lock, flock bool) (Lock, error)
	// SetLk takes or drops a lock for (session of f, owner). wait blocks
	// until granted or ctx ends (EINTR).
	SetLk(ctx context.Context, f FileID, owner uint64, l Lock, wait, flock bool) error
	// ReleaseOwner drops owner's flock locks on f's file (close of the last
	// descriptor that held them).
	ReleaseOwner(f FileID, owner uint64) error
	// Release drops everything the session holds.
	Release(session uint64)
}
