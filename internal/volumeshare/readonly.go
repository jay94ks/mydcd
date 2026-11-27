// SPDX-License-Identifier: Apache-2.0

package volumeshare

import (
	"context"
	"syscall"
)

// ReadOnly serves ops to a mount that may only read: every change is
// refused with EROFS on the home, whatever the consuming server sends.
// Opening for write and taking a write lock are changes too.
func ReadOnly(ops Ops) Ops { return readOnly{ops} }

type readOnly struct{ Ops }

func (r readOnly) SetAttr(context.Context, Caller, Handle, SetAttr) (Attr, error) {
	return Attr{}, syscall.EROFS
}
func (r readOnly) Symlink(context.Context, Caller, Handle, string, string) (Entry, error) {
	return Entry{}, syscall.EROFS
}
func (r readOnly) Mkdir(context.Context, Caller, Handle, string, uint32) (Entry, error) {
	return Entry{}, syscall.EROFS
}
func (r readOnly) Unlink(context.Context, Handle, string) error { return syscall.EROFS }
func (r readOnly) Rmdir(context.Context, Handle, string) error  { return syscall.EROFS }
func (r readOnly) Rename(context.Context, Handle, string, Handle, string, uint32) error {
	return syscall.EROFS
}
func (r readOnly) Link(context.Context, Handle, Handle, string) (Entry, error) {
	return Entry{}, syscall.EROFS
}
func (r readOnly) Create(context.Context, uint64, Caller, Handle, string, uint32, uint32) (Entry, FileID, error) {
	return Entry{}, 0, syscall.EROFS
}
func (r readOnly) Open(ctx context.Context, session uint64, h Handle, flags uint32) (FileID, error) {
	if flags&(syscall.O_WRONLY|syscall.O_RDWR|syscall.O_TRUNC|syscall.O_APPEND|syscall.O_CREAT) != 0 {
		return 0, syscall.EROFS
	}
	return r.Ops.Open(ctx, session, h, flags)
}
func (r readOnly) Write(context.Context, FileID, uint64, []byte) (uint32, error) {
	return 0, syscall.EROFS
}
func (r readOnly) SetLk(ctx context.Context, f FileID, owner uint64, l Lock, wait, flock bool) error {
	if l.Type == syscall.F_WRLCK {
		return syscall.EROFS
	}
	return r.Ops.SetLk(ctx, f, owner, l, wait, flock)
}
