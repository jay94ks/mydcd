// SPDX-License-Identifier: Apache-2.0

// Package localroot serves a Volume from a local directory on the home
// server. Every operation starts from a handle the home issued (an export
// file handle sealed with a per-Volume key) and touches at most one name
// below it, so no path is ever resolved through a symlink or "..".
package localroot

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jay94ks/seafield/internal/volumeshare"
	"github.com/jay94ks/seafield/internal/volumeshare/fuse"
	"golang.org/x/sys/unix"
)

const macSize = 16

// Root is one Volume directory served to other servers.
type Root struct {
	dir     int // fd of the Volume directory; also the mount fd for open_by_handle_at
	mountID int
	key     []byte
	root    volumeshare.Handle

	mu    sync.Mutex
	next  volumeshare.FileID
	files map[volumeshare.FileID]*file
	locks map[lockKey]int
}

type file struct {
	fd      int
	session uint64
	handle  []byte // raw export handle (type + bytes) for lock descriptors
	ino     uint64
}

type lockKey struct {
	session, owner, ino uint64
	flock               bool
}

// Open serves the directory at path. key seals handles; keep it stable
// for the Volume so handles survive a restart, and distinct per Volume so
// one Volume's handles are refused by another's Root. It needs
// CAP_DAC_READ_SEARCH (open_by_handle_at).
func Open(path string, key []byte) (*Root, error) {
	if len(key) < 32 {
		return nil, errors.New("localroot: key must be at least 32 bytes")
	}
	// Not O_PATH: open_by_handle_at refuses an O_PATH mount fd (EBADF).
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("localroot: open %s: %w", path, err)
	}
	return openFD(fd, path, key)
}

// OpenFD serves the directory open at fd (O_RDONLY|O_DIRECTORY, not O_PATH).
// It duplicates fd, so the caller still closes its own.
func OpenFD(fd int, key []byte) (*Root, error) {
	if len(key) < 32 {
		return nil, errors.New("localroot: key must be at least 32 bytes")
	}
	dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("localroot: dup: %w", err)
	}
	return openFD(dup, "fd "+strconv.Itoa(fd), key)
}

func openFD(fd int, path string, key []byte) (*Root, error) {
	r := &Root{dir: fd, key: append([]byte(nil), key...), files: map[volumeshare.FileID]*file{}, locks: map[lockKey]int{}}
	fh, mid, err := unix.NameToHandleAt(fd, "", unix.AT_EMPTY_PATH)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("localroot: %s has no export handles: %w", path, err)
	}
	r.mountID = mid
	r.root = r.seal(fh)
	return r, nil
}

// Shutdown releases every open file and lock and the directory.
func (r *Root) Shutdown() error {
	r.mu.Lock()
	for id, f := range r.files {
		unix.Close(f.fd)
		delete(r.files, id)
	}
	for k, fd := range r.locks {
		unix.Close(fd)
		delete(r.locks, k)
	}
	r.mu.Unlock()
	return unix.Close(r.dir)
}

func (r *Root) mac(raw []byte) []byte {
	m := hmac.New(sha256.New, r.key)
	m.Write([]byte("sfc-volumeshare-handle-1\x00"))
	m.Write(raw)
	return m.Sum(nil)[:macSize]
}

func (r *Root) seal(fh unix.FileHandle) volumeshare.Handle {
	raw := binary.LittleEndian.AppendUint32(nil, uint32(fh.Type()))
	raw = append(raw, fh.Bytes()...)
	return append(raw, r.mac(raw)...)
}

func (r *Root) unseal(h volumeshare.Handle) ([]byte, unix.FileHandle, error) {
	if len(h) < 4+macSize {
		return nil, unix.FileHandle{}, syscall.ESTALE
	}
	raw := h[:len(h)-macSize]
	if !hmac.Equal(h[len(h)-macSize:], r.mac(raw)) {
		return nil, unix.FileHandle{}, syscall.ESTALE
	}
	return raw, unix.NewFileHandle(int32(binary.LittleEndian.Uint32(raw)), raw[4:]), nil
}

func (r *Root) openH(h volumeshare.Handle, flags int) (int, error) {
	_, fh, err := r.unseal(h)
	if err != nil {
		return -1, err
	}
	return unix.OpenByHandleAt(r.dir, fh, flags|unix.O_CLOEXEC)
}

func validName(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsRune(name, '/') || strings.ContainsRune(name, 0) {
		return syscall.EINVAL
	}
	if len(name) > 255 {
		return syscall.ENAMETOOLONG
	}
	return nil
}

// dirFD opens dir for *at calls on name.
func (r *Root) dirFD(dir volumeshare.Handle, name string) (int, error) {
	if err := validName(name); err != nil {
		return -1, err
	}
	return r.openH(dir, unix.O_PATH|unix.O_DIRECTORY)
}

func attrOf(st *unix.Stat_t) volumeshare.Attr {
	return volumeshare.Attr{
		Ino: st.Ino, Size: uint64(st.Size), Blocks: uint64(st.Blocks),
		Atime: time.Unix(st.Atim.Unix()), Mtime: time.Unix(st.Mtim.Unix()), Ctime: time.Unix(st.Ctim.Unix()),
		Mode: st.Mode, Nlink: uint32(st.Nlink), UID: st.Uid, GID: st.Gid, Rdev: uint32(st.Rdev), Blksize: uint32(st.Blksize),
	}
}

// entry stats and seals name inside the open directory dfd. A name that is
// another file system's mount point is refused: a Volume never spans mounts.
func (r *Root) entry(dfd int, name string) (volumeshare.Entry, error) {
	var st unix.Stat_t
	if err := unix.Fstatat(dfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return volumeshare.Entry{}, err
	}
	fh, mid, err := unix.NameToHandleAt(dfd, name, 0)
	if err != nil {
		return volumeshare.Entry{}, err
	}
	if mid != r.mountID {
		return volumeshare.Entry{}, syscall.EXDEV
	}
	return volumeshare.Entry{Handle: r.seal(fh), Attr: attrOf(&st)}, nil
}

func (r *Root) Root() volumeshare.Handle { return r.root }

func (r *Root) Lookup(_ context.Context, dir volumeshare.Handle, name string) (volumeshare.Entry, error) {
	dfd, err := r.dirFD(dir, name)
	if err != nil {
		return volumeshare.Entry{}, err
	}
	defer unix.Close(dfd)
	return r.entry(dfd, name)
}

func (r *Root) GetAttr(_ context.Context, h volumeshare.Handle) (volumeshare.Attr, error) {
	fd, err := r.openH(h, unix.O_PATH)
	if err != nil {
		return volumeshare.Attr{}, err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return volumeshare.Attr{}, err
	}
	return attrOf(&st), nil
}

func procPath(fd int) string { return "/proc/self/fd/" + strconv.Itoa(fd) }

func timespec(t time.Time, set, now bool) unix.Timespec {
	switch {
	case now:
		return unix.Timespec{Nsec: unix.UTIME_NOW}
	case set:
		return unix.NsecToTimespec(t.UnixNano())
	}
	return unix.Timespec{Nsec: unix.UTIME_OMIT}
}

func (r *Root) SetAttr(ctx context.Context, _ volumeshare.Caller, h volumeshare.Handle, in volumeshare.SetAttr) (volumeshare.Attr, error) {
	fd, err := r.openH(h, unix.O_PATH)
	if err != nil {
		return volumeshare.Attr{}, err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return volumeshare.Attr{}, err
	}
	link := st.Mode&unix.S_IFMT == unix.S_IFLNK
	if in.Valid&fuse.SetSize != 0 {
		if err = r.truncate(h, in); err != nil {
			return volumeshare.Attr{}, err
		}
	}
	if in.Valid&fuse.SetMode != 0 && !link {
		if err = unix.Chmod(procPath(fd), in.Mode&0o7777); err != nil {
			return volumeshare.Attr{}, err
		}
	}
	if in.Valid&(fuse.SetUID|fuse.SetGID) != 0 {
		uid, gid := -1, -1
		if in.Valid&fuse.SetUID != 0 {
			uid = int(in.UID)
		}
		if in.Valid&fuse.SetGID != 0 {
			gid = int(in.GID)
		}
		if err = unix.Fchownat(fd, "", uid, gid, unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return volumeshare.Attr{}, err
		}
	}
	if in.Valid&(fuse.SetAtime|fuse.SetMtime|fuse.SetAtimeNow|fuse.SetMtimeNow) != 0 && !link {
		ts := []unix.Timespec{
			timespec(in.Atime, in.Valid&fuse.SetAtime != 0, in.Valid&fuse.SetAtimeNow != 0),
			timespec(in.Mtime, in.Valid&fuse.SetMtime != 0, in.Valid&fuse.SetMtimeNow != 0),
		}
		if err = unix.UtimesNanoAt(unix.AT_FDCWD, procPath(fd), ts, 0); err != nil {
			return volumeshare.Attr{}, err
		}
	}
	return r.GetAttr(ctx, h)
}

func (r *Root) truncate(h volumeshare.Handle, in volumeshare.SetAttr) error {
	if in.Valid&fuse.SetFH != 0 {
		r.mu.Lock()
		f := r.files[in.File]
		r.mu.Unlock()
		if f != nil {
			return unix.Ftruncate(f.fd, int64(in.Size))
		}
	}
	fd, err := r.openH(h, unix.O_WRONLY)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return unix.Ftruncate(fd, int64(in.Size))
}

func (r *Root) Readlink(_ context.Context, h volumeshare.Handle) (string, error) {
	fd, err := r.openH(h, unix.O_PATH)
	if err != nil {
		return "", err
	}
	defer unix.Close(fd)
	buf := make([]byte, unix.PathMax)
	n, err := unix.Readlinkat(fd, "", buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

func (r *Root) Symlink(_ context.Context, c volumeshare.Caller, dir volumeshare.Handle, name, target string) (volumeshare.Entry, error) {
	dfd, err := r.dirFD(dir, name)
	if err != nil {
		return volumeshare.Entry{}, err
	}
	defer unix.Close(dfd)
	if err = unix.Symlinkat(target, dfd, name); err != nil {
		return volumeshare.Entry{}, err
	}
	if err = unix.Fchownat(dfd, name, int(c.UID), int(c.GID), unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return volumeshare.Entry{}, err
	}
	return r.entry(dfd, name)
}

func (r *Root) Mkdir(_ context.Context, c volumeshare.Caller, dir volumeshare.Handle, name string, mode uint32) (volumeshare.Entry, error) {
	dfd, err := r.dirFD(dir, name)
	if err != nil {
		return volumeshare.Entry{}, err
	}
	defer unix.Close(dfd)
	if err = unix.Mkdirat(dfd, name, mode&0o7777); err != nil {
		return volumeshare.Entry{}, err
	}
	// The home's own umask must not narrow what the caller asked for.
	if err = unix.Fchmodat(dfd, name, mode&0o7777, 0); err != nil {
		return volumeshare.Entry{}, err
	}
	if err = unix.Fchownat(dfd, name, int(c.UID), int(c.GID), unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return volumeshare.Entry{}, err
	}
	return r.entry(dfd, name)
}

func (r *Root) Unlink(_ context.Context, dir volumeshare.Handle, name string) error {
	dfd, err := r.dirFD(dir, name)
	if err != nil {
		return err
	}
	defer unix.Close(dfd)
	return unix.Unlinkat(dfd, name, 0)
}

func (r *Root) Rmdir(_ context.Context, dir volumeshare.Handle, name string) error {
	dfd, err := r.dirFD(dir, name)
	if err != nil {
		return err
	}
	defer unix.Close(dfd)
	return unix.Unlinkat(dfd, name, unix.AT_REMOVEDIR)
}

func (r *Root) Rename(_ context.Context, dir volumeshare.Handle, name string, newDir volumeshare.Handle, newName string, flags uint32) error {
	dfd, err := r.dirFD(dir, name)
	if err != nil {
		return err
	}
	defer unix.Close(dfd)
	nfd, err := r.dirFD(newDir, newName)
	if err != nil {
		return err
	}
	defer unix.Close(nfd)
	return unix.Renameat2(dfd, name, nfd, newName, uint(flags))
}

func (r *Root) Link(_ context.Context, h, dir volumeshare.Handle, name string) (volumeshare.Entry, error) {
	src, err := r.openH(h, unix.O_PATH)
	if err != nil {
		return volumeshare.Entry{}, err
	}
	defer unix.Close(src)
	dfd, err := r.dirFD(dir, name)
	if err != nil {
		return volumeshare.Entry{}, err
	}
	defer unix.Close(dfd)
	if err = unix.Linkat(src, "", dfd, name, unix.AT_EMPTY_PATH); err != nil {
		return volumeshare.Entry{}, err
	}
	return r.entry(dfd, name)
}

// ReadDir lists dir from cookie (0 = start), at most max rows. "." and ".."
// are left to the front-end.
func (r *Root) ReadDir(_ context.Context, dir volumeshare.Handle, cookie uint64, max int) ([]volumeshare.DirEntry, error) {
	fd, err := r.openH(dir, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	if _, err = unix.Seek(fd, int64(cookie), 0); err != nil {
		return nil, err
	}
	buf := make([]byte, 32<<10)
	var out []volumeshare.DirEntry
	for len(out) < max {
		n, err := unix.Getdents(fd, buf)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			break
		}
		for b := buf[:n]; len(b) >= 19; {
			reclen := int(binary.NativeEndian.Uint16(b[16:]))
			if reclen < 19 || reclen > len(b) {
				return nil, syscall.EIO
			}
			name := b[19:reclen]
			if i := indexZero(name); i >= 0 {
				name = name[:i]
			}
			d := volumeshare.DirEntry{Ino: binary.NativeEndian.Uint64(b), Cookie: binary.NativeEndian.Uint64(b[8:]), Type: uint32(b[18]), Name: string(name)}
			b = b[reclen:]
			if d.Name == "." || d.Name == ".." {
				continue
			}
			out = append(out, d)
			if len(out) == max {
				break
			}
		}
	}
	return out, nil
}

func indexZero(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}

func (r *Root) StatFs(context.Context) (volumeshare.StatFs, error) {
	var st unix.Statfs_t
	if err := unix.Fstatfs(r.dir, &st); err != nil {
		return volumeshare.StatFs{}, err
	}
	return volumeshare.StatFs{Blocks: st.Blocks, Bfree: st.Bfree, Bavail: st.Bavail, Files: st.Files, Ffree: st.Ffree, Bsize: uint32(st.Bsize), Namelen: uint32(st.Namelen), Frsize: uint32(st.Frsize)}, nil
}

const openStrip = unix.O_CREAT | unix.O_EXCL | unix.O_NOCTTY | unix.O_PATH

func (r *Root) addFile(fd int, session uint64, handle volumeshare.Handle) (volumeshare.FileID, error) {
	raw, _, err := r.unseal(handle)
	if err != nil {
		return 0, err
	}
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return 0, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.next++
	r.files[r.next] = &file{fd: fd, session: session, handle: append([]byte(nil), raw...), ino: st.Ino}
	return r.next, nil
}

func (r *Root) Open(_ context.Context, session uint64, h volumeshare.Handle, flags uint32) (volumeshare.FileID, error) {
	fd, err := r.openH(h, int(flags)&^openStrip)
	if err != nil {
		return 0, err
	}
	id, err := r.addFile(fd, session, h)
	if err != nil {
		unix.Close(fd)
	}
	return id, err
}

func (r *Root) Create(_ context.Context, session uint64, c volumeshare.Caller, dir volumeshare.Handle, name string, flags, mode uint32) (volumeshare.Entry, volumeshare.FileID, error) {
	dfd, err := r.dirFD(dir, name)
	if err != nil {
		return volumeshare.Entry{}, 0, err
	}
	defer unix.Close(dfd)
	fd, err := unix.Openat(dfd, name, int(flags)&^(unix.O_NOCTTY|unix.O_PATH)|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode&0o7777)
	if err != nil {
		return volumeshare.Entry{}, 0, err
	}
	fail := func(err error) (volumeshare.Entry, volumeshare.FileID, error) {
		unix.Close(fd)
		return volumeshare.Entry{}, 0, err
	}
	if err = unix.Fchmod(fd, mode&0o7777); err != nil {
		return fail(err)
	}
	if err = unix.Fchown(fd, int(c.UID), int(c.GID)); err != nil {
		return fail(err)
	}
	e, err := r.entry(dfd, name)
	if err != nil {
		return fail(err)
	}
	id, err := r.addFile(fd, session, e.Handle)
	if err != nil {
		return fail(err)
	}
	return e, id, nil
}

func (r *Root) fileFD(f volumeshare.FileID) (*file, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if x := r.files[f]; x != nil {
		return x, nil
	}
	return nil, syscall.EBADF
}

func (r *Root) Read(_ context.Context, f volumeshare.FileID, off uint64, size uint32) ([]byte, error) {
	x, err := r.fileFD(f)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, size)
	n, err := unix.Pread(x.fd, buf, int64(off))
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (r *Root) Write(_ context.Context, f volumeshare.FileID, off uint64, data []byte) (uint32, error) {
	x, err := r.fileFD(f)
	if err != nil {
		return 0, err
	}
	n, err := unix.Pwrite(x.fd, data, int64(off))
	return uint32(n), err
}

func (r *Root) Fsync(_ context.Context, f volumeshare.FileID, datasync bool) error {
	x, err := r.fileFD(f)
	if err != nil {
		return err
	}
	if datasync {
		return unix.Fdatasync(x.fd)
	}
	return unix.Fsync(x.fd)
}

func (r *Root) Close(f volumeshare.FileID) error {
	r.mu.Lock()
	x := r.files[f]
	delete(r.files, f)
	r.mu.Unlock()
	if x == nil {
		return syscall.EBADF
	}
	return unix.Close(x.fd)
}

// lockFD returns the descriptor that holds owner's locks on f's file: one
// open file description per (session, owner), so OFD and flock locks of
// different owners conflict exactly like separate processes would.
func (r *Root) lockFD(f volumeshare.FileID, owner uint64, flock, create bool) (int, lockKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	x := r.files[f]
	if x == nil {
		return -1, lockKey{}, syscall.EBADF
	}
	k := lockKey{session: x.session, owner: owner, ino: x.ino, flock: flock}
	if fd, ok := r.locks[k]; ok || !create {
		if !ok {
			return -1, k, nil
		}
		return fd, k, nil
	}
	fh := unix.NewFileHandle(int32(binary.LittleEndian.Uint32(x.handle)), x.handle[4:])
	fd, err := unix.OpenByHandleAt(r.dir, fh, unix.O_RDWR|unix.O_CLOEXEC)
	if err != nil {
		if fd, err = unix.OpenByHandleAt(r.dir, fh, unix.O_RDONLY|unix.O_CLOEXEC); err != nil {
			return -1, k, err
		}
	}
	r.locks[k] = fd
	return fd, k, nil
}

func (r *Root) dropLock(k lockKey) {
	r.mu.Lock()
	fd, ok := r.locks[k]
	delete(r.locks, k)
	r.mu.Unlock()
	if ok {
		unix.Close(fd)
	}
}

func ofdLock(l volumeshare.Lock) unix.Flock_t {
	fl := unix.Flock_t{Type: int16(l.Type), Whence: 0, Start: int64(l.Start)}
	if l.End != ^uint64(0) {
		fl.Len = int64(l.End - l.Start + 1)
	}
	return fl
}

func (r *Root) GetLk(_ context.Context, f volumeshare.FileID, owner uint64, l volumeshare.Lock, flock bool) (volumeshare.Lock, error) {
	if flock {
		return volumeshare.Lock{}, syscall.EINVAL
	}
	fd, _, err := r.lockFD(f, owner, false, true)
	if err != nil {
		return volumeshare.Lock{}, err
	}
	fl := ofdLock(l)
	if err = unix.FcntlFlock(uintptr(fd), unix.F_OFD_GETLK, &fl); err != nil {
		return volumeshare.Lock{}, err
	}
	out := volumeshare.Lock{Type: uint32(fl.Type), Start: uint64(fl.Start), End: ^uint64(0)}
	if fl.Len > 0 {
		out.End = uint64(fl.Start + fl.Len - 1)
	}
	return out, nil
}

func (r *Root) SetLk(ctx context.Context, f volumeshare.FileID, owner uint64, l volumeshare.Lock, wait, flock bool) error {
	unlockAll := l.Type == unix.F_UNLCK && (flock || l.Start == 0 && l.End == ^uint64(0))
	fd, k, err := r.lockFD(f, owner, flock, !unlockAll)
	if err != nil {
		return err
	}
	if unlockAll {
		// Closing the owner's descriptor drops all its locks on the file.
		if fd >= 0 {
			r.dropLock(k)
		}
		return nil
	}
	try := func() error {
		if flock {
			how := unix.LOCK_SH
			if l.Type == unix.F_WRLCK {
				how = unix.LOCK_EX
			}
			return unix.Flock(fd, how|unix.LOCK_NB)
		}
		fl := ofdLock(l)
		return unix.FcntlFlock(uintptr(fd), unix.F_OFD_SETLK, &fl)
	}
	// Blocking waits poll instead of F_OFD_SETLKW/LOCK_EX: a blocked
	// syscall cannot be cancelled when the caller is interrupted or leaves.
	delay := 5 * time.Millisecond
	for {
		err = try()
		if err == nil || !wait || err != unix.EAGAIN && err != unix.EWOULDBLOCK {
			if err == unix.EWOULDBLOCK {
				err = unix.EAGAIN
			}
			return err
		}
		select {
		case <-ctx.Done():
			return syscall.EINTR
		case <-time.After(delay):
		}
		delay = min(delay*2, 200*time.Millisecond)
	}
}

func (r *Root) ReleaseOwner(f volumeshare.FileID, owner uint64) error {
	_, k, err := r.lockFD(f, owner, true, false)
	if err != nil {
		return err
	}
	r.dropLock(k)
	return nil
}

func (r *Root) Release(session uint64) {
	r.mu.Lock()
	var fds []int
	for id, f := range r.files {
		if f.session == session {
			fds = append(fds, f.fd)
			delete(r.files, id)
		}
	}
	for k, fd := range r.locks {
		if k.session == session {
			fds = append(fds, fd)
			delete(r.locks, k)
		}
	}
	r.mu.Unlock()
	for _, fd := range fds {
		unix.Close(fd)
	}
}

var _ volumeshare.Ops = (*Root)(nil)
