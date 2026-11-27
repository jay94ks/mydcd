// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
	"slices"
	"strings"
	"syscall"

	"github.com/jay94ks/seafield/internal/access"
	"golang.org/x/sys/unix"
)

var ErrFilePath = errors.New("VOLUME_FILE_PATH: invalid or unsafe volume file")
var ErrFileLimit = errors.New("VOLUME_FILE_LIMIT: file exceeds requested size")
var ErrFileConflict = errors.New("VOLUME_FILE_EXISTS: overwrite was not authorized")

const MaxFileBytes int64 = 1 << 30
const FilePageEntries = 64

type FileEntry struct {
	Path       string
	Size       int64
	ModifiedAt int64
}
type FileResult struct {
	Path   string
	Size   int64
	Digest [32]byte
}

// fileParent pins the directory below an already authorized and pinned Volume
// root. openat2 refuses every symlink/magiclink, not just the last component.
// Renaming a directory cannot redirect the returned descriptor to a new path.
func fileParent(root *os.Root, name string, create bool) (*os.File, string, error) {
	if root == nil || !access.ValidVolumeFilePath(name, false) {
		return nil, "", ErrFilePath
	}
	base, err := root.Open(".")
	if err != nil {
		return nil, "", err
	}
	defer base.Close()
	parts := strings.Split(name, "/")
	current := int(base.Fd())
	var owned int = -1
	for _, part := range parts[:len(parts)-1] {
		fd, e := unix.Openat2(current, part, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
		if e != nil && create && errors.Is(e, unix.ENOENT) {
			if e = unix.Mkdirat(current, part, 0700); e == nil || errors.Is(e, unix.EEXIST) {
				fd, e = unix.Openat2(current, part, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
			}
		}
		if e != nil {
			if owned >= 0 {
				unix.Close(owned)
			}
			return nil, "", errors.Join(ErrFilePath, e)
		}
		if owned >= 0 {
			unix.Close(owned)
		}
		owned = fd
		current = fd
	}
	if owned < 0 {
		owned, err = unix.Dup(current)
		if err != nil {
			return nil, "", err
		}
		unix.CloseOnExec(owned)
	}
	return os.NewFile(uintptr(owned), "volume-file-parent"), parts[len(parts)-1], nil
}

// PutFile stages a finite authenticated stream. Its reader must expose EOF
// only after checking request EOF; the caller holds the SAME shared
// writer consumer/local native pin until the returned parent sync completes.
// No content is placed in a shared checkpoint or public operation receipt.
func PutFile(ctx context.Context, root *os.Root, name, operation string, source io.Reader, size int64, digest [32]byte, overwrite bool) (FileResult, error) {
	return PutFileWithPublication(ctx, root, name, operation, source, size, digest, overwrite, nil)
}

// PutFileWithPublication syncs the caller journal with the original staged
// inode BEFORE rename. A failed callback cannot publish the file.
func PutFileWithPublication(ctx context.Context, root *os.Root, name, operation string, source io.Reader, size int64, digest [32]byte, overwrite bool, publish func(FilePublication) error) (out FileResult, err error) {
	mayPublish := false
	defer func() {
		if err != nil {
			err = &FileWriteError{Cause: err, MayHavePublished: mayPublish}
		}
	}()
	result := FileResult{Path: name, Size: size, Digest: digest}
	if source == nil || size < 0 || size > MaxFileBytes || len(operation) < 1 || len(operation) > 512 {
		return FileResult{}, ErrFileLimit
	}
	if root == nil || !access.ValidVolumeFilePath(name, false) {
		return FileResult{}, ErrFilePath
	}
	staging, err := root.Open(".")
	if err != nil {
		return FileResult{}, err
	}
	defer staging.Close()
	id := sha256.Sum256([]byte(operation))
	tmp := ".sfc-file-" + hex.EncodeToString(id[:])
	fd, err := unix.Openat(int(staging.Fd()), tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return FileResult{}, err
	}
	f := os.NewFile(uintptr(fd), "volume-file-staged")
	defer f.Close()
	defer unix.Unlinkat(int(staging.Fd()), tmp, 0)
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(&fileContextReader{ctx: ctx, reader: source}, size+1))
	if err != nil {
		return FileResult{}, err
	}
	if n != size {
		return FileResult{}, ErrFileLimit
	}
	var got [32]byte
	copy(got[:], h.Sum(nil))
	if got != digest {
		return FileResult{}, ErrFilePath
	}
	if err = f.Sync(); err != nil {
		return FileResult{}, err
	}
	info, err := f.Stat()
	if err != nil {
		return FileResult{}, err
	}
	st, ok := infoSys(info)
	if !ok || st.Nlink != 1 {
		return FileResult{}, ErrFilePath
	}
	publication := FilePublication{Path: name, Operation: operation, Staging: tmp, Device: uint64(st.Dev), Inode: st.Ino, Size: size, Digest: digest}
	if publish != nil {
		if err = publish(publication); err != nil {
			return FileResult{}, err
		}
	}
	if err = f.Close(); err != nil {
		return FileResult{}, err
	}
	if err = ctx.Err(); err != nil {
		return FileResult{}, err
	}
	parent, leaf, err := fileParent(root, name, true)
	if err != nil {
		return FileResult{}, err
	}
	defer parent.Close()
	if overwrite {
		// Never overwrite a symlink, directory or special file. Descriptor-relative
		// rename replaces only this basename and never follows a racing symlink.
		var st unix.Stat_t
		if e := unix.Fstatat(int(parent.Fd()), leaf, &st, unix.AT_SYMLINK_NOFOLLOW); e == nil && (st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1) {
			return FileResult{}, ErrFilePath
		} else if e != nil && !errors.Is(e, unix.ENOENT) {
			return FileResult{}, e
		}
		mayPublish = true
		err = unix.Renameat(int(staging.Fd()), tmp, int(parent.Fd()), leaf)
	} else {
		mayPublish = true
		err = unix.Renameat2(int(staging.Fd()), tmp, int(parent.Fd()), leaf, unix.RENAME_NOREPLACE)
	}
	if errors.Is(err, unix.EEXIST) {
		mayPublish = false
		return FileResult{}, ErrFileConflict
	}
	if err != nil {
		return FileResult{}, err
	}
	if err = parent.Sync(); err != nil {
		return FileResult{}, err
	}
	if err = staging.Sync(); err != nil {
		return FileResult{}, err
	}
	return result, nil
}

type fileContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *fileContextReader) Read(p []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	return r.reader.Read(p)
}

// OpenFileData never returns a host path and refuses hardlinked/special files.
// The caller keeps the Volume lease until this descriptor and all I/O close.
func OpenFileData(root *os.Root, name string, max int64) (*os.File, FileEntry, error) {
	if max < 1 || max > MaxFileBytes {
		return nil, FileEntry{}, ErrFileLimit
	}
	parent, leaf, err := fileParent(root, name, false)
	if err != nil {
		return nil, FileEntry{}, err
	}
	defer parent.Close()
	fd, err := unix.Openat(int(parent.Fd()), leaf, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, FileEntry{}, err
	}
	f := os.NewFile(uintptr(fd), "volume-file")
	info, err := f.Stat()
	st, ok := infoSys(info)
	if err != nil || !ok || !info.Mode().IsRegular() || st.Nlink != 1 {
		f.Close()
		return nil, FileEntry{}, ErrFilePath
	}
	if info.Size() > max {
		f.Close()
		return nil, FileEntry{}, ErrFileLimit
	}
	return f, FileEntry{Path: name, Size: info.Size(), ModifiedAt: info.ModTime().UnixNano()}, nil
}
func infoSys(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return st, ok
}

func DeleteFile(root *os.Root, name string) error {
	parent, leaf, err := fileParent(root, name, false)
	if err != nil {
		return err
	}
	defer parent.Close()
	var st unix.Stat_t
	if err = unix.Fstatat(int(parent.Fd()), leaf, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
		return ErrFilePath
	}
	if err = unix.Unlinkat(int(parent.Fd()), leaf, 0); err != nil {
		return err
	}
	return parent.Sync()
}

// ListFiles walks only an authorized directory prefix, with fixed memory/work
// budgets. Every result is a regular, single-linked file; internal staging and
// symlinks are excluded. Cursor ordering is lexical, never an OS directory offset.
func ListFiles(ctx context.Context, root *os.Root, prefix, after string) ([]FileEntry, string, error) {
	if !access.ValidVolumeFilePath(prefix, true) || !strings.HasSuffix(prefix, "/") || after != "" && (!access.ValidVolumeFilePath(after, false) || !strings.HasPrefix(after, prefix)) {
		return nil, "", ErrFilePath
	}
	dir := strings.TrimSuffix(prefix, "/")
	parent, leaf, err := fileParent(root, dir, false)
	if err != nil {
		return nil, "", err
	}
	defer parent.Close()
	fd, err := unix.Openat2(int(parent.Fd()), leaf, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, "", err
	}
	first := os.NewFile(uintptr(fd), "volume-file-list")
	defer first.Close()
	var out []FileEntry
	seen := 0
	var walk func(*os.File, string, int) error
	walk = func(f *os.File, rel string, depth int) error {
		if depth > 32 {
			return ErrFileLimit
		}
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			entries, e := f.ReadDir(64)
			if e != nil && !errors.Is(e, io.EOF) {
				return e
			}
			for _, entry := range entries {
				seen++
				if seen > 100000 {
					return ErrFileLimit
				}
				if strings.HasPrefix(entry.Name(), ".sfc-file-") {
					continue
				}
				name := path.Join(rel, entry.Name())
				var st unix.Stat_t
				if err := unix.Fstatat(int(f.Fd()), entry.Name(), &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
					return err
				}
				if st.Mode&unix.S_IFMT == unix.S_IFDIR {
					fd, err := unix.Openat2(int(f.Fd()), entry.Name(), &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
					if err != nil {
						return err
					}
					child := os.NewFile(uintptr(fd), "volume-file-list-child")
					err = walk(child, name, depth+1)
					child.Close()
					if err != nil {
						return err
					}
				} else if st.Mode&unix.S_IFMT == unix.S_IFREG && st.Nlink == 1 && name > after {
					out = append(out, FileEntry{Path: name, Size: st.Size, ModifiedAt: st.Mtim.Sec*1e9 + st.Mtim.Nsec})
					slices.SortFunc(out, func(a, b FileEntry) int { return strings.Compare(a.Path, b.Path) })
					if len(out) > FilePageEntries+1 {
						out = out[:FilePageEntries+1]
					}
				}
			}
			if errors.Is(e, io.EOF) {
				return nil
			}
		}
	}
	if err = walk(first, dir, 0); err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > FilePageEntries {
		out = out[:FilePageEntries]
		next = out[len(out)-1].Path
	}
	return out, next, nil
}

// FilePublication is node-local effect evidence, not file content and not a
// shared success claim. Device/inode bind the SAME staged file through rename.
type FilePublication struct {
	Path, Operation, Staging string
	Device, Inode            uint64
	Size                     int64
	Digest                   [32]byte
}

func RecoverPutFile(ctx context.Context, root *os.Root, receipt FilePublication) (FileResult, error) {
	if receipt.Operation == "" || receipt.Inode == 0 || receipt.Device == 0 || receipt.Size < 0 || receipt.Size > MaxFileBytes || receipt.Digest == ([32]byte{}) {
		return FileResult{}, ErrFilePath
	}
	expected := sha256.Sum256([]byte(receipt.Operation))
	if receipt.Staging != ".sfc-file-"+hex.EncodeToString(expected[:]) {
		return FileResult{}, ErrFilePath
	}
	file, info, err := OpenFileData(root, receipt.Path, MaxFileBytes)
	if err != nil {
		return FileResult{}, err
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return FileResult{}, err
	}
	native, ok := infoSys(stat)
	if !ok || uint64(native.Dev) != receipt.Device || native.Ino != receipt.Inode || info.Size != receipt.Size {
		return FileResult{}, ErrFilePath
	}
	hash := sha256.New()
	n, err := io.Copy(hash, &fileContextReader{ctx: ctx, reader: file})
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	if err != nil || n != receipt.Size || digest != receipt.Digest {
		return FileResult{}, errors.Join(ErrFilePath, err)
	}
	parent, _, err := fileParent(root, receipt.Path, false)
	if err != nil {
		return FileResult{}, err
	}
	defer parent.Close()
	if err = parent.Sync(); err != nil {
		return FileResult{}, err
	}
	return FileResult{Path: receipt.Path, Size: n, Digest: digest}, nil
}

type FileWriteError struct {
	Cause            error
	MayHavePublished bool
}

func (e *FileWriteError) Error() string { return e.Cause.Error() }
func (e *FileWriteError) Unwrap() error { return e.Cause }
