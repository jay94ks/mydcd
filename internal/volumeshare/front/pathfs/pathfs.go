// SPDX-License-Identifier: Apache-2.0

// Package pathfs reaches a Volume by slash paths instead of handles. It is
// the common layer of the path-shaped access fronts (S3 and SFTP, which
// arrive in 0.1.1): the mount front talks to the kernel by node ID and does
// not use it.
//
// Paths never leave the Volume: "." and ".." components, NUL, and a
// symbolic link in the middle of a path are refused, so a front cannot be
// walked outside its Volume by a crafted path. Errors are syscall.Errno
// values; a front maps them to its own codes.
package pathfs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"sort"
	"strings"
	"syscall"

	"github.com/jay94ks/seafield/internal/volumeshare"
)

// Chunk is the most one Read or Write call carries (the VolumeFS data
// extension).
const Chunk = 128 << 10

// tempPrefix starts the name of a file Put is still writing. Fronts hide
// such names, and Keys leaves them out.
const tempPrefix = ".sfc-put-"

const (
	dtDir = 4
	dtReg = 8
)

// FS is one Volume seen through ops, acting for who. session scopes the
// files it opens (volumeshare.Ops Open/Create).
type FS struct {
	ops     volumeshare.Ops
	who     volumeshare.Caller
	session uint64
}

func New(ops volumeshare.Ops, who volumeshare.Caller, session uint64) *FS {
	return &FS{ops: ops, who: who, session: session}
}

// Split turns p into its components. A leading or trailing "/" is allowed
// (the root is "" or "/"); empty, "." and ".." components and NUL are not.
func Split(p string) ([]string, error) {
	if p == "" || p == "/" {
		return nil, nil
	}
	p = strings.TrimSuffix(strings.TrimPrefix(p, "/"), "/")
	if p == "" {
		return nil, syscall.EINVAL
	}
	parts := strings.Split(p, "/")
	for _, c := range parts {
		if c == "" || c == "." || c == ".." || strings.ContainsRune(c, 0) {
			return nil, syscall.EINVAL
		}
		if len(c) > 255 {
			return nil, syscall.ENAMETOOLONG
		}
	}
	return parts, nil
}

// IsTemp reports whether name is a file Put has not finished.
func IsTemp(name string) bool { return strings.HasPrefix(name, tempPrefix) }

// walk follows comps from the root. Every component but the last must be a
// directory; a symbolic link there is ELOOP.
func (f *FS) walk(ctx context.Context, comps []string) (volumeshare.Entry, error) {
	e := volumeshare.Entry{Handle: f.ops.Root()}
	if len(comps) == 0 {
		a, err := f.ops.GetAttr(ctx, e.Handle)
		e.Attr = a
		return e, err
	}
	for i, c := range comps {
		if i > 0 {
			if err := dirOnly(e.Attr); err != nil {
				return volumeshare.Entry{}, err
			}
		}
		next, err := f.ops.Lookup(ctx, e.Handle, c)
		if err != nil {
			return volumeshare.Entry{}, err
		}
		e = next
	}
	return e, nil
}

func dirOnly(a volumeshare.Attr) error {
	switch a.Mode & syscall.S_IFMT {
	case syscall.S_IFDIR:
		return nil
	case syscall.S_IFLNK:
		return syscall.ELOOP
	default:
		return syscall.ENOTDIR
	}
}

// Resolve finds p. A symbolic link as the last component is returned as
// itself, not followed.
func (f *FS) Resolve(ctx context.Context, p string) (volumeshare.Entry, error) {
	comps, err := Split(p)
	if err != nil {
		return volumeshare.Entry{}, err
	}
	return f.walk(ctx, comps)
}

// Parent finds the directory p would be in, and p's last name. The root
// has no parent (EINVAL).
func (f *FS) Parent(ctx context.Context, p string) (volumeshare.Handle, string, error) {
	comps, err := Split(p)
	if err != nil {
		return nil, "", err
	}
	if len(comps) == 0 {
		return nil, "", syscall.EINVAL
	}
	dir, err := f.walk(ctx, comps[:len(comps)-1])
	if err != nil {
		return nil, "", err
	}
	if err := dirOnly(dir.Attr); err != nil {
		return nil, "", err
	}
	return dir.Handle, comps[len(comps)-1], nil
}

// MkdirAll makes p and any missing parents with mode, and returns p.
func (f *FS) MkdirAll(ctx context.Context, p string, mode uint32) (volumeshare.Entry, error) {
	comps, err := Split(p)
	if err != nil {
		return volumeshare.Entry{}, err
	}
	e, err := f.walk(ctx, nil)
	if err != nil {
		return volumeshare.Entry{}, err
	}
	for _, c := range comps {
		if err := dirOnly(e.Attr); err != nil {
			return volumeshare.Entry{}, err
		}
		next, err := f.ops.Lookup(ctx, e.Handle, c)
		if errors.Is(err, syscall.ENOENT) {
			next, err = f.ops.Mkdir(ctx, f.who, e.Handle, c, mode)
			if errors.Is(err, syscall.EEXIST) {
				// Another writer made it meanwhile.
				next, err = f.ops.Lookup(ctx, e.Handle, c)
			}
		}
		if err != nil {
			return volumeshare.Entry{}, err
		}
		e = next
	}
	if err := dirOnly(e.Attr); err != nil {
		return volumeshare.Entry{}, err
	}
	return e, nil
}

// File is one open file. Its ReadAt and WriteAt use the context it was
// opened with.
type File struct {
	ctx context.Context
	ops volumeshare.Ops
	id  volumeshare.FileID
}

// Open opens the regular file p with open(2) flags (no O_CREAT).
func (f *FS) Open(ctx context.Context, p string, flags uint32) (*File, error) {
	e, err := f.Resolve(ctx, p)
	if err != nil {
		return nil, err
	}
	if e.Attr.Mode&syscall.S_IFMT != syscall.S_IFREG {
		if e.Attr.Mode&syscall.S_IFMT == syscall.S_IFDIR {
			return nil, syscall.EISDIR
		}
		return nil, syscall.EINVAL
	}
	id, err := f.ops.Open(ctx, f.session, e.Handle, flags&^syscall.O_CREAT)
	if err != nil {
		return nil, err
	}
	return &File{ctx: ctx, ops: f.ops, id: id}, nil
}

// Create creates p in an existing directory with open(2) flags and mode.
func (f *FS) Create(ctx context.Context, p string, flags, mode uint32) (*File, volumeshare.Entry, error) {
	dir, name, err := f.Parent(ctx, p)
	if err != nil {
		return nil, volumeshare.Entry{}, err
	}
	return f.create(ctx, dir, name, flags, mode)
}

func (f *FS) create(ctx context.Context, dir volumeshare.Handle, name string, flags, mode uint32) (*File, volumeshare.Entry, error) {
	e, id, err := f.ops.Create(ctx, f.session, f.who, dir, name, flags|syscall.O_CREAT, mode)
	if err != nil {
		return nil, volumeshare.Entry{}, err
	}
	return &File{ctx: ctx, ops: f.ops, id: id}, e, nil
}

func (h *File) ReadAt(b []byte, off int64) (int, error) {
	if off < 0 {
		return 0, syscall.EINVAL
	}
	n := 0
	for n < len(b) {
		want := min(len(b)-n, Chunk)
		got, err := h.ops.Read(h.ctx, h.id, uint64(off)+uint64(n), uint32(want))
		if err != nil {
			return n, err
		}
		n += copy(b[n:], got)
		if len(got) < want {
			return n, io.EOF
		}
	}
	return n, nil
}

func (h *File) WriteAt(b []byte, off int64) (int, error) {
	if off < 0 {
		return 0, syscall.EINVAL
	}
	n := 0
	for n < len(b) {
		w, err := h.ops.Write(h.ctx, h.id, uint64(off)+uint64(n), b[n:n+min(len(b)-n, Chunk)])
		if err != nil {
			return n, err
		}
		if w == 0 {
			return n, io.ErrShortWrite
		}
		n += int(w)
	}
	return n, nil
}

func (h *File) Sync() error  { return h.ops.Fsync(h.ctx, h.id, false) }
func (h *File) Close() error { return h.ops.Close(h.id) }

// Put writes r to p as one replacement: the data goes to a hidden file in
// the same directory first and is renamed over p after fsync, so a reader
// sees the old content or the new one, never a part. Missing parents are
// made with mode 0755.
func (f *FS) Put(ctx context.Context, p string, r io.Reader, mode uint32) (volumeshare.Entry, error) {
	comps, err := Split(p)
	if err != nil {
		return volumeshare.Entry{}, err
	}
	if len(comps) == 0 {
		return volumeshare.Entry{}, syscall.EISDIR
	}
	name := comps[len(comps)-1]
	if IsTemp(name) {
		return volumeshare.Entry{}, syscall.EINVAL
	}
	dir, err := f.MkdirAll(ctx, strings.Join(comps[:len(comps)-1], "/"), 0o755)
	if err != nil {
		return volumeshare.Entry{}, err
	}
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return volumeshare.Entry{}, err
	}
	tmp := tempPrefix + hex.EncodeToString(rnd[:])
	h, _, err := f.create(ctx, dir.Handle, tmp, syscall.O_WRONLY|syscall.O_EXCL, mode)
	if err != nil {
		return volumeshare.Entry{}, err
	}
	fail := func(err error) (volumeshare.Entry, error) {
		_ = h.Close()
		_ = f.ops.Unlink(context.WithoutCancel(ctx), dir.Handle, tmp)
		return volumeshare.Entry{}, err
	}
	buf := make([]byte, Chunk)
	var off int64
	for {
		n, rerr := io.ReadFull(r, buf)
		if n > 0 {
			if _, err := h.WriteAt(buf[:n], off); err != nil {
				return fail(err)
			}
			off += int64(n)
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
		if rerr != nil {
			return fail(rerr)
		}
	}
	if err := h.Sync(); err != nil {
		return fail(err)
	}
	if err := h.Close(); err != nil {
		_ = f.ops.Unlink(context.WithoutCancel(ctx), dir.Handle, tmp)
		return volumeshare.Entry{}, err
	}
	if err := f.ops.Rename(ctx, dir.Handle, tmp, dir.Handle, name, 0); err != nil {
		_ = f.ops.Unlink(context.WithoutCancel(ctx), dir.Handle, tmp)
		return volumeshare.Entry{}, err
	}
	return f.ops.Lookup(ctx, dir.Handle, name)
}

// ReadDir lists dir whole, without "." and "..".
func (f *FS) ReadDir(ctx context.Context, dir volumeshare.Handle) ([]volumeshare.DirEntry, error) {
	var out []volumeshare.DirEntry
	var cookie uint64
	for {
		page, err := f.ops.ReadDir(ctx, dir, cookie, 1024)
		if err != nil {
			return nil, err
		}
		if len(page) == 0 {
			return out, nil
		}
		out = append(out, page...)
		cookie = page[len(page)-1].Cookie
	}
}

// Key is one regular file Keys found: its path from the Volume root, with
// no leading "/".
type Key struct {
	Path  string
	Entry volumeshare.Entry
}

// Keys lists up to max regular files whose path starts with prefix and
// sorts after after, in byte order of the whole path (the order S3
// ListObjectsV2 pages in, continuation = the last Path). Directories are
// read in name order with a directory sorting as name+"/", which keeps the
// depth-first walk in that order; subtrees that cannot hold a match are
// not read. Symbolic links, other file types and unfinished Put files are
// left out.
func (f *FS) Keys(ctx context.Context, prefix, after string, max int) ([]Key, error) {
	if max <= 0 {
		return nil, nil
	}
	root, err := f.walk(ctx, nil)
	if err != nil {
		return nil, err
	}
	var out []Key
	err = f.keys(ctx, root.Handle, "", prefix, after, max, &out)
	return out, err
}

func (f *FS) keys(ctx context.Context, dir volumeshare.Handle, at, prefix, after string, max int, out *[]Key) error {
	list, err := f.ReadDir(ctx, dir)
	if err != nil {
		return err
	}
	// Sort names as they appear in a key: a directory as name+"/".
	type child struct {
		name string
		key  string
	}
	var kids []child
	for _, d := range list {
		switch {
		case IsTemp(d.Name):
		case d.Type == dtDir:
			kids = append(kids, child{d.Name, d.Name + "/"})
		case d.Type == dtReg:
			kids = append(kids, child{d.Name, d.Name})
		case d.Type == 0:
			// The file system did not say: ask.
			e, err := f.ops.Lookup(ctx, dir, d.Name)
			if errors.Is(err, syscall.ENOENT) {
				continue
			} else if err != nil {
				return err
			}
			switch e.Attr.Mode & syscall.S_IFMT {
			case syscall.S_IFDIR:
				kids = append(kids, child{d.Name, d.Name + "/"})
			case syscall.S_IFREG:
				kids = append(kids, child{d.Name, d.Name})
			}
		}
	}
	sort.Slice(kids, func(i, j int) bool { return kids[i].key < kids[j].key })
	for _, k := range kids {
		p := at + k.key
		isDir := strings.HasSuffix(k.key, "/")
		if isDir {
			// Every key below starts with p.
			if !strings.HasPrefix(p, prefix) && !strings.HasPrefix(prefix, p) {
				continue
			}
			if after >= p && !strings.HasPrefix(after, p) {
				continue
			}
		} else if p <= after || !strings.HasPrefix(p, prefix) {
			continue
		}
		e, err := f.ops.Lookup(ctx, dir, k.name)
		if errors.Is(err, syscall.ENOENT) {
			continue // removed while listing
		} else if err != nil {
			return err
		}
		switch e.Attr.Mode & syscall.S_IFMT {
		case syscall.S_IFDIR:
			if !isDir {
				continue // replaced while listing
			}
			if err := f.keys(ctx, e.Handle, p, prefix, after, max, out); err != nil {
				return err
			}
		case syscall.S_IFREG:
			if isDir {
				continue
			}
			*out = append(*out, Key{Path: p, Entry: e})
		}
		if len(*out) == max {
			return nil
		}
	}
	return nil
}
