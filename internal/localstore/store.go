// SPDX-License-Identifier: Apache-2.0

// Package localstore accesses private Linux-user state under ~/.mydc. It uses
// directory descriptors, rejects symlinks/hard links and foreign ownership, and
// never chmods or adopts an existing unsafe object.
package localstore

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"syscall"
)

var ErrState = errors.New("unsafe or unavailable private local state")
var ErrBusy = errors.New("private local state is locked by another process")

type Root struct {
	home, root *os.Root
	identity   os.FileInfo
}

func private(info os.FileInfo, dir bool) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && info.Mode().Perm()&0077 == 0 && (dir && info.IsDir() || !dir && info.Mode().IsRegular() && stat.Nlink == 1)
}
func syncRoot(r *os.Root) error {
	f, e := r.Open(".")
	if e != nil {
		return ErrState
	}
	defer f.Close()
	if f.Sync() != nil {
		return ErrState
	}
	return nil
}
func Open(home string, create bool) (*Root, error) {
	h, e := os.OpenRoot(home)
	if e != nil {
		return nil, ErrState
	}
	failed := true
	defer func() {
		if failed {
			_ = h.Close()
		}
	}()
	if create {
		if e = h.Mkdir(".mydc", 0700); e != nil && !errors.Is(e, fs.ErrExist) {
			return nil, ErrState
		}
		if syncRoot(h) != nil {
			return nil, ErrState
		}
	}
	info, e := h.Lstat(".mydc")
	if e != nil {
		if errors.Is(e, fs.ErrNotExist) {
			return nil, fs.ErrNotExist
		}
		return nil, ErrState
	}
	if !private(info, true) {
		return nil, ErrState
	}
	r, e := h.OpenRoot(".mydc")
	if e != nil {
		return nil, ErrState
	}
	actual, e := r.Stat(".")
	if e != nil || !private(actual, true) || !os.SameFile(info, actual) {
		_ = r.Close()
		return nil, ErrState
	}
	failed = false
	return &Root{h, r, actual}, nil
}
func (r *Root) check() error {
	if r == nil || r.root == nil || r.home == nil {
		return ErrState
	}
	info, e := r.home.Lstat(".mydc")
	if e != nil || !private(info, true) || !os.SameFile(info, r.identity) {
		return ErrState
	}
	return nil
}
func validPath(name string) bool {
	if name == "" || len(name) > 4096 || path.Clean(name) != name || strings.HasPrefix(name, "/") || strings.ContainsAny(name, "\x00\\") {
		return false
	}
	for _, s := range strings.Split(name, "/") {
		if s == "." || s == ".." || s == "" || len(s) > 255 {
			return false
		}
	}
	return true
}

// parent walks every component without following symlinks. The returned root
// belongs to this call and remains anchored while the final operation executes.
func (r *Root) parent(name string, create bool) (*os.Root, string, error) {
	if r.check() != nil || !validPath(name) {
		return nil, "", ErrState
	}
	current, e := r.root.OpenRoot(".")
	if e != nil {
		return nil, "", ErrState
	}
	parts := strings.Split(name, "/")
	for _, part := range parts[:len(parts)-1] {
		if create {
			if e = current.Mkdir(part, 0700); e != nil && !errors.Is(e, fs.ErrExist) {
				_ = current.Close()
				return nil, "", ErrState
			}
			if syncRoot(current) != nil {
				_ = current.Close()
				return nil, "", ErrState
			}
		}
		info, e := current.Lstat(part)
		if e != nil {
			_ = current.Close()
			if errors.Is(e, fs.ErrNotExist) {
				return nil, "", fs.ErrNotExist
			}
			return nil, "", ErrState
		}
		if !private(info, true) {
			_ = current.Close()
			return nil, "", ErrState
		}
		next, e := current.OpenRoot(part)
		if e != nil {
			_ = current.Close()
			return nil, "", ErrState
		}
		actual, e := next.Stat(".")
		if e != nil || !private(actual, true) || !os.SameFile(info, actual) {
			_ = next.Close()
			_ = current.Close()
			return nil, "", ErrState
		}
		_ = current.Close()
		current = next
	}
	return current, parts[len(parts)-1], nil
}
func (r *Root) Read(name string, limit int) ([]byte, error) {
	if limit < 1 || limit > 2<<20 {
		return nil, ErrState
	}
	parent, leaf, e := r.parent(name, false)
	if e != nil {
		return nil, e
	}
	defer parent.Close()
	info, e := parent.Lstat(leaf)
	if e != nil {
		if errors.Is(e, fs.ErrNotExist) {
			return nil, fs.ErrNotExist
		}
		return nil, ErrState
	}
	if !private(info, false) {
		return nil, ErrState
	}
	f, e := parent.OpenFile(leaf, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, ErrState
	}
	defer f.Close()
	actual, e := f.Stat()
	if e != nil || !private(actual, false) || !os.SameFile(info, actual) {
		return nil, ErrState
	}
	b, e := io.ReadAll(io.LimitReader(f, int64(limit+1)))
	if e != nil || len(b) > limit {
		clear(b)
		return nil, ErrState
	}
	return b, nil
}
func (r *Root) WriteNew(name string, b []byte) (err error) {
	parent, leaf, e := r.parent(name, true)
	if e != nil {
		return e
	}
	defer parent.Close()
	f, e := parent.OpenFile(leaf, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return ErrState
	}
	info, e := f.Stat()
	if e != nil || !private(info, false) {
		_ = f.Close()
		return ErrState
	}
	defer func() {
		_ = f.Close()
		if err != nil {
			if now, e := parent.Lstat(leaf); e == nil && os.SameFile(info, now) {
				_ = parent.Remove(leaf)
				_ = syncRoot(parent)
			}
		}
	}()
	n, e := f.Write(b)
	if e != nil || n != len(b) || f.Sync() != nil {
		return ErrState
	}
	if f.Close() != nil || syncRoot(parent) != nil {
		return ErrState
	}
	return nil
}
func (r *Root) Rename(from, to string) error {
	src, a, e := r.parent(from, false)
	if e != nil {
		return e
	}
	defer src.Close()
	dst, b, e := r.parent(to, true)
	if e != nil {
		return e
	}
	defer dst.Close()
	i, e := src.Lstat(a)
	if e != nil || !private(i, false) {
		return ErrState
	}
	if i, e = dst.Lstat(b); e == nil {
		if !private(i, false) {
			return ErrState
		}
	} else if !errors.Is(e, fs.ErrNotExist) {
		return ErrState
	}
	// Root.Rename requires paths relative to one descriptor. Both parent walks
	// above validate components; the private-store lock coordinates our writers.
	if r.check() != nil || r.root.Rename(from, to) != nil {
		return ErrState
	}
	return nil
}
func (r *Root) Remove(name string) error {
	parent, leaf, e := r.parent(name, false)
	if e != nil {
		return e
	}
	defer parent.Close()
	info, e := parent.Lstat(leaf)
	if errors.Is(e, fs.ErrNotExist) {
		return nil
	}
	if e != nil || !private(info, false) {
		return ErrState
	}
	if parent.Remove(leaf) != nil {
		return ErrState
	}
	return nil
}
func (r *Root) Sync() error {
	if r.check() != nil {
		return ErrState
	}
	return syncRoot(r.root)
}
func (r *Root) Close() error {
	if r == nil {
		return nil
	}
	var e1, e2 error
	if r.root != nil {
		e1 = r.root.Close()
		r.root = nil
	}
	if r.home != nil {
		e2 = r.home.Close()
		r.home = nil
	}
	return errors.Join(e1, e2)
}

type Lock struct {
	file     *os.File
	root     *Root
	name     string
	identity os.FileInfo
}

func (r *Root) Lock(name string) (*Lock, error) {
	parent, leaf, e := r.parent(name, false)
	if e != nil {
		return nil, e
	}
	defer parent.Close()
	f, e := parent.OpenFile(leaf, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, ErrState
	}
	failed := true
	defer func() {
		if failed {
			_ = f.Close()
		}
	}()
	info, e := f.Stat()
	if e != nil || !private(info, false) {
		return nil, ErrState
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		if errors.Is(e, syscall.EWOULDBLOCK) {
			return nil, ErrBusy
		}
		return nil, ErrState
	}
	linked, e := parent.Lstat(leaf)
	if e != nil || !os.SameFile(info, linked) || !private(linked, false) {
		return nil, ErrState
	}
	if f.Sync() != nil || syncRoot(parent) != nil {
		return nil, ErrState
	}
	failed = false
	return &Lock{file: f, root: r, name: name, identity: info}, nil
}
func (l *Lock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	a := syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	b := l.file.Close()
	l.file = nil
	return errors.Join(a, b)
}

func (l *Lock) Check() error {
	if l == nil || l.file == nil || l.root == nil {
		return ErrState
	}
	parent, leaf, e := l.root.parent(l.name, false)
	if e != nil {
		return e
	}
	defer parent.Close()
	info, e := parent.Lstat(leaf)
	if e != nil || !private(info, false) || !os.SameFile(info, l.identity) {
		return ErrState
	}
	return nil
}

// Directory reports only a real, owned private directory. It never follows a
// link to discover another profile store or silently substitutes a default.
func (r *Root) Directory(name string, create bool) (bool, error) {
	parent, leaf, e := r.parent(name, create)
	if errors.Is(e, fs.ErrNotExist) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	defer parent.Close()
	if create {
		if e = parent.Mkdir(leaf, 0700); e != nil && !errors.Is(e, fs.ErrExist) {
			return false, ErrState
		}
		if syncRoot(parent) != nil {
			return false, ErrState
		}
	}
	info, e := parent.Lstat(leaf)
	if errors.Is(e, fs.ErrNotExist) {
		return false, nil
	}
	if e != nil || !private(info, true) {
		return false, ErrState
	}
	return true, nil
}
func (r *Root) Names(name string) ([]string, error) {
	parent, leaf, e := r.parent(name, false)
	if e != nil {
		return nil, e
	}
	defer parent.Close()
	info, e := parent.Lstat(leaf)
	if e != nil || !private(info, true) {
		return nil, ErrState
	}
	dir, e := parent.OpenRoot(leaf)
	if e != nil {
		return nil, ErrState
	}
	defer dir.Close()
	actual, e := dir.Stat(".")
	if e != nil || !os.SameFile(info, actual) {
		return nil, ErrState
	}
	f, e := dir.Open(".")
	if e != nil {
		return nil, ErrState
	}
	defer f.Close()
	names, e := f.Readdirnames(4097)
	if e != nil && e != io.EOF || len(names) > 4096 {
		return nil, ErrState
	}
	return names, nil
}
func (r *Root) ReadLink(name string) (string, bool, error) {
	parent, leaf, e := r.parent(name, false)
	if errors.Is(e, fs.ErrNotExist) {
		return "", false, nil
	}
	if e != nil {
		return "", false, e
	}
	defer parent.Close()
	return privateLink(parent, leaf)
}
func privateLink(parent *os.Root, leaf string) (string, bool, error) {
	info, e := parent.Lstat(leaf)
	if errors.Is(e, fs.ErrNotExist) {
		return "", false, nil
	}
	if e != nil {
		return "", false, ErrState
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || info.Mode()&os.ModeSymlink == 0 {
		return "", true, ErrState
	}
	target, e := parent.Readlink(leaf)
	if e != nil || target == "" || len(target) > 4096 || strings.ContainsRune(target, 0) {
		return "", true, ErrState
	}
	return target, true, nil
}

// SetLink changes one application-owned pointer under the caller's store lock.
// Only its caller knows the allowed relative target patterns (default/profile).
func (r *Root) SetLink(name, target string, expected *string) error {
	if target == "" || strings.HasPrefix(target, "/") || len(target) > 4096 || strings.ContainsRune(target, 0) {
		return ErrState
	}
	parent, leaf, e := r.parent(name, true)
	if e != nil {
		return e
	}
	defer parent.Close()
	current, exists, e := privateLink(parent, leaf)
	if e != nil {
		return e
	}
	if exists && current == target {
		return syncRoot(parent)
	}
	if expected == nil && exists || expected != nil && (!exists || current != *expected) {
		return ErrState
	}
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return ErrState
	}
	temp := leaf + ".new-" + hex.EncodeToString(nonce[:])
	if parent.Symlink(target, temp) != nil {
		return ErrState
	}
	info, e := parent.Lstat(temp)
	if e != nil {
		return ErrState
	}
	defer func() {
		if now, e := parent.Lstat(temp); e == nil && os.SameFile(now, info) {
			_ = parent.Remove(temp)
		}
	}()
	if syncRoot(parent) != nil {
		return ErrState
	}
	current, exists, e = privateLink(parent, leaf)
	if e != nil {
		return e
	}
	if expected == nil && exists || expected != nil && (!exists || current != *expected) {
		return ErrState
	}
	if r.check() != nil || parent.Rename(temp, leaf) != nil || syncRoot(parent) != nil {
		return ErrState
	}
	return nil
}

// RemoveLink removes only the caller's observed owned pointer. A replacement
// target/foreign inode is never treated as the old default to be cleaned up.
func (r *Root) RemoveLink(name, expected string) error {
	parent, leaf, err := r.parent(name, false)
	if err != nil {
		return err
	}
	defer parent.Close()
	current, exists, err := privateLink(parent, leaf)
	if err != nil {
		return err
	}
	if !exists {
		return syncRoot(parent)
	}
	if expected == "" || current != expected {
		return ErrState
	}
	before, err := parent.Lstat(leaf)
	if err != nil {
		return ErrState
	}
	current, exists, err = privateLink(parent, leaf)
	if err != nil || !exists || current != expected {
		return ErrState
	}
	after, err := parent.Lstat(leaf)
	if err != nil || !os.SameFile(before, after) || r.check() != nil || parent.Remove(leaf) != nil {
		return ErrState
	}
	return syncRoot(parent)
}
func (r *Root) SyncParent(name string) error {
	parent, _, e := r.parent(name, false)
	if e != nil {
		return e
	}
	defer parent.Close()
	return syncRoot(parent)
}

// ReplaceFile is a CAS against the exact old bytes. A fixed pending candidate
// can be reused only when it is exactly the accepted new bytes. The caller's
// durable intent is authoritative across an error/rename/directory-sync gap.
func (r *Root) ReplaceFile(name string, b []byte, expected [32]byte) error {
	current, e := r.Read(name, 2<<20)
	var got [32]byte
	if e == nil {
		got = sha256.Sum256(current)
	} else if !errors.Is(e, fs.ErrNotExist) {
		return e
	}
	clear(current)
	goal := sha256.Sum256(b)
	if got == goal {
		return r.SyncParent(name)
	}
	if got != expected {
		return ErrState
	}
	next := name + ".pending"
	candidate, e := r.Read(next, 2<<20)
	if errors.Is(e, fs.ErrNotExist) {
		if r.WriteNew(next, b) != nil {
			return ErrState
		}
	} else if e != nil || !bytes.Equal(candidate, b) {
		clear(candidate)
		return ErrState
	}
	clear(candidate)
	current, e = r.Read(name, 2<<20)
	got = [32]byte{}
	if e == nil {
		got = sha256.Sum256(current)
	} else if !errors.Is(e, fs.ErrNotExist) {
		return e
	}
	clear(current)
	if got != expected || r.Rename(next, name) != nil {
		return ErrState
	}
	return r.SyncParent(name)
}
