// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"bytes"
	"io"
	"io/fs"
	"path"
	"slices"
	"time"
)

// sourceFiles is the immutable import view shared by the interpreter and the
// compiler materializer. It has no OS/GOPATH fallback and exports no writable
// handles. It is not a sandbox for code execution.
type sourceFiles struct {
	files map[string][]byte
	dirs  map[string][]fs.DirEntry
}

func newSourceFiles(files map[string][]byte) *sourceFiles {
	f := &sourceFiles{files: map[string][]byte{}, dirs: map[string][]fs.DirEntry{".": nil}}
	for name, data := range files {
		f.files[name] = bytes.Clone(data)
		for dir := path.Dir(name); dir != "."; dir = path.Dir(dir) {
			f.dirs[dir] = nil
		}
	}
	for name, data := range f.files {
		dir := path.Dir(name)
		f.dirs[dir] = append(f.dirs[dir], sourceInfo{name: path.Base(name), size: int64(len(data))})
	}
	for name := range f.dirs {
		if name != "." {
			dir := path.Dir(name)
			f.dirs[dir] = append(f.dirs[dir], sourceInfo{name: path.Base(name), dir: true})
		}
	}
	for dir := range f.dirs {
		slices.SortFunc(f.dirs[dir], func(a, b fs.DirEntry) int {
			if a.Name() < b.Name() {
				return -1
			}
			if a.Name() > b.Name() {
				return 1
			}
			return 0
		})
	}
	return f
}

func (f *sourceFiles) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	if data, ok := f.files[name]; ok {
		return &sourceFile{Reader: bytes.NewReader(data), info: sourceInfo{name: path.Base(name), size: int64(len(data))}}, nil
	}
	if entries, ok := f.dirs[name]; ok {
		return &sourceFile{Reader: bytes.NewReader(nil), info: sourceInfo{name: path.Base(name), dir: true}, entries: entries}, nil
	}
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
}

func (f *sourceFiles) ReadFile(name string) ([]byte, error) {
	file, err := f.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, _ := file.Stat()
	if info.IsDir() {
		return nil, &fs.PathError{Op: "read", Path: name, Err: fs.ErrInvalid}
	}
	return io.ReadAll(file)
}

type sourceInfo struct {
	name string
	size int64
	dir  bool
}

func (s sourceInfo) Name() string { return s.name }
func (s sourceInfo) Size() int64  { return s.size }
func (s sourceInfo) Mode() fs.FileMode {
	if s.dir {
		return fs.ModeDir | 0555
	}
	return 0444
}
func (s sourceInfo) ModTime() time.Time         { return time.Time{} }
func (s sourceInfo) IsDir() bool                { return s.dir }
func (s sourceInfo) Sys() any                   { return nil }
func (s sourceInfo) Type() fs.FileMode          { return s.Mode().Type() }
func (s sourceInfo) Info() (fs.FileInfo, error) { return s, nil }

type sourceFile struct {
	*bytes.Reader
	info    sourceInfo
	entries []fs.DirEntry
	offset  int
	closed  bool
}

func (f *sourceFile) Stat() (fs.FileInfo, error) {
	if f.closed {
		return nil, fs.ErrClosed
	}
	return f.info, nil
}
func (f *sourceFile) Close() error { f.closed = true; return nil }
func (f *sourceFile) Read(p []byte) (int, error) {
	if f.closed {
		return 0, fs.ErrClosed
	}
	if f.info.dir {
		return 0, fs.ErrInvalid
	}
	return f.Reader.Read(p)
}
func (f *sourceFile) ReadDir(n int) ([]fs.DirEntry, error) {
	if f.closed {
		return nil, fs.ErrClosed
	}
	if !f.info.dir {
		return nil, fs.ErrInvalid
	}
	if f.offset == len(f.entries) && n > 0 {
		return nil, io.EOF
	}
	end := len(f.entries)
	if n > 0 && n < end-f.offset {
		end = f.offset + n
	}
	entries := slices.Clone(f.entries[f.offset:end])
	f.offset = end
	return entries, nil
}
