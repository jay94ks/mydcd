// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"io/fs"
	"slices"
	"strings"
)

type Entry struct {
	Path                  string
	Directory, Executable bool
	Bytes                 int64
	Digest                [32]byte
}
type Tree struct {
	Entries    []Entry
	Bytes      int64
	Dockerfile []byte `json:"-"`
}

func (t Tree) Digest() [32]byte {
	return digestJSON("mydc-imagebuild-tree-1", struct {
		Entries []Entry
		Bytes   int64
	}{t.Entries, t.Bytes})
}

type contextReader struct {
	ctx context.Context
	io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.Reader.Read(p)
}

// InspectZIP streams and checks every regular file's declared size, CRC and
// SHA-256. No extraction is performed and neither ZIP nor expanded tree is
// buffered in memory. Only the bounded Dockerfile and public tree are retained.
func InspectZIP(ctx context.Context, body io.ReaderAt, length int64, dockerfile string, expandedLimit int64) (Tree, error) {
	if length <= 0 || length > MaxZIPBytes || !ContextPath(dockerfile) || expandedLimit <= 0 || expandedLimit > MaxExpandedBytes {
		return Tree{}, ErrInvalid
	}
	if err := checkZIPBudget(body, length); err != nil {
		return Tree{}, err
	}
	z, err := zip.NewReader(body, length)
	if err != nil || len(z.File) == 0 || len(z.File) > MaxTreeEntries {
		return Tree{}, ErrInvalid
	}
	tree := Tree{}
	paths := map[string]bool{}
	found := false
	buf := make([]byte, 32<<10)
	for _, file := range z.File {
		if err := ctx.Err(); err != nil {
			return Tree{}, err
		}
		mode := file.Mode()
		dir := mode.IsDir()
		name := file.Name
		if dir {
			name = strings.TrimSuffix(name, "/")
		}
		if !ContextPath(name) || mode&(fs.ModeSymlink|fs.ModeDevice|fs.ModeNamedPipe|fs.ModeSocket|fs.ModeIrregular|fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) != 0 || file.ExternalAttrs&0x400 != 0 || !dir && !mode.IsRegular() || dir && file.UncompressedSize64 != 0 || unsafeZIPExtra(file.Extra) {
			return Tree{}, ErrInvalid
		}
		if _, exists := paths[name]; exists {
			return Tree{}, ErrInvalid
		}
		paths[name] = dir
		entry := Entry{Path: name, Directory: dir, Executable: !dir && mode.Perm()&0111 != 0}
		if !dir {
			remaining := expandedLimit - tree.Bytes
			if file.UncompressedSize64 > uint64(remaining) || name == dockerfile && file.UncompressedSize64 > MaxDockerfileBytes {
				return Tree{}, ErrInvalid
			}
			reader, err := file.Open()
			if err != nil {
				return Tree{}, ErrInvalid
			}
			hash := sha256.New()
			var target io.Writer = hash
			var script strings.Builder
			if name == dockerfile {
				target = io.MultiWriter(hash, &script)
			}
			// Exactly one extra byte detects malformed size metadata without an
			// unbounded read, including files with declared uncompressed size 0.
			n, copyErr := io.CopyBuffer(target, io.LimitReader(contextReader{ctx, reader}, int64(file.UncompressedSize64)+1), buf)
			closeErr := reader.Close()
			if copyErr != nil || closeErr != nil || n != int64(file.UncompressedSize64) {
				if err := ctx.Err(); err != nil {
					return Tree{}, err
				}
				return Tree{}, ErrInvalid
			}
			entry.Bytes = n
			copy(entry.Digest[:], hash.Sum(nil))
			tree.Bytes += n
			if name == dockerfile {
				tree.Dockerfile = []byte(script.String())
				found = true
			}
		}
		tree.Entries = append(tree.Entries, entry)
	}
	if !found {
		return Tree{}, ErrInvalid
	}
	// Directory/file prefix collisions must be checked after the full listing:
	// ZIP entry order cannot determine whether an ancestor is a file.
	for name := range paths {
		for prefix, _, ok := strings.Cut(name, "/"); ok; {
			if dir, exists := paths[prefix]; exists && !dir {
				return Tree{}, ErrInvalid
			}
			next := strings.IndexByte(name[len(prefix)+1:], '/')
			if next < 0 {
				break
			}
			prefix = name[:len(prefix)+1+next]
		}
	}
	slices.SortFunc(tree.Entries, func(a, b Entry) int { return strings.Compare(a.Path, b.Path) })
	return tree, nil
}

// Old Unix/ASi extensions can carry link targets even when a ZIP reader
// presents a regular mode. They are not part of the accepted context format.
func unsafeZIPExtra(extra []byte) bool {
	for len(extra) > 0 {
		if len(extra) < 4 {
			return true
		}
		kind, n := binary.LittleEndian.Uint16(extra), int(binary.LittleEndian.Uint16(extra[2:]))
		extra = extra[4:]
		if n > len(extra) || kind == 0x000d || kind == 0x756e {
			return true
		}
		extra = extra[n:]
	}
	return false
}
