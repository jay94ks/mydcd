// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"io/fs"
	"slices"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// WriteGitZIP consumes only an authenticated, already fetched repository and
// exact commit. It writes a deterministic context archive without checkout,
// hooks, local-file fallback or a submodule/LFS network request. The caller
// owns its registered-root output file and publishes a version only on success.
func WriteGitZIP(ctx context.Context, repo *git.Repository, commit, folder, dockerfile string, output io.Writer, expandedLimit int64) (Tree, error) {
	if repo == nil || output == nil || len(commit) != 40 || plumbing.NewHash(commit).String() != commit || folder != "." && !ContextPath(folder) || !ContextPath(dockerfile) || expandedLimit <= 0 || expandedLimit > MaxExpandedBytes {
		return Tree{}, ErrInvalid
	}
	c, err := repo.CommitObject(plumbing.NewHash(commit))
	if err != nil {
		return Tree{}, ErrSourceFetch
	}
	root, err := c.Tree()
	if err != nil {
		return Tree{}, ErrSourceFetch
	}
	if folder != "." {
		// Tree traversal never follows a symlink whose blob contains a path.
		for _, part := range strings.Split(folder, "/") {
			entry, err := root.FindEntry(part)
			if err != nil || entry.Mode != filemode.Dir {
				return Tree{}, ErrInvalid
			}
			root, err = repo.TreeObject(entry.Hash)
			if err != nil {
				return Tree{}, ErrSourceFetch
			}
		}
	}
	counted := &contextZIPWriter{output: output, remaining: MaxZIPBytes}
	w := zip.NewWriter(counted)
	tree := Tree{}
	found := false
	buffer := make([]byte, 32<<10)
	var walk func(*object.Tree, string, int) error
	walk = func(current *object.Tree, prefix string, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if depth > 32 {
			return ErrInvalid
		}
		entries := slices.Clone(current.Entries)
		slices.SortFunc(entries, func(a, b object.TreeEntry) int { return strings.Compare(a.Name, b.Name) })
		for _, e := range entries {
			name := prefix + e.Name
			if !ContextPath(name) || strings.Contains(e.Name, "/") || len(tree.Entries) >= MaxTreeEntries {
				return ErrInvalid
			}
			if e.Mode == filemode.Dir {
				dir, err := repo.TreeObject(e.Hash)
				if err != nil {
					return ErrSourceFetch
				}
				header := &zip.FileHeader{Name: name + "/", Method: zip.Store}
				header.SetMode(0700 | fs.ModeDir)
				if _, err := w.CreateHeader(header); err != nil {
					return ErrSourceFetch
				}
				tree.Entries = append(tree.Entries, Entry{Path: name, Directory: true})
				if err := walk(dir, name+"/", depth+1); err != nil {
					return err
				}
				continue
			}
			if e.Mode != filemode.Regular && e.Mode != filemode.Executable {
				return ErrInvalid
			}
			blob, err := repo.BlobObject(e.Hash)
			if err != nil || blob.Size < 0 || blob.Size > expandedLimit-tree.Bytes || name == dockerfile && blob.Size > MaxDockerfileBytes {
				return ErrInvalid
			}
			reader, err := blob.Reader()
			if err != nil {
				return ErrSourceFetch
			}
			peek := bufio.NewReader(reader)
			first, _ := peek.Peek(128)
			if bytes.HasPrefix(first, []byte("version https://git-lfs.github.com/spec/v1\n")) {
				_ = reader.Close()
				return ErrInvalid
			}
			header := &zip.FileHeader{Name: name, Method: zip.Store}
			header.SetMode(0600)
			if e.Mode == filemode.Executable {
				header.SetMode(0700)
			}
			out, err := w.CreateHeader(header)
			if err != nil {
				_ = reader.Close()
				return ErrSourceFetch
			}
			hash := sha256.New()
			destination := io.MultiWriter(out, hash)
			var script bytes.Buffer
			if name == dockerfile {
				destination = io.MultiWriter(out, hash, &script)
			}
			n, copyErr := io.CopyBuffer(destination, io.LimitReader(contextReader{ctx, peek}, blob.Size+1), buffer)
			closeErr := reader.Close()
			if copyErr != nil || closeErr != nil || n != blob.Size {
				return ErrSourceFetch
			}
			entry := Entry{Path: name, Bytes: n, Executable: e.Mode == filemode.Executable}
			copy(entry.Digest[:], hash.Sum(nil))
			tree.Entries = append(tree.Entries, entry)
			tree.Bytes += n
			if name == dockerfile {
				found = true
				tree.Dockerfile = script.Bytes()
			}
		}
		return nil
	}
	if err := walk(root, "", 0); err != nil {
		_ = w.Close()
		return Tree{}, err
	}
	if !found {
		_ = w.Close()
		return Tree{}, ErrInvalid
	}
	if err := w.Close(); err != nil {
		return Tree{}, ErrSourceFetch
	}
	slices.SortFunc(tree.Entries, func(a, b Entry) int { return strings.Compare(a.Path, b.Path) })
	return tree, nil
}

type contextZIPWriter struct {
	output    io.Writer
	remaining int64
}

func (w *contextZIPWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		return 0, ErrInvalid
	}
	n, err := w.output.Write(p)
	w.remaining -= int64(n)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	return n, err
}
