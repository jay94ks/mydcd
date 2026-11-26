// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"io/fs"
)

// WriteZIP freezes exactly this revision without editing it. File readers are
// opened one at a time and always closed; only the Dockerfile is buffered.
// The caller must keep the source store/root borrowed until this call returns.
func (d Draft) WriteZIP(ctx context.Context, output io.Writer, open func(Entry) (io.ReadCloser, error)) (Tree, error) {
	if d.Validate() != nil || output == nil || open == nil {
		return Tree{}, ErrInvalid
	}
	found := false
	for _, e := range d.Entries {
		if e.Path == d.Scope.Dockerfile && !e.Directory {
			found = true
		}
	}
	if !found {
		return Tree{}, ErrInvalid
	}
	w := zip.NewWriter(&contextZIPWriter{output: output, remaining: MaxZIPBytes})
	tree := Tree{Entries: make([]Entry, 0, len(d.Entries))}
	buffer := make([]byte, PartBytes)
	for _, e := range d.Entries {
		if err := ctx.Err(); err != nil {
			return Tree{}, err
		}
		header := &zip.FileHeader{Name: e.Path, Method: zip.Store}
		mode := fs.FileMode(0600)
		if e.Directory {
			header.Name += "/"
			mode = 0700 | fs.ModeDir
		} else if e.Executable {
			mode = 0700
		}
		header.SetMode(mode)
		out, err := w.CreateHeader(header)
		if err != nil {
			return Tree{}, err
		}
		if !e.Directory {
			reader, err := open(e)
			if err != nil {
				return Tree{}, err
			}
			if reader == nil {
				return Tree{}, ErrStorage
			}
			hash := sha256.New()
			dst := io.MultiWriter(out, hash)
			var script bytes.Buffer
			if e.Path == d.Scope.Dockerfile {
				dst = io.MultiWriter(out, hash, &script)
			}
			n, copyErr := io.CopyBuffer(dst, io.LimitReader(contextReader{ctx, reader}, e.Bytes+1), buffer)
			closeErr := reader.Close()
			if copyErr != nil {
				return Tree{}, copyErr
			}
			if closeErr != nil {
				return Tree{}, ErrStorage
			}
			if n != e.Bytes || !bytes.Equal(hash.Sum(nil), e.Digest[:]) {
				return Tree{}, ErrDigest
			}
			if e.Path == d.Scope.Dockerfile {
				tree.Dockerfile = script.Bytes()
			}
		}
		tree.Entries = append(tree.Entries, e)
		tree.Bytes += e.Bytes
	}
	if err := w.Close(); err != nil {
		return Tree{}, err
	}
	return tree, nil
}
