// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"archive/tar"
	"archive/zip"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"path"
	"slices"
	"strings"
	"time"
)

// WriteContextTAR is the native SDK input encoder. It emits only the fixed
// context/ subtree, from the same sealed ZIP validator used by admission.
// The owner retains the original artifact reader/root pin through completion.
// Partial output on error is NOT a staged/ready context or retry authority.
func WriteContextTAR(ctx context.Context, body io.ReaderAt, scope UploadScope, seal SealReceipt, output io.Writer) (Tree, error) {
	if ctx == nil || body == nil || output == nil || !seal.Valid(scope) {
		return Tree{}, ErrInvalid
	}
	hash := sha256.New()
	if n, err := io.CopyBuffer(hash, contextReader{ctx, io.NewSectionReader(body, 0, scope.Length)}, make([]byte, 32<<10)); err != nil || n != scope.Length {
		return Tree{}, errors.Join(ErrStorage, err)
	}
	if string(hash.Sum(nil)) != string(scope.Digest[:]) {
		return Tree{}, ErrDigest
	}
	tree, err := InspectZIP(ctx, body, scope.Length, scope.Dockerfile, scope.ExpandedLimit)
	if err != nil {
		return Tree{}, err
	}
	if tree.Digest() != seal.Tree || tree.Bytes != seal.ExpandedBytes || uint32(len(tree.Entries)) != seal.Entries {
		return Tree{}, ErrDigest
	}
	archive, err := zip.NewReader(body, scope.Length)
	if err != nil {
		return Tree{}, ErrInvalid
	}
	files := map[string]*zip.File{}
	for _, file := range archive.File {
		files[strings.TrimSuffix(file.Name, "/")] = file
	}
	// ZIPs need not spell out directories. Bound the implicit parent set too;
	// a collection of deeply nested paths cannot expand metadata without bound.
	entries := map[string]Entry{}
	for _, entry := range tree.Entries {
		entries[entry.Path] = entry
		for dir := path.Dir(entry.Path); dir != "."; dir = path.Dir(dir) {
			if old, found := entries[dir]; found && !old.Directory {
				return Tree{}, ErrInvalid
			}
			entries[dir] = Entry{Path: dir, Directory: true}
			if len(entries) > MaxTreeEntries {
				return Tree{}, ErrInvalid
			}
		}
	}
	if len(entries) > MaxTreeEntries {
		return Tree{}, ErrInvalid
	}
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	slices.Sort(names)
	limit := tree.Bytes + int64(len(entries)+1)*(6<<10) + 1024
	writer := &contextTARWriter{ctx: ctx, output: output, remaining: limit}
	tw := tar.NewWriter(writer)
	header := func(name string, entry Entry) error {
		mode := int64(0444)
		kind := byte(tar.TypeReg)
		if entry.Directory {
			mode, kind = 0555, tar.TypeDir
			name += "/"
		} else if entry.Executable {
			mode = 0555
		}
		return tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Typeflag: kind, Size: entry.Bytes, Uid: 0, Gid: 0, ModTime: time.Unix(0, 0), Format: tar.FormatPAX})
	}
	if err := header("context", Entry{Directory: true}); err != nil {
		return Tree{}, err
	}
	buffer := make([]byte, 32<<10)
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return Tree{}, err
		}
		entry := entries[name]
		if err := header("context/"+name, entry); err != nil {
			return Tree{}, err
		}
		if entry.Directory {
			continue
		}
		file := files[name]
		if file == nil {
			return Tree{}, ErrInvalid
		}
		reader, err := file.Open()
		if err != nil {
			return Tree{}, ErrInvalid
		}
		hash := sha256.New()
		n, copyErr := io.CopyBuffer(io.MultiWriter(tw, hash), io.LimitReader(contextReader{ctx, reader}, entry.Bytes+1), buffer)
		closeErr := reader.Close()
		if copyErr != nil || closeErr != nil || n != entry.Bytes || string(hash.Sum(nil)) != string(entry.Digest[:]) {
			return Tree{}, errors.Join(ErrDigest, copyErr, closeErr)
		}
	}
	if err := tw.Close(); err != nil {
		return Tree{}, err
	}
	return tree, nil
}

type contextTARWriter struct {
	ctx       context.Context
	output    io.Writer
	remaining int64
}

func (w *contextTARWriter) Write(p []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
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
