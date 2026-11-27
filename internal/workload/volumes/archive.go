// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"errors"
	"hash"
	"io"
	"math"
	"os"
	"path"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var ErrArchive = errors.New("volume archive incomplete, inconsistent or unsupported")
var ErrArchiveLimit = errors.New("volume archive budget exceeded")

// ArchiveOptions is a cluster-approved file profile, not permission to read a
// source or start a writer. MaxBytes includes tar metadata, padding and footer.
// Sparse placement/atime/ctime are not restored; logical contents and mtime are.
type ArchiveOptions struct {
	MaxBytes           uint64
	MaxEntries         uint32
	MaxDepth           int
	UID, GID, RootMode uint32
}

func (o ArchiveOptions) valid() bool {
	return o.MaxBytes >= 1024 && o.MaxBytes <= 1<<40 && o.MaxEntries > 0 && o.MaxEntries <= 1_000_000 && o.MaxDepth > 0 && o.MaxDepth <= 128 && o.UID > 0 && o.GID > 0 && o.UID <= math.MaxInt32 && o.GID <= math.MaxInt32 && o.RootMode&0700 == 0700 && o.RootMode&^uint32(0770) == 0
}

// ArchiveReceipt contains public integrity metadata, never filenames or data.
// It is not a quorum commit, synced-file proof or SQL consistency attestation.
type ArchiveReceipt struct {
	Schema           uint8
	Digest           [32]byte
	Bytes, DataBytes uint64
	Entries          uint32
}

func (r ArchiveReceipt) Validate(o ArchiveOptions) error {
	if !r.valid(o) {
		return ErrArchive
	}
	return nil
}
func (r ArchiveReceipt) valid(o ArchiveOptions) bool {
	return o.valid() && r.Schema == 1 && r.Digest != ([32]byte{}) && r.Bytes >= 1024 && r.Bytes <= o.MaxBytes && r.Bytes%512 == 0 && r.DataBytes <= r.Bytes && r.Entries > 0 && r.Entries <= o.MaxEntries
}

type archiveEntry struct {
	name      string
	mode      int64
	size      int64
	uid, gid  int
	modified  time.Time
	directory bool
	info      os.FileInfo
}

func archiveName(name string, root bool, depth int) bool {
	if root {
		return name == "."
	}
	return name != "." && name != "" && len(name) <= 4096 && !strings.ContainsAny(name, "\\\x00") && !path.IsAbs(name) && path.Clean(name) == name && name != ".." && !strings.HasPrefix(name, "../") && strings.Count(name, "/")+1 <= depth
}
func archiveError(err error) error {
	if errors.Is(err, ErrArchiveLimit) {
		return ErrArchiveLimit
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return errors.Join(ErrArchive, err)
	}
	var number syscall.Errno
	if errors.As(err, &number) {
		return errors.Join(ErrArchive, number)
	}
	return ErrArchive
}
func sameArchiveInfo(a, b os.FileInfo) bool {
	x, ok := a.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	y, ok := b.Sys().(*syscall.Stat_t)
	return ok && os.SameFile(a, b) && x.Mode == y.Mode && x.Uid == y.Uid && x.Gid == y.Gid && x.Nlink == y.Nlink && x.Size == y.Size && x.Mtim == y.Mtim && x.Ctim == y.Ctim
}
func archiveFile(root *os.Root, e archiveEntry) (*os.File, error) {
	flags := os.O_RDONLY | syscall.O_NOFOLLOW
	if e.directory {
		flags |= syscall.O_DIRECTORY
	}
	f, err := root.OpenFile(e.name, flags, 0)
	if err != nil {
		return nil, archiveError(err)
	}
	info, err := f.Stat()
	if err != nil || !sameArchiveInfo(e.info, info) {
		_ = f.Close()
		return nil, ErrArchive
	}
	count, err := unix.Flistxattr(int(f.Fd()), nil)
	if err != nil || count != 0 {
		_ = f.Close()
		return nil, ErrArchive
	}
	return f, nil
}
func planArchive(ctx context.Context, root *os.Root, o ArchiveOptions) ([]archiveEntry, error) {
	if !o.valid() || root == nil {
		return nil, ErrArchiveLimit
	}
	first, err := root.Lstat(".")
	if err != nil || !first.IsDir() {
		return nil, ErrArchive
	}
	stat, ok := first.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, ErrArchive
	}
	var entries []archiveEntry
	var data uint64
	var visit func(string, int) error
	visit = func(name string, depth int) error {
		if err := ctx.Err(); err != nil {
			return archiveError(err)
		}
		if uint32(len(entries)) >= o.MaxEntries || depth > o.MaxDepth {
			return ErrArchiveLimit
		}
		info, err := root.Lstat(name)
		if err != nil {
			return archiveError(err)
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Dev != stat.Dev || st.Uid != o.UID || st.Gid != o.GID || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || !info.IsDir() && !info.Mode().IsRegular() || !info.IsDir() && st.Nlink != 1 || st.Size < 0 || !archiveName(name, name == ".", o.MaxDepth) {
			return ErrArchive
		}
		if name == "." && uint32(info.Mode().Perm()) != o.RootMode {
			return ErrArchive
		}
		e := archiveEntry{name: name, mode: int64(info.Mode().Perm()), uid: int(st.Uid), gid: int(st.Gid), modified: info.ModTime(), directory: info.IsDir(), info: info}
		if !e.directory {
			e.size = st.Size
			if uint64(e.size) > o.MaxBytes-data {
				return ErrArchiveLimit
			}
			data += uint64(e.size)
		}
		f, err := archiveFile(root, e)
		if err != nil {
			return err
		}
		defer f.Close()
		entries = append(entries, e)
		if !e.directory {
			return nil
		}
		for {
			batch, err := f.ReadDir(64)
			if err != nil && !errors.Is(err, io.EOF) {
				return archiveError(err)
			}
			for _, child := range batch {
				if err := visit(path.Join(name, child.Name()), depth+1); err != nil {
					return err
				}
			}
			if errors.Is(err, io.EOF) {
				break
			}
		}
		after, err := f.Stat()
		if err != nil || !sameArchiveInfo(info, after) {
			return ErrArchive
		}
		return nil
	}
	if err = visit(".", 0); err != nil {
		return nil, err
	}
	// visit always appends the root first. Keep it there: valid child names
	// such as MySQL's #innodb_redo sort BEFORE ".". The reader requires the
	// root, then parents before children; lexical ordering of descendants
	// already preserves each parent prefix without moving the root.
	slices.SortFunc(entries[1:], func(a, b archiveEntry) int { return strings.Compare(a.name, b.name) })
	return entries, nil
}

type archiveIO struct {
	ctx      context.Context
	writer   io.Writer
	reader   io.Reader
	digest   hash.Hash
	limit, n uint64
}

func (s *archiveIO) Write(p []byte) (int, error) {
	if err := s.ctx.Err(); err != nil {
		return 0, archiveError(err)
	}
	if uint64(len(p)) > s.limit-s.n {
		return 0, ErrArchiveLimit
	}
	n, err := s.writer.Write(p)
	if n < 0 || n > len(p) {
		return 0, ErrArchive
	}
	if n > 0 {
		_, _ = s.digest.Write(p[:n])
		s.n += uint64(n)
	}
	if err != nil {
		return n, archiveError(err)
	}
	if n != len(p) {
		return n, io.ErrShortWrite
	}
	return n, nil
}
func (s *archiveIO) Read(p []byte) (int, error) {
	if err := s.ctx.Err(); err != nil {
		return 0, archiveError(err)
	}
	if s.n >= s.limit {
		return 0, ErrArchiveLimit
	}
	if uint64(len(p)) > s.limit-s.n {
		p = p[:s.limit-s.n]
	}
	n, err := s.reader.Read(p)
	if n > 0 {
		_, _ = s.digest.Write(p[:n])
		s.n += uint64(n)
	}
	return n, err
}

type archiveContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r archiveContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

// WriteArchive preflights the bounded source and detects changes while reading.
// Its caller must already hold the authoritative cold reader and native pin.
// On failure, any partial output is an unpublished owned staging artifact.
func WriteArchive(ctx context.Context, root *os.Root, out io.Writer, o ArchiveOptions) (ArchiveReceipt, error) {
	entries, err := planArchive(ctx, root, o)
	if err != nil {
		return ArchiveReceipt{}, err
	}
	if file, ok := out.(*os.File); ok {
		output, err := file.Stat()
		if err != nil {
			return ArchiveReceipt{}, ErrArchive
		}
		for _, entry := range entries {
			if os.SameFile(output, entry.info) {
				return ArchiveReceipt{}, ErrArchive
			}
		}
	}
	stream := &archiveIO{ctx: ctx, writer: out, digest: sha256.New(), limit: o.MaxBytes}
	writer := tar.NewWriter(stream)
	result := ArchiveReceipt{Schema: 1, Entries: uint32(len(entries))}
	buffer := make([]byte, 32<<10)
	for _, e := range entries {
		kind := byte(tar.TypeReg)
		if e.directory {
			kind = tar.TypeDir
		}
		header := tar.Header{Name: e.name, Mode: e.mode, Uid: e.uid, Gid: e.gid, Size: e.size, ModTime: e.modified, Typeflag: kind, Format: tar.FormatPAX}
		if err = writer.WriteHeader(&header); err != nil {
			return ArchiveReceipt{}, archiveError(err)
		}
		f, err := archiveFile(root, e)
		if err != nil {
			return ArchiveReceipt{}, err
		}
		if !e.directory {
			n, copyErr := io.CopyBuffer(writer, archiveContextReader{ctx, f}, buffer)
			if copyErr != nil || n != e.size {
				_ = f.Close()
				return ArchiveReceipt{}, archiveError(copyErr)
			}
			result.DataBytes += uint64(n)
		}
		after, statErr := f.Stat()
		closeErr := f.Close()
		if statErr != nil || closeErr != nil || !sameArchiveInfo(e.info, after) {
			return ArchiveReceipt{}, ErrArchive
		}
	}
	// This also catches source additions/removals and changes after an earlier file.
	latest, err := planArchive(ctx, root, o)
	if err != nil || len(latest) != len(entries) {
		return ArchiveReceipt{}, ErrArchive
	}
	for i, e := range latest {
		if e.name != entries[i].name || !sameArchiveInfo(entries[i].info, e.info) {
			return ArchiveReceipt{}, ErrArchive
		}
	}
	if err = writer.Close(); err != nil {
		return ArchiveReceipt{}, archiveError(err)
	}
	result.Bytes = stream.n
	copy(result.Digest[:], stream.digest.Sum(nil))
	return result, nil
}

func archiveHeader(h *tar.Header, o ArchiveOptions, first bool) (archiveEntry, error) {
	if !archiveName(h.Name, first, o.MaxDepth) || h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeDir || h.Mode < 0 || h.Mode&^int64(0777) != 0 || h.Uid != int(o.UID) || h.Gid != int(o.GID) || h.Size < 0 || h.Linkname != "" || h.Devmajor != 0 || h.Devminor != 0 || len(h.Xattrs) != 0 || h.Uname != "" || h.Gname != "" || h.Format != tar.FormatUSTAR && h.Format != tar.FormatPAX || !h.AccessTime.IsZero() || !h.ChangeTime.IsZero() {
		return archiveEntry{}, ErrArchive
	}
	for key := range h.PAXRecords {
		if key != "path" && key != "size" && key != "uid" && key != "gid" && key != "mtime" {
			return archiveEntry{}, ErrArchive
		}
	}
	directory := h.Typeflag == tar.TypeDir
	if directory && h.Size != 0 || first && (!directory || uint32(h.Mode) != o.RootMode) {
		return archiveEntry{}, ErrArchive
	}
	return archiveEntry{name: h.Name, mode: h.Mode, size: h.Size, uid: h.Uid, gid: h.Gid, modified: h.ModTime, directory: directory}, nil
}
func sameArchiveEntry(a, b archiveEntry) bool {
	return a.name == b.name && a.mode == b.mode && a.size == b.size && a.uid == b.uid && a.gid == b.gid && a.modified.Equal(b.modified) && a.directory == b.directory
}

// readArchive enforces exact EOF/footer and hashes every raw archive byte. An
// expected receipt is checked before any restore write and again during restore.
func readArchive(ctx context.Context, in io.ReadSeeker, expected ArchiveReceipt, o ArchiveOptions, consume func(*tar.Reader, archiveEntry) error) ([]archiveEntry, error) {
	if !expected.valid(o) {
		return nil, ErrArchive
	}
	length, err := in.Seek(0, io.SeekEnd)
	if err != nil || length < 0 || uint64(length) != expected.Bytes {
		return nil, ErrArchive
	}
	if _, err = in.Seek(0, io.SeekStart); err != nil {
		return nil, ErrArchive
	}
	stream := &archiveIO{ctx: ctx, reader: in, digest: sha256.New(), limit: expected.Bytes + 1}
	reader := tar.NewReader(stream)
	var entries []archiveEntry
	seen := map[string]bool{}
	var data uint64
	buffer := make([]byte, 32<<10)
	for {
		before := stream.n
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			if stream.n != expected.Bytes || stream.n-before < 1024 {
				return nil, ErrArchive
			}
			break
		}
		if err != nil || uint32(len(entries)) >= o.MaxEntries {
			return nil, ErrArchive
		}
		e, err := archiveHeader(header, o, len(entries) == 0)
		_, duplicate := seen[e.name]
		if err != nil || duplicate || len(entries) > 0 && !seen[path.Dir(e.name)] {
			return nil, ErrArchive
		}

		if uint64(e.size) > o.MaxBytes-data {
			return nil, ErrArchiveLimit
		}
		data += uint64(e.size)
		entries = append(entries, e)
		seen[e.name] = e.directory
		if consume == nil {
			if _, err = io.CopyBuffer(io.Discard, reader, buffer); err != nil {
				return nil, archiveError(err)
			}
		} else if err = consume(reader, e); err != nil {
			return nil, err
		}
	}
	var digest [32]byte
	copy(digest[:], stream.digest.Sum(nil))
	if digest != expected.Digest || uint32(len(entries)) != expected.Entries || data != expected.DataBytes {
		return nil, ErrArchive
	}
	return entries, nil
}

// archiveFiles is the actual file-write/sync boundary. Failure injection is
// isolated in tests; the product uses os.File directly and keeps one algorithm.
type archiveFiles struct {
	write func(*os.File, []byte) (int, error)
	sync  func(*os.File) error
}

func systemArchiveFiles() archiveFiles {
	return archiveFiles{write: (*os.File).Write, sync: (*os.File).Sync}
}

type archiveOutputFile struct {
	file  *os.File
	write func(*os.File, []byte) (int, error)
}

func (w archiveOutputFile) Write(p []byte) (int, error) { return w.write(w.file, p) }

// RestoreArchive changes only an empty inactive root. Invalid/partial artifacts
// fail before writes; later I/O failure leaves unpublished staging for explicit
// cleanup/recovery. It never empties or overwrites an existing data directory.
func RestoreArchive(ctx context.Context, root *os.Root, in io.ReadSeeker, expected ArchiveReceipt, o ArchiveOptions) error {
	return restoreArchive(ctx, root, in, expected, o, systemArchiveFiles())
}

// VerifyArchive uses the same strict profile/parser/digest as RestoreArchive
// without writing a target or accepting a readable prefix as completion.
func VerifyArchive(ctx context.Context, in io.ReadSeeker, expected ArchiveReceipt, o ArchiveOptions) error {
	_, err := readArchive(ctx, in, expected, o, nil)
	return err
}
func restoreArchive(ctx context.Context, root *os.Root, in io.ReadSeeker, expected ArchiveReceipt, o ArchiveOptions, files archiveFiles) error {
	if root == nil || files.write == nil || files.sync == nil {
		return ErrArchive
	}
	directory, err := root.Open(".")
	if err != nil {
		return ErrArchive
	}
	before, err := directory.ReadDir(1)
	_ = directory.Close()
	if !errors.Is(err, io.EOF) || len(before) != 0 {
		return ErrArchive
	}
	entries, err := readArchive(ctx, in, expected, o, nil)
	if err != nil {
		return err
	}
	index := 0
	buffer := make([]byte, 32<<10)
	consume := func(reader *tar.Reader, e archiveEntry) error {
		if index >= len(entries) || !sameArchiveEntry(entries[index], e) {
			return ErrArchive
		}
		index++
		if e.directory {
			if e.name != "." {
				if err := root.Mkdir(e.name, 0700); err != nil {
					return archiveError(err)
				}
			}
			return nil
		}
		f, err := root.OpenFile(e.name, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
		if err != nil {
			return archiveError(err)
		}
		n, copyErr := io.CopyBuffer(archiveOutputFile{f, files.write}, archiveContextReader{ctx, reader}, buffer)
		if copyErr == nil && n != e.size {
			copyErr = io.ErrUnexpectedEOF
		}
		if copyErr == nil {
			copyErr = f.Chown(e.uid, e.gid)
		}
		if copyErr == nil {
			copyErr = f.Chmod(os.FileMode(e.mode))
		}
		if copyErr == nil {
			copyErr = root.Chtimes(e.name, e.modified, e.modified)
		}
		if copyErr == nil {
			copyErr = files.sync(f)
		}
		closeErr := f.Close()
		if copyErr != nil {
			return archiveError(copyErr)
		}
		if closeErr != nil {
			return archiveError(closeErr)
		}
		return nil
	}
	if _, err = readArchive(ctx, in, expected, o, consume); err != nil {
		return err
	}
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		if !e.directory {
			continue
		}
		if err = root.Chown(e.name, e.uid, e.gid); err != nil {
			return archiveError(err)
		}
		if err = root.Chmod(e.name, os.FileMode(e.mode)); err != nil {
			return archiveError(err)
		}
		if err = root.Chtimes(e.name, e.modified, e.modified); err != nil {
			return archiveError(err)
		}
		f, err := root.OpenFile(e.name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
		if err != nil {
			return archiveError(err)
		}
		syncErr := files.sync(f)
		closeErr := f.Close()
		if syncErr != nil || closeErr != nil {
			return archiveError(errors.Join(syncErr, closeErr))
		}
	}
	return nil
}
