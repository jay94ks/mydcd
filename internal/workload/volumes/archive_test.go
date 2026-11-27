// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func archiveFixture(t *testing.T) (*os.Root, string, ArchiveOptions) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("filesystem profile core runs as the unprivileged build/test user")
	}
	name := t.TempDir()
	if err := os.Chmod(name, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root, name, ArchiveOptions{MaxBytes: 2 << 20, MaxEntries: 64, MaxDepth: 8, UID: uint32(os.Geteuid()), GID: uint32(os.Getegid()), RootMode: 0700}
}
func archiveEmpty(t *testing.T) *os.Root {
	t.Helper()
	name := t.TempDir()
	if err := os.Chmod(name, 0700); err != nil {
		t.Fatal(err)
	}
	r, e := os.OpenRoot(name)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func TestColdArchiveRootPrecedesMySQLPunctuationNames(t *testing.T) {
	root, name, o := archiveFixture(t)
	if err := os.Mkdir(filepath.Join(name, "#innodb_redo"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{"#innodb_redo/#ib_redo1", "!before-root", ".sfc-app-initialized", "mysql.ibd"} {
		if err := os.WriteFile(filepath.Join(name, file), []byte("original:"+file), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var body bytes.Buffer
	receipt, err := WriteArchive(context.Background(), root, &body, o)
	if err != nil {
		t.Fatal(err)
	}
	first, err := tar.NewReader(bytes.NewReader(body.Bytes())).Next()
	if err != nil || first.Name != "." {
		t.Fatalf("export root is not first: header=%v error=%v", first, err)
	}
	target := archiveEmpty(t)
	if err = RestoreArchive(context.Background(), target, bytes.NewReader(body.Bytes()), receipt, o); err != nil {
		t.Fatal("exported MySQL filename order cannot be restored", err)
	}
	var verified bytes.Buffer
	again, err := WriteArchive(context.Background(), target, &verified, o)
	if err != nil || again != receipt || !bytes.Equal(body.Bytes(), verified.Bytes()) {
		t.Fatal("restored metadata/content changed canonical receipt", err)
	}
}
func TestColdArchiveRoundTripMetadataAndOriginalPreservation(t *testing.T) {
	root, name, o := archiveFixture(t)
	directory := "database-" + strings.Repeat("table", 25) + "-한국어"
	if err := os.Mkdir(filepath.Join(name, directory), 0750); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("original transactional data\n"), 200)
	file := filepath.Join(name, directory, "data.ibd")
	if err := os.WriteFile(file, payload, 0640); err != nil {
		t.Fatal(err)
	}
	stamp := time.Unix(1700000000, 123456789)
	if err := os.Chtimes(file, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	receipt, err := WriteArchive(context.Background(), root, &body, o)
	if err != nil || receipt.Entries != 3 || receipt.DataBytes != uint64(len(payload)) || receipt.Bytes != uint64(body.Len()) {
		t.Fatal(receipt, err)
	}
	target := archiveEmpty(t)
	if err = RestoreArchive(context.Background(), target, bytes.NewReader(body.Bytes()), receipt, o); err != nil {
		t.Fatal(err)
	}
	got, err := target.ReadFile(directory + "/data.ibd")
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal("restored bytes", err)
	}
	info, err := target.Stat(directory + "/data.ibd")
	if err != nil || info.Mode().Perm() != 0640 || !info.ModTime().Equal(stamp) {
		t.Fatal("restored exact metadata", info, err)
	}
	after, err := os.Stat(file)
	if err != nil || !sameArchiveInfo(before, after) {
		t.Fatal("archive changed original", err)
	}
	if err = RestoreArchive(context.Background(), target, bytes.NewReader(body.Bytes()), receipt, o); err == nil {
		t.Fatal("existing target overwritten")
	}
	empty := archiveEmpty(t)
	var emptyBody bytes.Buffer
	emptyReceipt, err := WriteArchive(context.Background(), empty, &emptyBody, o)
	if err != nil || emptyReceipt.DataBytes != 0 || emptyReceipt.Entries != 1 {
		t.Fatal("empty original", err)
	}
	if err = RestoreArchive(context.Background(), archiveEmpty(t), bytes.NewReader(emptyBody.Bytes()), emptyReceipt, o); err != nil {
		t.Fatal("empty restore", err)
	}
}
func archiveBytes(t *testing.T, o ArchiveOptions, headers []tar.Header) ([]byte, ArchiveReceipt) {
	t.Helper()
	var b bytes.Buffer
	writer := tar.NewWriter(&b)
	var data uint64
	for _, h := range headers {
		if err := writer.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			if _, err := io.CopyN(writer, strings.NewReader(strings.Repeat("x", int(h.Size))), h.Size); err != nil {
				t.Fatal(err)
			}
			data += uint64(h.Size)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	raw := b.Bytes()
	return raw, ArchiveReceipt{Schema: 1, Digest: sha256.Sum256(raw), Bytes: uint64(len(raw)), DataBytes: data, Entries: uint32(len(headers))}
}
func TestColdArchiveRejectsUntrustedProfilesBeforeAnyRestoreWrite(t *testing.T) {
	_, _, o := archiveFixture(t)
	header := func(name string, dir bool) tar.Header {
		k := byte(tar.TypeReg)
		size := int64(1)
		mode := int64(0600)
		if dir {
			k = tar.TypeDir
			size = 0
			mode = 0700
		}
		return tar.Header{Name: name, Typeflag: k, Size: size, Mode: mode, Uid: int(o.UID), Gid: int(o.GID), ModTime: time.Unix(1700000000, 0), Format: tar.FormatPAX}
	}
	root, file := header(".", true), header("row", false)
	var cases [][]tar.Header
	for _, name := range []string{"../outside", "/absolute", "dir/../row", "a\\b", "missing/row"} {
		bad := file
		bad.Name = name
		cases = append(cases, []tar.Header{root, bad})
	}
	for _, modify := range []func(*tar.Header){func(h *tar.Header) { h.Typeflag = tar.TypeSymlink; h.Linkname = "../outside"; h.Size = 0 }, func(h *tar.Header) { h.Typeflag = tar.TypeLink; h.Linkname = "row"; h.Size = 0 }, func(h *tar.Header) { h.Mode = 04755 }, func(h *tar.Header) { h.Uid = 0 }, func(h *tar.Header) { h.PAXRecords = map[string]string{"vendor.unrecognized": "value"} }, func(h *tar.Header) { h.Format = tar.FormatGNU }} {
		bad := file
		modify(&bad)
		cases = append(cases, []tar.Header{root, bad})
	}
	cases = append(cases, []tar.Header{root, file, file}, []tar.Header{root, file, header("row/child", false)})
	for i, headers := range cases {
		raw, receipt := archiveBytes(t, o, headers)
		target := archiveEmpty(t)
		if err := RestoreArchive(context.Background(), target, bytes.NewReader(raw), receipt, o); err == nil {
			t.Fatal("unsafe profile accepted", i)
		}
		f, _ := target.Open(".")
		entries, err := f.ReadDir(1)
		_ = f.Close()
		if !errors.Is(err, io.EOF) || len(entries) != 0 {
			t.Fatal("invalid input changed staging", i, err)
		}
	}
	raw, receipt := archiveBytes(t, o, []tar.Header{root, file})
	for _, alter := range []func([]byte, ArchiveReceipt) ([]byte, ArchiveReceipt){
		func(b []byte, r ArchiveReceipt) ([]byte, ArchiveReceipt) { r.Digest[0] ^= 1; return b, r },
		func(b []byte, r ArchiveReceipt) ([]byte, ArchiveReceipt) {
			b = b[:len(b)-512]
			r.Bytes = uint64(len(b))
			r.Digest = sha256.Sum256(b)
			return b, r
		},
		func(b []byte, r ArchiveReceipt) ([]byte, ArchiveReceipt) {
			b = append(b, make([]byte, 512)...)
			r.Bytes = uint64(len(b))
			r.Digest = sha256.Sum256(b)
			return b, r
		},
	} {
		b, r := alter(bytes.Clone(raw), receipt)
		if err := RestoreArchive(context.Background(), archiveEmpty(t), bytes.NewReader(b), r, o); err == nil {
			t.Fatal("incomplete/extra/digest-mismatched input accepted")
		}
	}
	small := o
	small.MaxEntries = 1
	if err := RestoreArchive(context.Background(), archiveEmpty(t), bytes.NewReader(raw), receipt, small); err == nil {
		t.Fatal("entry budget ignored")
	}
}

type archiveDiskFull struct{}

func (archiveDiskFull) Write([]byte) (int, error) { return 0, syscall.ENOSPC }

type archiveMutatingWriter struct {
	buffer bytes.Buffer
	change func()
	done   bool
}

func (w *archiveMutatingWriter) Write(p []byte) (int, error) {
	if !w.done {
		w.done = true
		w.change()
	}
	return w.buffer.Write(p)
}
func TestColdArchiveSourceRefusalsBudgetsAndWriteFailure(t *testing.T) {
	root, name, o := archiveFixture(t)
	file := filepath.Join(name, "row")
	if err := os.WriteFile(file, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if r, err := WriteArchive(context.Background(), root, archiveDiskFull{}, o); !errors.Is(err, syscall.ENOSPC) || r != (ArchiveReceipt{}) {
		t.Fatal("disk failure became complete", r, err)
	}
	small := o
	small.MaxBytes = 1024
	if r, err := WriteArchive(context.Background(), root, new(bytes.Buffer), small); err == nil || r != (ArchiveReceipt{}) {
		t.Fatal("tar metadata/footer ignored by byte budget", r, err)
	}
	small = o
	small.MaxEntries = 1
	if _, err := WriteArchive(context.Background(), root, new(bytes.Buffer), small); !errors.Is(err, ErrArchiveLimit) {
		t.Fatal("entry budget", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := WriteArchive(ctx, root, new(bytes.Buffer), o); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation", err)
	}
	// Unsupported source metadata is refused before any output is written.
	for _, kind := range []string{"symlink", "hardlink", "fifo", "xattr"} {
		extra := filepath.Join(name, "unsupported")
		switch kind {
		case "symlink":
			if err := os.Symlink("../outside", extra); err != nil {
				t.Fatal(err)
			}
		case "hardlink":
			if err := os.Link(file, extra); err != nil {
				t.Fatal(err)
			}
		case "fifo":
			if err := syscall.Mkfifo(extra, 0600); err != nil {
				t.Fatal(err)
			}
		case "xattr":
			if err := unix.Setxattr(file, "user.sfc-test", []byte("metadata"), 0); err != nil {
				t.Fatal(err)
			}
		}
		var out bytes.Buffer
		if _, err := WriteArchive(context.Background(), root, &out, o); err == nil || out.Len() != 0 {
			t.Fatal("unsupported source silently changed", kind, err)
		}
		if kind == "xattr" {
			if err := unix.Removexattr(file, "user.sfc-test"); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := os.Remove(extra); err != nil {
				t.Fatal(err)
			}
		}
	}
	writer := &archiveMutatingWriter{change: func() {
		if err := os.WriteFile(file, []byte("changed source"), 0600); err != nil {
			t.Error(err)
		}
	}}
	if receipt, err := WriteArchive(context.Background(), root, writer, o); err == nil || receipt != (ArchiveReceipt{}) {
		t.Fatal("source mutation advertised complete", receipt, err)
	}
}
