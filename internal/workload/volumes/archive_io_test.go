// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestRestoreArchiveIOFailurePreservesPartialAndErrno(t *testing.T) {
	for _, stage := range []string{"write", "file-sync", "directory-sync"} {
		t.Run(stage, func(t *testing.T) {
			if os.Geteuid() == 0 {
				t.Skip("filesystem profile core runs as the unprivileged build/test user")
			}
			source := t.TempDir()
			if err := os.Chmod(source, 0700); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"one", "two"} {
				if err := os.WriteFile(filepath.Join(source, name), []byte("original:"+name), 0640); err != nil {
					t.Fatal(err)
				}
			}
			root, err := os.OpenRoot(source)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			options := ArchiveOptions{MaxBytes: 128 << 10, MaxEntries: 16, MaxDepth: 8, UID: uint32(os.Geteuid()), GID: uint32(os.Getegid()), RootMode: 0700}
			var archive bytes.Buffer
			receipt, err := WriteArchive(context.Background(), root, &archive, options)
			if err != nil {
				t.Fatal(err)
			}
			target := t.TempDir()
			if err = os.Chmod(target, 0700); err != nil {
				t.Fatal(err)
			}
			dest, err := os.OpenRoot(target)
			if err != nil {
				t.Fatal(err)
			}
			defer dest.Close()
			files := systemArchiveFiles()
			expected := error(syscall.EIO)
			if stage == "write" {
				expected = syscall.ENOSPC
				files.write = func(f *os.File, p []byte) (int, error) {
					n, err := f.Write(p[:3])
					return n, errors.Join(syscall.ENOSPC, err)
				}
			} else {
				files.sync = func(f *os.File) error {
					info, err := f.Stat()
					if err != nil {
						return err
					}
					if info.IsDir() == (stage == "directory-sync") {
						return syscall.EIO
					}
					return f.Sync()
				}
			}
			if err = restoreArchive(context.Background(), dest, bytes.NewReader(archive.Bytes()), receipt, options, files); !errors.Is(err, expected) {
				t.Fatal("lost original filesystem errno", stage, err)
			}
			before, err := os.ReadFile(filepath.Join(target, "one"))
			if err != nil {
				t.Fatal(err)
			}
			if stage == "write" && string(before) != "ori" {
				t.Fatal("partial write was not preserved", string(before))
			}
			if err = RestoreArchive(context.Background(), dest, bytes.NewReader(archive.Bytes()), receipt, options); err == nil {
				t.Fatal("nonempty failed staging recopied")
			}
			after, err := os.ReadFile(filepath.Join(target, "one"))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("failed staging was overwritten", err)
			}
			if stage == "directory-sync" {
				var exact bytes.Buffer
				got, err := WriteArchive(context.Background(), dest, &exact, options)
				if err != nil || got != receipt {
					t.Fatal("complete tree changed on failed final directory sync", err)
				}
			}
			if row, err := os.ReadFile(filepath.Join(source, "one")); err != nil || string(row) != "original:one" {
				t.Fatal("source changed", err)
			}
		})
	}
}
