// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/moby/moby/client"
)

func TestRealBoundaryColdRestoreWriteAndSyncFailures(t *testing.T) {
	ctx, engine, spec := realNativeVolume(t)
	db := filepath.Join(t.TempDir(), "native.db")
	m, err := OpenNative(db, engine)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	fixture := makeFixture(t)
	prepare := func(s NativeSpec) NativeReady {
		t.Helper()
		key, err := m.Desired(s, 1, 1, 4)
		if err != nil {
			t.Fatal(err)
		}
		if err = m.Step(ctx, key); err != nil {
			t.Fatal(err)
		}
		ready, err := m.Ready(ctx, key, fixture.a)
		if err != nil {
			t.Fatal(err)
		}
		return ready
	}
	release := func(core State, c Consumer) State {
		t.Helper()
		gone := Gone{Scope: core.Scope(), Consumer: c, Stopped: true, MountsGone: true}
		gone.Signature = ed25519.Sign(fixture.a, GoneBytes(gone))
		next, err := core.Release(gone)
		if err != nil {
			t.Fatal(err)
		}
		return next
	}
	remove := func(ready NativeReady) {
		t.Helper()
		key := NativeKey(ready.Spec)
		if err := m.DeleteDesired(key, 2, 1); err != nil {
			t.Fatal(err)
		}
		if err := m.Step(ctx, key); err != nil {
			t.Fatal(err)
		}
		if gone, err := m.Gone(ctx, key, 2, 1); err != nil || !gone {
			t.Fatal("exact native cleanup", err)
		}
	}
	source := prepare(spec)
	sourceDisk, err := engine.API.VolumeInspect(ctx, source.Owner.Native, client.VolumeInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	original := bytes.Repeat([]byte("original cold data\n"), 128)
	sourcePath := filepath.Join(sourceDisk.Volume.Mountpoint, "row")
	if err = os.WriteFile(sourcePath, original, 0640); err != nil {
		t.Fatal(err)
	}
	if err = os.Chown(sourcePath, int(spec.UID), int(spec.GID)); err != nil {
		t.Fatal(err)
	}
	sourceCore, err := New(fixture.c, "admin", spec.Scope, source.Owner, 4)
	if err != nil {
		t.Fatal(err)
	}
	sourceCore, reader, err := sourceCore.Acquire(fixture.c, "admin", sourceCore.Revision(), "backup", 1, false)
	if err != nil {
		t.Fatal(err)
	}
	sourceAuthority := func(_ context.Context, ready NativeReady, c Consumer) error {
		if ready.Spec != source.Spec || c != reader {
			return ErrVolume
		}
		return sourceCore.CheckActivation(c)
	}
	options := ArchiveOptions{MaxBytes: 128 << 10, MaxEntries: 16, MaxDepth: 8, UID: spec.UID, GID: spec.GID, RootMode: spec.Mode}
	file, err := os.OpenFile(filepath.Join(t.TempDir(), "original.tar"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	receipt, err := m.ExportCold(ctx, source, reader, sourceAuthority, file, options)
	if err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"write", "file-sync", "directory-sync"} {
		t.Run(stage, func(t *testing.T) {
			targetSpec := spec
			targetSpec.Scope.ID = stage
			targetSpec.Materialization = stage
			target := prepare(targetSpec)
			targetCore, err := New(fixture.c, "admin", targetSpec.Scope, target.Owner, 4)
			if err != nil {
				t.Fatal(err)
			}
			targetCore, writer, err := targetCore.Acquire(fixture.c, "admin", targetCore.Revision(), "restore", 1, true)
			if err != nil {
				t.Fatal(err)
			}
			authority := func(_ context.Context, ready NativeReady, c Consumer) error {
				if ready.Spec != target.Spec || c != writer {
					return ErrVolume
				}
				return targetCore.CheckActivation(c)
			}
			files := systemArchiveFiles()
			expected := error(syscall.EIO)
			if stage == "write" {
				expected = syscall.ENOSPC
				files.write = func(f *os.File, p []byte) (int, error) {
					n, err := f.Write(p[:7])
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
			m.archiveIO = files
			if err = m.RestoreCold(ctx, target, writer, authority, file, receipt, options); !errors.Is(err, expected) {
				t.Fatal("native restore lost original I/O errno", stage, err)
			}
			disk, err := engine.API.VolumeInspect(ctx, target.Owner.Native, client.VolumeInspectOptions{})
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(disk.Volume.Mountpoint, "row")
			partial, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if stage == "write" && !bytes.Equal(partial, original[:7]) {
				t.Fatal("partial native target was not preserved")
			}
			if stage == "directory-sync" {
				if err = m.VerifyRestoreCold(ctx, target, writer, authority, receipt, options); !errors.Is(err, syscall.EIO) {
					t.Fatal("readable tree bypassed failed directory sync", err)
				}
			}
			if err = m.Close(); err != nil {
				t.Fatal(err)
			}
			m, err = OpenNative(db, engine)
			if err != nil {
				t.Fatal(err)
			}
			record, err := m.View(NativeKey(targetSpec))
			if err != nil || record.State.LastID != 1 || record.State.Pending != nil || len(record.Consumers) != 0 {
				t.Fatal("original native identity/pins on reopen", err)
			}
			if err = m.RestoreCold(ctx, target, writer, authority, file, receipt, options); err == nil {
				t.Fatal("failed target recopied")
			}
			recovered := m.VerifyRestoreCold(ctx, target, writer, authority, receipt, options)
			if stage == "directory-sync" && recovered != nil {
				t.Fatal("complete original tree did not recover read-only", recovered)
			}
			if stage != "directory-sync" && recovered == nil {
				t.Fatal("incomplete original tree falsely verified")
			}
			after, err := os.Stat(path)
			data, readErr := os.ReadFile(path)
			if err != nil || readErr != nil || !os.SameFile(before, after) || !bytes.Equal(partial, data) {
				t.Fatal("read-only recovery replaced original staging", err, readErr)
			}
			if len(targetCore.Consumers()) != 1 || targetCore.Consumers()[0] != writer {
				t.Fatal("I/O failure returned shared staging writer")
			}
			if err = m.CloseRestoreCold(ctx, target, writer, options); err != nil {
				t.Fatal(err)
			}
			targetCore = release(targetCore, writer)
			if len(targetCore.Consumers()) != 0 {
				t.Fatal("original writer remained")
			}
			remove(target)
		})
	}
	if row, err := os.ReadFile(sourcePath); err != nil || !bytes.Equal(row, original) {
		t.Fatal("source data changed", err)
	}
	sourceCore = release(sourceCore, reader)
	remove(source)
	t.Log("actual SDK/local native DB/owned source and inactive targets: injected partial Write ENOSPC, file Sync EIO, directory Sync EIO retain errno/original target/shared core writer; same DB/native Apply1, no recopy; incomplete target refuses read-only verify, complete final-sync failure re-syncs original inode without data rewrite; exact cold pin closure/native nonforce removal. Authority is existing product core fixture, not Raft/CLI/SQL proof")
}
