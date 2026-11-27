// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestVolumeFileAtomicPublicationAndDelegatedPathBoundary(t *testing.T) {
	base := t.TempDir()
	root, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	ctx := context.Background()
	body := []byte("bounded backup content")
	digest := sha256.Sum256(body)
	for _, name := range []string{"../escape", "/absolute", "sfc-web-backups/../foreign", "sfc-web-backups\\file", "sfc-web-backups/.sfc-file-private", "sfc-web-backups//file"} {
		if _, err = PutFile(ctx, root, name, "original", bytes.NewReader(body), int64(len(body)), digest, false); err == nil {
			t.Fatalf("unsafe path %q accepted", name)
		}
	}
	outside := t.TempDir()
	if err = os.Symlink(outside, filepath.Join(base, "symlink")); err != nil {
		t.Fatal(err)
	}
	if _, err = PutFile(ctx, root, "symlink/escape", "symlink", bytes.NewReader(body), int64(len(body)), digest, false); err == nil {
		t.Fatal("followed symlink parent")
	}
	name := "sfc-web-backups/one.bin"
	var publication FilePublication
	got, err := PutFileWithPublication(ctx, root, name, "original", bytes.NewReader(body), int64(len(body)), digest, false, func(p FilePublication) error {
		publication = p
		if _, err := root.Stat(name); !os.IsNotExist(err) {
			t.Fatal("published before durable rename intent")
		}
		return nil
	})
	if err != nil || got.Path != name || got.Digest != digest || publication.Inode == 0 {
		t.Fatal(got, publication, err)
	}
	if _, err = PutFile(ctx, root, name, "overwrite-refused", bytes.NewReader(body), int64(len(body)), digest, false); !errors.Is(err, ErrFileConflict) {
		t.Fatal("overwrite without consent", err)
	}
	f, metadata, err := OpenFileData(root, name, 1024)
	if err != nil {
		t.Fatal(err)
	}
	read, err := io.ReadAll(f)
	f.Close()
	if err != nil || !bytes.Equal(read, body) || metadata.Size != int64(len(body)) {
		t.Fatal("get", metadata, err)
	}
	rows, next, err := ListFiles(ctx, root, "sfc-web-backups/", "")
	if err != nil || next != "" || len(rows) != 1 || rows[0].Path != name {
		t.Fatal("list", rows, next, err)
	}
	if err = DeleteFile(root, name); err != nil {
		t.Fatal(err)
	}
	if _, err = root.Stat(name); !os.IsNotExist(err) {
		t.Fatal("delete did not remove exact file", err)
	}
}

func TestVolumeFileEOFAndOriginalInodeAreRequiredForUnknownPutRecovery(t *testing.T) {
	base := t.TempDir()
	root, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	ctx := context.Background()
	body := []byte("same bytes do not prove the original rename")
	digest := sha256.Sum256(body)
	name := "sfc-web-backups/backup.bin"
	if err = root.Mkdir("sfc-web-backups", 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(base, name), body, 0600); err != nil {
		t.Fatal(err)
	}
	for _, input := range [][]byte{body[:3], append(bytes.Clone(body), 'x')} {
		if _, err = PutFile(ctx, root, name, "bad-eof", bytes.NewReader(input), int64(len(body)), digest, true); err == nil {
			t.Fatal("inexact input was published")
		}
		got, _ := os.ReadFile(filepath.Join(base, name))
		if !bytes.Equal(got, body) {
			t.Fatal("failed input changed original")
		}
	}
	var receipt FilePublication
	syncFailure := errors.New("injected local journal sync failure")
	if _, err = PutFileWithPublication(ctx, root, name, "before-rename-db-loss", bytes.NewReader(body), int64(len(body)), digest, true, func(p FilePublication) error { receipt = p; return syncFailure }); !errors.Is(err, syncFailure) {
		t.Fatal(err)
	}
	if _, err = RecoverPutFile(ctx, root, receipt); err == nil {
		t.Fatal("existing equal content was mistaken for original staged inode")
	}
	// Simulate publication followed by loss of the final owner DB reply. The
	// saved pre-rename receipt binds that exact inode at the public basename.
	if _, err = PutFileWithPublication(ctx, root, name, "after-rename-db-loss", bytes.NewReader(body), int64(len(body)), digest, true, func(p FilePublication) error { receipt = p; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err = RecoverPutFile(ctx, root, receipt); err != nil {
		t.Fatal("exact original rename could not recover", err)
	}
	replacement := filepath.Join(base, "other")
	if err = os.WriteFile(replacement, body, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(replacement, filepath.Join(base, name)); err != nil {
		t.Fatal(err)
	}
	if _, err = RecoverPutFile(ctx, root, receipt); err == nil {
		t.Fatal("a later writer's equal bytes were adopted")
	}
}

func TestVolumeFileOperationsRefuseSymlinkAndHardlinkTargets(t *testing.T) {
	base := t.TempDir()
	root, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err = os.WriteFile(filepath.Join(base, "original"), []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Link(filepath.Join(base, "original"), filepath.Join(base, "hardlink")); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink("original", filepath.Join(base, "symlink")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"original", "hardlink", "symlink"} {
		if f, _, err := OpenFileData(root, name, 1024); err == nil {
			f.Close()
			t.Fatal("unsafe inode read", name)
		}
		if err = DeleteFile(root, name); err == nil {
			t.Fatal("unsafe inode delete", name)
		}
		body := []byte("replacement")
		if _, err = PutFile(context.Background(), root, name, "reject-link-"+name, bytes.NewReader(body), int64(len(body)), sha256.Sum256(body), true); err == nil {
			t.Fatal("unsafe inode overwrite", name)
		}
	}
	if body, err := os.ReadFile(filepath.Join(base, "original")); err != nil || string(body) != "private" {
		t.Fatal("refused overwrite changed original data", string(body), err)
	}
}

func TestVolumeFileOverwriteChangesOnlyTheExplicitRegularTarget(t *testing.T) {
	base := t.TempDir()
	root, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	old := []byte("old backup")
	newBody := []byte("replacement backup")
	for _, name := range []string{"target", "retained"} {
		if _, err = PutFile(context.Background(), root, name, "original-"+name, bytes.NewReader(old), int64(len(old)), sha256.Sum256(old), false); err != nil {
			t.Fatal(err)
		}
	}
	before, err := root.Stat("target")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = PutFile(context.Background(), root, "target", "replacement", bytes.NewReader(newBody), int64(len(newBody)), sha256.Sum256(newBody), true); err != nil {
		t.Fatal("explicit regular-file overwrite", err)
	}
	after, err := root.Stat("target")
	got, readErr := root.ReadFile("target")
	retained, retainedErr := root.ReadFile("retained")
	if err != nil || readErr != nil || retainedErr != nil || os.SameFile(before, after) || !bytes.Equal(got, newBody) || !bytes.Equal(retained, old) {
		t.Fatal("overwrite did not publish only its requested new inode", err, readErr, retainedErr)
	}
}
