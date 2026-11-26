// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// Actual bbolt/openat2/ZIP evidence. Shared authority is covered by the control
// reducer tests; this does not claim an end-to-end user/Raft owner path.
func TestSpoolContentInspectionRetainsOriginalAndRefusesReplacedOrReclaimedFile(t *testing.T) {
	raw := makeZIP(t, zipInput{name: "Dockerfile", body: "FROM scratch\n"})
	spool, scope, _, _ := openTestSpool(t, raw)
	_, key := testScope(int64(len(raw)), sha256.Sum256(raw))
	ctx := context.Background()
	if err := spool.Begin(ctx, scope); err != nil {
		t.Fatal(err)
	}
	upload, _ := BeginUpload(scope, 100)
	for index := uint32(0); index < scope.Parts(); index++ {
		start := int(index) * PartBytes
		part, err := spool.Put(ctx, scope, index, raw[start:start+scope.PartLength(index)], key)
		if err != nil {
			t.Fatal(err)
		}
		upload, err = upload.Put(scope.Creator, upload.Revision, 101, part)
		if err != nil {
			t.Fatal(err)
		}
	}
	seal, _, err := spool.Seal(ctx, scope, key)
	if err != nil {
		t.Fatal(err)
	}
	closed, err := upload.Consume(scope.Creator, scope.Context, upload.Revision, 102, seal)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := spool.Inspect(ctx, scope, seal)
	if err != nil {
		t.Fatal(err)
	}
	content, err := NewContent(tree, scope, seal)
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.CheckSeal(scope, seal); err != nil {
		t.Fatal(err)
	}
	// Derive the native path from the actual open directory, not a parallel
	// test namespace convention (the spool also binds its root generation).
	name := filepath.Join("/proc/self/fd", strconv.FormatUint(uint64(spool.dir.Fd()), 10), scopeName(scope)+".zip")
	if err := os.Truncate(name, int64(len(raw)-1)); err != nil {
		t.Fatal(err)
	}
	if err := spool.CheckSeal(scope, seal); err == nil {
		t.Fatal("cached view hid truncated original")
	}
	if err := os.WriteFile(name, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := spool.Reclaim(closed, true); !errors.Is(err, ErrUsed) {
		t.Fatal("live shared reference not protected", err)
	}
	if err := spool.Reclaim(closed, false); err != nil {
		t.Fatal(err)
	}
	if err := spool.CheckSeal(scope, seal); err == nil {
		t.Fatal("cached view hid physical reclamation")
	}
	if _, err := spool.Inspect(ctx, scope, seal); err == nil {
		t.Fatal("reclaimed original inspected")
	}
	page, err := content.Read(ContentQuery{Version: closed.Version, Part: "dockerfile"}, 0)
	if err != nil || !bytes.Equal(page.Data, tree.Dockerfile) {
		t.Fatal("cached bytes were mutable", err)
	}
}

func TestReadOnlySpoolNeverInitializesMissingOriginalNamespace(t *testing.T) {
	raw := makeZIP(t, zipInput{name: "Dockerfile", body: "FROM scratch\n"})
	_, scope, root, db := openTestSpool(t, raw)
	existing, err := OpenExistingSpool(int(root.Fd()), scope.Root, db)
	if err != nil {
		t.Fatal(err)
	}
	if err := existing.Close(); err != nil {
		t.Fatal(err)
	}
	path := t.TempDir()
	fresh, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	ref := scope.Root
	ref.Path = path
	if _, err := OpenExistingSpool(int(fresh.Fd()), ref, db); err == nil {
		t.Fatal("absent evidence became new read namespace")
	}
	if _, err := os.Stat(filepath.Join(path, ".mydc-imagebuild")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("read-only query created directory", err)
	}
}
