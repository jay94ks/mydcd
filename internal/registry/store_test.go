// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// Go 1.27 TempDir's numbered leaf uses 0777 before umask. The product
// requires its own explicit private root, not a permission assumption in tests.
func privateRegistryRoot(t *testing.T) string {
	t.Helper()
	path, err := os.MkdirTemp(t.TempDir(), "registry-")
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRegistryStoreOwnsOneRootRetainsDataAndRejectsKnownDBLoss(t *testing.T) {
	ctx := context.Background()
	path := privateRegistryRoot(t)
	owner := metadataScope("alpha")
	meta := MetadataLimits{ManifestBytes: 4096, Records: 64, TotalBytes: 1 << 20}
	limits := smallBlobLimits()
	s, err := OpenStore(ctx, path, owner, meta, limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := OpenStore(ctx, path, owner, meta, limits); err == nil {
		t.Fatal("second root owner")
	}
	data := []byte("retained")
	u, err := s.Blobs.Begin(ctx, "app")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Blobs.Append(ctx, "app", u.ID, 0, int64(len(data)), bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	digest := blobDigest(data)
	if _, err = s.Blobs.Commit(ctx, "app", u.ID, digest); err != nil {
		t.Fatal(err)
	}
	h, _ := v1.NewHash(digest)
	reader, err := s.Blobs.Get(ctx, "app", h)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err = s.Close(); !errors.Is(err, ErrReaders) {
		t.Fatal("closed DB/root before reader join", err)
	}
	if err = reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = OpenStore(ctx, path, metadataScope("beta"), meta, limits); err == nil {
		t.Fatal("tenant changed original store")
	}
	s, err = OpenStore(ctx, path, owner, meta, limits)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readFixtureBlob(t, s.Blobs, "app", digest), data) {
		t.Fatal("stop deleted image")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	// Move aside, never overwrite/delete the original test DB. The constructor
	// must refuse to initialize a new one beside the known object directory.
	dbPath := filepath.Join(path, "registry.db")
	if err = os.Rename(dbPath, dbPath+".original"); err != nil {
		t.Fatal(err)
	}
	if _, err = OpenStore(ctx, path, owner, meta, limits); err == nil {
		t.Fatal("known DB loss became empty registry")
	}
	if _, err = os.Lstat(dbPath); !os.IsNotExist(err) {
		t.Fatal("created replacement DB", err)
	}
}

func TestRegistryUploadCreatingAndCancelingRecoverOnlyOriginalID(t *testing.T) {
	for _, phase := range []string{"creating", "canceling"} {
		t.Run(phase, func(t *testing.T) {
			f := newBlobFixture(t, smallBlobLimits())
			ctx := context.Background()
			u, err := f.b.Begin(ctx, "app")
			if err != nil {
				t.Fatal(err)
			}
			original := f.b.uploads[u.ID]
			original.Phase = phase
			if err = f.b.Close(); err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(original)
			if err = f.db.Write(map[string][]byte{uploadPrefix + u.ID: raw}); err != nil {
				t.Fatal(err)
			}
			if err = os.Remove(filepath.Join(f.path, "uploads", u.ID)); err != nil {
				t.Fatal(err)
			}
			f.reopen(t)
			if len(f.b.uploads) != 1 {
				t.Fatal("recovery created replacement ID")
			}
			if phase == "creating" {
				status, err := f.b.Status(ctx, "app", u.ID)
				if err != nil || status.ID != u.ID || status.Offset != 0 {
					t.Fatal(status, err)
				}
			} else if f.b.uploads[u.ID].Phase != "canceled" {
				t.Fatal("original cancellation not closed")
			}
		})
	}
}

func TestRegistryBlobRecoveryRejectsLostReceiptMissingBytesAndOrphans(t *testing.T) {
	for _, fault := range []string{"lost-receipt", "missing-blob", "orphan-file"} {
		t.Run(fault, func(t *testing.T) {
			f := newBlobFixture(t, smallBlobLimits())
			ctx := context.Background()
			data := []byte("original")
			u := appendFixtureBlob(t, f, "app", data)
			digest := blobDigest(data)
			if _, err := f.b.Commit(ctx, "app", u.ID, digest); err != nil {
				t.Fatal(err)
			}
			if err := f.b.Close(); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "lost-receipt":
				if err := f.db.Write(map[string][]byte{uploadPrefix + u.ID: nil}); err != nil {
					t.Fatal(err)
				}
			case "missing-blob":
				rel, _ := blobPath(digest)
				if err := os.Remove(filepath.Join(f.path, rel)); err != nil {
					t.Fatal(err)
				}
			case "orphan-file":
				if err := os.WriteFile(filepath.Join(f.path, "uploads", "unowned"), []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, err := f.db.ScanBounded("registry/", 256, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := openBlobs(ctx, f.path, f.m, f.limits); err == nil {
				t.Fatal("known loss adopted or repaired", fault)
			}
			after, err := f.db.ScanBounded("registry/", 256, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			if len(before) != len(after) {
				t.Fatal("recovery changed record set")
			}
			for key, value := range before {
				if !bytes.Equal(value, after[key]) {
					t.Fatal("recovery replaced original evidence", key)
				}
			}
			if fault == "orphan-file" {
				if raw, err := os.ReadFile(filepath.Join(f.path, "uploads", "unowned")); err != nil || string(raw) != "keep" {
					t.Fatal("unknown write deleted", err)
				}
			}
		})
	}
}
