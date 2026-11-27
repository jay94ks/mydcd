// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func openTestSpool(t *testing.T, raw []byte) (*Spool, UploadScope, *os.File, *bolt.DB) {
	t.Helper()
	scope, _ := testScope(int64(len(raw)), sha256.Sum256(raw))
	rootPath := t.TempDir()
	scope.Root.Path = rootPath
	root, err := os.Open(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	db, err := bolt.Open(filepath.Join(t.TempDir(), "observations.db"), 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	spool, err := OpenSpool(int(root.Fd()), scope.Root, db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = spool.Close() })
	return spool, scope, root, db
}

func TestSpoolUnorderedPartsNativeReceiptAndReaderReclaimFence(t *testing.T) {
	raw := makeZIP(t, zipInput{name: "Dockerfile", body: "FROM scratch\n"}, zipInput{name: "payload", body: string(bytes.Repeat([]byte{17}, 3*PartBytes))})
	spool, scope, _, _ := openTestSpool(t, raw)
	_, key := testScope(int64(len(raw)), sha256.Sum256(raw))
	ctx := context.Background()
	if err := spool.Begin(ctx, scope); err != nil {
		t.Fatal(err)
	}
	upload, _ := BeginUpload(scope, 100)
	for index := scope.Parts(); index > 0; {
		index--
		start := int(index) * PartBytes
		part, err := spool.Put(ctx, scope, index, raw[start:start+scope.PartLength(index)], key)
		if err != nil || !part.Valid(scope) {
			t.Fatal("native part", index, err)
		}
		upload, err = upload.Put(scope.Creator, upload.Revision, 101, part)
		if err != nil {
			t.Fatal("replicated receipt", err)
		}
	}
	seal, tree, err := spool.Seal(ctx, scope, key)
	if err != nil || !seal.Valid(scope) || seal.Tree != tree.Digest() {
		t.Fatal("seal", err)
	}
	duplicate, err := spool.Put(ctx, scope, 0, raw[:PartBytes], key)
	if err != nil || !duplicate.Valid(scope) {
		t.Fatal("same original part after seal", err)
	}
	other := append([]byte(nil), raw[:PartBytes]...)
	other[0] ^= 1
	if _, err := spool.Put(ctx, scope, 0, other, key); !errors.Is(err, ErrConflict) {
		t.Fatal("sealed part overwritten", err)
	}
	closed, err := upload.Consume(scope.Creator, scope.Context, upload.Revision, 102, seal)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := spool.Open(ctx, scope, seal)
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.Close(); !errors.Is(err, ErrUsed) {
		t.Fatal("open reader lost root pin", err)
	}
	if err := spool.Reclaim(closed, false); !errors.Is(err, ErrUsed) {
		t.Fatal("reclaimed an open reader", err)
	}
	body, err := io.ReadAll(reader)
	if err != nil || !bytes.Equal(body, raw) {
		t.Fatal("artifact changed", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := spool.Reclaim(closed, true); !errors.Is(err, ErrUsed) {
		t.Fatal("referenced version reclaimed", err)
	}
	if err := spool.Reclaim(closed, false); err != nil {
		t.Fatal(err)
	}
	if err := spool.Reclaim(closed, false); err != nil {
		t.Fatal("original reclaim recovery", err)
	}
	if err := spool.Begin(ctx, scope); err == nil {
		t.Fatal("tombstone reset into new upload")
	}
}

func TestSpoolLastPartMismatchRemainsOriginal(t *testing.T) {
	raw := makeZIP(t, zipInput{name: "Dockerfile", body: "FROM scratch\n"}, zipInput{name: "payload", body: string(bytes.Repeat([]byte{19}, PartBytes))})
	spool, scope, _, _ := openTestSpool(t, raw)
	_, key := testScope(int64(len(raw)), sha256.Sum256(raw))
	scope.Digest = sha256.Sum256([]byte("different original archive"))
	if err := spool.Begin(context.Background(), scope); err != nil {
		t.Fatal(err)
	}
	for index := uint32(0); index < scope.Parts(); index++ {
		start := int(index) * PartBytes
		part, err := spool.Put(context.Background(), scope, index, raw[start:start+scope.PartLength(index)], key)
		if index+1 == scope.Parts() {
			if !errors.Is(err, ErrDigest) || len(part.Signature) != 0 {
				t.Fatal("bad full digest acknowledged", err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := spool.Seal(context.Background(), scope, key); err == nil {
		t.Fatal("invalid upload sealed")
	}
	if _, err := spool.Put(context.Background(), scope, 0, raw[:PartBytes], key); !errors.Is(err, ErrDigest) {
		t.Fatal("invalid original upload silently reset", err)
	}
}

func TestSpoolConfirmedPartRecoveryNeverRecreatesMissingOriginal(t *testing.T) {
	raw := bytes.Repeat([]byte{23}, PartBytes+5)
	spool, scope, root, db := openTestSpool(t, raw)
	_, key := testScope(int64(len(raw)), sha256.Sum256(raw))
	ctx := context.Background()
	if err := spool.Begin(ctx, scope); err != nil {
		t.Fatal(err)
	}
	part, err := spool.Put(ctx, scope, 0, raw[:PartBytes], key)
	if err != nil {
		t.Fatal(err)
	}
	again, err := spool.RecoverPart(ctx, scope, 0, part.Digest, key)
	if err != nil || !bytes.Equal(part.Signature, again.Signature) {
		t.Fatal("original native receipt changed", err)
	}
	if _, err := spool.RecoverPart(ctx, scope, 1, sha256.Sum256(raw[PartBytes:]), key); err == nil {
		t.Fatal("missing part treated as stored")
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		b := spool.bucket(tx, scope)
		pending, _ := json.Marshal(localPart{Digest: part.Digest, Stored: false})
		return b.Put(partKey(0), pending)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := spool.RecoverPart(ctx, scope, 0, part.Digest, key); err == nil {
		t.Fatal("pending completion promoted during ACK lookup")
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		b := spool.bucket(tx, scope)
		stored, _ := json.Marshal(localPart{Digest: part.Digest, Stored: true})
		return b.Put(partKey(0), stored)
	}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root.Name(), ".sfc-imagebuild", scopeName(scope)+".zip")
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, changed := file.WriteAt([]byte{99}, 0)
	closed := file.Close()
	if changed != nil || closed != nil {
		t.Fatal(changed, closed)
	}
	if _, err := spool.RecoverPart(ctx, scope, 0, part.Digest, key); err == nil {
		t.Fatal("changed native bytes acknowledged")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := spool.RecoverPart(ctx, scope, 0, part.Digest, key); err == nil {
		t.Fatal("missing original native file acknowledged")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("ACK lookup recreated lost original", err)
	}
}

func TestSpoolRecoversExactPendingPartAndNeverMissingOriginal(t *testing.T) {
	raw := makeZIP(t, zipInput{name: "Dockerfile", body: "FROM scratch\n"})
	spool, scope, root, db := openTestSpool(t, raw)
	_, key := testScope(int64(len(raw)), sha256.Sum256(raw))
	ctx := context.Background()
	if err := spool.Begin(ctx, scope); err != nil {
		t.Fatal(err)
	}
	// Crash boundary: original pending intent persisted, only half the native
	// bytes written, no success receipt. This does not duplicate the algorithm.
	digest := sha256.Sum256(raw)
	err := db.Update(func(tx *bolt.Tx) error {
		pending, _ := json.Marshal(localPart{Digest: digest})
		return spool.bucket(tx, scope).Put(partKey(0), pending)
	})
	if err != nil {
		t.Fatal(err)
	}
	h, _ := spool.header(scope)
	file, err := spool.file(h, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt(raw[:len(raw)/2], 0); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenSpool(int(root.Fd()), scope.Root, db)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	other := append([]byte(nil), raw...)
	other[0] ^= 1
	if _, err := reopened.Put(ctx, scope, 0, other, key); !errors.Is(err, ErrConflict) {
		t.Fatal("pending part overwritten", err)
	}
	part, err := reopened.Put(ctx, scope, 0, raw, key)
	if err != nil || !part.Valid(scope) {
		t.Fatal("same original pending recovery", err)
	}
	name := filepath.Join(scope.Root.Path, ".sfc-imagebuild", scopeName(scope)+".zip")
	if err := os.Rename(name, name+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Begin(ctx, scope); !errors.Is(err, ErrStorage) {
		t.Fatal("replaced inode accepted", err)
	}
	if err := os.Remove(name); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Begin(ctx, scope); !errors.Is(err, ErrStorage) {
		t.Fatal("missing original recreated", err)
	}
}

func TestSpoolPreparationCrashCanBeReclaimedOnlyWhenEmpty(t *testing.T) {
	raw := makeZIP(t, zipInput{name: "Dockerfile", body: "FROM scratch\n"})
	spool, scope, _, db := openTestSpool(t, raw)
	err := db.Update(func(tx *bolt.Tx) error {
		parent := tx.Bucket(spoolBucket).Bucket(spool.key)
		b, err := parent.CreateBucket([]byte(scopeName(scope)))
		if err != nil {
			return err
		}
		data, _ := json.Marshal(localUpload{Scope: scope})
		return b.Put(spoolHeader, data)
	})
	if err != nil {
		t.Fatal(err)
	}
	upload, _ := BeginUpload(scope, 100)
	closed, err := upload.Abort(scope.Creator, upload.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.Reclaim(closed, false); err != nil {
		t.Fatal("empty preparing intent cleanup", err)
	}
	if err := spool.Begin(context.Background(), scope); err == nil {
		t.Fatal("reclaimed preparing upload reset")
	}
}

// This source is executed only in RQ6's final batch with an explicit large
// artifact opt-in. It exercises actual disk parts/native receipts/shared core,
// not the still-to-be-connected User/Raft/CLI path or a BuildKit job.
func TestSpoolHundredMBZIP(t *testing.T) {
	if os.Getenv("SFC_IMAGEBUILD_LARGE") != "1" {
		t.Skip("RQ6 final large artifact batch")
	}
	ctx := context.Background()
	file, err := os.CreateTemp(t.TempDir(), "context-*.zip")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	z := zip.NewWriter(file)
	w, err := z.CreateHeader(&zip.FileHeader{Name: "Dockerfile", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, "FROM scratch\nCOPY payload /payload\n"); err != nil {
		t.Fatal(err)
	}
	w, err = z.CreateHeader(&zip.FileHeader{Name: "payload", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.CopyN(w, zeroReader{}, 100_000_000); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
	stat, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := fileDigest(ctx, file, stat.Size())
	if err != nil {
		t.Fatal(err)
	}
	spool, scope, _, _ := openTestSpool(t, []byte("placeholder"))
	scope.Length, scope.Digest = stat.Size(), digest
	_, key := testScope(scope.Length, scope.Digest)
	if err := spool.Begin(ctx, scope); err != nil {
		t.Fatal(err)
	}
	upload, err := BeginUpload(scope, 100)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, PartBytes)
	for index := scope.Parts(); index > 0; {
		index--
		part := buffer[:scope.PartLength(index)]
		if _, err := file.ReadAt(part, int64(index)*PartBytes); err != nil {
			t.Fatal(err)
		}
		receipt, err := spool.Put(ctx, scope, index, part, key)
		if err != nil {
			t.Fatal(index, err)
		}
		upload, err = upload.Put(scope.Creator, upload.Revision, 101, receipt)
		if err != nil {
			t.Fatal(index, err)
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
	if err := spool.Reclaim(closed, false); err != nil {
		t.Fatal(err)
	}
}

type zeroReader struct{}

func TestSpoolClosedBeforeBeginHasNativeTombstoneAndNoFreshFile(t *testing.T) {
	raw := makeZIP(t, zipInput{name: "Dockerfile", body: "FROM scratch\n"})
	spool, scope, _, _ := openTestSpool(t, raw)
	u, err := BeginUpload(scope, 100)
	if err != nil {
		t.Fatal(err)
	}
	u, err = u.Abort(scope.Creator, u.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.Reclaim(u, false); err != nil {
		t.Fatal(err)
	}
	evidence, err := spool.ReclaimEvidence(scope)
	if err != nil || evidence == ([32]byte{}) {
		t.Fatal("missing native tombstone", err)
	}
	if err := spool.Begin(context.Background(), scope); err == nil {
		t.Fatal("reclaimed unstarted original created a fresh file")
	}
}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }
