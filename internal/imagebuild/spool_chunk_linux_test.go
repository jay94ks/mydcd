// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// Owned temporary files and the actual local bbolt spool, not transport or
// consensus/native-container success. Both accepted formats share one core.
func TestSpoolChunkSizeUnorderedReopenWholeDigestSealAndReclaim(t *testing.T) {
	for _, size := range []uint32{0, UploadPartBytes} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			raw := makeZIP(t, zipInput{name: "Dockerfile", body: "FROM scratch\n"}, zipInput{name: "payload", body: string(bytes.Repeat([]byte{17}, 2*UploadPartBytes+7))})
			spool, scope, root, db := openTestSpool(t, raw)
			scope.ChunkBytes = size
			_, key := testScope(int64(len(raw)), sha256.Sum256(raw))
			ctx := context.Background()
			if err := spool.Begin(ctx, scope); err != nil {
				t.Fatal(err)
			}
			u, _ := BeginUpload(scope, 100)
			receipts := make([]PartReceipt, scope.Parts())
			for index := scope.Parts(); index > 0; {
				index--
				start := int64(index) * scope.PartSize()
				part, err := spool.Put(ctx, scope, index, raw[start:start+int64(scope.PartLength(index))], key)
				if err != nil || !part.Valid(scope) {
					t.Fatal("actual fixed-offset part", index, err)
				}
				receipts[index] = part
				u, err = u.Put(scope.Creator, u.Revision, 101, part)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := spool.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := OpenExistingSpool(int(root.Fd()), scope.Root, db)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			for index, original := range receipts {
				again, err := reopened.RecoverPart(ctx, scope, uint32(index), original.Digest, key)
				if err != nil || !bytes.Equal(again.Signature, original.Signature) {
					t.Fatal("stored offset/signature changed on reopen", index, err)
				}
			}
			seal, _, err := reopened.Seal(ctx, scope, key)
			if err != nil || !seal.Valid(scope) || seal.ZIP != sha256.Sum256(raw) {
				t.Fatal("whole hash/ZIP validation/seal", err)
			}
			closed, err := u.Consume(scope.Creator, scope.Context, u.Revision, 102, seal)
			if err != nil {
				t.Fatal(err)
			}
			reader, err := reopened.Open(ctx, scope, seal)
			if err != nil {
				t.Fatal(err)
			}
			if err := reopened.Reclaim(closed, false); !errors.Is(err, ErrUsed) {
				t.Fatal("live original reader lost retained root", err)
			}
			got, err := io.ReadAll(reader)
			closeErr := reader.Close()
			if err != nil || closeErr != nil || !bytes.Equal(got, raw) {
				t.Fatal("original archive changed", err, closeErr)
			}
			if err := reopened.Reclaim(closed, false); err != nil {
				t.Fatal("positive reader return/reclaim", err)
			}
			if err := reopened.Begin(ctx, scope); err == nil {
				t.Fatal("reclaimed original silently recreated")
			}
		})
	}
}

func TestSpoolChunkSizeRecoveryPreservesLegacyOffsetAndPendingSlot(t *testing.T) {
	for _, size := range []uint32{0, UploadPartBytes} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			raw := bytes.Repeat([]byte{23}, 2*UploadPartBytes+7)
			spool, scope, root, db := openTestSpool(t, raw)
			scope.ChunkBytes = size
			_, key := testScope(int64(len(raw)), sha256.Sum256(raw))
			ctx := context.Background()
			if err := spool.Begin(ctx, scope); err != nil {
				t.Fatal(err)
			}
			index := uint32(1)
			start := int64(index) * scope.PartSize()
			part, err := spool.Put(ctx, scope, index, raw[start:start+int64(scope.PartLength(index))], key)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root.Name(), ".mydc-imagebuild", scopeName(scope)+".zip")
			before, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			changed := scope
			if size == 0 {
				changed.ChunkBytes = UploadPartBytes
			} else {
				changed.ChunkBytes = 0
			}
			if _, err := spool.RecoverPart(ctx, changed, index, part.Digest, key); err == nil {
				t.Fatal("original slot reinterpreted under another chunk size")
			}
			if _, err := os.Stat(filepath.Join(root.Name(), ".mydc-imagebuild", scopeName(changed)+".zip")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("recovery created a replacement scope", err)
			}
			if err := db.Update(func(tx *bolt.Tx) error {
				pending, _ := json.Marshal(localPart{Digest: part.Digest})
				return spool.bucket(tx, scope).Put(partKey(index), pending)
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := spool.RecoverPart(ctx, scope, index, part.Digest, key); err == nil {
				t.Fatal("pending slot fabricated a stored receipt")
			}
			if err := db.Update(func(tx *bolt.Tx) error {
				stored, _ := json.Marshal(localPart{Digest: part.Digest, Stored: true})
				return spool.bucket(tx, scope).Put(partKey(index), stored)
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := spool.RecoverPart(ctx, scope, index, part.Digest, key); err != nil {
				t.Fatal("exact original stored offset did not recover", err)
			}
			after, err := os.Stat(path)
			if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() {
				t.Fatal("recovery replaced original inode/offset", err)
			}
		})
	}
}

func TestSpool32KiBWholeHashFailureNeverSealsOrResets(t *testing.T) {
	raw := bytes.Repeat([]byte{31}, UploadPartBytes+7)
	spool, scope, _, _ := openTestSpool(t, raw)
	scope.ChunkBytes, scope.Digest = UploadPartBytes, sha256.Sum256([]byte("different original archive"))
	_, key := testScope(int64(len(raw)), sha256.Sum256(raw))
	ctx := context.Background()
	if err := spool.Begin(ctx, scope); err != nil {
		t.Fatal(err)
	}
	if _, err := spool.Put(ctx, scope, 0, raw[:UploadPartBytes], key); err != nil {
		t.Fatal(err)
	}
	if receipt, err := spool.Put(ctx, scope, 1, raw[UploadPartBytes:], key); !errors.Is(err, ErrDigest) || len(receipt.Signature) != 0 {
		t.Fatal("wrong whole hash obtained final receipt", err)
	}
	if _, _, err := spool.Seal(ctx, scope, key); err == nil {
		t.Fatal("wrong whole hash sealed")
	}
	if err := spool.Begin(ctx, scope); !errors.Is(err, ErrDigest) {
		t.Fatal("bad original digest reset after interruption", err)
	}
}
