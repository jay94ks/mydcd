// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/nodestorage"
)

func TestUploadChunkSizePreservesLegacyJSONHashAndFixedLengths(t *testing.T) {
	scope, _ := testScope(2*UploadPartBytes+7, sha256.Sum256([]byte("original archive")))
	legacy := struct {
		Schema                           uint8
		Cluster                          [32]byte
		Tenant, Context, Upload, Creator string
		Root                             nodestorage.Reference
		ContextRevision, PolicyRevision  uint64
		Length                           int64
		Digest                           [32]byte
		Dockerfile                       string
		ExpandedLimit                    int64
		ExpiresAt                        uint64
	}{scope.Schema, scope.Cluster, scope.Tenant, scope.Context, scope.Upload, scope.Creator, scope.Root, scope.ContextRevision, scope.PolicyRevision, scope.Length, scope.Digest, scope.Dockerfile, scope.ExpandedLimit, scope.ExpiresAt}
	oldJSON, _ := json.Marshal(legacy)
	currentJSON, _ := json.Marshal(scope)
	if !bytes.Equal(oldJSON, currentJSON) || scope.Hash() != digestJSON("sfc-imagebuild-upload-1", legacy) || scope.PartSize() != PartBytes || bytes.Contains(currentJSON, []byte("ChunkBytes")) {
		t.Fatal("omitted size changed original scope JSON/hash/offset")
	}
	var restored UploadScope
	if err := json.Unmarshal(oldJSON, &restored); err != nil || restored != scope || restored.Validate() != nil {
		t.Fatal("legacy scope restore", err)
	}
	modern := scope
	modern.ChunkBytes = UploadPartBytes
	if modern.Validate() != nil || modern.PartSize() != UploadPartBytes || modern.Parts() != 3 || modern.PartLength(0) != UploadPartBytes || modern.PartLength(2) != 7 || modern.PartLength(3) != 0 || modern.Hash() == scope.Hash() {
		t.Fatal("explicit scope size did not bind fixed original offsets")
	}
	for _, size := range []uint32{1, PartBytes, UploadPartBytes - 1, UploadPartBytes + 1, ^uint32(0)} {
		changed := scope
		changed.ChunkBytes = size
		if changed.Validate() == nil || changed.PartSize() != 0 || changed.Parts() != 0 || changed.PartLength(0) != 0 {
			t.Fatal("invalid explicit chunk size admitted", size)
		}
	}
}

func TestUpload32KiBUnorderedRestoreDuplicatePartialSealAndExpiry(t *testing.T) {
	scope, key := testScope(2*UploadPartBytes+7, sha256.Sum256([]byte("fixed original whole ZIP hash")))
	scope.ChunkBytes = UploadPartBytes
	u, err := BeginUpload(scope, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, index := range []uint32{2, 0, 1} {
		part := signPart(scope, index, sha256.Sum256([]byte{byte(index + 1)}), key)
		u, err = u.Put(scope.Creator, u.Revision, 101, part)
		if err != nil {
			t.Fatal("unordered original receipt", index, err)
		}
		revision := u.Revision
		u, err = u.Put(scope.Creator, revision, 101, part)
		if err != nil || u.Revision != revision {
			t.Fatal("duplicate receipt advanced original CAS", err)
		}
		raw, _ := json.Marshal(u)
		var restored Upload
		if err = json.Unmarshal(raw, &restored); err != nil || restored.Validate() != nil || restored.Scope != scope || restored.Part(index) != part.Digest {
			t.Fatal("partial metadata restore changed scope or slot", err)
		}
		u = restored
	}
	seal := SealReceipt{Schema: 1, Scope: scope.Hash(), ZIP: scope.Digest, Tree: sha256.Sum256([]byte("declared native tree")), Entries: 1, ExpandedBytes: scope.Length}
	seal.Signature = ed25519.Sign(key, SealReceiptBytes(seal))
	closed, err := u.Consume(scope.Creator, scope.Context, u.Revision, 102, seal)
	if err != nil || !closed.Closed || closed.Validate() != nil || closed.Scope != scope || closed.Version != VersionID(seal) {
		t.Fatal("original 32 KiB seal not consumed", err)
	}
	legacy := scope
	legacy.ChunkBytes = 0
	if seal.Valid(legacy) || signPart(scope, 0, [32]byte{1}, key).Valid(legacy) {
		t.Fatal("new receipt authorized legacy offsets")
	}
	expiry := ExpiryReceipt{Schema: 1, Scope: scope.Hash(), At: scope.ExpiresAt}
	expiry.Signature = ed25519.Sign(key, ExpiryReceiptBytes(expiry))
	expired, err := u.Expire(u.Revision, expiry)
	if err != nil || !expired.Closed || expired.Scope != scope {
		t.Fatal("original expiry changed scope", err)
	}
	if _, err := u.Put(scope.Creator, u.Revision, scope.ExpiresAt, signPart(scope, 0, [32]byte{1}, key)); !errors.Is(err, ErrExpired) {
		t.Fatal("larger part bypassed expiry", err)
	}
}

func TestUpload32KiBProofBindsChunkSizeAndRejectsLegacyReinterpretation(t *testing.T) {
	data := bytes.Repeat([]byte{3}, UploadPartBytes)
	scope, _ := testScope(int64(len(data)+7), sha256.Sum256([]byte("whole archive")))
	scope.ChunkBytes = UploadPartBytes
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32))
	session := access.Session{Schema: 1, Cluster: scope.Cluster, User: scope.Creator, Key: [32]byte(key.Public().(ed25519.PublicKey)), IssuedAt: 1, ExpiresAt: 1000}
	proof := PartProof{Schema: 1, Scope: scope.Hash(), Index: 0, Length: uint32(len(data)), Digest: sha256.Sum256(data), Expected: 1, At: 100, ExpiresAt: 200, Nonce: [32]byte{1}}
	proof.Signature = ed25519.Sign(key, PartProofBytes(proof))
	q := Transfer{Upload: scope.Upload, Kind: "part", Expected: 1, Data: data, Proof: &proof}
	if !q.Valid() || q.Authorize(scope, session, 101) != nil {
		t.Fatal("fixed 32 KiB part did not use actual authorization core")
	}
	legacy := scope
	legacy.ChunkBytes = 0
	if q.Authorize(legacy, session, 101) == nil {
		t.Fatal("old original silently reinterpreted at new offsets")
	}
	changed := proof
	changed.Scope = legacy.Hash()
	q.Proof = &changed
	if q.Authorize(scope, session, 101) == nil {
		t.Fatal("unsigned scope hash substitution accepted")
	}
	changed.Signature = ed25519.Sign(key, PartProofBytes(changed))
	if q.Authorize(legacy, session, 101) == nil {
		t.Fatal("signed 32 KiB data ignored legacy fixed part length")
	}
	q.Data = append(bytes.Clone(data), 1)
	if q.Valid() {
		t.Fatal("transfer exceeded unchanged 32 KiB part ceiling")
	}
}
