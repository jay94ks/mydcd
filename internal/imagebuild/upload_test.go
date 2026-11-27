// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/jay94ks/seafield/internal/nodestorage"
)

func testScope(length int64, digest [32]byte) (UploadScope, ed25519.PrivateKey) {
	key := ed25519.NewKeyFromSeed(slices.Repeat([]byte{7}, ed25519.SeedSize))
	var owner [32]byte
	copy(owner[:], key.Public().(ed25519.PublicKey))
	cluster := [32]byte{2}
	return UploadScope{Schema: 1, Cluster: cluster, Tenant: "tenant-a", Context: "app-source", Upload: "upload-one", Creator: "alice", Root: nodestorage.Reference{Cluster: cluster, Node: "node-a", Key: owner, ID: "data", Generation: 1, Path: "/srv/sfc"}, ContextRevision: 1, PolicyRevision: 1, Length: length, Digest: digest, Dockerfile: "Dockerfile", ExpandedLimit: 1 << 30, ExpiresAt: 1000}, key
}

func TestUploadOriginalScopeCASAndCreator(t *testing.T) {
	scope, key := testScope(2*PartBytes+5, sha256.Sum256([]byte("original")))
	upload, err := BeginUpload(scope, 100)
	if err != nil {
		t.Fatal(err)
	}
	original := upload
	last := signPart(scope, 2, sha256.Sum256([]byte("last!")), key)
	if _, err := upload.Put("bob", 1, 101, last); err == nil {
		t.Fatal("another creator accepted")
	}
	if _, _, err := upload.Missing("bob", 101, 0, 8); err == nil {
		t.Fatal("another creator can read upload progress")
	}
	if _, err := upload.Put("alice", 2, 101, last); err == nil {
		t.Fatal("stale CAS accepted")
	}
	upload, err = upload.Put("alice", 1, 101, last)
	if err != nil || upload.Part(2) != last.Digest || original.Part(2) != ([32]byte{}) {
		t.Fatal("out-of-order or immutable update", err)
	}
	revision := upload.Revision
	upload, err = upload.Put("alice", revision, 101, last)
	if err != nil || upload.Revision != revision {
		t.Fatal("exact duplicate is not idempotent", err)
	}
	conflicting := signPart(scope, 2, sha256.Sum256([]byte("other")), key)
	if _, err := upload.Put("alice", revision, 101, conflicting); err == nil {
		t.Fatal("part overwritten")
	}
	changed := scope
	changed.Context = "other-context"
	if last.Valid(changed) {
		t.Fatal("part receipt crosses context")
	}
	changed = scope
	changed.Root.Generation++
	if last.Valid(changed) {
		t.Fatal("part receipt retargets root generation")
	}
	changed = scope
	changed.PolicyRevision++
	if last.Valid(changed) {
		t.Fatal("part receipt retargets policy")
	}
	missing, next, err := upload.Missing("alice", 101, 0, 1)
	if err != nil || !slices.Equal(missing, []uint32{0}) || next != 1 {
		t.Fatal("missing part page", missing, next, err)
	}
	missing, next, err = upload.Missing("alice", 101, next, 8)
	if err != nil || !slices.Equal(missing, []uint32{1}) || next != 3 {
		t.Fatal("missing part continuation", missing, next, err)
	}
	if _, err := upload.Put("alice", revision, scope.ExpiresAt, last); !errors.Is(err, ErrExpired) {
		t.Fatal("expired upload accepted", err)
	}
}

func TestUploadConsumeAndDelayedFacts(t *testing.T) {
	scope, key := testScope(5, sha256.Sum256([]byte("zip!!")))
	upload, _ := BeginUpload(scope, 100)
	seal := SealReceipt{Schema: 1, Scope: scope.Hash(), ZIP: scope.Digest, Tree: sha256.Sum256([]byte("tree")), Entries: 1, ExpandedBytes: 5}
	seal.Signature = ed25519.Sign(key, SealReceiptBytes(seal))
	if _, err := upload.Consume("alice", scope.Context, 1, 101, seal); err == nil {
		t.Fatal("incomplete upload consumed")
	}
	part := signPart(scope, 0, scope.Digest, key)
	upload, _ = upload.Put("alice", 1, 101, part)
	if _, err := upload.Consume("alice", "other", upload.Revision, 101, seal); err == nil {
		t.Fatal("another context consumes upload")
	}
	if _, err := upload.Consume("bob", scope.Context, upload.Revision, 101, seal); err == nil {
		t.Fatal("another creator consumes upload")
	}
	closed, err := upload.Consume("alice", scope.Context, upload.Revision, 101, seal)
	if err != nil || !closed.Closed || closed.Version == ([32]byte{}) || len(closed.Parts) != 0 || closed.Validate() != nil {
		t.Fatal("consume", err)
	}
	if _, err := closed.Put("alice", closed.Revision, 101, part); err == nil {
		t.Fatal("closed upload adopted delayed fact")
	}
	if _, err := closed.Consume("alice", scope.Context, closed.Revision, 101, seal); err == nil {
		t.Fatal("closed upload consumed twice")
	}
	expiry := ExpiryReceipt{Schema: 1, Scope: scope.Hash(), At: scope.ExpiresAt}
	expiry.Signature = ed25519.Sign(key, ExpiryReceiptBytes(expiry))
	expired, err := upload.Expire(upload.Revision, expiry)
	if err != nil || !expired.Closed || expired.Version != ([32]byte{}) {
		t.Fatal("owner expiry", err)
	}
	expiry.At--
	expiry.Signature = ed25519.Sign(key, ExpiryReceiptBytes(expiry))
	if _, err := upload.Expire(upload.Revision, expiry); err == nil {
		t.Fatal("early local expiry accepted")
	}
}

func TestUploadHalfGigabyteMetadataHasNoContent(t *testing.T) {
	scope, key := testScope(MaxZIPBytes, sha256.Sum256([]byte("large-artifact")))
	upload, err := BeginUpload(scope, 100)
	if err != nil || len(upload.Parts) != 651072 || scope.PartLength(scope.Parts()-1) <= 0 {
		t.Fatal("size bound", err)
	}
	part := signPart(scope, scope.Parts()-1, sha256.Sum256([]byte("last")), key)
	raw, _ := json.Marshal(part)
	if len(raw) > 1024 {
		t.Fatalf("replicated part receipt too large: %d", len(raw))
	}
	if _, err := BeginUpload(func() UploadScope { x := scope; x.Length++; return x }(), 100); err == nil {
		t.Fatal("oversize accepted")
	}
	// This checks metadata/admission only, not a 500 MB end-to-end transfer.
}
