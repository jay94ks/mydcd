// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"crypto/ed25519"
	"encoding/json"
	"math"

	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/nodestorage"
)

// UploadScope is immutable. A policy/root/context change cannot retarget an
// upload accepted against another original scope. It contains no credentials.
type UploadScope struct {
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
	ChunkBytes                       uint32 `json:",omitempty"`
}

func (s UploadScope) Validate() error {
	if s.ChunkBytes != 0 && s.ChunkBytes != UploadPartBytes {
		return ErrInvalid
	}
	if s.Schema != 1 || s.Cluster == ([32]byte{}) || !lifecycle.ValidID(s.Tenant) || !lifecycle.ValidID(s.Context) || !lifecycle.ValidID(s.Upload) || !lifecycle.ValidID(s.Creator) || s.Root.Validate() != nil || s.Root.Cluster != s.Cluster || s.ContextRevision == 0 || s.PolicyRevision == 0 || s.Length <= 0 || s.Length > MaxZIPBytes || s.Digest == ([32]byte{}) || !ContextPath(s.Dockerfile) || s.ExpandedLimit <= 0 || s.ExpandedLimit > MaxExpandedBytes || s.ExpiresAt == 0 || s.ExpiresAt > math.MaxInt64 {
		return ErrInvalid
	}
	return nil
}
func (s UploadScope) Hash() [32]byte { return digestJSON("sfc-imagebuild-upload-1", s) }

// PartSize belongs to the immutable accepted scope. Omitted ChunkBytes keeps
// the original 24 KiB offsets and hash; only explicit new uploads use 32 KiB.
func (s UploadScope) PartSize() int64 {
	if s.ChunkBytes == 0 {
		return PartBytes
	}
	if s.ChunkBytes == UploadPartBytes {
		return UploadPartBytes
	}
	return 0
}
func (s UploadScope) Parts() uint32 {
	partSize := s.PartSize()
	if partSize == 0 || s.Length <= 0 || s.Length > MaxZIPBytes {
		return 0
	}
	return uint32((s.Length + partSize - 1) / partSize)
}
func (s UploadScope) PartLength(index uint32) int {
	if s.Length <= 0 || s.Length > MaxZIPBytes || index >= s.Parts() {
		return 0
	}
	n := s.Length - int64(index)*s.PartSize()
	if n > s.PartSize() {
		n = s.PartSize()
	}
	return int(n)
}
func (s UploadScope) Current(creator string, now uint64) error {
	if s.Validate() != nil || creator != s.Creator || now == 0 {
		return ErrInvalid
	}
	if now >= s.ExpiresAt {
		return ErrExpired
	}
	return nil
}

type PartReceipt struct {
	Schema    uint8
	Scope     [32]byte
	Index     uint32
	Length    uint32
	Digest    [32]byte
	Signature []byte
}

func PartReceiptBytes(r PartReceipt) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("sfc-imagebuild-part-1\x00"), raw...)
}
func (r PartReceipt) Valid(scope UploadScope) bool {
	return scope.Validate() == nil && r.Schema == 1 && r.Scope == scope.Hash() && r.Length == uint32(scope.PartLength(r.Index)) && r.Length > 0 && r.Digest != ([32]byte{}) && len(r.Signature) == ed25519.SignatureSize && ed25519.Verify(scope.Root.Key[:], PartReceiptBytes(r), r.Signature)
}

// Upload holds fixed-width part hashes, not raw content. A 500 MB upload uses
// at most 651,072 bytes here; a put mutation carries one <=32 KiB part to the
// owner and just its signed receipt into Raft. Zero slots mean missing.
type Upload struct {
	Scope    UploadScope
	Revision uint64
	Parts    []byte
	Received uint32
	Closed   bool
	Version  [32]byte `json:",omitempty"`
}

func BeginUpload(scope UploadScope, now uint64) (Upload, error) {
	if scope.Current(scope.Creator, now) != nil || scope.ExpiresAt-now > MaxUploadLifetime {
		return Upload{}, ErrInvalid
	}
	return Upload{Scope: scope, Revision: 1, Parts: make([]byte, int(scope.Parts())*32)}, nil
}
func (u Upload) Validate() error {
	if u.Scope.Validate() != nil || u.Revision == 0 || u.Received > u.Scope.Parts() {
		return ErrInvalid
	}
	if u.Closed {
		if len(u.Parts) != 0 || u.Received != 0 {
			return ErrInvalid
		}
		return nil
	}
	if u.Version != ([32]byte{}) || len(u.Parts) != int(u.Scope.Parts())*32 {
		return ErrInvalid
	}
	var count uint32
	for i := uint32(0); i < u.Scope.Parts(); i++ {
		if u.Part(i) != ([32]byte{}) {
			count++
		}
	}
	if count != u.Received {
		return ErrInvalid
	}
	return nil
}
func (u Upload) Part(index uint32) (out [32]byte) {
	start := int(index) * 32
	if index < u.Scope.Parts() && start+32 <= len(u.Parts) {
		copy(out[:], u.Parts[start:start+32])
	}
	return
}
func (u Upload) Put(creator string, expected, now uint64, receipt PartReceipt) (Upload, error) {
	if u.Validate() != nil || u.Closed || expected != u.Revision || u.Revision == math.MaxUint64 {
		return Upload{}, ErrConflict
	}
	if err := u.Scope.Current(creator, now); err != nil {
		return Upload{}, err
	}
	if !receipt.Valid(u.Scope) {
		return Upload{}, ErrInvalid
	}
	if before := u.Part(receipt.Index); before != ([32]byte{}) {
		if before != receipt.Digest {
			return Upload{}, ErrConflict
		}
		return u, nil // exact same receipt is idempotent, never another CAS edit
	}
	u.Parts = append([]byte(nil), u.Parts...)
	copy(u.Parts[int(receipt.Index)*32:], receipt.Digest[:])
	u.Received++
	u.Revision++
	return u, nil
}
func (u Upload) Missing(creator string, now uint64, after uint32, limit int) ([]uint32, uint32, error) {
	if u.Validate() != nil || u.Closed || limit < 1 || limit > 256 || after > u.Scope.Parts() {
		return nil, 0, ErrInvalid
	}
	if err := u.Scope.Current(creator, now); err != nil {
		return nil, 0, err
	}
	var missing []uint32
	for i := after; i < u.Scope.Parts(); i++ {
		if u.Part(i) == ([32]byte{}) {
			missing = append(missing, i)
		}
		if len(missing) == limit {
			return missing, i + 1, nil
		}
	}
	return missing, u.Scope.Parts(), nil
}

type SealReceipt struct {
	Schema           uint8
	Scope, ZIP, Tree [32]byte
	Entries          uint32
	ExpandedBytes    int64
	Signature        []byte
}

func SealReceiptBytes(r SealReceipt) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("sfc-imagebuild-seal-1\x00"), raw...)
}
func (r SealReceipt) Valid(s UploadScope) bool {
	return s.Validate() == nil && r.Schema == 1 && r.Scope == s.Hash() && r.ZIP == s.Digest && r.Tree != ([32]byte{}) && r.Entries > 0 && r.Entries <= MaxTreeEntries && r.ExpandedBytes >= 0 && r.ExpandedBytes <= s.ExpandedLimit && len(r.Signature) == ed25519.SignatureSize && ed25519.Verify(s.Root.Key[:], SealReceiptBytes(r), r.Signature)
}
func (u Upload) Consume(creator, context string, expected, now uint64, seal SealReceipt) (Upload, error) {
	if u.Validate() != nil || u.Closed || context != u.Scope.Context || expected != u.Revision || u.Revision == math.MaxUint64 || u.Received != u.Scope.Parts() {
		return Upload{}, ErrConflict
	}
	if err := u.Scope.Current(creator, now); err != nil {
		return Upload{}, err
	}
	if !seal.Valid(u.Scope) {
		return Upload{}, ErrInvalid
	}
	u.Version = VersionID(seal)
	u.Closed, u.Parts, u.Received = true, nil, 0
	u.Revision++
	return u, nil
}

func VersionID(seal SealReceipt) [32]byte {
	return digestJSON("sfc-imagebuild-context-version-1", struct{ Scope, ZIP, Tree [32]byte }{seal.Scope, seal.ZIP, seal.Tree})
}

// Abort and Expire commit before native reclamation. Expiry never runs a clock
// inside the FSM; the owner's signed observation is a fixed input. Closed
// tombstones prevent delayed part/seal adoption.
func (u Upload) Abort(creator string, expected uint64) (Upload, error) {
	if creator != u.Scope.Creator {
		return Upload{}, ErrInvalid
	}
	return u.close(expected)
}

type ExpiryReceipt struct {
	Schema    uint8
	Scope     [32]byte
	At        uint64
	Signature []byte
}

func ExpiryReceiptBytes(r ExpiryReceipt) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("sfc-imagebuild-expiry-1\x00"), raw...)
}
func (u Upload) Expire(expected uint64, receipt ExpiryReceipt) (Upload, error) {
	if !receipt.Valid(u.Scope) {
		return Upload{}, ErrInvalid
	}
	return u.close(expected)
}
func (u Upload) close(expected uint64) (Upload, error) {
	if u.Validate() != nil || expected != u.Revision || u.Revision == math.MaxUint64 {
		return Upload{}, ErrConflict
	}
	if u.Closed {
		return u, nil
	}
	u.Closed, u.Parts, u.Received = true, nil, 0
	u.Revision++
	return u, nil
}
