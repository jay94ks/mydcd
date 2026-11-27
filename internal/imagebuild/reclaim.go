// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"crypto/ed25519"
	"encoding/json"
	"math"
)

type ReclaimReceipt struct {
	Schema                 uint8
	Scope, Version, Native [32]byte
	At                     uint64
	Signature              []byte
}

func ReclaimReceiptBytes(r ReclaimReceipt) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("sfc-imagebuild-reclaimed-1\x00"), raw...)
}
func (r ReclaimReceipt) Valid(scope UploadScope, version [32]byte) bool {
	return scope.Validate() == nil && r.Schema == 1 && r.Scope == scope.Hash() && r.Version == version && r.Native != ([32]byte{}) && r.At > 0 && r.At <= math.MaxInt64 && len(r.Signature) == ed25519.SignatureSize && ed25519.Verify(scope.Root.Key[:], ReclaimReceiptBytes(r), r.Signature)
}
func (r ExpiryReceipt) Valid(scope UploadScope) bool {
	return scope.Validate() == nil && r.Schema == 1 && r.Scope == scope.Hash() && r.At >= scope.ExpiresAt && r.At <= math.MaxInt64 && len(r.Signature) == ed25519.SignatureSize && ed25519.Verify(scope.Root.Key[:], ExpiryReceiptBytes(r), r.Signature)
}
