// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"crypto/ed25519"
	"encoding/json"
	"math"

	"github.com/jay94ks/seafield/internal/access"
)

type GitSaveProof struct {
	Schema        uint8
	Plan          [32]byte
	At, ExpiresAt int64
	Nonce         [32]byte
	Signature     []byte
	Result        bool `json:",omitempty"`
}

func GitSaveProofBytes(p GitSaveProof) []byte {
	p.Signature = nil
	raw, _ := json.Marshal(p)
	return append([]byte("sfc-imagebuild-git-request-1\x00"), raw...)
}

type GitSaveRequest struct {
	Plan   GitSavePlan
	Proof  GitSaveProof
	Result bool `json:",omitempty"`
}

func (q GitSaveRequest) Valid() bool { return q.Plan.Validate() == nil && q.Result == q.Proof.Result }
func (q GitSaveRequest) Authorize(session access.Session, now int64) error {
	p := q.Proof
	if !q.Valid() || q.Plan.Creator != session.User || q.Plan.Root.Cluster != session.Cluster || now <= 0 || uint64(now) < q.Plan.CreatedAt || !q.Result && uint64(now) >= q.Plan.ExpiresAt || p.Schema != 1 || p.Plan != q.Plan.Digest() || p.Nonce == ([32]byte{}) || p.At <= 0 || p.At > now || p.At > math.MaxInt64-120 || p.ExpiresAt <= now || p.ExpiresAt > p.At+120 || p.ExpiresAt > session.ExpiresAt || len(p.Signature) != ed25519.SignatureSize || !ed25519.Verify(session.Key[:], GitSaveProofBytes(p), p.Signature) {
		return access.ErrDenied
	}
	return nil
}

type GitSaveResponse struct {
	Schema    uint8
	Plan      [32]byte
	Code      string
	Saved     *SavedGit `json:",omitempty"`
	Reclaimed bool      `json:",omitempty"`
}

func (r GitSaveResponse) Valid(q GitSaveRequest) bool {
	if !q.Valid() || r.Schema != 1 || r.Plan != q.Plan.Digest() || r.Reclaimed && !q.Result {
		return false
	}
	if r.Code == "SAVED" {
		return r.Saved != nil && r.Saved.Valid() && r.Saved.Plan == q.Plan
	}
	if q.Result {
		return r.Saved == nil && !r.Reclaimed && (r.Code == "PENDING" || r.Code == "NOT_INITIALIZED" || r.Code == "DISCARDED")
	}
	return r.Saved == nil && (r.Code == "PENDING" || r.Code == "SOURCE_FETCH" || r.Code == "INVALID_CONTEXT")
}
