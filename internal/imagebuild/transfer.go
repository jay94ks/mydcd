// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"math"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
)

// PartProof survives an installed-member relay and proves the exact creator
// requested these bytes, not just that the relay can present a Session. It
// contains no ZIP body and admits only idempotent staging of this original.
type PartProof struct {
	Schema        uint8
	Scope         [32]byte
	Index, Length uint32
	Digest        [32]byte
	Expected      uint64
	At, ExpiresAt int64
	Nonce         [32]byte
	Record        bool      `json:",omitempty"`
	Session       *[32]byte `json:",omitempty"`
	Signature     []byte
}

func PartProofBytes(p PartProof) []byte {
	p.Signature = nil
	raw, _ := json.Marshal(p)
	return append([]byte("mydc-imagebuild-part-request-1\x00"), raw...)
}

// Include the independent approval too: dropping or replacing a narrower
// approval must not widen a recorded part's original credential ceiling.
func PartSessionDigest(s access.Session) [32]byte {
	return digestJSON("mydc-imagebuild-part-session-1", s)
}

type Transfer struct {
	Upload, Kind string
	Expected     uint64
	Index        uint32     `json:",omitempty"`
	Data         []byte     `json:",omitempty"`
	Proof        *PartProof `json:",omitempty"`
	Record       bool       `json:",omitempty"`
}

func (q Transfer) Valid() bool {
	if !lifecycle.ValidID(q.Upload) || q.Expected == 0 {
		return false
	}
	if q.Kind == "seal" {
		return q.Index == 0 && q.Data == nil && q.Proof == nil && !q.Record
	}
	return q.Kind == "part" && q.Proof != nil && len(q.Data) > 0 && len(q.Data) <= UploadPartBytes && q.Proof.Schema == 1 && q.Proof.Index == q.Index && q.Proof.Length == uint32(len(q.Data)) && q.Proof.Digest == sha256.Sum256(q.Data) && q.Proof.Expected == q.Expected && q.Proof.Record == q.Record
}
func (q Transfer) Authorize(scope UploadScope, session access.Session, now int64) error {
	if !q.Valid() || scope.Validate() != nil || scope.Current(session.User, uint64(now)) != nil || q.Upload != scope.Upload || session.Cluster != scope.Cluster || session.User != scope.Creator || now <= 0 {
		return ErrInvalid
	}
	if q.Kind == "seal" {
		return nil
	}
	return q.Proof.Authorize(scope, session, now)
}

// Authorize validates the same exact user proof at the native transfer and
// metadata-only owner report boundaries. It grants no begin/consume authority.
func (p PartProof) Authorize(scope UploadScope, session access.Session, now int64) error {
	if p.Record && (p.Session == nil || *p.Session != PartSessionDigest(session)) || !p.Record && p.Session != nil {
		return ErrInvalid
	}
	if scope.Validate() != nil || now <= 0 || scope.Current(session.User, uint64(now)) != nil || session.Cluster != scope.Cluster || session.User != scope.Creator || p.Schema != 1 || p.Scope != scope.Hash() || p.Index >= scope.Parts() || p.Length != uint32(scope.PartLength(p.Index)) || p.Digest == ([32]byte{}) || p.Expected == 0 || p.Nonce == ([32]byte{}) || p.At <= 0 || p.At < session.IssuedAt || p.At > now || p.At > math.MaxInt64-120 || p.ExpiresAt <= now || p.ExpiresAt > p.At+120 || p.ExpiresAt > session.ExpiresAt || len(p.Signature) != ed25519.SignatureSize || !ed25519.Verify(session.Key[:], PartProofBytes(p), p.Signature) {
		return ErrInvalid
	}
	return nil
}
