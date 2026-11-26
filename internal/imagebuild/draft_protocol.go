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

// DraftProof preserves the user's approval of one exact staged edit through
// an installed-member relay. It does not authorize a build or publish a version.
type DraftProof struct {
	Schema        uint8
	Scope, Edit   [32]byte
	At, ExpiresAt int64
	Nonce         [32]byte
	Signature     []byte
	Transfer      *DraftTransferProof `json:",omitempty"`
}

type DraftTransferProof struct {
	Kind string
	Part *DraftFilePart `json:",omitempty"`
}
type DraftFilePart struct {
	Index, Length uint32
	Digest        [32]byte
}
type DraftFileProgress struct {
	Edit                          [32]byte
	Parts, Received, Offset, Next uint32
	Complete                      bool
	Part                          *DraftFilePart `json:",omitempty"`
	Missing                       []uint32       `json:",omitempty"`
}

func (q DraftRequest) Mutation() bool {
	return q.Kind == "edit" || q.Kind == "file-part" || q.Kind == "file-seal" || q.Kind == "freeze"
}

func (q DraftRequest) Result() bool        { return q.Kind == "result" || q.Kind == "freeze-result" }
func (q DraftRequest) RequiresProof() bool { return q.Mutation() || q.Result() }

func DraftProofBytes(p DraftProof) []byte {
	p.Signature = nil
	raw, _ := json.Marshal(p)
	return append([]byte("mydc-imagebuild-draft-request-1\x00"), raw...)
}

type DraftRequest struct {
	Context  string
	Kind     string
	Scope    *DraftScope      `json:",omitempty"`
	Edit     *DraftEdit       `json:",omitempty"`
	Proof    *DraftProof      `json:",omitempty"`
	Data     []byte           `json:",omitempty"`
	Revision uint64           `json:",omitempty"`
	Digest   *[32]byte        `json:",omitempty"`
	Offset   uint32           `json:",omitempty"`
	Freeze   *DraftFreezePlan `json:",omitempty"`
	Path     string           `json:",omitempty"`
}

func (q DraftRequest) Valid() bool {
	if !lifecycle.ValidID(q.Context) {
		return false
	}
	if q.Kind != "file" && q.Path != "" {
		return false
	}
	if q.Kind != "freeze" && q.Kind != "freeze-result" && q.Freeze != nil {
		return false
	}
	if q.Kind == "plan" {
		return q.Scope == nil && q.Edit == nil && q.Proof == nil && q.Data == nil && q.Revision == 0 && q.Digest == nil && q.Offset == 0
	}
	if q.Scope == nil || q.Scope.Validate() != nil || q.Scope.Context != q.Context {
		return false
	}
	if q.Kind == "freeze" || q.Kind == "freeze-result" {
		return q.Freeze != nil && q.Freeze.Validate() == nil && q.Freeze.Scope == *q.Scope && q.Edit == nil && q.Proof != nil && q.Proof.Transfer != nil && q.Proof.Transfer.Kind == q.Kind && q.Proof.Transfer.Part == nil && q.Data == nil && q.Revision == 0 && q.Digest == nil && q.Offset == 0
	}
	if q.Kind == "tree" {
		return q.Edit == nil && q.Proof == nil && q.Data == nil && q.Offset <= MaxTreeEntries && (q.Revision == 0 && q.Digest == nil && q.Offset == 0 || q.Revision > 0 && q.Digest != nil && *q.Digest != ([32]byte{}))
	}
	if q.Kind == "file" {
		return ContextPath(q.Path) && q.Edit == nil && q.Proof == nil && q.Data == nil && q.Revision > 0 && q.Digest != nil && *q.Digest != ([32]byte{})
	}
	if q.Kind == "file-status" {
		return q.Edit != nil && q.Edit.Validate() == nil && q.Edit.Kind == "put" && q.Edit.File.Bytes > 0 && q.Proof == nil && q.Data == nil && q.Revision == 0 && q.Digest == nil && q.Offset <= draftFileParts(*q.Edit)
	}
	if q.Kind == "result" {
		return q.Edit != nil && q.Edit.Validate() == nil && q.Proof != nil && q.Proof.Transfer != nil && q.Proof.Transfer.Kind == "result" && q.Proof.Transfer.Part == nil && q.Data == nil && q.Revision == 0 && q.Digest == nil && q.Offset == 0
	}
	if q.Kind == "file-part" || q.Kind == "file-seal" {
		if q.Edit == nil || q.Edit.Validate() != nil || q.Edit.Kind != "put" || q.Edit.File.Bytes <= 0 || q.Proof == nil || q.Proof.Transfer == nil || q.Proof.Transfer.Kind != q.Kind || q.Revision != 0 || q.Digest != nil || q.Offset != 0 {
			return false
		}
		part := q.Proof.Transfer.Part
		if q.Kind == "file-seal" {
			return q.Data == nil && part == nil
		}
		return part != nil && len(q.Data) > 0 && len(q.Data) == DraftFilePartLength(*q.Edit, part.Index) && part.Length == uint32(len(q.Data)) && part.Digest == sha256.Sum256(q.Data)
	}
	if q.Kind != "edit" || q.Edit == nil || q.Edit.Validate() != nil || q.Proof == nil || q.Revision != 0 || q.Digest != nil || q.Offset != 0 {
		return false
	}
	if q.Proof.Transfer != nil {
		return false
	}
	if q.Edit.Kind != "put" {
		return q.Data == nil
	}
	// Inline staging is one bounded chunk. Multipart files use the same edit
	// contract and native content store; accepting a partial file is forbidden.
	return len(q.Data) <= PartBytes && int64(len(q.Data)) == q.Edit.File.Bytes && sha256.Sum256(q.Data) == q.Edit.File.Digest
}

func (q DraftRequest) Authorize(scope DraftScope, session access.Session, now int64) error {
	if !q.Valid() || !q.RequiresProof() || q.Scope == nil || *q.Scope != scope || scope.Root.Cluster != session.Cluster || now <= 0 {
		return ErrInvalid
	}
	p := q.Proof
	var subject [32]byte
	if q.Freeze != nil {
		if q.Freeze.Creator != session.User || uint64(now) < q.Freeze.CreatedAt || !q.Result() && uint64(now) >= q.Freeze.ExpiresAt {
			return ErrInvalid
		}
		subject = q.Freeze.Digest()
	} else {
		subject = q.Edit.Digest()
	}
	if p.Schema != 1 || p.Scope != scope.Digest() || p.Edit != subject || p.Nonce == ([32]byte{}) || p.At <= 0 || p.At > now || p.At > math.MaxInt64-120 || p.ExpiresAt <= now || p.ExpiresAt > p.At+120 || p.ExpiresAt > session.ExpiresAt || len(p.Signature) != ed25519.SignatureSize || !ed25519.Verify(session.Key[:], DraftProofBytes(*p), p.Signature) {
		return ErrInvalid
	}
	return nil
}

type DraftResponse struct {
	Schema              uint8
	Scope               DraftScope
	Code                string
	Revision            uint64
	Digest              *[32]byte `json:",omitempty"`
	Offset, Total, Next uint32
	Entries             []Entry            `json:",omitempty"`
	Edit                *DraftEditResult   `json:",omitempty"`
	File                *DraftFileProgress `json:",omitempty"`
	Frozen              *FrozenDraft       `json:",omitempty"`
	Reclaimed           bool               `json:",omitempty"`
	Content             *FilePage          `json:",omitempty"`
}

func (r DraftResponse) Valid(q DraftRequest) bool {
	if !q.Valid() || r.Schema != 1 || r.Scope.Validate() != nil || r.Scope.Context != q.Context || q.Scope != nil && *q.Scope != r.Scope {
		return false
	}
	if r.Reclaimed && q.Kind != "freeze-result" {
		return false
	}
	if q.Kind != "file" && r.Content != nil {
		return false
	}
	if q.Kind == "file" {
		if r.Edit != nil || r.File != nil || r.Frozen != nil || len(r.Entries) != 0 || r.Offset != 0 || r.Total != 0 || r.Next != 0 {
			return false
		}
		if r.Code != "OK" {
			return (r.Code == "PENDING" || r.Code == "NOT_INITIALIZED") && r.Content == nil && r.Revision == 0 && r.Digest == nil
		}
		return r.Revision == q.Revision && r.Digest != nil && *r.Digest == *q.Digest && r.Content != nil && r.Content.Valid(q.Path, uint64(q.Offset))
	}
	if q.Kind == "freeze" || q.Kind == "freeze-result" {
		if r.Revision != 0 || r.Digest != nil || r.Offset != 0 || r.Total != 0 || r.Next != 0 || len(r.Entries) != 0 || r.Edit != nil || r.File != nil {
			return false
		}
		if r.Code == "FROZEN" {
			return r.Frozen != nil && r.Frozen.Valid() && r.Frozen.Plan == *q.Freeze
		}
		return (r.Code == "PENDING" || r.Code == "NOT_INITIALIZED" || q.Kind == "freeze-result" && r.Code == "DISCARDED") && r.Frozen == nil && !r.Reclaimed
	}
	if r.Frozen != nil {
		return false
	}
	if q.Kind == "plan" {
		return r.Code == "PLAN" && r.Revision == 0 && r.Digest == nil && r.Offset == 0 && r.Total == 0 && r.Next == 0 && len(r.Entries) == 0 && r.Edit == nil && r.File == nil
	}
	if q.Kind == "file-part" || q.Kind == "file-status" {
		if r.Code == "STAGED" {
			return r.Revision == 0 && r.Digest == nil && r.Edit == nil && len(r.Entries) == 0 && r.Offset == 0 && r.Total == 0 && r.Next == 0 && r.File != nil && r.File.valid(q)
		}
		return (r.Code == "NOT_INITIALIZED" || r.Code == "PENDING") && r.Revision == 0 && r.Digest == nil && r.Offset == 0 && r.Total == 0 && r.Next == 0 && len(r.Entries) == 0 && r.Edit == nil && r.File == nil
	}
	if r.File != nil {
		return false
	}
	if r.Code != "OK" {
		return (r.Code == "NOT_INITIALIZED" || r.Code == "PENDING" || q.Kind == "result" && r.Code == "DISCARDED") && r.Revision == 0 && r.Digest == nil && r.Offset == 0 && r.Total == 0 && r.Next == 0 && len(r.Entries) == 0 && r.Edit == nil
	}
	if q.Kind == "edit" || q.Kind == "file-seal" || q.Kind == "result" {
		return r.Revision == q.Edit.Expected+1 && r.Digest != nil && *r.Digest != ([32]byte{}) && r.Edit != nil && r.Edit.Edit == q.Edit.Digest() && r.Edit.Draft == *r.Digest && r.Edit.Revision == r.Revision && r.Offset == 0 && r.Total == 0 && r.Next == 0 && len(r.Entries) == 0
	}
	if q.Kind != "tree" || r.Edit != nil || r.Revision == 0 || r.Digest == nil || *r.Digest == ([32]byte{}) || q.Revision != 0 && (r.Revision != q.Revision || *r.Digest != *q.Digest) || r.Offset != q.Offset || r.Total > MaxTreeEntries || r.Offset > r.Total || uint32(len(r.Entries)) != min(uint32(8), r.Total-r.Offset) {
		return false
	}
	end := r.Offset + uint32(len(r.Entries))
	if r.Next != 0 && r.Next != end || (end < r.Total) != (r.Next != 0) {
		return false
	}
	for i, entry := range r.Entries {
		if !validContentEntry(entry) || i > 0 && r.Entries[i-1].Path >= entry.Path {
			return false
		}
	}
	return true
}

func (p DraftFileProgress) valid(q DraftRequest) bool {
	if q.Edit == nil || p.Edit != q.Edit.Digest() || p.Parts != draftFileParts(*q.Edit) || p.Received > p.Parts || p.Complete && p.Received != p.Parts {
		return false
	}
	if q.Kind == "file-part" {
		return p.Part != nil && q.Proof.Transfer != nil && q.Proof.Transfer.Part != nil && *p.Part == *q.Proof.Transfer.Part && p.Offset == 0 && p.Next == 0 && len(p.Missing) == 0 && p.Received > 0
	}
	if q.Kind != "file-status" || p.Part != nil || p.Offset != q.Offset || p.Offset > p.Parts || len(p.Missing) > 256 || uint32(len(p.Missing)) > p.Parts-p.Received || p.Complete && (len(p.Missing) != 0 || p.Next != 0) || p.Next != 0 && (len(p.Missing) != 256 || p.Next != p.Missing[len(p.Missing)-1]+1 || p.Next >= p.Parts) || p.Next == 0 && p.Offset == 0 && p.Received+uint32(len(p.Missing)) != p.Parts {
		return false
	}
	for i, missing := range p.Missing {
		if missing < p.Offset || missing >= p.Parts || i > 0 && missing <= p.Missing[i-1] {
			return false
		}
	}
	return true
}

func draftFileParts(edit DraftEdit) uint32 {
	if edit.File == nil || edit.File.Bytes < 0 || edit.File.Bytes > MaxZIPBytes {
		return 0
	}
	return uint32((edit.File.Bytes + PartBytes - 1) / PartBytes)
}
func DraftFilePartLength(edit DraftEdit, index uint32) int {
	if edit.Validate() != nil || edit.Kind != "put" || index >= draftFileParts(edit) {
		return 0
	}
	return int(min(int64(PartBytes), edit.File.Bytes-int64(index)*PartBytes))
}
