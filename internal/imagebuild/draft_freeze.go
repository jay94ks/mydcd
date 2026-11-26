// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"crypto/ed25519"
	"encoding/json"
	"math"

	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
)

// DraftFreezePlan is an immutable save input, not a rolling pointer to the
// latest editor revision. Renewing transport proof never changes this plan.
type DraftFreezePlan struct {
	Schema               uint8
	Scope                DraftScope
	ID, Creator          string
	Revision             uint64
	Draft                [32]byte
	CreatedAt, ExpiresAt uint64
}

func (p DraftFreezePlan) Validate() error {
	if p.Schema != 1 || p.Scope.Validate() != nil || !lifecycle.ValidID(p.ID) || !lifecycle.ValidID(p.Creator) || p.Revision == 0 || p.Draft == ([32]byte{}) || p.CreatedAt == 0 || p.ExpiresAt <= p.CreatedAt || p.ExpiresAt > math.MaxInt64 || p.ExpiresAt-p.CreatedAt > MaxUploadLifetime {
		return ErrInvalid
	}
	return nil
}
func (p DraftFreezePlan) Digest() [32]byte { return digestJSON("mydc-imagebuild-draft-freeze-1", p) }
func (p DraftFreezePlan) ArchiveScope(length int64, digest [32]byte) UploadScope {
	return UploadScope{Schema: 1, Cluster: p.Scope.Root.Cluster, Tenant: p.Scope.Tenant, Context: p.Scope.Context, Upload: p.ID, Creator: p.Creator, Root: p.Scope.Root, ContextRevision: p.Scope.ContextRevision, PolicyRevision: p.Scope.PolicyRevision, Length: length, Digest: digest, Dockerfile: p.Scope.Dockerfile, ExpandedLimit: p.Scope.ExpandedLimit, ExpiresAt: p.ExpiresAt}
}

// FrozenDraft is owner evidence of actual original archive bytes. Publishing
// it still requires the creator's signed User operation and current authority.
type FrozenDraft struct {
	Schema    uint8
	Plan      DraftFreezePlan
	Scope     UploadScope
	Fact      SealReceipt
	Signature []byte
}

func FrozenDraftBytes(r FrozenDraft) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("mydc-imagebuild-frozen-draft-1\x00"), raw...)
}
func (r FrozenDraft) Valid() bool {
	return r.Schema == 1 && r.Plan.Validate() == nil && r.Scope.Validate() == nil && r.Scope == r.Plan.ArchiveScope(r.Scope.Length, r.Scope.Digest) && r.Fact.Valid(r.Scope) && len(r.Signature) == ed25519.SignatureSize && ed25519.Verify(r.Scope.Root.Key[:], FrozenDraftBytes(r), r.Signature)
}
