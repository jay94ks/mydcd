// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"math"

	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/nodestorage"
)

// GitSavePlan fixes the exact checked commit/tree. Ref discovery may happen
// before this plan, never as an implicit replacement while resuming it.
type GitSavePlan struct {
	Schema                          uint8
	Tenant, Context, ID, Creator    string
	Root                            nodestorage.Reference
	ContextRevision, PolicyRevision uint64
	Dockerfile                      string
	ExpandedLimit                   int64
	Commit                          string
	Tree                            [32]byte
	CreatedAt, ExpiresAt            uint64
}

func ValidGitCommit(commit string) bool {
	raw, err := hex.DecodeString(commit)
	return err == nil && len(raw) == 20 && hex.EncodeToString(raw) == commit && commit != "0000000000000000000000000000000000000000"
}
func (p GitSavePlan) Validate() error {
	if p.Schema != 1 || !lifecycle.ValidID(p.Tenant) || !lifecycle.ValidID(p.Context) || !lifecycle.ValidID(p.ID) || !lifecycle.ValidID(p.Creator) || p.Root.Validate() != nil || p.ContextRevision == 0 || p.PolicyRevision == 0 || !ContextPath(p.Dockerfile) || p.ExpandedLimit <= 0 || p.ExpandedLimit > MaxExpandedBytes || !ValidGitCommit(p.Commit) || p.Tree == ([32]byte{}) || p.CreatedAt == 0 || p.ExpiresAt <= p.CreatedAt || p.ExpiresAt > math.MaxInt64 || p.ExpiresAt-p.CreatedAt > MaxUploadLifetime {
		return ErrInvalid
	}
	return nil
}
func (p GitSavePlan) Digest() [32]byte { return digestJSON("sfc-imagebuild-git-save-1", p) }
func (p GitSavePlan) ArchiveScope(length int64, digest [32]byte) UploadScope {
	return UploadScope{Schema: 1, Cluster: p.Root.Cluster, Tenant: p.Tenant, Context: p.Context, Upload: p.ID, Creator: p.Creator, Root: p.Root, ContextRevision: p.ContextRevision, PolicyRevision: p.PolicyRevision, Length: length, Digest: digest, Dockerfile: p.Dockerfile, ExpandedLimit: p.ExpandedLimit, ExpiresAt: p.ExpiresAt}
}

// SavedGit is evidence of retained bytes, not authority to publish a version.
type SavedGit struct {
	Schema    uint8
	Plan      GitSavePlan
	Scope     UploadScope
	Fact      SealReceipt
	Signature []byte
}

func SavedGitBytes(r SavedGit) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("sfc-imagebuild-saved-git-1\x00"), raw...)
}
func (r SavedGit) Valid() bool {
	return r.Schema == 1 && r.Plan.Validate() == nil && r.Scope.Validate() == nil && r.Scope == r.Plan.ArchiveScope(r.Scope.Length, r.Scope.Digest) && r.Fact.Valid(r.Scope) && r.Fact.Tree == r.Plan.Tree && len(r.Signature) == ed25519.SignatureSize && ed25519.Verify(r.Scope.Root.Key[:], SavedGitBytes(r), r.Signature)
}
