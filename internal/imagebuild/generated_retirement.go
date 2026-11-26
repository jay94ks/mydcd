// SPDX-License-Identifier: Apache-2.0

package imagebuild

import "github.com/jay94ks/mydcd/internal/reconcile"

// GeneratedArtifact identifies existing native source evidence, never a new
// upload/operation. Only one original plan is present.
type GeneratedArtifact struct {
	Scope UploadScope
	Draft *DraftFreezePlan `json:",omitempty"`
	Git   *GitSavePlan     `json:",omitempty"`
}

func (a GeneratedArtifact) Valid() bool {
	if a.Scope.Validate() != nil || (a.Draft == nil) == (a.Git == nil) {
		return false
	}
	if a.Draft != nil {
		return a.Draft.Validate() == nil && a.Scope == a.Draft.ArchiveScope(a.Scope.Length, a.Scope.Digest)
	}
	return a.Git.Validate() == nil && a.Scope == a.Git.ArchiveScope(a.Scope.Length, a.Scope.Digest)
}
func (a GeneratedArtifact) PlanDigest() [32]byte {
	if a.Draft != nil {
		return a.Draft.Digest()
	}
	if a.Git != nil {
		return a.Git.Digest()
	}
	return [32]byte{}
}
func (a GeneratedArtifact) Digest() [32]byte {
	return digestJSON("mydc-imagebuild-generated-artifact-1", a)
}

type GeneratedArchiveGrant struct {
	Artifact                        GeneratedArtifact
	ContextRevision, PolicyRevision uint64
	Deleted                         bool
	Index, Epoch                    uint64
}

func (g GeneratedArchiveGrant) Valid() bool {
	s := g.Artifact.Scope
	return g.Artifact.Valid() && g.ContextRevision >= s.ContextRevision && g.PolicyRevision >= s.PolicyRevision && (g.Deleted || g.ContextRevision > s.ContextRevision || g.PolicyRevision > s.PolicyRevision) && g.Index > 0 && g.Epoch > 0
}

type GeneratedArchiveRetirement struct {
	Artifact                        [32]byte
	ContextRevision, PolicyRevision uint64
	Deleted                         bool
	Index, Epoch                    uint64
	Lease                           reconcile.Lease
	Borrowed, Returning, Returned   bool
}

func (r GeneratedArchiveRetirement) valid(h localUpload) bool {
	s := h.Scope
	return s.Validate() == nil && r.Artifact != ([32]byte{}) && r.ContextRevision >= s.ContextRevision && r.PolicyRevision >= s.PolicyRevision && (r.Deleted || r.ContextRevision > s.ContextRevision || r.PolicyRevision > s.PolicyRevision) && r.Index > 0 && r.Epoch > 0 && h.Generated != nil && *h.Generated != ([32]byte{}) && h.Device != 0 && h.Inode != 0 && (r.Borrowed && r.Lease.Token > 0 && r.Lease.Generation == s.Root.Generation || !r.Borrowed && r.Lease == (reconcile.Lease{})) && (!r.Returning || h.Deleted && !h.Deleting) && (!r.Returned || r.Returning)
}
