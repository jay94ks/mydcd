// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/hex"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"
)

// The owner reports a fact inside the accepted upload. Session and proof retain
// the creator's exact scope, bytes, CAS, expiry and explicit recording mode.
type ImageBuildPartProgress struct {
	Session access.Session
	Proof   imagebuild.PartProof
	Receipt imagebuild.PartReceipt
	At      int64
}

func validBuildPartProgress(r ImageBuildOwnerReport, scope imagebuild.UploadScope) bool {
	part := r.Part
	if part == nil || r.Schema != 1 || r.Action != "part" || r.Cluster != scope.Cluster || r.Tenant != scope.Tenant || r.Upload != scope.Upload || r.Owner != scope.Root.Key || r.Epoch == 0 || r.RootRevision == 0 || r.Expiry != nil || r.Reclaimed != nil || !ed25519.Verify(r.Owner[:], ImageBuildOwnerReportBytes(r), r.Signature) {
		return false
	}
	s := part.Session
	if s.Schema != 1 || s.AccountRevision == 0 || s.Key == ([32]byte{}) || s.Issuer == ([32]byte{}) || s.IssuerEpoch == 0 || s.IssuedAt < 0 || part.At < s.IssuedAt || part.At >= s.ExpiresAt || s.ExpiresAt-s.IssuedAt > access.MaxSessionSeconds || !access.ValidateScopes(s.Scopes) || !ed25519.Verify(s.Issuer[:], access.SessionBytes(s), s.Signature) || s.Approval != nil && s.Approval.VerifyBinding(s) != nil {
		return false
	}
	return part.Proof.Record && part.Proof.Expected == r.Expected && part.Proof.Authorize(scope, s, part.At) == nil && part.Receipt.Valid(scope) && part.Receipt.Index == part.Proof.Index && part.Receipt.Length == part.Proof.Length && part.Receipt.Digest == part.Proof.Digest
}

// Restore validates the retained fact at its original instant. Current user
// authority is checked at report admission, not reapplied to committed history.
func validBuildPartCheckpoint(s state.State, r ImageBuildUploadRecord, expired bool) bool {
	p := r.Progress
	if p == nil || !validBuildPartProgress(*p, r.Scope) || r.Closed || r.Revision < 2 || p.Expected != r.Revision-1 || uint64(r.Received)+1 != r.Revision || p.Epoch > s.ModuleEpoch() || p.RootRevision > s.Object(ImageBuildKey).Revision {
		return false
	}
	if !expired && s.Object(buildPartKey(r.Scope.Tenant, r.Scope.Upload, p.Part.Receipt.Index)).Value != hex.EncodeToString(p.Part.Receipt.Digest[:]) {
		return false
	}
	switch r.Origin.Change.Action {
	case "begin-build-zip-upload":
		return buildJSONEqual(r.Begin, r.Origin)
	case "put-build-zip-part":
		var original ImageBuildUploadPart
		return canonical(r.Origin.Change.Payload, &original) == nil && original.Tenant == r.Scope.Tenant && original.Upload == r.Scope.Upload && original.Receipt.Valid(r.Scope) && r.Origin.Change.Expected <= p.Expected && (expired || s.Object(buildPartKey(original.Tenant, original.Upload, original.Receipt.Index)).Value == hex.EncodeToString(original.Receipt.Digest[:]))
	}
	return false
}
