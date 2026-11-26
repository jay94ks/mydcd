// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/hex"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/nodestorage"
)

type ImageBuildIOCall struct {
	Session access.Session
	Tenant  string
	Request imagebuild.Transfer
	At      int64
}

// ImageBuildPartPermitCall is the metadata-only quorum read for one original
// user-signed part. It cannot carry ZIP bytes or request a seal/native effect.
// Record and the session/approval fingerprint stay in the unchanged PartProof.
type ImageBuildPartPermitCall struct {
	Session  access.Session
	Tenant   string
	Upload   string
	Expected uint64
	Index    uint32
	Proof    imagebuild.PartProof
	At       int64
}

// PartPermit only removes bytes after the effect path has checked their exact
// length and digest. The returned metadata is not a replacement Transfer.
func (q ImageBuildIOCall) PartPermit() (ImageBuildPartPermitCall, error) {
	if q.Request.Kind != "part" || !q.Request.Valid() {
		return ImageBuildPartPermitCall{}, access.ErrInvalid
	}
	return ImageBuildPartPermitCall{Session: q.Session, Tenant: q.Tenant, Upload: q.Request.Upload, Expected: q.Request.Expected, Index: q.Request.Index, Proof: *q.Request.Proof, At: q.At}, nil
}

func (q ImageBuildPartPermitCall) valid() bool {
	return validID(q.Tenant) && validID(q.Upload) && q.At > 0 && q.Expected > 0 && q.Proof.Schema == 1 && q.Proof.Index == q.Index && q.Proof.Expected == q.Expected && q.Proof.Length > 0 && q.Proof.Length <= imagebuild.UploadPartBytes && q.Proof.Digest != ([32]byte{})
}

type ImageBuildIOWork struct {
	Schema                 uint8
	Cluster                [32]byte
	Scope                  imagebuild.UploadScope
	Root                   nodestorage.Root
	Expected, Epoch, Index uint64
	Recorded               bool   `json:",omitempty"`
	RootRevision           uint64 `json:",omitempty"`
}
type ImageBuildIOResult struct {
	Schema         uint8
	Scope          [32]byte
	Code           string
	Part           *imagebuild.PartReceipt `json:",omitempty"`
	Seal           *imagebuild.SealReceipt `json:",omitempty"`
	Recorded       bool                    `json:",omitempty"`
	UploadRevision uint64                  `json:",omitempty"`
}

func (r ImageBuildIOResult) Valid(scope imagebuild.UploadScope, q imagebuild.Transfer) bool {
	if scope.Validate() != nil || !q.Valid() || r.Schema != 1 || r.Scope != scope.Hash() {
		return false
	}
	if r.Code != "OK" {
		return !r.Recorded && r.UploadRevision == 0 && r.Part == nil && r.Seal == nil && (r.Code == "STORAGE_UNAVAILABLE" || r.Code == "DIGEST_MISMATCH" || r.Code == "INVALID_ZIP" || r.Code == "CONFLICT")
	}
	if q.Kind == "part" {
		return r.Recorded == (r.UploadRevision > 0) && (!r.Recorded || q.Record && r.UploadRevision >= q.Expected) && r.Part != nil && r.Seal == nil && r.Part.Valid(scope) && r.Part.Index == q.Index && r.Part.Digest == q.Proof.Digest
	}
	return q.Kind == "seal" && !r.Recorded && r.UploadRevision == 0 && r.Part == nil && r.Seal != nil && r.Seal.Valid(scope)
}
func (p Policy) ImageBuildIOPermit(s state.State, caller [32]byte, q ImageBuildIOCall) (ImageBuildIOWork, error) {
	if !q.Request.Valid() {
		return ImageBuildIOWork{}, access.ErrInvalid
	}
	return p.imageBuildIOPermit(s, caller, q)
}

func (p Policy) ImageBuildPartPermit(s state.State, caller [32]byte, q ImageBuildPartPermitCall) (ImageBuildIOWork, error) {
	if !q.valid() {
		return ImageBuildIOWork{}, access.ErrInvalid
	}
	// Only the private common permit core accepts a part without Data. Every
	// public effect/full-data entry still requires Transfer.Valid and its SHA.
	call := ImageBuildIOCall{Session: q.Session, Tenant: q.Tenant, At: q.At, Request: imagebuild.Transfer{Upload: q.Upload, Kind: "part", Expected: q.Expected, Index: q.Index, Proof: &q.Proof, Record: q.Proof.Record}}
	return p.imageBuildIOPermit(s, caller, call)
}

func (p Policy) imageBuildIOPermit(s state.State, caller [32]byte, q ImageBuildIOCall) (ImageBuildIOWork, error) {
	p, err := p.Current(s)
	if err != nil {
		return ImageBuildIOWork{}, err
	}
	if !validID(q.Tenant) || q.At <= 0 {
		return ImageBuildIOWork{}, access.ErrInvalid
	}
	b, err := p.ImageBuilds(s)
	if err != nil {
		return ImageBuildIOWork{}, err
	}
	u, ok := b.Upload(q.Tenant, q.Request.Upload)
	if !ok || caller != u.Scope.Root.Key || q.Request.Upload != u.Scope.Upload {
		return ImageBuildIOWork{}, access.ErrDenied
	}
	// PartProof.Authorize is the same signed scope/creator/session/expiry
	// check used by Transfer.Authorize, without hashing bytes on a quorum read.
	// Seal continues through the original full Transfer authorization.
	if q.Request.Kind == "part" && q.Request.Proof.Authorize(u.Scope, q.Session, q.At) != nil || q.Request.Kind == "seal" && q.Request.Authorize(u.Scope, q.Session, q.At) != nil {
		return ImageBuildIOWork{}, access.ErrDenied
	}
	recorded := q.Request.Record && q.Request.Kind == "part" && s.Object(buildPartKey(q.Tenant, q.Request.Upload, q.Request.Index)).Value == hex.EncodeToString(q.Request.Proof.Digest[:])
	if q.Request.Expected > u.Revision || q.Request.Expected != u.Revision && !recorded {
		return ImageBuildIOWork{}, access.ErrConflict
	}
	c, err := p.Catalog(s)
	if err != nil {
		return ImageBuildIOWork{}, err
	}
	action := "put-build-zip-part"
	if q.Request.Kind == "seal" {
		action = "upload-build-zip"
		if u.Received != u.Scope.Parts() {
			return ImageBuildIOWork{}, access.ErrConflict
		}
	}
	if c.OperationAllowed(q.Session, action) != nil || p.currentBuildUpload(s, c, q.Session, q.At, b, u) != nil {
		return ImageBuildIOWork{}, access.ErrDenied
	}
	roots, err := p.NodeStorage(s)
	if err != nil {
		return ImageBuildIOWork{}, err
	}
	root, ok := roots.Root(u.Scope.Root.Node, u.Scope.Root.ID)
	if !ok || root.Reference(p.Cluster) != u.Scope.Root {
		return ImageBuildIOWork{}, access.ErrDenied
	}
	work := ImageBuildIOWork{Schema: 1, Cluster: p.Cluster, Scope: u.Scope, Root: root, Expected: u.Revision, Epoch: s.ModuleEpoch(), Index: s.Index(), Recorded: recorded}
	if q.Request.Record {
		work.RootRevision = s.Object(ImageBuildKey).Revision
	}
	return work, nil
}
