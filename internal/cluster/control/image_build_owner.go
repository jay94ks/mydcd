// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"math"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/nodestorage"
)

type ImageBuildArtifactSelection struct{ Tenant, Upload string }
type ImageBuildArtifactWork struct {
	Schema                     uint8
	Cluster                    [32]byte
	Upload                     ImageBuildUploadRecord
	Root                       nodestorage.Root
	Reclaim                    bool
	Epoch, RootRevision, Index uint64
}

func (b ImageBuildCatalog) ArtifactReferenced(u ImageBuildUploadRecord) bool {
	if u.Version != ([32]byte{}) && b.VersionUsed(u.Scope.Tenant, u.Version) {
		return true
	}
	if !u.Closed {
		return true
	}
	if u.Version == ([32]byte{}) {
		return false
	}
	v, ok := b.Version(u.Scope.Tenant, u.Version)
	return !ok || !v.Deleted
}
func (p Policy) ImageBuildArtifactWork(s state.State, caller [32]byte, q ImageBuildArtifactSelection) (ImageBuildArtifactWork, error) {
	p, err := p.Current(s)
	if err != nil {
		return ImageBuildArtifactWork{}, err
	}
	b, err := p.ImageBuilds(s)
	if err != nil {
		return ImageBuildArtifactWork{}, err
	}
	u, ok := b.Upload(q.Tenant, q.Upload)
	if !ok || u.Scope.Root.Key != caller {
		return ImageBuildArtifactWork{}, access.ErrDenied
	}
	owner, err := p.nodeOwner(s, u.Scope.Root.Node)
	if err != nil || owner != caller {
		return ImageBuildArtifactWork{}, access.ErrDenied
	}
	roots, err := p.NodeStorage(s)
	if err != nil {
		return ImageBuildArtifactWork{}, err
	}
	root, ok := roots.Root(u.Scope.Root.Node, u.Scope.Root.ID)
	if !ok || root.Reference(p.Cluster) != u.Scope.Root {
		return ImageBuildArtifactWork{}, access.ErrDenied
	}
	return ImageBuildArtifactWork{Schema: 1, Cluster: p.Cluster, Upload: u, Root: root, Reclaim: u.Reclaimed == nil && !b.ArtifactReferenced(u), Epoch: s.ModuleEpoch(), RootRevision: s.Object(ImageBuildKey).Revision, Index: s.Index()}, nil
}

type ImageBuildOwnerReport struct {
	Schema                        uint8
	Cluster, Owner                [32]byte
	Tenant, Upload, Action        string
	Expected, RootRevision, Epoch uint64
	Expiry                        *imagebuild.ExpiryReceipt  `json:",omitempty"`
	Reclaimed                     *imagebuild.ReclaimReceipt `json:",omitempty"`
	Part                          *ImageBuildPartProgress    `json:",omitempty"`
	Signature                     []byte
}

func ImageBuildOwnerReportBytes(r ImageBuildOwnerReport) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("sfc-imagebuild-owner-report-1\x00"), raw...)
}
func (r ImageBuildOwnerReport) Command() (state.Command, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return state.Command{}, err
	}
	cmd := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(r.Owner[:]), Epoch: r.Epoch, Key: ImageBuildKey, Expected: r.RootRevision, Value: string(raw)}
	cmd.RequestID = state.ReportRequestID(cmd)
	_, err = state.EncodeCommand(cmd)
	return cmd, err
}
func (p Policy) imageBuildOwnerReport(s state.State, cmd state.Command) (ImageBuildOwnerReport, ImageBuildArtifactWork, error) {
	var r ImageBuildOwnerReport
	current, err := p.Current(s)
	if err != nil {
		return r, ImageBuildArtifactWork{}, err
	}
	p = current
	if cmd.Kind != state.ModuleReport || cmd.Key != ImageBuildKey || canonical([]byte(cmd.Value), &r) != nil || r.Schema != 1 || r.Cluster != p.Cluster || r.Epoch != s.ModuleEpoch() || len(r.Signature) != ed25519.SignatureSize || !ed25519.Verify(r.Owner[:], ImageBuildOwnerReportBytes(r), r.Signature) {
		return r, ImageBuildArtifactWork{}, ErrCatalog
	}
	want, err := r.Command()
	if err != nil || want != cmd {
		return r, ImageBuildArtifactWork{}, ErrCatalog
	}
	work, err := p.ImageBuildArtifactWork(s, r.Owner, ImageBuildArtifactSelection{r.Tenant, r.Upload})
	if err != nil {
		return r, work, err
	}
	if r.Expected != work.Upload.Revision || work.Upload.Revision == math.MaxUint64 {
		return r, work, access.ErrConflict
	}
	switch r.Action {
	case "expired":
		if work.Upload.Closed || r.Expiry == nil || r.Reclaimed != nil || r.Part != nil || !r.Expiry.Valid(work.Upload.Scope) {
			return r, work, access.ErrDenied
		}
	case "reclaimed":
		if !work.Reclaim || r.Expiry != nil || r.Reclaimed == nil || r.Part != nil || !r.Reclaimed.Valid(work.Upload.Scope, work.Upload.Version) {
			return r, work, access.ErrDenied
		}
	case "part":
		if !validBuildPartProgress(r, work.Upload.Scope) || work.Upload.Closed {
			return r, work, access.ErrDenied
		}
		users, err := p.Catalog(s)
		if err != nil {
			return r, work, err
		}
		book, err := p.ImageBuilds(s)
		if err != nil || users.OperationAllowed(r.Part.Session, "put-build-zip-part") != nil || p.currentBuildUpload(s, users, r.Part.Session, r.Part.At, book, work.Upload) != nil {
			return r, work, access.ErrDenied
		}
		if s.Object(buildPartKey(r.Tenant, r.Upload, r.Part.Receipt.Index)).Present {
			return r, work, access.ErrConflict // a confirmed slot needs only an ACK
		}
	default:
		return r, work, access.ErrInvalid
	}
	return r, work, nil
}
func (p Policy) ResolveImageBuildOwnerReport(s state.State, caller [32]byte, raw []byte) (state.Command, error) {
	var report ImageBuildOwnerReport
	if canonical(raw, &report) != nil || report.Owner != caller {
		return state.Command{}, access.ErrDenied
	}
	cmd, err := report.Command()
	if err != nil {
		return cmd, err
	}
	if _, found := s.LookupResult(cmd); found {
		return cmd, nil // exact retained result, never a fresh effect
	}
	_, _, err = p.imageBuildOwnerReport(s, cmd)
	return cmd, err
}
func (p Policy) reduceImageBuildOwner(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	r, work, err := p.imageBuildOwnerReport(s, cmd)
	if err != nil {
		return nil, state.Forbidden
	}
	u := work.Upload
	writes := map[string][]byte{}
	if r.Action == "part" {
		core, err := hydrateBuildUpload(s, u)
		if err != nil {
			return nil, state.Invalid
		}
		progress, err := core.Put(r.Part.Session.User, r.Expected, uint64(r.Part.At), r.Part.Receipt)
		if err != nil || progress.Revision != u.Revision+1 {
			return nil, state.ConditionFailed
		}
		u.Revision, u.Received, u.Progress = progress.Revision, progress.Received, &r
		writes[buildPartKey(r.Tenant, r.Upload, r.Part.Receipt.Index)] = []byte(hex.EncodeToString(r.Part.Receipt.Digest[:]))
	} else if r.Action == "expired" {
		core, err := hydrateBuildUpload(s, u)
		if err != nil {
			return nil, state.Invalid
		}
		closed, err := core.Expire(u.Revision, *r.Expiry)
		if err != nil {
			return nil, state.ConditionFailed
		}
		u.ExpiryReceived, u.Expiry = u.Received, r.Expiry
		u.Revision, u.Received, u.Closed = closed.Revision, closed.Received, closed.Closed
		for key, obj := range s.Objects(buildPartPrefix(u.Scope.Tenant, u.Scope.Upload)) {
			if obj.Present {
				writes[key] = nil
			}
		}
	} else {
		u.Reclaimed = r.Reclaimed
	}
	if writeBuildRecord(writes, "upload", u.Scope.Tenant, u.Scope.Upload, u) != nil {
		return nil, state.Invalid
	}
	writes[ImageBuildKey] = []byte(s.Object(ImageBuildKey).Value)
	return writes, state.Applied
}
