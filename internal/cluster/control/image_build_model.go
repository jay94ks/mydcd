// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/nodestorage"
)

const ImageBuildKey = "control/image-builds"
const maxImageBuildRecords = 4096

type ImageBuildSelection struct{ Tenant, ID string }
type ImageBuildVersionSelection struct {
	Tenant string
	ID     [32]byte
}
type ImageBuildPolicyPut struct{ Spec imagebuild.Policy }
type ImageBuildContextPut struct{ Spec imagebuild.ContextSpec }
type ImageBuildUploadBegin struct {
	Tenant, Context, Upload string
	Length                  int64
	Digest                  [32]byte
	ExpiresAt               uint64
	ChunkBytes              uint32 `json:",omitempty"`
}
type ImageBuildUploadPart struct {
	Tenant, Upload string
	Receipt        imagebuild.PartReceipt
}
type ImageBuildUploadSelection struct{ Tenant, Upload string }
type ImageBuildZIPConsume struct {
	Tenant, ID, Upload string
	Fact               imagebuild.SealReceipt
}
type ImageBuildPolicyRecord struct {
	Spec               imagebuild.Policy
	Revision           uint64
	Deleted            bool
	Definition, Origin UserOperation
}
type ImageBuildContextRecord struct {
	Spec                  imagebuild.ContextSpec
	Revision, NextVersion uint64
	Deleted               bool
	Definition, Origin    UserOperation
	DataGeneration        uint64                    `json:",omitempty"`
	GitObservation        *ImageBuildGitObservation `json:",omitempty"`
}

// Legacy records are anchored to their last visible definition revision. The
// first following update captures that anchor; ordinary updates retain it.
func (r ImageBuildContextRecord) DraftGeneration() uint64 {
	if r.DataGeneration != 0 {
		return r.DataGeneration
	}
	return r.Revision
}

type ImageBuildUploadRecord struct {
	Scope          imagebuild.UploadScope
	Revision       uint64
	Received       uint32
	Closed         bool
	Version        [32]byte
	Begin, Origin  UserOperation
	Expiry         *imagebuild.ExpiryReceipt     `json:",omitempty"`
	ExpiryReceived uint32                        `json:",omitempty"`
	Reclaimed      *imagebuild.ReclaimReceipt    `json:",omitempty"`
	Automatic      *ImageBuildAutomaticGitReport `json:",omitempty"`
	Progress       *ImageBuildOwnerReport        `json:",omitempty"`
}
type ImageBuildVersionRecord struct {
	Tenant, Context, Upload string
	Number                  uint64
	ID                      [32]byte
	Fact                    imagebuild.SealReceipt
	Deleted                 bool
	Origin                  UserOperation
	DeletedBy               *UserOperation `json:",omitempty"`
	Commit                  string         `json:",omitempty"`
}
type ImageBuildCatalog struct {
	Policies    []ImageBuildPolicyRecord
	Contexts    []ImageBuildContextRecord
	Uploads     []ImageBuildUploadRecord
	Versions    []ImageBuildVersionRecord
	CachePrunes []ImageBuildCachePruneRecord
	Jobs        []ImageBuildJobRecord
}
type imageBuildRoot struct {
	Schema                                uint8
	Cluster                               [32]byte
	Policies, Contexts, Uploads, Versions uint32
	Jobs                                  uint32 `json:",omitempty"`
	CachePrunes                           uint32 `json:",omitempty"`
}

func buildRecordKey(kind, tenant, id string) string {
	return ImageBuildKey + "/records/" + kind + "/" + tenant + "/" + id
}
func buildPartPrefix(tenant, upload string) string {
	return ImageBuildKey + "/slots/" + tenant + "/" + upload + "/"
}
func buildPartKey(tenant, upload string, index uint32) string {
	return fmt.Sprintf("%s%08d", buildPartPrefix(tenant, upload), index)
}
func buildVersionName(id [32]byte) string { return hex.EncodeToString(id[:]) }
func (b ImageBuildCatalog) Policy(tenant string) (ImageBuildPolicyRecord, bool) {
	for _, r := range b.Policies {
		if r.Spec.Tenant == tenant {
			return r, true
		}
	}
	return ImageBuildPolicyRecord{}, false
}
func (b ImageBuildCatalog) Context(tenant, id string) (ImageBuildContextRecord, bool) {
	for _, r := range b.Contexts {
		if r.Spec.Tenant == tenant && r.Spec.ID == id {
			return r, true
		}
	}
	return ImageBuildContextRecord{}, false
}
func (b ImageBuildCatalog) Upload(tenant, id string) (ImageBuildUploadRecord, bool) {
	for _, r := range b.Uploads {
		if r.Scope.Tenant == tenant && r.Scope.Upload == id {
			return r, true
		}
	}
	return ImageBuildUploadRecord{}, false
}
func (b ImageBuildCatalog) Version(tenant string, id [32]byte) (ImageBuildVersionRecord, bool) {
	for _, r := range b.Versions {
		if r.Tenant == tenant && r.ID == id {
			return r, true
		}
	}
	return ImageBuildVersionRecord{}, false
}

// ImageBuilds decodes public metadata/accepted original intents only. The large
// part slots are hydrated only for their selected upload or a changed-state
// validation, never into a catalog page or root checkpoint.
func (p Policy) ImageBuilds(s state.State) (ImageBuildCatalog, error) {
	var out ImageBuildCatalog

	root := s.Object(ImageBuildKey)
	objects := s.Objects(ImageBuildKey + "/records/")
	if root.Revision == 0 {
		for _, obj := range s.Objects(ImageBuildKey + "/") {
			if obj.Present {
				return out, ErrCatalog
			}
		}
		return out, nil
	}
	var head imageBuildRoot
	if !root.Present || canonical([]byte(root.Value), &head) != nil || head.Schema != 1 || head.Cluster != p.Cluster {
		return out, ErrCatalog
	}
	count := uint64(head.Policies) + uint64(head.Contexts) + uint64(head.Uploads) + uint64(head.Versions) + uint64(head.Jobs) + uint64(head.CachePrunes)
	if count > maxImageBuildRecords {
		return out, ErrCatalog
	}
	for key, obj := range objects {
		if !obj.Present || strings.HasPrefix(key, ImageBuildKey+"/slots/") {
			continue
		}
		switch {
		case strings.HasPrefix(key, ImageBuildKey+"/records/cache-prune/") || strings.HasPrefix(key, ImageBuildKey+"/records/cache-automatic/"):
			var r ImageBuildCachePruneRecord
			if canonical([]byte(obj.Value), &r) != nil {
				return out, ErrCatalog
			}
			want, err := r.recordKey()
			if err != nil || key != want {
				return out, ErrCatalog
			}
			out.CachePrunes = append(out.CachePrunes, r)
		case strings.HasPrefix(key, ImageBuildKey+"/records/job/"):
			var r ImageBuildJobRecord
			if canonical([]byte(obj.Value), &r) != nil || r.Run.Shape() != nil || r.Run.Spec.Cluster != p.Cluster || key != buildRecordKey("job", r.Run.Spec.Tenant, r.Run.Spec.ID) {
				return out, ErrCatalog
			}
			out.Jobs = append(out.Jobs, r)
		case strings.HasPrefix(key, ImageBuildKey+"/records/policy/"):
			var r ImageBuildPolicyRecord
			if canonical([]byte(obj.Value), &r) != nil || r.Spec.Validate(p.Cluster) != nil || r.Revision == 0 || key != buildRecordKey("policy", r.Spec.Tenant, "policy") {
				return out, ErrCatalog
			}
			out.Policies = append(out.Policies, r)
		case strings.HasPrefix(key, ImageBuildKey+"/records/context/"):
			var r ImageBuildContextRecord
			if canonical([]byte(obj.Value), &r) != nil || r.Spec.Validate() != nil || r.Spec.Root.Cluster != p.Cluster || r.Revision == 0 || r.DataGeneration > r.Revision || key != buildRecordKey("context", r.Spec.Tenant, r.Spec.ID) {
				return out, ErrCatalog
			}
			out.Contexts = append(out.Contexts, r)
		case strings.HasPrefix(key, ImageBuildKey+"/records/upload/"):
			var r ImageBuildUploadRecord
			if canonical([]byte(obj.Value), &r) != nil || r.Scope.Validate() != nil || r.Scope.Cluster != p.Cluster || r.Revision == 0 || r.Received > r.Scope.Parts() || r.Closed && r.Received != 0 || !r.Closed && r.Version != ([32]byte{}) || key != buildRecordKey("upload", r.Scope.Tenant, r.Scope.Upload) {
				return out, ErrCatalog
			}
			out.Uploads = append(out.Uploads, r)
		case strings.HasPrefix(key, ImageBuildKey+"/records/version/"):
			var r ImageBuildVersionRecord
			if canonical([]byte(obj.Value), &r) != nil || !validID(r.Tenant) || !validID(r.Context) || !validID(r.Upload) || r.Number == 0 || r.Commit != "" && !imagebuild.ValidGitCommit(r.Commit) || r.ID != imagebuild.VersionID(r.Fact) || key != buildRecordKey("version", r.Tenant, buildVersionName(r.ID)) {
				return out, ErrCatalog
			}
			out.Versions = append(out.Versions, r)
		default:
			return out, ErrCatalog
		}
	}
	if len(out.Policies) != int(head.Policies) || len(out.Contexts) != int(head.Contexts) || len(out.Uploads) != int(head.Uploads) || len(out.Versions) != int(head.Versions) || len(out.Jobs) != int(head.Jobs) || len(out.CachePrunes) != int(head.CachePrunes) {
		return out, ErrCatalog
	}
	slices.SortFunc(out.Policies, func(a, b ImageBuildPolicyRecord) int { return strings.Compare(a.Spec.Tenant, b.Spec.Tenant) })
	slices.SortFunc(out.Contexts, func(a, b ImageBuildContextRecord) int {
		return strings.Compare(a.Spec.Tenant+"/"+a.Spec.ID, b.Spec.Tenant+"/"+b.Spec.ID)
	})
	slices.SortFunc(out.Uploads, func(a, b ImageBuildUploadRecord) int {
		return strings.Compare(a.Scope.Tenant+"/"+a.Scope.Upload, b.Scope.Tenant+"/"+b.Scope.Upload)
	})
	slices.SortFunc(out.Versions, func(a, b ImageBuildVersionRecord) int {
		return strings.Compare(a.Tenant+"/"+buildVersionName(a.ID), b.Tenant+"/"+buildVersionName(b.ID))
	})
	slices.SortFunc(out.Jobs, func(a, b ImageBuildJobRecord) int {
		return strings.Compare(a.Run.Spec.Tenant+"/"+a.Run.Spec.ID, b.Run.Spec.Tenant+"/"+b.Run.Spec.ID)
	})
	if err := p.validateImageBuildCachePrunes(out, p.Cluster); err != nil {
		return out, err
	}
	slices.SortFunc(out.CachePrunes, func(a, b ImageBuildCachePruneRecord) int {
		x, _ := a.Change()
		y, _ := b.Change()
		return strings.Compare(x.Tenant+"/"+x.ID, y.Tenant+"/"+y.ID)
	})
	return out, nil
}

func hydrateBuildUpload(s state.State, r ImageBuildUploadRecord) (imagebuild.Upload, error) {
	u := imagebuild.Upload{Scope: r.Scope, Revision: r.Revision, Received: r.Received, Closed: r.Closed, Version: r.Version}
	if !r.Closed {
		u.Parts = make([]byte, int(r.Scope.Parts())*32)
	}
	prefix := buildPartPrefix(r.Scope.Tenant, r.Scope.Upload)
	for key, obj := range s.RangeObjects(prefix) {
		if !obj.Present {
			continue
		}
		if r.Closed {
			return u, ErrCatalog
		}
		parsed, err := strconv.ParseUint(key[len(prefix):], 10, 32)
		index := uint32(parsed)
		raw, decodeErr := hex.DecodeString(obj.Value)
		if err != nil || key != buildPartKey(r.Scope.Tenant, r.Scope.Upload, index) || index >= r.Scope.Parts() || decodeErr != nil || len(raw) != 32 || hex.EncodeToString(raw) != obj.Value || string(raw) == string(make([]byte, 32)) {
			return u, ErrCatalog
		}
		copy(u.Parts[int(index)*32:], raw)
	}
	if u.Validate() != nil {
		return u, ErrCatalog
	}
	return u, nil
}
func buildUploadRecord(r ImageBuildUploadRecord, u imagebuild.Upload, op UserOperation) ImageBuildUploadRecord {
	r.Revision, r.Received, r.Closed, r.Version, r.Origin = u.Revision, u.Received, u.Closed, u.Version, op
	r.Progress = nil // this original user mutation now explains the current CAS
	return r
}
func writeBuildRecord(writes map[string][]byte, kind, tenant, id string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > 64<<10 {
		return ErrCatalog
	}
	writes[buildRecordKey(kind, tenant, id)] = raw
	return nil
}
func (b ImageBuildCatalog) root(cluster [32]byte) ([]byte, error) {
	if len(b.Policies)+len(b.Contexts)+len(b.Uploads)+len(b.Versions)+len(b.Jobs)+len(b.CachePrunes) > maxImageBuildRecords {
		return nil, ErrCatalog
	}
	return json.Marshal(imageBuildRoot{Schema: 1, Cluster: cluster, Policies: uint32(len(b.Policies)), Contexts: uint32(len(b.Contexts)), Uploads: uint32(len(b.Uploads)), Versions: uint32(len(b.Versions)), Jobs: uint32(len(b.Jobs)), CachePrunes: uint32(len(b.CachePrunes))})
}
func (b ImageBuildCatalog) RootReferences(ref nodestorage.Reference) int {
	count := 0
	for _, row := range b.CachePrunes {
		q, err := row.Change()
		source, found := b.Job(q.Tenant, row.Source)
		if err == nil && found && row.Pending() && source.Run.Spec.Scope.Root == ref {
			count++
		}
	}

	for _, r := range b.Jobs {
		if !r.Run.Terminal() && r.Run.Spec.Scope.Root == ref {
			count++
		}
	}
	for _, r := range b.Policies {
		if !r.Deleted {
			for _, n := range r.Spec.Nodes {
				if n.Root == ref {
					count++
				}
			}
		}
	}
	for _, r := range b.Contexts {
		if !r.Deleted && r.Spec.Root == ref {
			count++
		}
	}
	// Closed upload records still name retained bytes. Native closure is an
	// independent owner fact and will release this reference, not user abort.
	for _, r := range b.Uploads {
		if r.Scope.Root == ref && r.Reclaimed == nil {
			count++
		}
	}
	return count
}
