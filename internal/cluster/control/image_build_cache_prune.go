// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/json"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"
)

const ImageBuildCachePruneAction = "prune-build-cache"

type ImageBuildCachePruneChange struct {
	Tenant, ID, Node string
	Cache            [32]byte
	Filter           imagebuild.CachePruneFilter
}

func (q ImageBuildCachePruneChange) Valid() bool {
	return validID(q.Tenant) && validID(q.ID) && validID(q.Node) && q.Cache != ([32]byte{}) && q.Filter.Valid()
}

// Source is a retained immutable shared job reference, not a new build or a
// request to replay that job. Its Spec is never duplicated into this record.
type ImageBuildCachePruneRecord struct {
	Origin       UserOperation
	Source       string
	SourceDigest [32]byte
	State        string
	Revision, At uint64
	Reports      []ImageBuildCachePruneReport    `json:",omitempty"`
	Automatic    *ImageBuildCacheAutomaticReport `json:",omitempty"`
}
type ImageBuildCachePruneView struct {
	ID, Node, Context, User, State string
	Cache                          [32]byte
	Filter                         imagebuild.CachePruneFilter
	Revision, At                   uint64
	Code                           string `json:",omitempty"`
	ClosedAt, RemovedCount         uint64 `json:",omitempty"`
	ReportedBytes                  int64  `json:",omitempty"`
	Automatic                      bool   `json:",omitempty"`
	Sequence                       uint64 `json:",omitempty"`
}

func imageBuildCachePruneView(r ImageBuildCachePruneRecord, q ImageBuildCachePruneChange, context string) ImageBuildCachePruneView {
	v := ImageBuildCachePruneView{ID: q.ID, Node: q.Node, Context: context, User: r.Origin.Session.User, Cache: q.Cache, Filter: q.Filter.Own(), State: r.State, Revision: r.Revision, At: r.At}
	if r.Automatic != nil {
		v.Automatic, v.Sequence = true, r.Automatic.Sequence
	}
	if len(r.Reports) > 0 {
		last := r.Reports[len(r.Reports)-1]
		v.Code, v.ClosedAt, v.RemovedCount, v.ReportedBytes = last.Code, last.ClosedAt, last.RemovedCount, last.ReportedBytes
	}
	return v
}
func (v ImageBuildCachePruneView) Valid() bool {
	filterValid := !v.Automatic && v.Sequence == 0 && v.Filter.Valid() || v.Automatic && v.Sequence > 0 && v.Filter.Mode == "policy" && len(v.Filter.IDs) == 0 && v.Filter.UnusedDays == 0
	if !validID(v.ID) || !validID(v.Node) || !validID(v.Context) || !validID(v.User) || v.Cache == ([32]byte{}) || !filterValid || v.At == 0 || v.ReportedBytes < 0 {
		return false
	}
	switch v.State {
	case "queued", "running", "unknown":
		revision := map[string]uint64{"queued": 1, "running": 2, "unknown": 3}[v.State]
		return v.Revision == revision && v.ClosedAt == 0 && v.Code == "" && v.RemovedCount == 0 && v.ReportedBytes == 0
	case "succeeded":
		return (v.Revision == 3 || v.Revision == 4) && v.Code == "OK" && v.ClosedAt > 0 && v.ClosedAt <= v.At
	case "failed":
		if v.Revision < 2 || v.Revision > 4 || v.ClosedAt == 0 || v.ClosedAt > v.At || v.Revision == 2 && (v.RemovedCount != 0 || v.ReportedBytes != 0) {
			return false
		}
		return v.Code == "FAILED" || v.Code == "PERMISSION_REVOKED" || v.Code == "TIMEOUT"
	}
	return false
}

func (r ImageBuildCachePruneRecord) Change() (ImageBuildCachePruneChange, error) {
	if r.Automatic != nil {
		q := r.Automatic.Change()
		if !validID(q.Tenant) || !validID(q.ID) || !validID(q.Node) || q.Cache == ([32]byte{}) {
			return q, ErrCatalog
		}
		return q, nil
	}
	var q ImageBuildCachePruneChange
	if canonical(r.Origin.Change.Payload, &q) != nil || !q.Valid() || r.Origin.Change.Action != ImageBuildCachePruneAction {
		return q, ErrCatalog
	}
	return q, nil
}
func (r ImageBuildCachePruneRecord) Pending() bool {
	return r.State == "queued" || r.State == "running" || r.State == "unknown"
}

func (b ImageBuildCatalog) CachePruneBlocks(cache [32]byte, buildRoot uint64) bool {
	for _, row := range b.CachePrunes {
		q, err := row.Change()
		if err == nil && q.Cache == cache && row.Pending() && row.SubmissionRootRevision() < buildRoot {
			return true
		}
	}
	return false
}

type ImageBuildCachePruneWorkQuery struct {
	Tenant, ID string
	At         int64
}
type ImageBuildCachePruneWork struct {
	Schema                     uint8
	Cluster                    [32]byte
	Record                     ImageBuildCachePruneRecord
	Source                     imagebuild.JobSpec
	RootRevision, Epoch, Index uint64
	Allowed                    bool
	Blocked                    string
}

// NativeGrant keeps the maintenance intent distinct from the retained build
// used to select its cache. It never constructs a replacement build job.
func (w ImageBuildCachePruneWork) NativeGrant() (imagebuild.NativeCachePruneGrant, error) {
	q, err := w.Record.Change()
	if err != nil || w.Schema != 1 || w.Cluster != w.Source.Cluster || w.Record.Origin.VerifyOriginal(w.Cluster) != nil || w.Source.Digest() != w.Record.SourceDigest || w.Source.ID != w.Record.Source || q.Cache != imagebuild.CacheIdentity(w.Source) || q.Node != w.Source.Scope.Root.Node || q.Tenant != w.Source.Tenant || w.RootRevision <= w.Record.SubmissionRootRevision() || w.Index < w.RootRevision || w.Epoch < w.Record.SubmissionEpoch() || w.Allowed && !w.Record.Pending() || w.Record.Automatic != nil && !w.Record.Automatic.valid(w.Record.Origin, w.Source, true) {
		return imagebuild.NativeCachePruneGrant{}, ErrCatalog
	}
	phase, revision, at, err := cachePruneReportState(w.Record, w.Source, true)
	if err != nil || phase != w.Record.State || revision != w.Record.Revision || at != w.Record.At {
		return imagebuild.NativeCachePruneGrant{}, ErrCatalog
	}
	spec, err := w.Record.NativeSpec(w.Source)
	if err != nil {
		return imagebuild.NativeCachePruneGrant{}, err
	}
	g := imagebuild.NativeCachePruneGrant{Spec: spec, Index: w.Index, Revision: revision, Epoch: w.Epoch, Phase: phase, Allowed: w.Allowed}
	if !g.Valid() {
		return imagebuild.NativeCachePruneGrant{}, ErrCatalog
	}
	return g, nil
}

func (p Policy) ImageBuildCachePruneWork(s state.State, caller [32]byte, q ImageBuildCachePruneWorkQuery) (ImageBuildCachePruneWork, error) {
	p, err := p.Current(s)
	if err != nil {
		return ImageBuildCachePruneWork{}, err
	}
	if !validID(q.Tenant) || !validID(q.ID) || q.At <= 0 {
		return ImageBuildCachePruneWork{}, access.ErrInvalid
	}
	b, err := p.ImageBuilds(s)
	if err != nil {
		return ImageBuildCachePruneWork{}, err
	}
	for _, row := range b.CachePrunes {
		change, _ := row.Change()
		if change.Tenant != q.Tenant || change.ID != q.ID {
			continue
		}
		source, found := b.Job(q.Tenant, row.Source)
		if !found || source.Run.Spec.Scope.Root.Key != caller {
			return ImageBuildCachePruneWork{}, access.ErrDenied
		}
		owner, err := p.nodeOwner(s, change.Node)
		if err != nil || owner != caller {
			return ImageBuildCachePruneWork{}, access.ErrDenied
		}
		work := ImageBuildCachePruneWork{Schema: 1, Cluster: p.Cluster, Record: row, Source: source.Run.Spec.Own(), RootRevision: s.Object(ImageBuildKey).Revision, Epoch: s.ModuleEpoch(), Index: s.Index(), Blocked: "PERMISSION_REVOKED"}
		if !row.Pending() {
			work.Blocked = "CLOSED"
			return work, nil
		}
		limits, err := row.Limits(work.Source)
		if err != nil {
			return work, err
		}
		if uint64(q.At) < row.AcceptedAt() {
			work.Blocked = "NOT_READY"
			return work, nil
		}
		if uint64(q.At) >= row.AcceptedAt()+limits.Seconds {
			work.Blocked = "TIMEOUT"
			return work, nil
		}
		if p.acceptedCachePruneAuthority(s, b, row) != nil {
			return work, nil
		}
		c, err := p.Catalog(s)
		if err != nil {
			return work, err
		}
		if _, err := c.CheckImageTrust(q.Tenant, work.Source.Policy.BuilderImage); err != nil {
			work.Blocked = "UNTRUSTED_BUILDER"
			return work, nil
		}
		if p.imageCacheAvailable(s, change.Node, work.Source.Policy.BuilderImage) != nil {
			work.Blocked = "BUILDER_UNAVAILABLE"
			return work, nil
		}
		if row.State == "queued" {
			for _, job := range b.Jobs {
				if !job.Run.Terminal() && imagebuild.CacheIdentity(job.Run.Spec) == change.Cache && job.SubmissionRootRevision() < row.SubmissionRootRevision() {
					work.Blocked = "WAITING_FOR_CACHE"
					return work, nil
				}
			}
			if b.activeBuildWorkers(q.Tenant) >= limits.Concurrency {
				work.Blocked = "WAITING_FOR_SLOT"
				return work, nil
			}
			if !p.imageBuildNeedAvailable(s, work.Source.Tenant, work.Source.Scope.Root.Node, work.Source.Scope.Root.Key, limits.CPUMillis, limits.MemoryBytes) {
				work.Blocked = "WAITING_FOR_BUDGET"
				return work, nil
			}
		}
		work.Allowed, work.Blocked = true, ""
		return work, nil
	}
	return ImageBuildCachePruneWork{}, access.ErrConflict
}

func validateImageBuildCachePrune(b ImageBuildCatalog, r ImageBuildCachePruneRecord, cluster [32]byte, signature bool) error {
	q, err := r.Change()
	if err != nil || r.Origin.At <= 0 || r.Automatic == nil && r.Origin.Change.Expected != 0 || !validID(r.Source) || r.SourceDigest == ([32]byte{}) {
		return ErrCatalog
	}
	if signature && r.Origin.VerifyOriginal(cluster) != nil {
		return ErrCatalog
	}
	source, found := b.Job(q.Tenant, r.Source)
	if !found || source.Run.Spec.Digest() != r.SourceDigest || source.Run.Spec.Scope.Root.Node != q.Node || imagebuild.CacheIdentity(source.Run.Spec) != q.Cache {
		return ErrCatalog
	}
	if r.Automatic != nil && (!r.Automatic.valid(r.Origin, source.Run.Spec, signature) || r.Source != r.Automatic.Source || r.SourceDigest != r.Automatic.SourceDigest) {
		return ErrCatalog
	}
	phase, revision, at, err := cachePruneReportState(r, source.Run.Spec, signature)
	if err != nil || r.State != phase || r.Revision != revision || r.At != at {
		return ErrCatalog
	}
	return nil
}

func (p Policy) reduceImageBuildCachePrune(s state.State, b ImageBuildCatalog, op UserOperation, writes map[string][]byte) (ImageBuildCatalog, state.Code) {
	var q ImageBuildCachePruneChange
	if canonical(op.Change.Payload, &q) != nil || !q.Valid() || op.Change.Expected != 0 {
		return b, state.Invalid
	}
	for _, row := range b.CachePrunes {
		prior, err := row.Change()
		if err != nil {
			return b, state.Invalid
		}
		if prior.Tenant == q.Tenant && prior.ID == q.ID || prior.Cache == q.Cache && row.Pending() {
			return b, state.ConditionFailed
		}
	}
	source, found := imageBuildCacheRepresentative(b, q.Tenant, q.Node, q.Cache)
	if !found {
		return b, state.ConditionFailed
	}
	owner, err := p.nodeOwner(s, q.Node)
	if err != nil || owner != source.Run.Spec.Scope.Root.Key {
		return b, state.Forbidden
	}
	c, err := p.Catalog(s)
	if err != nil {
		return b, state.Invalid
	}
	if p.buildRootCurrent(s, c, op.Session, op.At, q.Tenant, source.Run.Spec.Scope.Root) != nil {
		return b, state.Forbidden
	}
	if _, err = c.CheckImageTrust(q.Tenant, source.Run.Spec.Policy.BuilderImage); err != nil {
		return b, state.Forbidden
	}
	if p.imageCacheAvailable(s, q.Node, source.Run.Spec.Policy.BuilderImage) != nil {
		return b, state.ConditionFailed
	}
	row := ImageBuildCachePruneRecord{Origin: op, Source: source.Run.Spec.ID, SourceDigest: source.Run.Spec.Digest(), State: "queued", Revision: 1, At: uint64(op.At)}
	if validateImageBuildCachePrune(b, row, p.Cluster, true) != nil {
		return b, state.Invalid
	}
	// Preserve room for the owner result/closure that the native path adds;
	// do not accept a near-limit user envelope that could strand its record.
	raw, err := json.Marshal(row)
	if err != nil || len(raw) > 48<<10 || writeBuildRecord(writes, "cache-prune", q.Tenant, q.ID, row) != nil {
		return b, state.ConditionFailed
	}
	b.CachePrunes = append(b.CachePrunes, row)
	return b, state.Applied
}

func (p Policy) validateImageBuildCachePrunes(b ImageBuildCatalog, cluster [32]byte) error {
	pending := map[[32]byte]bool{}
	ids := map[string]bool{}
	automatic := map[[32]byte]bool{}
	for _, row := range b.CachePrunes {
		if validateImageBuildCachePrune(b, row, cluster, false) != nil {
			return ErrCatalog
		}
		q, _ := row.Change()
		key := q.Tenant + "/" + q.ID
		if ids[key] || row.Automatic != nil && automatic[q.Cache] {
			return ErrCatalog
		}
		ids[key] = true
		if row.Automatic != nil {
			automatic[q.Cache] = true
		}
		if row.Pending() {
			if pending[q.Cache] {
				return ErrCatalog
			}
			pending[q.Cache] = true
		}
	}
	return nil
}

func (p Policy) acceptedCachePruneAuthority(s state.State, b ImageBuildCatalog, row ImageBuildCachePruneRecord) error {
	q, err := row.Change()
	if err != nil {
		return err
	}
	if row.Automatic != nil {
		source, found := b.Job(q.Tenant, row.Source)
		if !found || source.Run.Spec.Digest() != row.SourceDigest || row.Automatic.Epoch != s.ModuleEpoch() {
			return access.ErrDenied
		}
		return p.currentCacheAutomaticAuthority(s, b, row.Origin, source.Run.Spec)
	}
	c, err := p.Catalog(s)
	if err != nil {
		return err
	}
	if c.OperationAllowed(row.Origin.Session, ImageBuildCachePruneAction) != nil || c.AuthorizeAccepted(row.Origin.Session, p.Cluster, row.Origin.At, q.Tenant, access.ManageRegistry, q.Node) != nil {
		return access.ErrDenied
	}
	source, found := b.Job(q.Tenant, row.Source)
	if !found || source.Run.Spec.Digest() != row.SourceDigest {
		return access.ErrConflict
	}
	owner, err := p.workNodeOwner(s, q.Node)
	if err != nil || owner != source.Run.Spec.Scope.Root.Key {
		return access.ErrDenied
	}
	roots, err := p.NodeStorage(s)
	if err != nil {
		return err
	}
	root, err := roots.CanBuild(c, row.Origin.Session.User, q.Tenant, q.Node, source.Run.Spec.Scope.Root.ID, source.Run.Spec.Scope.Root.Generation)
	if err != nil || root.Reference(p.Cluster) != source.Run.Spec.Scope.Root {
		return access.ErrDenied
	}
	return nil
}
