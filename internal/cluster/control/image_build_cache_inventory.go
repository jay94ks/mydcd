// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/registryclient"
)

const ImageBuildCacheInventoryRows = 4

func newerImageBuildCacheJob(a, b imagebuild.JobSpec) bool {
	return a.CreatedAt > b.CreatedAt || a.CreatedAt == b.CreatedAt && a.ID > b.ID
}

func imageBuildCacheRepresentative(b ImageBuildCatalog, tenant, node string, cache [32]byte) (ImageBuildJobRecord, bool) {
	var selected ImageBuildJobRecord
	found := false
	for _, row := range b.Jobs {
		spec := row.Run.Spec
		if spec.Tenant == tenant && spec.Scope.Root.Node == node && imagebuild.CacheIdentity(spec) == cache && (!found || newerImageBuildCacheJob(spec, selected.Run.Spec)) {
			selected = row
			found = true
		}
	}
	return selected, found
}

type ImageBuildCacheInventoryRow struct {
	Cache, Owner, RepresentativeSnapshot            [32]byte
	Node, Context, Root, Builder, RepresentativeJob string
	RootGeneration                                  uint64
	JobDeleted, ContextDeleted                      bool
	Code                                            string
	Usage                                           *imagebuild.CacheSummary `json:",omitempty"`
}

func (r ImageBuildCacheInventoryRow) Key() string {
	return r.Node + "/" + r.Context + "/" + hex.EncodeToString(r.Cache[:])
}
func (r ImageBuildCacheInventoryRow) Valid(q ImageBuildQuery, observed bool) bool {
	if q.Part != "caches" || !q.Valid() || r.Cache == ([32]byte{}) || r.Owner == ([32]byte{}) || r.RepresentativeSnapshot == ([32]byte{}) || !validID(r.Node) || !validID(r.Context) || !validID(r.Root) || !validID(r.RepresentativeJob) || r.RootGeneration == 0 || len(r.Builder) > 512 || q.Node != "" && q.Node != r.Node || q.ID != "" && q.ID != r.Context {
		return false
	}
	if pin, err := access.PinImage(r.Builder); err != nil || pin.Reference != r.Builder {
		return false
	}
	if !observed {
		return r.Code == "" && r.Usage == nil
	}
	return r.Code == "OK" && r.Usage != nil && r.Usage.Valid(r.Cache) || r.Code == "UNAVAILABLE" && r.Usage == nil
}

func (p Policy) imageBuildCacheInventoryPage(s state.State, c access.Catalog, b ImageBuildCatalog, session access.Session, at int64, tenant string, q ImageBuildQuery, after string) (ImageBuildPage, error) {
	canRead := func(node string) bool {
		return c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.Read, node) == nil || c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.ManageRegistry, node) == nil
	}
	if q.Node != "" && !canRead(q.Node) {
		return ImageBuildPage{}, access.ErrDenied
	}
	grouped := map[[32]byte]imagebuild.JobSpec{}
	deleted := map[[32]byte]bool{}
	for _, row := range b.Jobs {
		spec := row.Run.Spec
		if spec.Tenant != tenant || q.Node != "" && spec.Scope.Root.Node != q.Node || q.ID != "" && spec.Context.ID != q.ID || !canRead(spec.Scope.Root.Node) {
			continue
		}
		cache := imagebuild.CacheIdentity(spec)
		before, exists := grouped[cache]
		if !exists || newerImageBuildCacheJob(spec, before) {
			grouped[cache] = spec
			deleted[cache] = row.Deleted
		}
	}
	var rows []ImageBuildCacheInventoryRow
	for cache, spec := range grouped {
		ctx, exists := b.Context(tenant, spec.Context.ID)
		rows = append(rows, ImageBuildCacheInventoryRow{Cache: cache, Owner: spec.Scope.Root.Key, RepresentativeSnapshot: spec.Digest(), Node: spec.Scope.Root.Node, Context: spec.Context.ID, Root: spec.Scope.Root.ID, Builder: spec.Policy.BuilderImage, RepresentativeJob: spec.ID, RootGeneration: spec.Scope.Root.Generation, JobDeleted: deleted[cache], ContextDeleted: !exists || ctx.Deleted})
	}
	slices.SortFunc(rows, func(a, b ImageBuildCacheInventoryRow) int { return strings.Compare(a.Key(), b.Key()) })
	raw, _ := json.Marshal(struct {
		Cluster [32]byte
		Tenant  string
		Query   ImageBuildQuery
		Epoch   uint64
		Rows    []ImageBuildCacheInventoryRow
	}{p.Cluster, tenant, q, s.ModuleEpoch(), rows})
	root := sha256.Sum256(append([]byte("sfc-imagebuild-cache-inventory-1\x00"), raw...))
	prior, key, err := registryclient.CatalogueCursor(after)
	if err != nil {
		return ImageBuildPage{}, access.ErrInvalid
	}
	if after != "" && prior != root {
		return ImageBuildPage{}, access.ErrConflict
	}
	if key != "" && !slices.ContainsFunc(rows, func(r ImageBuildCacheInventoryRow) bool { return r.Key() == key }) {
		return ImageBuildPage{}, access.ErrInvalid
	}
	out := ImageBuildPage{Schema: 1, Tenant: tenant, Part: "caches", RootRevision: s.Object(ImageBuildKey).Revision, Epoch: s.ModuleEpoch(), InventoryRoot: &root}
	for _, r := range rows {
		if r.Key() <= key {
			continue
		}
		if len(out.Caches) == ImageBuildCacheInventoryRows {
			out.Next = buildPageNext(root, out.Caches[len(out.Caches)-1].Key())
			break
		}
		out.Caches = append(out.Caches, r)
	}
	return out, nil
}

type ImageBuildCacheInventoryRead struct {
	Session     access.Session
	Tenant      string
	Query       ImageBuildQuery
	After       string
	Root, Cache [32]byte
	Epoch       uint64
}

func (p Policy) CurrentImageBuildCacheInventory(s state.State, r ImageBuildCacheInventoryRead, at int64) (imagebuild.JobSpec, error) {
	if r.Query.Part != "caches" || r.Root == ([32]byte{}) || r.Cache == ([32]byte{}) {
		return imagebuild.JobSpec{}, access.ErrInvalid
	}
	page, err := p.ImageBuildPage(s, r.Session, at, r.Tenant, r.Query, r.After)
	if err != nil {
		return imagebuild.JobSpec{}, err
	}
	if page.InventoryRoot == nil || *page.InventoryRoot != r.Root || page.Epoch != r.Epoch {
		return imagebuild.JobSpec{}, access.ErrConflict
	}
	i := slices.IndexFunc(page.Caches, func(row ImageBuildCacheInventoryRow) bool { return row.Cache == r.Cache })
	if i < 0 {
		return imagebuild.JobSpec{}, access.ErrDenied
	}
	row := page.Caches[i]
	b, err := p.ImageBuilds(s)
	if err != nil {
		return imagebuild.JobSpec{}, err
	}
	job, found := b.Job(r.Tenant, row.RepresentativeJob)
	if !found || job.Run.Spec.Digest() != row.RepresentativeSnapshot || imagebuild.CacheIdentity(job.Run.Spec) != row.Cache {
		return imagebuild.JobSpec{}, access.ErrConflict
	}
	owner, err := p.nodeOwner(s, row.Node)
	if err != nil || owner != row.Owner {
		return imagebuild.JobSpec{}, access.ErrDenied
	}
	return job.Run.Spec.Own(), nil
}

func ValidImageBuildCacheInventoryPage(page ImageBuildPage, q ImageBuildQuery, after string, observed bool) bool {
	if q.Part != "caches" || !q.Valid() || page.Schema != 1 || !validID(page.Tenant) || page.Part != "caches" || page.Epoch == 0 || page.InventoryRoot == nil || *page.InventoryRoot == ([32]byte{}) || len(page.Caches) > ImageBuildCacheInventoryRows || len(page.Policies)+len(page.Contexts)+len(page.Versions)+len(page.Uploads)+len(page.Jobs)+len(page.Missing)+len(page.CachePrunes) != 0 || page.UploadRevision != 0 {
		return false
	}
	root, key, err := registryclient.CatalogueCursor(after)
	if err != nil || after != "" && root != *page.InventoryRoot {
		return false
	}
	for _, r := range page.Caches {
		if !r.Valid(q, observed) || r.Key() <= key {
			return false
		}
		key = r.Key()
	}
	if page.Next != "" && (len(page.Caches) == 0 || page.Next != buildPageNext(*page.InventoryRoot, key)) {
		return false
	}
	raw, err := json.Marshal(page)
	return err == nil && len(raw) <= 24<<10
}
