// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/nodestorage"
)

// The real image-build contract (image_builds.go) over the fake build
// world (fake_builds.go), which the REQ-47 zip upload also changes. What
// that world lacks is kept beside it in realBuildState: the exact policy
// and context specs last put, signed version seals, and cache prunes.
//
// Fake-only rules:
//   - a node's build root is the tenant's first storage root on that node
//     (node-storage), otherwise nodestorage.Reference{ID "build", Path
//     /var/lib/mydc/build, Generation 1}; Key is the node's public key.
//   - versions are sealed and signed by the root's node key, so
//     JobSpec.Validate holds; version IDs are imagebuild.VersionID.
//   - a Git commit shorter than 40 hex digits reads padded from its digest.
//   - prune-build-cache finishes at once unless Fake.SetBuildHold is on
//     (then Fake.FinishCachePrune ends it).
//   - Epoch is fakeBuildEpoch.

const fakeBuildEpoch = 1

type realBuildState struct {
	policy  map[string]realPolicy  // tenant
	specs   map[string]realSpec    // tenant/context
	seals   map[string]realSeal    // tenant/context/number
	prunes  map[string][]realPrune // tenant
	uploads map[string]*realUpload // tenant/upload (fake_build_zip_real.go)
}

type realPolicy struct {
	spec    imagebuild.Policy
	rev     uint64
	deleted bool
}

type realSpec struct {
	spec imagebuild.ContextSpec
}

type realSeal struct {
	scope imagebuild.UploadScope
	seal  imagebuild.SealReceipt
}

type realPrune struct {
	view    control.ImageBuildCachePruneView
	context string
}

func (r *realBuildState) ready() {
	if r.policy == nil {
		*r = realBuildState{policy: map[string]realPolicy{}, specs: map[string]realSpec{}, seals: map[string]realSeal{}, prunes: map[string][]realPrune{},
			uploads: map[string]*realUpload{}}
	}
}

// --- translation ---

func (w *world) buildRoot(tenant, node string) nodestorage.Reference {
	for _, r := range w.nodeStorage {
		if r.Node == node && slices.Contains(r.Tenants, tenant) && !r.Draining {
			return w.storageRef(r)
		}
	}
	return nodestorage.Reference{Cluster: w.cluster, Node: node, Key: pub32(FixtureKey(node)), ID: "build", Generation: 1, Path: "/var/lib/mydc/build"}
}

// storageRef: a node-storage root as the reference a policy names (REQ-58:
// tenant-storage rows carry it).
func (w *world) storageRef(r FixtureStorageRoot) nodestorage.Reference {
	return nodestorage.Reference{Cluster: w.cluster, Node: r.Node, Key: pub32(FixtureKey(r.Node)), ID: r.ID, Generation: max(r.Generation, 1), Path: r.Path}
}

// policyRootAllowed: root is one of the tenant's storage roots on node that
// is not draining, or the node's default build root (no storage there).
func (w *world) policyRootAllowed(tenant, node string, root nodestorage.Reference) bool {
	for _, r := range w.nodeStorage {
		if r.Node == node && slices.Contains(r.Tenants, tenant) && w.storageRef(r) == root {
			return !r.Draining
		}
	}
	return root == w.buildRoot(tenant, node)
}

// imagePolicy: the tenant's policy, its revision, deleted, and whether one
// was ever set.
func (w *world) imagePolicy(t string) (imagebuild.Policy, uint64, bool, bool) {
	b := &w.build
	b.real.ready()
	old, ok := b.policy[t]
	cp := b.cachePolicy[t]
	if rp, has := b.real.policy[t]; has {
		p := rp.spec.Own()
		if rp.deleted {
			return p, rp.rev, true, true
		}
		p.Cleanup = imagebuild.CleanupPolicy{HighWaterPercent: uint8(cp.MaxPercent), UnusedDays: uint32(cp.IdleDays)}
		return p, old.Revision, false, true
	}
	if !ok {
		return imagebuild.Policy{}, 0, false, false
	}
	p := imagebuild.Policy{Schema: 1, Tenant: t, Concurrency: uint32(old.Concurrent), Seconds: uint64(old.TimeoutSeconds), CPUMillis: uint64(old.CPUs * 1000),
		MemoryBytes: int64(old.MemoryBytes), WorkspaceBytes: int64(old.ScratchBytes), CacheBytes: int64(old.CacheBytes), Registry: old.Registry,
		Platforms: slices.Clone(old.Platforms), BuilderImage: digestOnly(fakeBuilder), Cleanup: imagebuild.CleanupPolicy{HighWaterPercent: uint8(cp.MaxPercent), UnusedDays: uint32(cp.IdleDays)}}
	for _, n := range old.Nodes {
		p.Nodes = append(p.Nodes, imagebuild.NodeRoot{Node: n, Root: w.buildRoot(t, n)})
	}
	return p, old.Revision, false, true
}

// digestOnly drops the tag of name:tag@digest (the real builder image is
// pinned by digest alone).
func digestOnly(image string) string {
	name, digest, ok := strings.Cut(image, "@")
	if i := strings.LastIndex(name, ":"); ok && i > strings.LastIndex(name, "/") {
		name = name[:i]
	}
	if !ok {
		return image
	}
	return name + "@" + digest
}

func realKind(kind string) string {
	if kind == BuildInline {
		return "draft"
	}
	return kind
}

func oldKind(kind string) string {
	if kind == "draft" {
		return BuildInline
	}
	return kind
}

func (w *world) contextSpec(x *buildCtx) imagebuild.ContextSpec {
	b := &w.build
	b.real.ready()
	if s, ok := b.real.specs[x.row.Tenant+"/"+x.row.ID]; ok {
		return s.spec.Own()
	}
	r := x.row
	s := imagebuild.ContextSpec{Tenant: r.Tenant, ID: r.ID, Kind: realKind(r.Kind), Dockerfile: r.Dockerfile, Repository: r.Repository,
		Tags: []string{r.TagRule}, Platforms: slices.Clone(r.Platforms)}
	if p, _, _, _ := w.imagePolicy(r.Tenant); len(p.Nodes) > 0 {
		s.Root = p.Nodes[0].Root
	}
	for _, a := range r.Args {
		if a.Secret == nil { // the real contract has no secret ARG
			if s.Arguments == nil {
				s.Arguments = map[string]string{}
			}
			s.Arguments[a.Name] = a.Value
		}
	}
	for _, m := range r.Secrets {
		s.Secrets = append(s.Secrets, imagebuild.SecretMount{ID: m.ID, Realm: m.Realm, Secret: m.Object, Key: m.Key})
	}
	if g := r.Git; g != nil {
		p := strings.Trim(g.Folder, "/")
		if p == "" {
			p = "."
		}
		s.Git = &imagebuild.GitContext{Repository: g.Repository, Ref: g.Ref, Path: p, CredentialProfile: g.CredentialProfile, Automatic: g.AutoBuild}
	}
	return s
}

// forget drops what the real actions kept for a deleted context.
func (r *realBuildState) forget(tenant, id string) {
	r.ready()
	delete(r.specs, tenant+"/"+id)
	for k := range r.seals {
		if strings.HasPrefix(k, tenant+"/"+id+"/") {
			delete(r.seals, k)
		}
	}
}

func fullCommit(c string) string {
	if len(c) == 40 || c == "" {
		return c
	}
	d := fakeDigest("commit", c)
	return hexOf(d[:20])
}

func contentEntries(files map[string][]byte) []imagebuild.Entry {
	dirs := map[string]bool{}
	var out []imagebuild.Entry
	for _, p := range sortedKeys(files) {
		for d := path.Dir(p); d != "."; d = path.Dir(d) {
			dirs[d] = true
		}
		out = append(out, imagebuild.Entry{Path: p, Bytes: int64(len(files[p])), Executable: strings.HasPrefix(string(files[p]), "#!"), Digest: sha256.Sum256(files[p])})
	}
	for d := range dirs {
		out = append(out, imagebuild.Entry{Path: d, Directory: true})
	}
	slices.SortFunc(out, func(a, b imagebuild.Entry) int { return strings.Compare(a.Path, b.Path) })
	return out
}

func treeDigest(entries []imagebuild.Entry) [32]byte {
	raw, _ := json.Marshal(entries)
	return fakeDigest("tree", string(raw))
}

// versionSeal seals version n on first use and keeps it, so its ID stays.
func (w *world) versionSeal(x *buildCtx, n uint64) (realSeal, bool) {
	b := &w.build
	b.real.ready()
	key := fmt.Sprintf("%s/%s/%d", x.row.Tenant, x.row.ID, n)
	if s, ok := b.real.seals[key]; ok {
		return s, true
	}
	files, ok := x.versions[n]
	if !ok {
		return realSeal{}, false
	}
	spec := w.contextSpec(x)
	pol, prev, _, _ := w.imagePolicy(x.row.Tenant)
	entries := contentEntries(files)
	var expanded int64
	for _, e := range entries {
		expanded += e.Bytes
	}
	scope := imagebuild.UploadScope{Schema: 1, Cluster: w.cluster, Tenant: x.row.Tenant, Context: x.row.ID, Upload: fmt.Sprintf("v%d", n), Creator: "fixture",
		Root: spec.Root, ContextRevision: max(x.row.Revision, 1), PolicyRevision: max(prev, 1), Length: max(expanded, 1), Digest: fakeDigest("build-zip", key),
		Dockerfile: spec.Dockerfile, ExpandedLimit: max(pol.WorkspaceBytes, expanded, 1), ExpiresAt: 1 << 40}
	seal := imagebuild.SealReceipt{Schema: 1, Scope: scope.Hash(), ZIP: scope.Digest, Tree: treeDigest(entries), Entries: uint32(len(entries)), ExpandedBytes: expanded}
	if spec.Root.Node != "" {
		seal.Signature = ed25519.Sign(FixtureKey(spec.Root.Node), imagebuild.SealReceiptBytes(seal))
	}
	s := realSeal{scope: scope, seal: seal}
	b.real.seals[key] = s
	return s, true
}

func (w *world) findVersion(tenant string, id [32]byte) (*buildCtx, uint64, realSeal, bool) {
	for _, x := range w.build.ctxs[tenant] {
		for _, n := range x.row.Versions {
			if s, ok := w.versionSeal(x, n); ok && imagebuild.VersionID(s.seal) == id {
				return x, n, s, true
			}
		}
	}
	return nil, 0, realSeal{}, false
}

func (w *world) versionView(x *buildCtx, n uint64) control.ImageBuildVersionView {
	s, _ := w.versionSeal(x, n)
	v := control.ImageBuildVersionView{ID: imagebuild.VersionID(s.seal), Context: x.row.ID, Number: n, Bytes: s.scope.Length, ExpandedBytes: s.seal.ExpandedBytes,
		Entries: s.seal.Entries, Tree: s.seal.Tree}
	if x.row.Kind == BuildUpload {
		v.Upload = s.scope.Upload
	}
	if x.row.Git != nil && n == x.row.Version {
		v.Commit = fullCommit(x.row.Git.Commit)
	}
	return v
}

// jobSpec: the spec a build of version n would run now (begin-image-build
// compares its digest with the plan's Snapshot).
func (w *world) jobSpec(x *buildCtx, id string, n uint64, at uint64) (imagebuild.JobSpec, bool) {
	s, ok := w.versionSeal(x, n)
	pol, prev, deleted, has := w.imagePolicy(x.row.Tenant)
	if !ok || !has || deleted {
		return imagebuild.JobSpec{}, false
	}
	spec := w.contextSpec(x)
	j := imagebuild.JobSpec{Schema: 1, Cluster: w.cluster, Tenant: x.row.Tenant, ID: id, Version: imagebuild.VersionID(s.seal), Number: n, Scope: s.scope, Seal: s.seal,
		Context: spec, Policy: pol, ContextRevision: x.row.Revision, PolicyRevision: prev, RegistryAuthority: builtinRegistryHost, RegistryGeneration: 1,
		RegistrySpec: fakeDigest("registry", x.row.Tenant, pol.Registry), CreatedAt: at}
	if x.row.Git != nil {
		j.Commit = fullCommit(x.row.Git.Commit)
	}
	return j.Own(), true
}

// stampJob keeps the spec a build started with.
func (w *world) stampJob(r *buildRec) {
	if r.spec != nil {
		return
	}
	x := w.build.find(r.b.Tenant, r.b.Context)
	if x == nil {
		return
	}
	if j, ok := w.jobSpec(x, r.b.ID, r.b.ContextVersion, uint64(r.b.StartedAt)); ok {
		r.spec = &j
	}
}

func jobPhase(status string) string {
	if status == BuildCanceled {
		return ImageBuildCancelled
	}
	return status // queued, running, succeeded, failed
}

func (r *buildRec) revision() uint64 {
	rev := uint64(1)
	if r.b.Status != BuildRunning && r.b.Status != BuildQueued {
		rev++
	}
	if r.cancel {
		rev++
	}
	if r.deleted {
		rev++
	}
	return rev
}

func (w *world) jobView(r *buildRec) control.ImageBuildJobView {
	v := control.ImageBuildJobView{ID: r.b.ID, Context: r.b.Context, Node: r.b.Node, User: r.b.Submitter, Phase: jobPhase(r.b.Status), Number: r.b.ContextVersion,
		Revision: r.revision(), CreatedAt: uint64(r.b.StartedAt), ClosedAt: uint64(r.b.FinishedAt), Cancel: r.cancel, Deleted: r.deleted}
	if r.spec != nil {
		v.Version = r.spec.Version
	}
	switch r.b.Status {
	case BuildSucceeded:
		v.Result = &imagebuild.JobResult{Code: "OK", Image: builtinRegistryHost + "/" + r.b.Image + "@" + r.b.Digest, Bytes: int64(r.b.Bytes)}
	case BuildFailed:
		v.Result = &imagebuild.JobResult{Code: r.b.Code}
	case BuildCanceled:
		v.Result = &imagebuild.JobResult{Code: "CANCELLED"}
	}
	return v
}

func (b *buildState) job(tenant, id string) *buildRec {
	for _, r := range b.builds[tenant] {
		if r.b.ID == id {
			return r
		}
	}
	return nil
}

// --- cache ---

var realCacheKind = map[string]string{BuildCacheExec: "regular", BuildCacheBase: "regular", BuildCacheMount: "exec.cachemount", BuildCacheSource: "source.local"}

// cacheGroup: the cache scope of (node, context) and the newest job that
// used it.
type cacheGroup struct {
	id      [32]byte
	node    string
	job     *buildRec
	entries []BuildCacheEntry
}

func (w *world) cacheGroups(tenant string) []cacheGroup {
	b := &w.build
	var out []cacheGroup
	for _, e := range b.cache[tenant] {
		for _, ctxID := range e.Contexts {
			var job *buildRec
			for _, r := range b.builds[tenant] {
				if r.b.Context == ctxID && r.b.Node == e.Node && r.spec != nil && (job == nil || r.seq > job.seq) {
					job = r
				}
			}
			if job == nil {
				continue
			}
			id := imagebuild.CacheIdentity(*job.spec)
			i := slices.IndexFunc(out, func(g cacheGroup) bool { return g.id == id && g.node == e.Node })
			if i < 0 {
				out = append(out, cacheGroup{id: id, node: e.Node, job: job})
				i = len(out) - 1
			}
			out[i].entries = append(out[i].entries, e)
		}
	}
	return out
}

func (g cacheGroup) summary(b *buildState, tenant string, now uint64) *imagebuild.CacheSummary {
	s := &imagebuild.CacheSummary{Schema: 1, Cache: g.id, Snapshot: fakeDigest("cache-snapshot", hexOf(g.id[:]), fmt.Sprint(len(g.entries))), ObservedBy: g.job.spec.Digest(),
		Recorded: true, Allocated: true, Available: true, ObservedAt: now, LastAttemptAt: now, LastAttemptCode: "OK"}
	kinds := map[string]*imagebuild.CacheKindUsage{}
	for _, e := range g.entries {
		k := realCacheKind[e.Kind]
		if kinds[k] == nil {
			kinds[k] = &imagebuild.CacheKindUsage{Kind: k}
		}
		kinds[k].Count++
		kinds[k].ReportedBytes += int64(e.Bytes)
		if b.cacheInUse(tenant, e) {
			kinds[k].InUse++
		}
		s.Count++
		s.ReportedBytes += int64(e.Bytes)
	}
	for _, k := range sortedKeys(kinds) {
		s.Kinds = append(s.Kinds, *kinds[k])
	}
	return s
}

func (w *world) cacheRow(tenant string, g cacheGroup, now uint64) control.ImageBuildCacheInventoryRow {
	spec := *g.job.spec
	x := w.build.find(tenant, spec.Context.ID)
	return control.ImageBuildCacheInventoryRow{Cache: g.id, Owner: spec.Scope.Root.Key, RepresentativeSnapshot: spec.Digest(), Node: g.node, Context: spec.Context.ID,
		Root: spec.Scope.Root.ID, Builder: spec.Policy.BuilderImage, RepresentativeJob: spec.ID, RootGeneration: spec.Scope.Root.Generation,
		JobDeleted: g.job.deleted, ContextDeleted: x == nil, Code: "OK", Usage: g.summary(&w.build, tenant, now)}
}

// --- reads ---

// ImageBuilds: `image-builds` (tenant Read), one Part per call.
func (c *fakeConn) ImageBuilds(ctx context.Context, tenant string, q control.ImageBuildQuery, after string) (control.ImageBuildPage, error) {
	const m = "image-builds"
	if !q.Valid() {
		return control.ImageBuildPage{}, fail(m, CodeInvalid, "query")
	}
	if err := checkAfter(m, after); err != nil {
		return control.ImageBuildPage{}, err
	}
	if err := c.appRead(ctx, m, tenant); err != nil {
		return control.ImageBuildPage{}, err
	}
	defer c.unlock()
	w := c.f.w
	b := &w.build
	out := control.ImageBuildPage{Schema: 1, Tenant: tenant, Part: q.Part, RootRevision: w.keyRoot(control.ImageBuildKey), Epoch: fakeBuildEpoch}
	page := func(n int, key func(int) string, keep func(int)) {
		idx := make([]int, n)
		for i := range idx {
			idx[i] = i
		}
		p := paginate(idx, key, after, c.f.pageSize, b.rev[tenant])
		for _, i := range p.Items {
			keep(i)
		}
		out.Next = p.Next
	}
	now := uint64(c.f.now().Unix())
	switch q.Part {
	case "policy":
		if p, rev, deleted, ok := w.imagePolicy(tenant); ok {
			out.Policies = []control.ImageBuildPolicyView{{Spec: p, Revision: rev, Deleted: deleted}}
		}
	case "contexts":
		var rows []control.ImageBuildContextView
		for _, x := range b.ctxs[tenant] {
			if q.ID == "" || x.row.ID == q.ID {
				rows = append(rows, control.ImageBuildContextView{Spec: w.contextSpec(x), Revision: x.row.Revision, NextVersion: slices.Max(append([]uint64{0}, x.row.Versions...)) + 1})
			}
		}
		page(len(rows), func(i int) string { return rows[i].Spec.ID }, func(i int) { out.Contexts = append(out.Contexts, rows[i]) })
	case "versions":
		x := b.find(tenant, q.ID)
		if x == nil {
			return control.ImageBuildPage{}, fail(m, CodeMissing, "context")
		}
		vs := slices.Sorted(slices.Values(x.row.Versions))
		page(len(vs), func(i int) string { return fmt.Sprintf("%020d", vs[i]) }, func(i int) { out.Versions = append(out.Versions, w.versionView(x, vs[i])) })
	case "uploads":
		rows := w.uploadRows(tenant, c.session.User, q.Upload)
		page(len(rows), func(i int) string { return rows[i].Scope.Upload }, func(i int) { out.Uploads = append(out.Uploads, rows[i]) })
	case "missing":
		p, code := w.uploadMissing(tenant, c.session.User, q.Upload, after, now)
		if code != "" {
			return control.ImageBuildPage{}, fail(m, code, "upload")
		}
		out.Missing, out.UploadRevision, out.Next = p.Missing, p.UploadRevision, p.Next
	case "jobs":
		var rows []*buildRec
		for _, r := range b.builds[tenant] {
			if (q.ID == "" || r.b.Context == q.ID) && (q.Job == "" || r.b.ID == q.Job) {
				rows = append(rows, r)
			}
		}
		page(len(rows), func(i int) string { return fmt.Sprintf("%016x", ^rows[i].seq) }, func(i int) { out.Jobs = append(out.Jobs, w.jobView(rows[i])) })
	case "caches":
		var rows []control.ImageBuildCacheInventoryRow
		for _, g := range w.cacheGroups(tenant) {
			if (q.Node == "" || g.node == q.Node) && (q.ID == "" || g.job.b.Context == q.ID) {
				rows = append(rows, w.cacheRow(tenant, g, now))
			}
		}
		page(len(rows), func(i int) string { return rows[i].Node + "/" + hexOf(rows[i].Cache[:]) }, func(i int) { out.Caches = append(out.Caches, rows[i]) })
		root := fakeDigest("cache-inventory", tenant, fmt.Sprint(b.rev[tenant]))
		out.InventoryRoot = &root
	case "cache-prunes":
		b.real.ready()
		var rows []control.ImageBuildCachePruneView
		for _, p := range b.real.prunes[tenant] {
			if (q.Node == "" || p.view.Node == q.Node) && (q.ID == "" || p.view.ID == q.ID) {
				rows = append(rows, p.view)
			}
		}
		page(len(rows), func(i int) string { return rows[i].ID }, func(i int) { out.CachePrunes = append(out.CachePrunes, rows[i]) })
	}
	return out, nil
}

// BuildContextContent: `build-context-content` — a frozen version's tree
// (8 entries a page), its Dockerfile, or one regular file (Part
// file, Path, Offset or a cursor; 24 KiB pages).
func (c *fakeConn) BuildContextContent(ctx context.Context, tenant string, q imagebuild.ContentQuery, after string) (control.ImageBuildContentPage, error) {
	const m = "build-context-content"
	if !q.Valid() {
		return control.ImageBuildContentPage{}, fail(m, CodeInvalid, "query")
	}
	if err := checkAfter(m, after); err != nil {
		return control.ImageBuildContentPage{}, err
	}
	if err := c.appRead(ctx, m, tenant); err != nil {
		return control.ImageBuildContentPage{}, err
	}
	defer c.unlock()
	w := c.f.w
	x, n, s, ok := w.findVersion(tenant, q.Version)
	if !ok {
		return control.ImageBuildContentPage{}, fail(m, CodeMissing, "version")
	}
	read := control.ImageBuildContentRead{Tenant: tenant, Query: q, After: after, Scope: s.scope, Seal: s.seal, Epoch: fakeBuildEpoch}
	offset, err := read.Offset()
	if err != nil {
		return control.ImageBuildContentPage{}, fail(m, CodeInvalid, "after")
	}
	p := imagebuild.ContentPage{Schema: 1, Version: q.Version, Tree: s.seal.Tree, Part: q.Part}
	switch q.Part {
	case "file": // one 24 KiB page of a regular file
		files := x.versions[n]
		entries := contentEntries(files)
		i := slices.IndexFunc(entries, func(e imagebuild.Entry) bool { return e.Path == q.Path })
		if i < 0 {
			if slices.ContainsFunc(entries, func(e imagebuild.Entry) bool { return strings.HasPrefix(e.Path, q.Path+"/") }) {
				return control.ImageBuildContentPage{}, fail(m, CodeInvalid, "a directory")
			}
			return control.ImageBuildContentPage{}, fail(m, CodeMissing, "file")
		}
		fp, err := filePage(entries[i], files[q.Path], offset)
		if err != nil {
			return control.ImageBuildContentPage{}, fail(m, CodeInvalid, err.Error())
		}
		p.File = &fp
	case "tree":
		entries := contentEntries(x.versions[n])
		p.Total = uint32(len(entries))
		if offset > uint64(p.Total) {
			return control.ImageBuildContentPage{}, fail(m, CodeInvalid, "after")
		}
		p.Offset = uint32(offset)
		end := min(p.Total, p.Offset+8)
		p.Entries = entries[p.Offset:end]
		if end < p.Total {
			p.Next = end
		}
	default:
		data := x.versions[n][s.scope.Dockerfile]
		p.Total = uint32(len(data))
		if offset > uint64(p.Total) {
			return control.ImageBuildContentPage{}, fail(m, CodeInvalid, "after")
		}
		p.Offset = uint32(offset)
		end := min(p.Total, p.Offset+imagebuild.PartBytes)
		p.Data = slices.Clone(data[p.Offset:end])
		if end < p.Total {
			p.Next = end
		}
	}
	out, err := read.Page(p)
	if err != nil {
		return control.ImageBuildContentPage{}, fail(m, CodeInvalid, "page")
	}
	return out, nil
}

// CheckBuildContext: `check-build-context` for a Git context: fetch, then
// check the Dockerfile and its FROM sources (codes OK, SOURCE_FETCH,
// UNTRUSTED_BASE, INVALID_CONTEXT).
func (c *fakeConn) CheckBuildContext(ctx context.Context, tenant string, q control.ImageBuildSourceQuery) (control.ImageBuildSourceResult, error) {
	const m = "check-build-context"
	if !q.Valid() {
		return control.ImageBuildSourceResult{}, fail(m, CodeInvalid, "query")
	}
	if err := c.appRead(ctx, m, tenant); err != nil {
		return control.ImageBuildSourceResult{}, err
	}
	defer c.unlock()
	w := c.f.w
	x := w.build.find(tenant, q.ID)
	if x == nil || x.row.Kind != BuildGit {
		return control.ImageBuildSourceResult{}, fail(m, CodeInvalid, "not a Git context")
	}
	_, prev, _, _ := w.imagePolicy(tenant)
	out := control.ImageBuildSourceResult{Schema: 1, Context: q.ID, ContextRevision: x.row.Revision, PolicyRevision: prev, Epoch: fakeBuildEpoch}
	src, code := w.fetchGit(x)
	if code != "" {
		out.Code = "SOURCE_FETCH"
		return out, nil
	}
	entries := contentEntries(src.files)
	out.Commit, out.Tree, out.Entries = fullCommit(src.commit), treeDigest(entries), uint32(len(entries))
	for _, e := range entries {
		out.ExpandedBytes += e.Bytes
	}
	df, ok := src.files[x.row.Dockerfile]
	if !ok {
		out.Code = "INVALID_CONTEXT"
		return out, nil
	}
	from := parseDockerfile(string(df)).from
	out.Code, out.BaseSources = "OK", uint32(len(from))
	for _, f := range from {
		if !w.trustedImage(tenant, f) {
			out.Code = "UNTRUSTED_BASE"
		}
	}
	return out, nil
}

// PlanImageBuildJob: `image-build-job-plan` (ManageRegistry): the job spec
// a build of the version would run, and the begin-image-build payload
// (Change) to sign. The plan is good for 120 seconds.
func (c *fakeConn) PlanImageBuildJob(ctx context.Context, tenant string, q control.ImageBuildJobQuery) (control.ImageBuildJobPlan, error) {
	const m = "image-build-job-plan"
	if !identifierRE.MatchString(q.ID) || !identifierRE.MatchString(q.Context) || q.Version == ([32]byte{}) {
		return control.ImageBuildJobPlan{}, fail(m, CodeInvalid, "query")
	}
	if err := c.appRead(ctx, m, tenant); err != nil {
		return control.ImageBuildJobPlan{}, err
	}
	defer c.unlock()
	w := c.f.w
	if !w.canManage(c.session.User, tenant) {
		return control.ImageBuildJobPlan{}, fail(m, CodeDenied, "")
	}
	x, n, _, ok := w.findVersion(tenant, q.Version)
	if !ok || x.row.ID != q.Context {
		return control.ImageBuildJobPlan{}, fail(m, CodeMissing, "version")
	}
	if w.build.job(tenant, q.ID) != nil {
		return control.ImageBuildJobPlan{}, fail(m, CodeConflict, "job exists")
	}
	at := uint64(c.f.now().Unix())
	spec, ok := w.jobSpec(x, q.ID, n, at)
	if !ok {
		return control.ImageBuildJobPlan{}, fail(m, CodeConflict, "no build policy")
	}
	return control.ImageBuildJobPlan{Schema: 1, Spec: spec, Change: control.ImageBuildJobStart{Tenant: tenant, ID: q.ID, Context: q.Context, Version: q.Version, Snapshot: spec.Digest(), At: at},
		RootRevision: w.keyRoot(control.ImageBuildKey), Epoch: fakeBuildEpoch, Index: w.root}, nil
}

// ImageBuildLogs: `image-build-logs`, redacted log bytes after the cursor
// (MaxBytes ≤ imagebuild.MaxLogPageBytes). Unclosed while the job runs.
func (c *fakeConn) ImageBuildLogs(ctx context.Context, tenant string, q imagebuild.LogQuery, after string) (control.ImageBuildLogPage, error) {
	return c.imageBuildLogs(ctx, tenant, q, after)
}

// imageBuildLogs: REQ-59 Tail (no After) reads the last page, Offset =
// max(0, Total−MaxBytes); its Next reads on without Tail.
func (c *fakeConn) imageBuildLogs(ctx context.Context, tenant string, q imagebuild.LogQuery, after string) (control.ImageBuildLogPage, error) {
	const m = "image-build-logs"
	if !q.Valid() {
		return control.ImageBuildLogPage{}, fail(m, CodeInvalid, "query")
	}
	if err := checkAfter(m, after); err != nil {
		return control.ImageBuildLogPage{}, err
	}
	if err := c.appRead(ctx, m, tenant); err != nil {
		return control.ImageBuildLogPage{}, err
	}
	defer c.unlock()
	w := c.f.w
	r := w.build.job(tenant, q.Job)
	if r == nil || r.deleted || r.spec == nil {
		return control.ImageBuildLogPage{}, fail(m, CodeConflict, "job")
	}
	read := control.ImageBuildLogRead{Tenant: tenant, Query: q, After: after, Spec: r.spec.Own(), Epoch: fakeBuildEpoch, Phase: jobPhase(r.b.Status)}
	offset, err := read.Offset()
	if err != nil {
		return control.ImageBuildLogPage{}, fail(m, CodeInvalid, "after")
	}
	var text []byte
	for _, l := range r.log {
		text = append(text, l+"\n"...)
	}
	text = text[:min(len(text), imagebuild.MaxLogBytes)]
	if q.Tail {
		offset = uint32(len(text)) - min(uint32(len(text)), q.MaxBytes)
	}
	if int(offset) > len(text) {
		return control.ImageBuildLogPage{}, fail(m, CodeConflict, "after")
	}
	end := min(uint32(len(text)), offset+q.MaxBytes)
	ended := r.b.Status != BuildRunning && r.b.Status != BuildQueued
	p := imagebuild.LogPage{Schema: 1, Job: r.spec.Digest(), Offset: offset, Next: end, Total: uint32(len(text)), Data: slices.Clone(text[offset:end]), Available: true, Unclosed: !ended}
	out, err := read.Page(p)
	if err != nil {
		return control.ImageBuildLogPage{}, fail(m, CodeInvalid, "page")
	}
	return out, nil
}

// ImageBuildCacheUsage: `image-build-cache`, the entries of one cache
// scope (by Job, or by Cache + Node), 32 a page.
func (c *fakeConn) ImageBuildCacheUsage(ctx context.Context, tenant string, q imagebuild.CacheQuery, after string) (control.ImageBuildCachePage, error) {
	const m = "image-build-cache"
	if !q.Valid() {
		return control.ImageBuildCachePage{}, fail(m, CodeInvalid, "query")
	}
	if err := checkAfter(m, after); err != nil {
		return control.ImageBuildCachePage{}, err
	}
	if err := c.appRead(ctx, m, tenant); err != nil {
		return control.ImageBuildCachePage{}, err
	}
	defer c.unlock()
	w := c.f.w
	b := &w.build
	var group *cacheGroup
	var spec imagebuild.JobSpec
	groups := w.cacheGroups(tenant)
	if q.Job != "" {
		r := b.job(tenant, q.Job)
		if r == nil || r.spec == nil {
			return control.ImageBuildCachePage{}, fail(m, CodeMissing, "job")
		}
		spec = *r.spec
		id := imagebuild.CacheIdentity(spec)
		for i := range groups {
			if groups[i].id == id && groups[i].node == r.b.Node {
				group = &groups[i]
			}
		}
	} else {
		for i := range groups {
			if groups[i].id == *q.Cache && groups[i].node == q.Node {
				group, spec = &groups[i], *groups[i].job.spec
			}
		}
		if group == nil {
			return control.ImageBuildCachePage{}, fail(m, CodeMissing, "cache")
		}
	}
	read := control.ImageBuildCacheRead{Tenant: tenant, Query: q, After: after, Spec: spec.Own(), Epoch: fakeBuildEpoch}
	snapshot, offset, err := read.Offset()
	if err != nil {
		return control.ImageBuildCachePage{}, fail(m, CodeInvalid, "after")
	}
	p := imagebuild.CachePage{Schema: 1, Cache: imagebuild.CacheIdentity(spec), Offset: offset}
	if group != nil {
		now := uint64(c.f.now().Unix())
		s := group.summary(b, tenant, now)
		if snapshot != ([32]byte{}) && snapshot != s.Snapshot {
			return control.ImageBuildCachePage{}, fail(m, CodeConflict, "cache changed: restart")
		}
		entries := slices.Clone(group.entries)
		slices.SortFunc(entries, func(a, b BuildCacheEntry) int { return strings.Compare(a.ID, b.ID) })
		if int(offset) > len(entries) {
			return control.ImageBuildCachePage{}, fail(m, CodeInvalid, "after")
		}
		end := min(uint32(len(entries)), offset+imagebuild.CachePageItems)
		p.Snapshot, p.ObservedBy, p.Available, p.ObservedAt, p.LastAttemptAt, p.LastAttemptCode = s.Snapshot, s.ObservedBy, true, now, now, "OK"
		p.ReportedBytes, p.Count = s.ReportedBytes, uint32(len(entries))
		for _, e := range entries[offset:end] {
			p.Entries = append(p.Entries, imagebuild.CacheEntry{ID: e.ID, Kind: realCacheKind[e.Kind], Bytes: int64(e.Bytes), CreatedAt: e.LastUsed, LastUsedAt: e.LastUsed, Uses: 1, InUse: b.cacheInUse(tenant, e)})
		}
		if end < p.Count {
			p.Next = end
		}
	}
	out, err := read.Page(p)
	if err != nil {
		return control.ImageBuildCachePage{}, fail(m, CodeInvalid, "page")
	}
	return out, nil
}

// --- injection ---

// FinishCachePrune ends a held prune-build-cache: code "" succeeds (the
// selected entries not in use go), otherwise fails with FAILED/TIMEOUT/
// PERMISSION_REVOKED.
func (f *Fake) FinishCachePrune(tenant, id, code string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w := f.w
	w.build.real.ready()
	for i := range w.build.real.prunes[tenant] {
		p := &w.build.real.prunes[tenant][i]
		if p.view.ID == id && (p.view.State == ImageBuildQueued || p.view.State == ImageBuildRunning) {
			w.bumpKey(control.ImageBuildKey)
			w.runPrune(tenant, p, code, uint64(f.now().Unix()))
			w.build.rev[tenant] = w.root
		}
	}
}

func (w *world) runPrune(tenant string, p *realPrune, code string, now uint64) {
	v := &p.view
	v.At, v.ClosedAt, v.Revision = now, now, 3
	if code != "" {
		v.State, v.Code = ImageBuildFailed, code
		return
	}
	b := &w.build
	var removed uint64
	var freed int64
	b.cache[tenant] = slices.DeleteFunc(b.cache[tenant], func(e BuildCacheEntry) bool {
		hit := e.Node == v.Node && slices.Contains(e.Contexts, p.context) && !b.cacheInUse(tenant, e) && (v.Filter.Mode == "all" ||
			v.Filter.Mode == "entries" && slices.Contains(v.Filter.IDs, e.ID) ||
			v.Filter.Mode == "unused" && e.LastUsed < int64(now)-int64(v.Filter.UnusedDays)*86400)
		if hit {
			removed++
			freed += int64(e.Bytes)
		}
		return hit
	})
	v.State, v.Code, v.RemovedCount, v.ReportedBytes = ImageBuildSucceeded, "OK", removed, freed
}

// --- actions ---

func (c *fakeConn) applyImageBuild(op UserOperation, actor string, next uint64) error {
	w := c.f.w
	b := &w.build
	b.real.ready()
	ch := op.Change
	var tenant struct{ Tenant string }
	var put struct{ Spec struct{ Tenant string } }
	if json.Unmarshal(ch.Payload, &tenant) != nil || json.Unmarshal(ch.Payload, &put) != nil {
		return errors.New("payload")
	}
	t := tenant.Tenant + put.Spec.Tenant
	if t == "" {
		return errors.New("payload: tenant")
	}
	if !w.canManage(actor, t) {
		return errForbidden
	}
	now := c.f.now().Unix()
	switch ch.Action {
	case ActionSetImageBuildPolicy:
		var q control.ImageBuildPolicyPut
		if decodePayload(ch.Payload, &q) != nil || q.Spec.Validate(w.cluster) != nil {
			return errors.New("payload")
		}
		if q.Spec.Registry != ImageRegistryBuiltin {
			return errors.New("payload: registry")
		}
		for _, n := range q.Spec.Nodes {
			if !slices.Contains(w.tenantNodes[t], n.Node) || !w.policyRootAllowed(t, n.Node, n.Root) {
				return errors.New("payload: node or root not allowed for the tenant")
			}
		}
		if _, rev, _, _ := w.imagePolicy(t); rev != ch.Expected {
			return errCAS
		}
		p := q.Spec.Own()
		old := BuildPolicy{Tenant: t, Revision: next, Concurrent: int(p.Concurrency), TimeoutSeconds: int(p.Seconds), CPUs: float64(p.CPUMillis) / 1000,
			MemoryBytes: uint64(p.MemoryBytes), ScratchBytes: uint64(p.WorkspaceBytes), CacheBytes: uint64(p.CacheBytes), Registry: p.Registry, Platforms: slices.Clone(p.Platforms), Builder: p.BuilderImage}
		for _, n := range p.Nodes {
			old.Nodes = append(old.Nodes, n.Node)
		}
		b.policy[t] = old
		b.cachePolicy[t] = BuildCachePolicy{MaxPercent: int(p.Cleanup.HighWaterPercent), IdleDays: int(p.Cleanup.UnusedDays)}
		b.real.policy[t] = realPolicy{spec: p, rev: next}
	case ActionDeleteImageBuildPolicy:
		var q control.ImageBuildSelection
		if decodePayload(ch.Payload, &q) != nil || q.ID != "" {
			return errors.New("payload")
		}
		p, rev, deleted, ok := w.imagePolicy(t)
		if !ok || deleted || rev != ch.Expected || b.running(t) > 0 {
			return errCAS
		}
		delete(b.policy, t)
		b.real.policy[t] = realPolicy{spec: p, rev: next, deleted: true}
	case ActionPutBuildContext:
		var q control.ImageBuildContextPut
		if decodePayload(ch.Payload, &q) != nil || q.Spec.Validate() != nil {
			return errors.New("payload")
		}
		pol, _, deleted, ok := w.imagePolicy(t)
		if !ok || deleted || !q.Spec.Under(pol) {
			return errCAS // mydcd: ConditionFailed
		}
		s := q.Spec.Own()
		for _, m := range s.Secrets {
			realm := m.Realm
			if realm == "" {
				realm = t
			}
			if v := w.vaultObject(realm, m.Secret); realm != t || v == nil || !slices.Contains(v.Keys, m.Key) {
				return errors.New("payload: secret")
			}
		}
		x := b.find(t, s.ID)
		have := uint64(0)
		if x != nil {
			have = x.row.Revision
			if x.row.Kind != oldKind(s.Kind) || w.contextSpec(x).Root != s.Root {
				return errCAS // kind and build server are fixed once saved
			}
		}
		if have != ch.Expected {
			return errCAS
		}
		if x == nil {
			x = &buildCtx{versions: map[uint64]map[string][]byte{}, row: BuildContext{Tenant: t, ID: s.ID, Name: s.ID}}
			if s.Kind == "draft" {
				x.draft = map[string][]byte{} // NOT_INITIALIZED until its first edit
			}
			b.ctxs[t] = append(b.ctxs[t], x)
			slices.SortFunc(b.ctxs[t], func(a, c *buildCtx) int { return strings.Compare(a.row.ID, c.row.ID) })
		}
		keep := x.row
		row := BuildContext{Tenant: t, ID: s.ID, Name: keep.Name, Kind: oldKind(s.Kind), Revision: next, Version: keep.Version, Versions: keep.Versions,
			Dockerfile: s.Dockerfile, Repository: s.Repository, TagRule: s.Tags[0], Platforms: slices.Clone(s.Platforms)}
		for _, k := range sortedKeys(s.Arguments) {
			row.Args = append(row.Args, BuildArg{Name: k, Value: s.Arguments[k]})
		}
		for _, m := range s.Secrets {
			row.Secrets = append(row.Secrets, BuildSecret{ID: m.ID, Realm: t, Object: m.Secret, Key: m.Key})
		}
		if g := s.Git; g != nil {
			row.Git = &BuildGitSource{Repository: g.Repository, Ref: g.Ref, Folder: strings.TrimPrefix(g.Path, "."), CredentialProfile: g.CredentialProfile, AutoBuild: g.Automatic}
			if keep.Git != nil && keep.Git.Repository == g.Repository {
				row.Git.Commit = keep.Git.Commit
			}
		}
		x.row = row
		b.real.specs[t+"/"+s.ID] = realSpec{spec: s}
	case ActionDeleteBuildContext:
		var q control.ImageBuildSelection
		if decodePayload(ch.Payload, &q) != nil {
			return errors.New("payload")
		}
		x := b.find(t, q.ID)
		// mydcd: versions go first (delete-build-version), and no job runs.
		if x == nil || x.row.Revision != ch.Expected || len(x.versions) > 0 || slices.ContainsFunc(b.builds[t], func(r *buildRec) bool {
			return r.b.Context == q.ID && (r.b.Status == BuildRunning || r.b.Status == BuildQueued)
		}) {
			return errCAS
		}
		b.ctxs[t] = slices.DeleteFunc(b.ctxs[t], func(y *buildCtx) bool { return y == x })
		b.real.forget(t, q.ID)
	case ActionDeleteBuildVersion:
		var q control.ImageBuildVersionSelection
		if decodePayload(ch.Payload, &q) != nil {
			return errors.New("payload")
		}
		x, n, _, ok := w.findVersion(t, q.ID)
		// mydcd: any version no undeleted job used, the newest too; the
		// context revision stays.
		if !ok || n != ch.Expected || slices.ContainsFunc(b.builds[t], func(r *buildRec) bool {
			return r.b.Context == x.row.ID && r.b.ContextVersion == n && !r.deleted
		}) {
			return errCAS
		}
		delete(x.versions, n)
		x.row.Versions = slices.DeleteFunc(x.row.Versions, func(v uint64) bool { return v == n })
		if x.row.Version == n {
			x.row.Version = slices.Max(append([]uint64{0}, x.row.Versions...))
		}
	case ActionBeginImageBuild:
		var q control.ImageBuildJobStart
		if decodePayload(ch.Payload, &q) != nil || ch.Expected != 0 || !identifierRE.MatchString(q.ID) {
			return errors.New("payload")
		}
		if q.At > uint64(now) || uint64(now)-q.At > 120 {
			return errCAS
		}
		x, n, _, ok := w.findVersion(t, q.Version)
		if !ok || x.row.ID != q.Context || b.job(t, q.ID) != nil {
			return errCAS
		}
		spec, ok := w.jobSpec(x, q.ID, n, q.At)
		if !ok || spec.Digest() != q.Snapshot {
			return errCAS // the context or policy changed since the plan
		}
		if len(w.missingApprovals(op)) > 0 {
			return errors.New("group approval required")
		}
		if err := c.startBuild(t, q.Context, q.ID, actor, now, n); err != nil {
			return err
		}
		if r := b.job(t, q.ID); r != nil {
			r.spec = &spec
		}
	case ActionCancelImageBuild, ActionDeleteImageBuildJob:
		var q control.ImageBuildSelection
		if decodePayload(ch.Payload, &q) != nil {
			return errors.New("payload")
		}
		r := b.job(t, q.ID)
		if r == nil || r.deleted || r.revision() != ch.Expected {
			return errCAS
		}
		ended := r.b.Status != BuildRunning && r.b.Status != BuildQueued
		if ch.Action == ActionCancelImageBuild {
			if ended {
				return errCAS
			}
			w.cancelBuild(r, actor, now)
		} else {
			if !ended {
				return errCAS
			}
			r.deleted, r.log = true, nil
		}
	case ActionPruneBuildCache:
		var q control.ImageBuildCachePruneChange
		if decodePayload(ch.Payload, &q) != nil || ch.Expected != 0 || !q.Valid() {
			return errors.New("payload")
		}
		var g *cacheGroup
		for _, x := range w.cacheGroups(t) {
			if x.id == q.Cache && x.node == q.Node {
				g = &x
			}
		}
		if g == nil || slices.ContainsFunc(b.real.prunes[t], func(p realPrune) bool {
			pending := p.view.State == ImageBuildQueued || p.view.State == ImageBuildRunning
			return p.view.ID == q.ID || p.view.Cache == q.Cache && pending
		}) {
			return errCAS
		}
		p := realPrune{context: g.job.b.Context, view: control.ImageBuildCachePruneView{ID: q.ID, Node: q.Node, Context: g.job.b.Context, User: actor, State: ImageBuildQueued,
			Cache: q.Cache, Filter: q.Filter, Revision: 1, At: uint64(now)}}
		p.view.Filter.IDs = slices.Clone(q.Filter.IDs)
		if !b.hold[t] {
			w.runPrune(t, &p, "", uint64(now))
		}
		b.real.prunes[t] = append(b.real.prunes[t], p)
	default:
		return errors.New("action")
	}
	b.rev[t] = next
	return nil
}

// filePage: imagebuild.FilePage of a regular file from offset (mydcd's
// readAtFilePage): 24 KiB, Next 0 at the end. A directory is refused.
func filePage(e imagebuild.Entry, data []byte, offset uint64) (imagebuild.FilePage, error) {
	if e.Directory {
		return imagebuild.FilePage{}, errors.New("not a regular file")
	}
	if offset > uint64(len(data)) {
		return imagebuild.FilePage{}, errors.New("offset")
	}
	end := min(uint64(len(data)), offset+imagebuild.PartBytes)
	p := imagebuild.FilePage{Entry: e, Offset: offset, Total: uint64(len(data)), Data: slices.Clone(data[offset:end])}
	if end < p.Total {
		p.Next = end
	}
	return p, nil
}
