// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/registryclient"
	"github.com/jay94ks/seafield/internal/web/sfc"
	"github.com/jay94ks/seafield/internal/web/store"
)

// Registry images in sfcd's real REQ-18 contract (UI-84 '이미지 목록',
// UI-8A '정리'; docs/reference/registry-images.md, registry-maintenance.md,
// image-usages.md): `registry-catalog` pages, `image-usages`,
// `registry-maintenance-plan` → delete-registry-image / gc-registry,
// `registry-prune-preview` → prune-registry-images, and
// `registry-maintenance-status` / `registry-prune-results` for progress.
// sfcd lists, judges use and permissions, and removes; Applied is only
// the job's acceptance. The web only
//   - keeps a short in-memory cache of catalogue pages (imageCacheTTL) so
//     the tab does not walk the registry on every open; a cached page is
//     served only after sfcd confirms the caller still reads the
//     workspace;
//   - adds what only the web knows: apps archived by '내리기' (web bbolt)
//     still name images, so usage lists them and prune keeps their digests
//     in ProtectedDigests.
//
// The stable operation ID of a web job is "web-<opId>".

const (
	imageCacheTTL  = 10 * time.Minute
	imageCacheRows = 256
	maxUsageRefs   = 32
	maxUsagePages  = 16 // 16 rows a page
	maxProtected   = 256
)

// imageCacheKey includes the user: a page sfcd answered for one user is
// never handed to another, so each user's first read asks sfcd.
type imageCacheKey struct{ user, tenant, kind, registry, repository, after string }

type imageCacheEntry struct {
	page control.RegistryCatalogueResult
	at   time.Time
}

// imageCache is the web's catalogue cache (memory only, never bbolt: it is
// a copy of cluster state and must not outlive the process).
type imageCache struct {
	mu   sync.Mutex
	rows map[imageCacheKey]imageCacheEntry
}

func (c *imageCache) get(k imageCacheKey, now time.Time) (imageCacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.rows[k]
	if !ok || now.Sub(e.at) >= imageCacheTTL || now.Before(e.at) {
		return imageCacheEntry{}, false
	}
	return e, true
}

func (c *imageCache) put(k imageCacheKey, e imageCacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rows == nil {
		c.rows = map[imageCacheKey]imageCacheEntry{}
	}
	if len(c.rows) >= imageCacheRows {
		var oldest imageCacheKey
		first := true
		for k, v := range c.rows {
			if first || v.at.Before(c.rows[oldest].at) {
				oldest, first = k, false
			}
		}
		delete(c.rows, oldest)
	}
	c.rows[k] = e
}

// drop forgets every user's pages of one registry (after a change the web
// sent).
func (c *imageCache) drop(tenant, registry string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.rows {
		if k.tenant == tenant && k.registry == registry {
			delete(c.rows, k)
		}
	}
}

func registryKind(r *http.Request) (string, bool) {
	if r.URL.Query().Get("external") == "1" {
		return "external", true
	}
	return "managed", false
}

func tagsOf(t []string) []string {
	if t == nil {
		return []string{}
	}
	return t
}

func msRFC(ms uint64) string { return rfc3339(time.UnixMilli(int64(ms))) }

type registryImageView struct {
	Repository    string `json:"repository"`
	Reference     string `json:"reference"` // a tag or the digest itself
	Digest        string `json:"digest"`
	MediaType     string `json:"mediaType"`
	ManifestBytes int64  `json:"manifestBytes"`
	ImageBytes    int64  `json:"imageBytes"`
	UploadedAt    string `json:"uploadedAt,omitempty"` // only when sfcd knows it
}

func viewImage(m registryclient.ImageMetadata) registryImageView {
	v := registryImageView{m.Repository, m.Reference, m.Digest, m.MediaType, m.ManifestBytes, m.ImageBytes, ""}
	if m.UploadedAtKnown {
		v.UploadedAt = msRFC(m.UploadedAt)
	}
	return v
}

type registryCatalogueView struct {
	Kind             string              `json:"kind"`
	ID               string              `json:"id"`
	Authority        string              `json:"authority"`
	Repository       string              `json:"repository,omitempty"`
	Code             string              `json:"code,omitempty"` // "" = OK
	Live             bool                `json:"live"`
	UntaggedComplete bool                `json:"untaggedComplete"`
	Repositories     []string            `json:"repositories"`
	Items            []registryImageView `json:"items"`
	Next             string              `json:"next"`
	AsOf             string              `json:"asOf"`
	CachedAt         string              `json:"cachedAt"`
}

func (s *Server) viewCatalogue(p control.RegistryCatalogueResult, cachedAt time.Time) registryCatalogueView {
	pg := p.Page
	v := registryCatalogueView{Kind: p.Kind, ID: p.ID, Authority: pg.Authority, Repository: pg.Repository, Live: pg.Live, UntaggedComplete: pg.UntaggedComplete,
		Repositories: tagsOf(pg.Repositories), Items: []registryImageView{}, Next: pg.Next, AsOf: rfc3339(s.now()), CachedAt: rfc3339(cachedAt)}
	if pg.Code != "OK" {
		v.Code = lowerCode(pg.Code)
	}
	for _, im := range pg.Images {
		v.Items = append(v.Items, viewImage(im))
	}
	return v
}

// GET /t/{t}/registries/{id}/images?external=1&repository=&after=&refresh=1
// → registryCatalogueView (`registry-catalog`, 8 rows a page). Without
// repository the page lists repositories; with it the repository's tag and
// digest rows (several tags may name one digest). external=1 reads the
// external source {id} through its bound reader. A page read in the last
// 10 minutes comes from the web's memory (cachedAt says when sfcd
// answered); refresh=1 reads sfcd now. Changes sent through this web drop
// the registry's cached pages.
func (s *Server) handleRegistryImages(w http.ResponseWriter, r *http.Request, ws *webSession) {
	tenant, id := r.PathValue("t"), r.PathValue("id")
	kind, _ := registryKind(r)
	q := control.RegistryCatalogueQuery{Kind: kind, ID: id, Repository: r.URL.Query().Get("repository")}
	k := imageCacheKey{ws.user.ID, tenant, kind, id, q.Repository, r.URL.Query().Get("after")}
	if !q.Valid() || len(k.after) > 512 {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "registry and repository: names")
		return
	}
	if r.URL.Query().Get("refresh") != "1" {
		if e, ok := s.images.get(k, s.now()); ok {
			// sfcd still decides who reads: no access, no cached rows.
			if !s.requireRole(w, r, ws, tenant, false) {
				return
			}
			writeJSON(w, http.StatusOK, s.viewCatalogue(e.page, e.at))
			return
		}
	}
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (registryCatalogueView, error) {
		p, err := c.RegistryCatalogue(ctx, tenant, q, k.after)
		if err != nil {
			return registryCatalogueView{}, err
		}
		at := s.now()
		if p.Page.Code == "OK" {
			s.images.put(k, imageCacheEntry{p, at})
		}
		return s.viewCatalogue(p, at), nil
	})
}

// --- usage ---

// archivedImage is one image an archived app's app.yaml names.
type archivedImage struct {
	app *store.ArchivedApp
	ref string
}

// archivedImages reads services.*.image of every archived app of tenant
// (web bbolt; the web saved these app.yaml files itself).
func (s *Server) archivedImages(tenant string) ([]archivedImage, error) {
	rows, err := s.opt.Store.ListArchived(tenant)
	if err != nil {
		return nil, err
	}
	var out []archivedImage
	for _, a := range rows {
		var doc struct {
			Services map[string]struct {
				Image string `yaml:"image"`
			} `yaml:"services"`
		}
		if yaml.Unmarshal(a.Source, &doc) != nil {
			continue
		}
		var refs []string
		for _, svc := range doc.Services {
			if img := strings.TrimSpace(svc.Image); img != "" && !strings.Contains(img, "${") {
				refs = append(refs, img)
			}
		}
		slices.Sort(refs)
		for _, ref := range slices.Compact(refs) {
			out = append(out, archivedImage{a, ref})
		}
	}
	return out, nil
}

// sameImage: an archived app's ref names the image ref asks about: the same
// normalized name, or (for a bare digest or a pinned ref) the same digest.
func sameImage(archived, ref string) bool {
	an, _, _, err := registryclient.Normalize(archived)
	if err != nil {
		return false
	}
	_, ad, _ := strings.Cut(an, "@")
	if strings.HasPrefix(ref, "sha256:") {
		return ad == ref
	}
	rn, _, _, err := registryclient.Normalize(ref)
	if err != nil {
		return false
	}
	if _, rd, ok := strings.Cut(rn, "@"); ok && ad != "" {
		return rd == ad
	}
	return an == rn
}

type usageRowView struct {
	ID         string `json:"id"`
	App        string `json:"app,omitempty"`
	Deployment string `json:"deployment,omitempty"`
	Node       string `json:"node,omitempty"`
	Service    string `json:"service,omitempty"`
	Instance   string `json:"instance,omitempty"`
	Image      string `json:"image,omitempty"`
	Kind       string `json:"kind"`
	Task       string `json:"task,omitempty"`
	Operation  string `json:"operation,omitempty"`
	Version    uint64 `json:"version,omitempty"`
	Unknown    bool   `json:"unknown,omitempty"`
	Match      string `json:"match"`
}

type archivedUseView struct {
	Key    string `json:"key"`
	App    string `json:"app"`
	Image  string `json:"image"`
	DownAt string `json:"downAt"`
}

type imageUseView struct {
	Ref       string            `json:"ref"`
	Rows      []usageRowView    `json:"rows"`
	Truncated bool              `json:"truncated"`
	Archived  []archivedUseView `json:"archived"`
}

// imageUses reads every `image-usages` page for one ref (again from the
// start once when the rows change between pages).
func imageUses(ctx context.Context, c sfc.Conn, tenant, ref string) ([]control.ImageUsage, bool, error) {
	var me *sfc.Error
	for try := 0; ; try++ {
		var out []control.ImageUsage
		after, more := "", false
		var err error
		for i := 0; ; i++ {
			var p control.ImageUsagesPage
			if p, err = c.ImageUsages(ctx, tenant, control.ImageUsageQuery{Refs: []string{ref}}, after); err != nil {
				break
			}
			out = append(out, p.Rows...)
			if after = p.Next; after == "" {
				break
			}
			if i+1 == maxUsagePages {
				more = true
				break
			}
		}
		if err == nil {
			return out, more, nil
		}
		if try > 0 || !errors.As(err, &me) || me.Code != sfc.CodeConflict {
			return nil, false, err
		}
	}
}

// usageOf is who uses ref, with the archived apps naming it.
func (s *Server) usageOf(ctx context.Context, c sfc.Conn, tenant, ref string, arch []archivedImage) (imageUseView, error) {
	rows, more, err := imageUses(ctx, c, tenant, ref)
	if err != nil {
		return imageUseView{}, err
	}
	v := imageUseView{Ref: ref, Rows: []usageRowView{}, Truncated: more, Archived: []archivedUseView{}}
	for _, u := range rows {
		v.Rows = append(v.Rows, usageRowView{u.ID, u.App, u.Deployment, u.Node, u.Service, u.Instance, u.Image, u.Kind, u.Task, u.Operation, u.Version, u.Unknown, u.Match})
	}
	for _, a := range arch {
		if sameImage(a.ref, ref) {
			v.Archived = append(v.Archived, archivedUseView{archiveKeyOut(a.app.Key), a.app.App, a.ref, rfc3339(a.app.DownAt)})
		}
	}
	return v, nil
}

// POST /t/{t}/image-usage {refs:[ref or sha256 digest]} → {items:[{ref,
// rows, truncated, archived}]}: who uses each image (`image-usages`, one
// query per ref; at most 32 refs and 256 rows each). archived lists the
// apps the web archived whose app.yaml names the same image.
func (s *Server) handleImageUsage(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Refs []string `json:"refs"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if len(req.Refs) == 0 || len(req.Refs) > maxUsageRefs || slices.ContainsFunc(req.Refs, func(v string) bool { return v == "" || len(v) > 512 }) {
		s.writeOpOutcome(w, ws, nil, 0, invalid("refs: 1..32 image refs or digests"))
		return
	}
	tenant := r.PathValue("t")
	arch, err := s.archivedImages(tenant)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (map[string]any, error) {
		items := make([]imageUseView, 0, len(req.Refs))
		for _, ref := range req.Refs {
			v, err := s.usageOf(ctx, c, tenant, ref, arch)
			if err != nil {
				return nil, err
			}
			items = append(items, v)
		}
		return map[string]any{"items": items}, nil
	})
}

// protectedDigests: digests archived apps still name (prune keeps them).
// A pinned ref gives its digest; a tag is resolved with image-resolve on
// the user's session (a ref sfcd cannot resolve protects nothing).
func (s *Server) protectedDigests(ctx context.Context, c sfc.Conn, tenant string) ([]string, error) {
	arch, err := s.archivedImages(tenant)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, a := range arch {
		if n, _, _, err := registryclient.Normalize(a.ref); err == nil {
			if _, d, ok := strings.Cut(n, "@"); ok {
				out = append(out, d)
				continue
			}
		}
		res, err := c.ResolveImage(ctx, tenant, control.ImageResolveQuery{Ref: a.ref})
		if err != nil {
			return nil, err
		}
		if res.Code == "OK" && res.Image != nil {
			out = append(out, res.Image.Digest)
		}
	}
	slices.Sort(out)
	out = slices.Compact(out)
	if len(out) > maxProtected {
		out = out[:maxProtected]
	}
	return out, nil
}

// --- delete and GC ---

func webOperation(opID string) string { return "web-" + opID }

// maintenancePlan asks sfcd for the plan and fills the web job's stable
// operation ID; InUse refuses a delete before anything is sent.
func maintenanceChange(ctx context.Context, c sfc.Conn, tenant, opID string, q control.RegistryMaintenanceQuery) (any, uint64, error) {
	if !q.Valid(true) {
		return nil, 0, invalid("repository, reference (a tag or the digest) and digest (sha256:<64 hex>)")
	}
	plan, err := c.PlanRegistryMaintenance(ctx, tenant, q)
	var me *sfc.Error
	if errors.As(err, &me) && me.Code == sfc.CodeConflict {
		return nil, 0, &httpErr{http.StatusConflict, "busy", "the registry has a pending job or is not serving; try again when it settles"}
	}
	if err != nil {
		return nil, 0, err
	}
	if plan.InUse {
		return nil, 0, &httpErr{http.StatusConflict, "image-in-use", "something still uses this image; see image-usage"}
	}
	ch := plan.Change
	ch.Operation = webOperation(opID)
	return rootedPayload{ch, plan.RootRevision}, plan.Expected, nil
}

// POST /t/{t}/registries/{id}/images/delete {opId, external?, repository,
// reference, digest} → delete-registry-image. reference is a tag (only
// that tag goes) or the digest (the image and every tag on it); digest is
// the image the browser showed (a tag moved since fails
// REFERENCE_CHANGED). An image in use is 409 image-in-use. The op is only
// the acceptance: GET /t/{t}/registry-maintenance/web-<opId> follows it.
func (s *Server) handleDeleteRegistryImage(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID       string `json:"opId"`
		External   bool   `json:"external,omitempty"`
		Repository string `json:"repository"`
		Reference  string `json:"reference"`
		Digest     string `json:"digest"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant, id := r.PathValue("t"), r.PathValue("id")
	defer s.images.drop(tenant, id)
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		q := control.RegistryMaintenanceQuery{Action: sfc.ActionDeleteRegistryImage, ID: id, Repository: req.Repository, Reference: req.Reference, Digest: req.Digest, External: req.External}
		p, exp, err := maintenanceChange(ctx, c, tenant, req.OpID, q)
		return sfc.ActionDeleteRegistryImage, p, exp, "registry/" + id, err
	})
}

// POST /t/{t}/registries/{id}/gc {opId} → gc-registry (built-in only):
// frees the blobs no image uses. Followed like a delete.
func (s *Server) handleRegistryGC(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID string `json:"opId"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant, id := r.PathValue("t"), r.PathValue("id")
	defer s.images.drop(tenant, id)
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		p, exp, err := maintenanceChange(ctx, c, tenant, req.OpID, control.RegistryMaintenanceQuery{Action: sfc.ActionGCRegistry, ID: id})
		return sfc.ActionGCRegistry, p, exp, "registry/" + id, err
	})
}

type maintenanceResultView struct {
	Code           string            `json:"code"`
	At             string            `json:"at"`
	ReclaimedBytes int64             `json:"reclaimedBytes"`
	Native         string            `json:"native,omitempty"`
	Prune          *pruneSummaryView `json:"prune,omitempty"`
}

type pruneSummaryView struct {
	Processed uint32 `json:"processed"`
	Deleted   uint32 `json:"deleted"`
	Skipped   uint32 `json:"skipped"`
	Failed    uint32 `json:"failed"`
	GCCode    string `json:"gcCode,omitempty"`
	GCAt      string `json:"gcAt,omitempty"`
}

type maintenanceStatusView struct {
	Operation  string                 `json:"operation"`
	Action     string                 `json:"action"`
	User       string                 `json:"user"`
	State      string                 `json:"state"` // queued / running / done / failed / unknown
	Revision   uint64                 `json:"revision"`
	At         string                 `json:"at"`
	Registry   string                 `json:"registry"`
	External   bool                   `json:"external"`
	Repository string                 `json:"repository,omitempty"`
	Reference  string                 `json:"reference,omitempty"`
	Digest     string                 `json:"digest,omitempty"`
	Result     *maintenanceResultView `json:"result,omitempty"`
}

func viewMaintenanceResult(r *control.RegistryMaintenanceResult) *maintenanceResultView {
	if r == nil {
		return nil
	}
	v := &maintenanceResultView{Code: lowerCode(r.Code), At: msRFC(r.At), ReclaimedBytes: r.ReclaimedBytes}
	if r.Native != ([32]byte{}) {
		v.Native = hex.EncodeToString(r.Native[:])
	}
	if p := r.Prune; p != nil {
		v.Prune = &pruneSummaryView{Processed: p.Processed, Deleted: p.Deleted, Skipped: p.Skipped, Failed: p.Failed}
		if p.GCCode != "" {
			v.Prune.GCCode = lowerCode(p.GCCode)
		}
		if p.GCAt != 0 {
			v.Prune.GCAt = msRFC(p.GCAt)
		}
	}
	return v
}

// GET /t/{t}/registry-maintenance/{operation} → maintenanceStatusView
// (`registry-maintenance-status`). A web job's operation is web-<opId>.
func (s *Server) handleMaintenanceStatus(w http.ResponseWriter, r *http.Request, ws *webSession) {
	tenant, opn := r.PathValue("t"), r.PathValue("operation")
	if !(control.RegistryMaintenanceQuery{Operation: opn}).Valid(false) {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "operation")
		return
	}
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (maintenanceStatusView, error) {
		st, err := c.RegistryMaintenanceStatus(ctx, tenant, opn)
		if err != nil {
			return maintenanceStatusView{}, err
		}
		ch := st.Change
		return maintenanceStatusView{Operation: st.Operation, Action: st.Action, User: st.User, State: st.State, Revision: st.Revision, At: unixRFC(int64(st.At)),
			Registry: ch.RegistryID(), External: ch.External != nil, Repository: ch.Repository, Reference: ch.Reference, Digest: ch.Digest, Result: viewMaintenanceResult(st.Result)}, nil
	})
}

func unixRFC(v int64) string { return rfc3339(time.Unix(v, 0)) }

// --- prune ---

// pruneConditions: the browser's rule (before in Unix seconds, 0 = none);
// lists are sorted and deduplicated here, as sfcd wants them.
type pruneConditions struct {
	Repositories            []string `json:"repositories"`
	KeepRecentPerRepository uint32   `json:"keepRecentPerRepository"`
	Before                  int64    `json:"before"`
	ExcludeTags             []string `json:"excludeTags"`
	IncludeUntagged         bool     `json:"includeUntagged"`
	ProtectedDigests        []string `json:"protectedDigests"`
	GC                      bool     `json:"gc"`
}

func sortedSet(v []string) []string {
	out := slices.Clone(v)
	slices.Sort(out)
	return tagsOf(slices.Compact(out))
}

func (p pruneConditions) real() (registryclient.PruneConditions, error) {
	if p.Before < 0 {
		return registryclient.PruneConditions{}, invalid("before: Unix seconds, 0 for none")
	}
	c := registryclient.PruneConditions{Repositories: sortedSet(p.Repositories), KeepRecentPerRepository: p.KeepRecentPerRepository, Before: uint64(p.Before) * 1000,
		ExcludeTags: sortedSet(p.ExcludeTags), IncludeUntagged: p.IncludeUntagged, ProtectedDigests: sortedSet(p.ProtectedDigests), GC: p.GC}
	for _, f := range []*[]string{&c.Repositories, &c.ExcludeTags, &c.ProtectedDigests} {
		if len(*f) == 0 {
			*f = nil
		}
	}
	if !c.Valid() {
		return c, invalid("conditions: at most 256 repositories, 32 tag patterns (no /), 256 sha256 digests; keepRecentPerRepository at most 16384")
	}
	return c, nil
}

func webConditions(c registryclient.PruneConditions) pruneConditions {
	return pruneConditions{tagsOf(c.Repositories), c.KeepRecentPerRepository, int64(c.Before / 1000), tagsOf(c.ExcludeTags), c.IncludeUntagged, tagsOf(c.ProtectedDigests), c.GC}
}

// The preview token is the owner-signed Fact, passed back verbatim; sfcd
// checks its signature and age, so the browser cannot change it.
func previewToken(f control.RegistryPruneFact) string {
	raw, _ := json.Marshal(f)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func readPreviewToken(tok string) (*control.RegistryPruneFact, error) {
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	var f control.RegistryPruneFact
	if err != nil || len(tok) > 16<<10 || json.Unmarshal(raw, &f) != nil {
		return nil, invalid("preview: the token the first preview page gave")
	}
	return &f, nil
}

type pruneRowView struct {
	ID          string            `json:"id"`
	Image       registryImageView `json:"image"`
	Aliases     uint32            `json:"aliases"`
	AliasDigest string            `json:"aliasDigest"`
	Code        string            `json:"code,omitempty"`
	At          string            `json:"at,omitempty"`
}

type pruneRetainedView struct {
	Image registryImageView `json:"image"`
	Code  string            `json:"code"`
}

type prunePageView struct {
	Conditions              pruneConditions     `json:"conditions,omitzero"`
	Preview                 string              `json:"preview,omitempty"`
	Operation               string              `json:"operation,omitempty"`
	Items                   uint32              `json:"items"`
	Retained                uint32              `json:"retained"`
	ImageBytes              int64               `json:"imageBytes"`
	EstimatedReclaimedBytes int64               `json:"estimatedReclaimedBytes"`
	EstimateKnown           bool                `json:"estimateKnown"`
	Live                    bool                `json:"live"`
	ExpiresAt               string              `json:"expiresAt,omitempty"`
	Part                    string              `json:"part"`
	Total                   uint32              `json:"total"`
	Processed               uint32              `json:"processed"`
	Rows                    []pruneRowView      `json:"rows"`
	RetainedRows            []pruneRetainedView `json:"retainedRows"`
	Next                    string              `json:"next"`
}

func viewPrune(v control.RegistryPruneView) prunePageView {
	out := prunePageView{Part: v.Page.Part, Total: v.Page.Total, Processed: v.Page.Processed, Rows: []pruneRowView{}, RetainedRows: []pruneRetainedView{}, Next: v.Page.Next}
	if t := v.Plan.Change.Prune; t != nil {
		f := t.Fact
		out.Items, out.Retained, out.ImageBytes, out.EstimatedReclaimedBytes, out.EstimateKnown, out.Live = f.Items, f.Retained, f.ImageBytes, f.EstimatedReclaimedBytes, f.EstimateKnown, f.Live
		out.ExpiresAt = unixRFC(int64(f.At + control.RegistryPrunePreviewSeconds))
	}
	for _, r := range v.Page.Rows {
		row := pruneRowView{ID: r.ID, Image: viewImage(r.Image), Aliases: r.Aliases, AliasDigest: r.AliasDigest}
		if r.Code != "" {
			row.Code, row.At = lowerCode(r.Code), msRFC(r.At)
		}
		out.Rows = append(out.Rows, row)
	}
	for _, r := range v.Page.Retained {
		out.RetainedRows = append(out.RetainedRows, pruneRetainedView{viewImage(r.Image), lowerCode(r.Code)})
	}
	return out
}

// POST /t/{t}/registries/{id}/prune/preview {external?, part(items |
// retained), conditions, preview?, after?} → prunePageView
// (`registry-prune-preview`, 8 rows a page). The first page (no preview)
// adds the archived apps' digests to conditions.protectedDigests and
// gives the preview token; later pages and the other part send the same
// conditions and preview back (after empty when changing part). A preview
// is good for 10 minutes (expiresAt).
func (s *Server) handlePrunePreview(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		External   bool            `json:"external,omitempty"`
		Part       string          `json:"part"`
		Conditions pruneConditions `json:"conditions"`
		Preview    string          `json:"preview,omitempty"`
		After      string          `json:"after,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant, id := r.PathValue("t"), r.PathValue("id")
	if req.Part == "" {
		req.Part = "items"
	}
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (prunePageView, error) {
		q := control.RegistryPruneQuery{ID: id, Part: req.Part, External: req.External}
		if req.Preview == "" {
			protected, err := s.protectedDigests(ctx, c, tenant)
			if err != nil {
				return prunePageView{}, err
			}
			req.Conditions.ProtectedDigests = append(req.Conditions.ProtectedDigests, protected...)
			if req.After != "" {
				return prunePageView{}, invalid("after: only with the preview token")
			}
		} else {
			f, err := readPreviewToken(req.Preview)
			if err != nil {
				return prunePageView{}, err
			}
			q.Fact = f
		}
		cond, err := req.Conditions.real()
		if err != nil {
			return prunePageView{}, err
		}
		q.Conditions = &cond
		if !q.Valid(false) {
			return prunePageView{}, invalid("part: items or retained; gc only for the built-in registry")
		}
		v, err := c.RegistryPrune(ctx, tenant, q, req.After, false)
		if err != nil {
			return prunePageView{}, pruneErr(err)
		}
		out := viewPrune(v)
		out.Conditions = webConditions(cond)
		if t := v.Plan.Change.Prune; t != nil {
			out.Preview = previewToken(t.Fact)
		}
		return out, nil
	})
}

func pruneErr(err error) error {
	var me *sfc.Error
	if errors.As(err, &me) && me.Code == sfc.CodeConflict {
		return &httpErr{http.StatusConflict, "preview-expired", "the preview no longer matches the registry or is older than 10 minutes; preview again"}
	}
	return err
}

// POST /t/{t}/registries/{id}/prune {opId, external?, conditions, preview}
// → prune-registry-images with the preview's plan (one job for every item
// and the optional GC). conditions and preview are the ones the preview
// pages gave. Followed like a delete; its items' results are
// GET /t/{t}/registry-maintenance/web-<opId>/items.
func (s *Server) handlePrune(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID       string          `json:"opId"`
		External   bool            `json:"external,omitempty"`
		Conditions pruneConditions `json:"conditions"`
		Preview    string          `json:"preview"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant, id := r.PathValue("t"), r.PathValue("id")
	defer s.images.drop(tenant, id)
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		f, err := readPreviewToken(req.Preview)
		if err != nil {
			return "", nil, 0, "", err
		}
		cond, err := req.Conditions.real()
		if err != nil {
			return "", nil, 0, "", err
		}
		v, err := c.RegistryPrune(ctx, tenant, control.RegistryPruneQuery{ID: id, Part: "items", External: req.External, Conditions: &cond, Fact: f}, "", false)
		if err != nil {
			return "", nil, 0, "", pruneErr(err)
		}
		ch := v.Plan.Change
		ch.Operation = webOperation(req.OpID)
		return control.RegistryPruneAction, rootedPayload{ch, v.Plan.RootRevision}, v.Plan.Expected, "registry/" + id, nil
	})
}

// GET /t/{t}/registry-maintenance/{operation}/items?after= → prunePageView
// (`registry-prune-results`): each item's code and time, as the job
// recorded them.
func (s *Server) handlePruneResults(w http.ResponseWriter, r *http.Request, ws *webSession) {
	tenant, opn := r.PathValue("t"), r.PathValue("operation")
	q := control.RegistryPruneQuery{Operation: opn, Part: "items"}
	if !q.Valid(true) {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "operation")
		return
	}
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (prunePageView, error) {
		v, err := c.RegistryPrune(ctx, tenant, q, r.URL.Query().Get("after"), true)
		if err != nil {
			return prunePageView{}, err
		}
		out := viewPrune(v)
		out.Operation, out.ExpiresAt = opn, ""
		return out, nil
	})
}

func validDigest(d string) bool {
	h, ok := strings.CutPrefix(d, "sha256:")
	if !ok || len(h) != 64 || strings.ToLower(h) != h {
		return false
	}
	_, err := hex.DecodeString(h)
	return err == nil
}
