// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/imagesource"
	"github.com/jay94ks/seafield/internal/registryclient"
)

// REQ-18 in sfcd's real shape: docs/reference/registry-images.md
// (`registry-catalog`), registry-maintenance.md (`registry-maintenance-plan`
// / `-status`, `registry-prune-preview` / `-results`, actions
// delete-registry-image · gc-registry · prune-registry-images) and
// image-usages.md.
//
// Fake-only:
//   - The built-in registry's images are w.img.images (fixture Images). A
//     digest row is listed with each tag row; ManifestBytes 1024, ImageBytes
//     = Bytes, UploadedAt = PushedAt.
//   - An external source lists the images the tenant's apps, standalones
//     and CD candidates use under that source (digest = the same fake
//     manifest digest ResolveImage gives). Live, no upload time.
//   - The owner key of a built-in run is FixtureKey(spec node); of an
//     external source its reader's FixtureKey(node).
//   - Plan RootRevision is the control/registry-maintenance root (fake_roots.go).
//   - Accepted jobs are queued, running after 1 s and settled after 3 s
//     (Fake.FinishRegistryMaintenance settles now, HoldRegistryMaintenance
//     keeps them running).
//   - Task image tags of the built-in registry are pinned to the fixture
//     digest in the reference core ("repo:tag@sha256:…", as sfcd pins at
//     deploy), so only the running digest of a repository is in use.

type maintState struct {
	jobs     []control.RegistryMaintenanceRecord
	extra    map[string]*maintJob // operation → fake progress
	previews map[[32]byte]registryclient.PrunePreview
	hold     bool
}

type maintJob struct {
	accepted int64
	results  []control.RegistryPruneRow
}

func (w *world) maint() *maintState {
	if w.mnt.extra == nil {
		w.mnt.extra, w.mnt.previews = map[string]*maintJob{}, map[[32]byte]registryclient.PrunePreview{}
	}
	return &w.mnt
}

// HoldRegistryMaintenance keeps accepted jobs queued/running until released.
func (f *Fake) HoldRegistryMaintenance(hold bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.w.maint().hold = hold
}

// FinishRegistryMaintenance settles every pending job now.
func (f *Fake) FinishRegistryMaintenance() {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.w.maint()
	m.hold = false
	f.w.settleMaintenance(f.now().Unix(), true)
}

// --- the shared image reference core ---

// imageReferences: what sfcd's ImageReferences returns for the fake: app
// tasks, standalones (app-execution) and CD candidates (cd-candidate).
func (w *world) imageReferences(tenant string) []control.ImageReference {
	var refs []control.ImageReference
	for _, k := range sortedKeys(w.apps) {
		a := w.apps[k]
		if a.view.Tenant != tenant || a.view.Retiring {
			continue
		}
		for _, t := range a.tasks {
			refs = append(refs, control.ImageReference{Tenant: tenant, App: a.view.App, Deployment: a.view.Deployment, Node: t.Node, Service: t.Service, Instance: t.Instance, Image: w.pinnedImage(tenant, t.Image), Kind: "app-execution"})
		}
	}
	for _, k := range sortedKeys(w.standalones) {
		if s := w.standalones[k]; s.view.Tenant == tenant && !s.removed() {
			refs = append(refs, control.ImageReference{Tenant: tenant, App: s.view.Name, Node: s.view.Node, Service: s.view.Name, Image: w.pinnedImage(tenant, s.view.Image), Kind: "app-execution"})
		}
	}
	for _, app := range sortedKeys(w.img.candidates[tenant]) {
		refs = append(refs, control.ImageReference{Tenant: tenant, App: app, Image: w.pinnedImage(tenant, w.img.candidates[tenant][app]), Kind: "cd-candidate"})
	}
	return refs
}

// pinnedImage adds the fixture digest to a built-in registry tag.
func (w *world) pinnedImage(tenant, image string) string {
	n, authority, repo, err := registryclient.Normalize(image)
	if err != nil || strings.Contains(n, "@") || authority != w.builtinEndpoint(tenant) {
		return image
	}
	tag := n[strings.LastIndexByte(n, ':')+1:]
	for _, im := range w.img.images[tenant] {
		if im.Repository == repo && slices.Contains(im.Tags, tag) {
			return n + "@" + im.Digest
		}
	}
	return image
}

func (w *world) imagesInUse(tenant string, images ...string) bool {
	for _, row := range w.imageReferences(tenant) {
		for _, image := range images {
			if row.Unknown || row.MatchImage(image) != "" {
				return true
			}
		}
	}
	return false
}

// --- targets ---

func (w *world) registryRow(tenant, id string) *RegistryView {
	for i := range w.registries {
		if r := &w.registries[i]; r.Tenant == tenant && r.ID == id {
			return r
		}
	}
	return nil
}

func (w *world) registryRun(r *RegistryView) control.RegistryRunRef {
	return control.RegistryRunRef{Generation: r.Generation, SpecRevision: r.Revision, Spec: r.Spec, Owner: pub32(FixtureKey(r.Spec.Node)), Principal: "registry/" + r.Tenant + "/" + r.ID,
		DefinitionDigest: fakeDigest("registry-definition", r.Tenant, r.ID, itoa(r.Revision)), OriginDigest: fakeDigest("registry-origin", r.Tenant, r.ID, itoa(r.Generation))}
}

func registryServing(r *RegistryView) bool {
	return !r.Deleted && r.Spec.Enabled && r.Active && !r.Draining && r.ObservedAt != 0
}

func (w *world) extTarget(x *extSource) control.ExternalRegistryMaintenanceTarget {
	sel := control.ExternalRegistryReadSelection{Tenant: x.spec.Tenant, ID: x.spec.ID, Generation: x.reader.Generation}
	return control.ExternalRegistryMaintenanceTarget{Selection: sel, Spec: imagesource.Own(x.spec), Node: x.reader.Node, Owner: x.reader.Owner, Revision: x.revision,
		ReadSet: fakeDigest("external-readset", x.spec.Tenant, x.spec.ID, itoa(x.reader.Generation))}
}

// maintenanceChange: the plan's Change (Operation "") or the CodeDenied /
// CodeConflict refusal of PlanRegistryMaintenance.
func (w *world) maintenanceChange(tenant string, q control.RegistryMaintenanceQuery, now int64) (control.RegistryMaintenanceChange, Code) {
	change := control.RegistryMaintenanceChange{Tenant: tenant, Repository: q.Repository, Reference: q.Reference, Digest: q.Digest}
	if q.External {
		e := w.extReal()
		e.settle(now)
		x := e.rows[tenant+"/"+q.ID]
		if x == nil || x.deleted {
			return change, CodeDenied
		}
		if !x.spec.Enabled || x.reader == nil || x.reader.Draining {
			return change, CodeConflict
		}
		t := w.extTarget(x)
		change.External = &t
		if q.Repository != "" {
			if _, ok := x.spec.Match(access.Image{Registry: x.spec.Authority, Repository: q.Repository}); !ok {
				return change, CodeDenied
			}
		}
	} else {
		r := w.registryRow(tenant, q.ID)
		if r == nil || r.Deleted || !r.Active {
			return change, CodeDenied
		}
		if !registryServing(r) {
			return change, CodeConflict
		}
		change.Run = w.registryRun(r)
	}
	for _, j := range w.maint().jobs {
		if j.Pending() && j.Change.Tenant == tenant && j.Change.RegistryID() == q.ID && (j.Change.External != nil) == q.External {
			return change, CodeConflict
		}
	}
	return change, ""
}

func (w *world) maintenancePlan(tenant, action string, change control.RegistryMaintenanceChange) control.RegistryMaintenancePlan {
	p := control.RegistryMaintenancePlan{Schema: 1, Cluster: w.cluster, Tenant: tenant, Action: action, Expected: change.ExpectedRevision(), RootRevision: w.keyRoot(control.RegistryMaintenanceKey), Epoch: w.ledgerEpoch, Change: change}
	if action == "delete-registry-image" {
		p.InUse = w.imagesInUse(tenant, deleteRefs(change)...)
	}
	return p
}

func deleteRefs(q control.RegistryMaintenanceChange) []string {
	refs := []string{q.Authority() + "/" + q.Repository + "@" + q.Digest}
	if !strings.HasPrefix(q.Reference, "sha256:") {
		refs = append(refs, q.Authority()+"/"+q.Repository+":"+q.Reference)
	}
	return refs
}

func (c *fakeConn) PlanRegistryMaintenance(ctx context.Context, tenant string, q control.RegistryMaintenanceQuery) (control.RegistryMaintenancePlan, error) {
	const m = "registry-maintenance-plan"
	if tenant == "" || !q.Valid(true) || q.Action == control.RegistryPruneAction {
		return control.RegistryMaintenancePlan{}, fail(m, CodeInvalid, "query")
	}
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return control.RegistryMaintenancePlan{}, err
	}
	defer c.unlock()
	w := c.f.w
	if !w.canManage(user, tenant) {
		return control.RegistryMaintenancePlan{}, fail(m, CodeDenied, "")
	}
	now := c.f.now().Unix()
	w.settleMaintenance(now, false)
	change, code := w.maintenanceChange(tenant, q, now)
	if code != "" {
		return control.RegistryMaintenancePlan{}, fail(m, code, "")
	}
	return w.maintenancePlan(tenant, q.Action, change), nil
}

func (c *fakeConn) RegistryMaintenanceStatus(ctx context.Context, tenant, operation string) (control.RegistryMaintenanceStatus, error) {
	const m = "registry-maintenance-status"
	if !(control.RegistryMaintenanceQuery{Operation: operation}).Valid(false) {
		return control.RegistryMaintenanceStatus{}, fail(m, CodeInvalid, "operation")
	}
	if err := c.appRead(ctx, m, tenant); err != nil {
		return control.RegistryMaintenanceStatus{}, err
	}
	defer c.unlock()
	w := c.f.w
	w.settleMaintenance(c.f.now().Unix(), false)
	row, ok := (control.RegistryMaintenanceJobs{Records: w.maint().jobs}).Record(operation)
	if !ok || row.Change.Tenant != tenant {
		return control.RegistryMaintenanceStatus{}, fail(m, CodeDenied, "")
	}
	return control.RegistryMaintenanceStatus{Schema: 1, Tenant: tenant, Operation: operation, Action: row.Origin.Change.Action, User: row.Origin.Session.User, State: row.State,
		Revision: row.Revision, RootRevision: w.keyRoot(control.RegistryMaintenanceKey), At: row.At, Change: row.Change, Result: row.Result}, nil
}

// maintenanceSummary: registry list's Maintenance.
func (w *world) maintenanceSummary(tenant, id string) *control.RegistryMaintenanceSummary {
	return (control.RegistryMaintenanceJobs{Records: w.maint().jobs}).Summary(tenant, id)
}

// --- registry-catalog ---

// managedImages: every reference row of a registry, sorted by
// repository then reference.
func (w *world) managedImages(tenant, id string) []registryclient.ImageMetadata {
	var out []registryclient.ImageMetadata
	for _, im := range w.img.images[tenant] {
		if im.Registry != id {
			continue
		}
		row := registryclient.ImageMetadata{Repository: im.Repository, Reference: im.Digest, Digest: im.Digest, MediaType: fakeImageManifestType, ManifestBytes: 1024, ImageBytes: int64(im.Bytes)}
		if im.PushedAt > 0 {
			row.UploadedAt, row.UploadedAtKnown = uint64(im.PushedAt)*1000, true
		}
		out = append(out, row)
		for _, tag := range im.Tags {
			row.Reference = tag
			out = append(out, row)
		}
	}
	sortMetadata(out)
	return out
}

func sortMetadata(rows []registryclient.ImageMetadata) {
	slices.SortFunc(rows, func(a, b registryclient.ImageMetadata) int {
		return strings.Compare(a.Repository+"\x00"+a.Reference, b.Repository+"\x00"+b.Reference)
	})
}

func (w *world) externalImages(tenant string, x *extSource) []registryclient.ImageMetadata {
	defs := w.extDefinitions(tenant)
	seen := map[string]bool{}
	var out []registryclient.ImageMetadata
	for _, r := range w.imageReferences(tenant) {
		n, authority, repo, err := registryclient.Normalize(r.Image)
		if err != nil || authority != x.spec.Authority || strings.Contains(n, "@") {
			continue
		}
		if d, err := imagesource.Lookup(defs, tenant, access.Image{Registry: authority, Repository: repo}); err != nil || d == nil || d.Spec.ID != x.spec.ID {
			continue
		}
		tag := n[strings.LastIndexByte(n, ':')+1:]
		if seen[repo+":"+tag] {
			continue
		}
		seen[repo+":"+tag] = true
		d := fakeDigest("manifest", n)
		out = append(out, registryclient.ImageMetadata{Repository: repo, Reference: tag, Digest: "sha256:" + hex.EncodeToString(d[:]), MediaType: fakeImageManifestType, ManifestBytes: 1024, ImageBytes: 48 << 20})
	}
	sortMetadata(out)
	return out
}

func (w *world) extDefinitions(tenant string) []imagesource.Definition {
	e := w.extReal()
	var defs []imagesource.Definition
	for _, k := range sortedKeys(e.rows) {
		if x := e.rows[k]; x.spec.Tenant == tenant {
			defs = append(defs, imagesource.Definition{Spec: imagesource.Own(x.spec), Deleted: x.deleted})
		}
	}
	return defs
}

// extReadCode: the code an external read gets from the fake source.
func (w *world) extReadCode(x *extSource) string {
	switch {
	case w.loginResult[x.spec.Authority] != "" && w.loginResult[x.spec.Authority] != "ok":
		return realLoginCode(w.loginResult[x.spec.Authority])
	case strings.Contains(x.spec.Authority, "unreachable"):
		return "UNAVAILABLE"
	case x.spec.Credential != nil && !w.extCredentialOK(*x.spec.Credential):
		return "INVALID_CREDENTIAL"
	}
	return "OK"
}

func (c *fakeConn) RegistryCatalogue(ctx context.Context, tenant string, q control.RegistryCatalogueQuery, after string) (control.RegistryCatalogueResult, error) {
	const m = "registry-catalog"
	if _, _, err := registryclient.CatalogueCursor(after); err != nil || !q.Valid() {
		return control.RegistryCatalogueResult{}, fail(m, CodeInvalid, "query")
	}
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return control.RegistryCatalogueResult{}, err
	}
	defer c.unlock()
	w := c.f.w
	if !w.canRead(user, tenant) {
		return control.RegistryCatalogueResult{}, fail(m, CodeDenied, "")
	}
	out := control.RegistryCatalogueResult{Kind: q.Kind, ID: q.ID}
	var authority string
	var rows []registryclient.ImageMetadata
	code := "OK"
	if q.Kind == "managed" {
		r := w.registryRow(tenant, q.ID)
		if r == nil || r.Deleted {
			return out, fail(m, CodeDenied, "")
		}
		if !registryServing(r) {
			return out, fail(m, CodeConflict, "registry is not serving")
		}
		authority, rows = r.Spec.Authority, w.managedImages(tenant, q.ID)
	} else {
		e := w.extReal()
		e.settle(c.f.now().Unix())
		x := e.rows[tenant+"/"+q.ID]
		if x == nil || x.deleted {
			return out, fail(m, CodeDenied, "")
		}
		if !x.spec.Enabled || x.reader == nil || x.reader.Draining {
			return out, fail(m, CodeConflict, "bind the source to a server first")
		}
		if q.Repository != "" {
			if _, ok := x.spec.Match(access.Image{Registry: x.spec.Authority, Repository: q.Repository}); !ok {
				return out, fail(m, CodeDenied, "")
			}
		}
		authority, code = x.spec.Authority, w.extReadCode(x)
		rows = w.externalImages(tenant, x)
	}
	page := registryclient.CataloguePage{Schema: 1, Authority: authority, Repository: q.Repository, Code: code}
	if code == "OK" {
		var names []string
		entries := map[string]registryclient.ImageMetadata{}
		for _, r := range rows {
			switch {
			case q.Repository == "" && !slices.Contains(names, r.Repository):
				names = append(names, r.Repository)
			case q.Repository != "" && r.Repository == q.Repository:
				names = append(names, r.Reference)
				entries[r.Reference] = r
			}
		}
		if q.Repository != "" && len(names) == 0 {
			page.Code = "NOT_FOUND"
		} else {
			basis := fakeDigest("registry-catalogue", tenant, user, q.Kind, q.ID)
			p, selected, err := registryclient.CatalogueRange(authority, q.Repository, basis, names, entries, after)
			if errors.Is(err, registryclient.ErrCatalogueChanged) {
				return out, fail(m, CodeConflict, "catalogue changed: read again")
			}
			if err != nil {
				return out, fail(m, CodeInvalid, "after")
			}
			page = p
			for _, name := range selected {
				if q.Repository == "" {
					page.Repositories = append(page.Repositories, name)
				} else {
					page.Images = append(page.Images, entries[name])
				}
			}
		}
	}
	page.Live, page.UntaggedComplete = q.Kind == "external", q.Kind == "managed"
	if page.Code != "OK" {
		page.Live, page.UntaggedComplete = false, false
	}
	out.Page = page
	return out, nil
}

// --- registry-prune-preview / -results ---

func (w *world) pruneInventory(tenant string, change control.RegistryMaintenanceChange) (registryclient.PruneInventory, error) {
	in := registryclient.PruneInventory{Schema: 1, Authority: change.Authority()}
	if change.External != nil {
		e := w.extReal()
		x := e.rows[tenant+"/"+change.RegistryID()]
		if code := w.extReadCode(x); code != "OK" {
			return in, errors.New(code)
		}
		in.Live, in.Images = true, w.externalImages(tenant, x)
	} else {
		in.UntaggedComplete, in.PhysicalComplete = true, true
		in.Images = w.managedImages(tenant, change.RegistryID())
		for _, im := range w.img.images[tenant] {
			if im.Registry == change.RegistryID() {
				layer := fakeDigest("layer", im.Repository, im.Digest)
				in.Blobs = append(in.Blobs, registryclient.PruneBlob{Repository: im.Repository, Manifest: im.Digest, Digest: "sha256:" + hex.EncodeToString(layer[:]), Size: int64(im.Bytes)})
			}
		}
	}
	refs := w.imageReferences(tenant)
	seen := map[string]bool{}
	for _, im := range in.Images {
		key := im.Repository + "@" + im.Digest
		if seen[key] {
			continue
		}
		seen[key] = true
		ref := in.Authority + "/" + key
		for _, row := range refs {
			if row.Unknown || row.MatchImage(ref) != "" {
				in.Protected = append(in.Protected, registryclient.PruneProtection{Repository: im.Repository, Digest: im.Digest, Code: "IMAGE_IN_USE"})
				break
			}
		}
	}
	return in, nil
}

func (c *fakeConn) RegistryPrune(ctx context.Context, tenant string, q control.RegistryPruneQuery, after string, results bool) (control.RegistryPruneView, error) {
	m := "registry-prune-preview"
	if results {
		m = "registry-prune-results"
	}
	if tenant == "" || !q.Valid(results) || len(after) > 512 {
		return control.RegistryPruneView{}, fail(m, CodeInvalid, "query")
	}
	if _, _, err := registryclient.CatalogueCursor(after); err != nil {
		return control.RegistryPruneView{}, fail(m, CodeInvalid, "after")
	}
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return control.RegistryPruneView{}, err
	}
	defer c.unlock()
	w := c.f.w
	now := c.f.now().Unix()
	w.settleMaintenance(now, false)
	if results {
		return w.pruneResults(m, user, tenant, q, after)
	}
	if !w.canManage(user, tenant) {
		return control.RegistryPruneView{}, fail(m, CodeDenied, "")
	}
	change, code := w.maintenanceChange(tenant, control.RegistryMaintenanceQuery{Action: control.RegistryPruneAction, ID: q.ID, External: q.External}, now)
	if code != "" {
		return control.RegistryPruneView{}, fail(m, code, "")
	}
	base := w.maintenancePlan(tenant, control.RegistryPruneAction, change)
	var preview registryclient.PrunePreview
	var fact control.RegistryPruneFact
	if q.Fact != nil {
		if !q.Fact.Valid(w.cluster, change, *q.Conditions) || uint64(now) < q.Fact.At || uint64(now)-q.Fact.At > control.RegistryPrunePreviewSeconds {
			return control.RegistryPruneView{}, fail(m, CodeConflict, "preview expired or changed: preview again")
		}
		p, ok := w.maint().previews[q.Fact.Preview]
		if !ok {
			return control.RegistryPruneView{}, fail(m, CodeConflict, "preview expired: preview again")
		}
		preview, fact = p, *q.Fact
	} else {
		if after != "" {
			return control.RegistryPruneView{}, fail(m, CodeInvalid, "after without Fact")
		}
		in, err := w.pruneInventory(tenant, change)
		if err != nil {
			return control.RegistryPruneView{}, fail(m, CodeUnavailable, err.Error())
		}
		preview, err = registryclient.BuildPrunePreview(in, *q.Conditions)
		if err != nil {
			var re *registryclient.Error
			if errors.As(err, &re) && re.Code == "UNSUPPORTED" {
				return control.RegistryPruneView{}, fail(m, CodeUnsupported, "IncludeUntagged needs a complete listing")
			}
			return control.RegistryPruneView{}, fail(m, CodeUnavailable, "preview")
		}
		w.maint().previews[preview.Digest()] = preview
		owner := FixtureKey(change.NodeID())
		fact = control.RegistryPruneFact{Schema: 1, Cluster: w.cluster, Owner: change.OwnerKey(), Target: change.PruneBase().DigestValue(), Conditions: control.PruneConditionsDigest(preview.Conditions), Preview: preview.Digest(),
			Tenant: tenant, Registry: change.RegistryID(), External: change.External != nil, Items: uint32(len(preview.Items)), Retained: uint32(len(preview.Retained)),
			ImageBytes: preview.ImageBytes, EstimatedReclaimedBytes: preview.EstimatedReclaimedBytes, EstimateKnown: preview.EstimateKnown, Live: preview.Live, At: uint64(now)}
		fact.Public = control.RegistryPrunePreviewPublicDigest(preview)
		fact.Signature = ed25519.Sign(owner, control.RegistryPruneFactBytes(fact))
	}
	base.Change.Prune = &control.RegistryPruneTarget{Conditions: preview.Conditions, Fact: fact}
	count := len(preview.Items)
	if q.Part == "retained" {
		count = len(preview.Retained)
	}
	start, end, next, err := registryclient.PrunePageRange(q.Part, fact.Preview, uint32(count), after)
	if err != nil {
		return control.RegistryPruneView{}, fail(m, CodeConflict, "preview changed: read again")
	}
	out := control.RegistryPruneView{Schema: 1, Tenant: tenant, Plan: base, Page: control.RegistryPrunePage{Schema: 1, Root: fact.Preview, Part: q.Part, Total: uint32(count), Next: next}}
	if q.Part == "items" {
		for _, item := range preview.Items[start:end] {
			out.Page.Rows = append(out.Page.Rows, control.PrunePublicItem(item))
		}
	} else {
		out.Page.Retained = slices.Clone(preview.Retained[start:end])
	}
	return out, nil
}

func (w *world) pruneResults(m, user, tenant string, q control.RegistryPruneQuery, after string) (control.RegistryPruneView, error) {
	if !w.canRead(user, tenant) {
		return control.RegistryPruneView{}, fail(m, CodeDenied, "")
	}
	row, ok := (control.RegistryMaintenanceJobs{Records: w.maint().jobs}).Record(q.Operation)
	if !ok || row.Change.Tenant != tenant || row.Change.Prune == nil {
		return control.RegistryPruneView{}, fail(m, CodeDenied, "")
	}
	rows := w.maint().extra[q.Operation].results
	root := control.RegistryPruneResultRoot(row.Change.PruneBase().DigestValue(), uint32(len(rows)), row.Result)
	start, end, next, err := registryclient.PruneResultRange(root, uint32(len(rows)), after)
	if err != nil {
		return control.RegistryPruneView{}, fail(m, CodeConflict, "results changed: read again")
	}
	plan := control.RegistryMaintenancePlan{Schema: 1, Cluster: w.cluster, Tenant: tenant, Action: control.RegistryPruneAction, Expected: row.Change.ExpectedRevision(), RootRevision: w.keyRoot(control.RegistryMaintenanceKey), Epoch: w.ledgerEpoch, Change: row.Change}
	return control.RegistryPruneView{Schema: 1, Tenant: tenant, Plan: plan,
		Page: control.RegistryPrunePage{Schema: 1, Root: root, Part: "items", Total: uint32(len(rows)), Processed: uint32(len(rows)), Rows: slices.Clone(rows[start:end]), Next: next}}, nil
}

// --- actions ---

func (c *fakeConn) applyRegistryMaintenance(op UserOperation, actor string) error {
	w := c.f.w
	action := op.Change.Action
	var q control.RegistryMaintenanceChange
	if decodePayload(op.Change.Payload, &q) != nil || !q.Valid(w.cluster, action) || op.Change.Expected != q.ExpectedRevision() {
		return errors.New("payload")
	}
	if !w.canManage(actor, q.Tenant) {
		return errForbidden
	}
	now := c.f.now().Unix()
	w.settleMaintenance(now, false)
	current, code := w.maintenanceChange(q.Tenant, q.Query(action), now)
	if code != "" {
		return errCAS
	}
	current.Operation, current.Prune = q.Operation, q.Prune
	a, _ := json.Marshal(current)
	b, _ := json.Marshal(q)
	if string(a) != string(b) {
		return errCAS
	}
	mt := w.maint()
	if _, dup := mt.extra[q.Operation]; dup || len(mt.jobs) >= 128 {
		return errCAS
	}
	if q.Prune != nil {
		if uint64(now) < q.Prune.Fact.At || uint64(now)-q.Prune.Fact.At > control.RegistryPrunePreviewSeconds {
			return errCAS
		}
		for _, j := range mt.jobs {
			if j.Pending() && j.Change.Authority() == q.Authority() && (j.Change.Prune != nil || j.Origin.Change.Action == "gc-registry") {
				return errCAS
			}
		}
	}
	mt.jobs = append(mt.jobs, control.RegistryMaintenanceRecord{Origin: op, Change: q, State: "queued", Revision: 1, At: uint64(now)})
	mt.extra[q.Operation] = &maintJob{accepted: now}
	return nil
}

func (w *world) settleMaintenance(now int64, all bool) {
	mt := w.maint()
	for i := range mt.jobs {
		j := &mt.jobs[i]
		x := mt.extra[j.Change.Operation]
		if !j.Pending() || mt.hold && !all {
			continue
		}
		if all || now-x.accepted >= 3 {
			j.Result = w.runMaintenance(j, x, now)
			j.State = "failed"
			if j.Result.Code == "OK" || j.Result.Code == "ALREADY_ABSENT" {
				j.State = "done"
			}
			j.Revision++
			j.At = uint64(now)
			w.bumpKey(control.RegistryMaintenanceKey)
		} else if now-x.accepted >= 1 && j.State == "queued" {
			j.State, j.At = "running", uint64(now)
			j.Revision++
		}
	}
}

func (w *world) runMaintenance(j *control.RegistryMaintenanceRecord, x *maintJob, now int64) *control.RegistryMaintenanceResult {
	q := j.Change
	at := uint64(now) * 1000
	native := fakeDigest("registry-native", q.Operation)
	switch j.Origin.Change.Action {
	case "gc-registry":
		reclaimed := int64(w.img.unref[q.Tenant])
		w.img.unref[q.Tenant] = 0
		return &control.RegistryMaintenanceResult{Code: "OK", At: at, ReclaimedBytes: reclaimed, Native: native}
	case "delete-registry-image":
		code := w.deleteImage(q, q.Repository, q.Reference, q.Digest, nil)
		r := &control.RegistryMaintenanceResult{Code: code, At: at}
		if code == "OK" || code == "ALREADY_ABSENT" {
			r.Native = native
		}
		return r
	}
	// prune-registry-images
	preview, ok := w.maint().previews[q.Prune.Fact.Preview]
	sum := &control.RegistryPruneSummary{}
	if !ok {
		return &control.RegistryMaintenanceResult{Code: "PREVIEW_UNAVAILABLE", At: at, Prune: sum}
	}
	for _, item := range preview.Items {
		var aliases []string
		if strings.HasPrefix(item.Image.Reference, "sha256:") {
			aliases = sortedCopy(item.Tags)
		}
		code := w.deleteImage(q, item.Image.Repository, item.Image.Reference, item.Image.Digest, aliases)
		row := control.PrunePublicItem(item)
		row.Code, row.At = code, at
		sum.Processed++
		switch {
		case control.PruneResultSuccess(code):
			sum.Deleted++
			row.Native = fakeDigest("registry-native", q.Operation, row.ID)
		case control.PruneResultSkipped(code):
			sum.Skipped++
		default:
			sum.Failed++
		}
		x.results = append(x.results, row)
	}
	r := &control.RegistryMaintenanceResult{Code: "OK", At: at, Native: native, Prune: sum}
	if q.Prune.Conditions.GC {
		r.ReclaimedBytes = int64(w.img.unref[q.Tenant])
		w.img.unref[q.Tenant] = 0
		sum.GCCode, sum.GCAt = "OK", at
	}
	if sum.Failed > 0 {
		r.Code = "PARTIAL"
	}
	return r
}

// deleteImage removes a tag (tag reference) or a digest with its tags
// (digest reference; aliases, when given, must still be its tag set).
func (w *world) deleteImage(q control.RegistryMaintenanceChange, repo, ref, digest string, aliases []string) string {
	tenant := q.Tenant
	refs := deleteRefs(control.RegistryMaintenanceChange{Run: q.Run, External: q.External, Repository: repo, Reference: ref, Digest: digest})
	if q.External != nil {
		switch {
		case !strings.HasPrefix(ref, "sha256:"):
			return "UNSUPPORTED"
		case w.imagesInUse(tenant, refs...):
			return "IMAGE_IN_USE"
		}
		x := w.extReal().rows[tenant+"/"+q.RegistryID()]
		if x == nil || x.reader == nil {
			return "UNAVAILABLE"
		}
		if code := w.extReadCode(x); code != "OK" {
			if code == "UNAUTHORIZED" {
				return "DENIED"
			}
			return code
		}
		return "OK"
	}
	imgs := w.img.images[tenant]
	i := slices.IndexFunc(imgs, func(im RegistryImage) bool {
		return im.Registry == q.RegistryID() && im.Repository == repo && (im.Digest == ref || slices.Contains(im.Tags, ref))
	})
	if i < 0 {
		return "ALREADY_ABSENT"
	}
	im := &imgs[i]
	if im.Digest != digest || aliases != nil && !slices.Equal(sortedCopy(im.Tags), aliases) {
		return "REFERENCE_CHANGED"
	}
	if w.imagesInUse(tenant, refs...) {
		return "IMAGE_IN_USE"
	}
	if strings.HasPrefix(ref, "sha256:") {
		w.img.unref[tenant] += im.Bytes * 7 / 10
		w.img.images[tenant] = slices.Delete(imgs, i, i+1)
	} else {
		im.Tags = slices.DeleteFunc(slices.Clone(im.Tags), func(t string) bool { return t == ref })
	}
	return "OK"
}

func sortedCopy(s []string) []string {
	s = slices.Clone(s)
	slices.Sort(s)
	if s == nil {
		s = []string{}
	}
	return s
}
