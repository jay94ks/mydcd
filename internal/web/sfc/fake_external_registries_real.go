// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/imagecache"
	"github.com/jay94ks/seafield/internal/imagesource"
	"github.com/jay94ks/seafield/internal/observability"
	"github.com/jay94ks/seafield/internal/registryclient"
	"github.com/jay94ks/seafield/internal/secrets"
)

// REQ-17 in sfcd's real shape (docs/reference/external-registries.md):
// imagesource.Source definitions with a record Revision (put/delete/bind/
// unbind each +1), a reader bound to one server (bind-external-registry,
// with the vault Group approvals of its secrets), registry-login-test
// through that reader, external-registry-pulls and image-usages with the
// ExternalSource selector. The state is w.ext, seeded from
// Fixture.ExternalRegistries.
//
// A draining reader (unbind, put, delete) is closed by its owner a few
// seconds later (Fake.CloseExternalRegistryReaders closes them at once);
// bind needs no reader.

const extReaderCloseSeconds = 5

type extSource struct {
	spec     imagesource.Source
	revision uint64
	deleted  bool
	reader   *control.ExternalRegistryReaderView
	drainAt  int64
}

type extPull struct {
	row  observability.RegistryPull
	node string
}

type extRealState struct {
	seeded bool
	root   uint64                // ExternalRegistriesRootRevision
	rows   map[string]*extSource // tenant/id
	pulls  map[string]extPull    // tenant/authority/node
	seq    uint64
}

func (w *world) extReal() *extRealState {
	e := &w.ext
	if e.seeded {
		return e
	}
	e.seeded, e.root, e.rows, e.pulls = true, 1, map[string]*extSource{}, map[string]extPull{}
	for _, r := range w.extSeed {
		if r.Source.Validate() != nil {
			continue
		}
		x := &extSource{spec: imagesource.Own(r.Source), revision: 1}
		if r.Bound != "" { // put (1) then bind (2)
			x.revision = 2
			x.reader = &control.ExternalRegistryReaderView{Node: r.Bound, Owner: pub32(FixtureKey(r.Bound)), Generation: 2}
		}
		e.rows[r.Source.Key()] = x
		if r.PullNode != "" {
			e.seq++
			e.pulls[r.Source.Tenant+"/"+r.Source.Authority+"/"+r.PullNode] = extPull{node: r.PullNode, row: observability.RegistryPull{Tenant: r.Source.Tenant, Authority: r.Source.Authority,
				Source: r.Source.ID, Stage: "load", Code: "OK", CompletedAt: uint64(r.PullAt) * 1000, Sequence: e.seq}}
		}
	}
	return e
}

// realLoginCode maps the old lower-case codes Fake.SetRegistryLoginResult
// may get to the real bounded vocabulary.
func realLoginCode(code string) string {
	switch code {
	case "ok":
		return "OK"
	case "unauthorized":
		return "UNAUTHORIZED"
	case "forbidden":
		return "DENIED"
	case "unreachable":
		return "UNAVAILABLE"
	case "secret-unavailable":
		return "INVALID_CREDENTIAL"
	}
	return code
}

// settle closes draining readers whose owner had time to stop.
func (e *extRealState) settle(now int64) {
	for _, x := range e.rows {
		if x.reader != nil && x.reader.Draining && now >= x.drainAt+extReaderCloseSeconds {
			x.reader = nil
			e.root++
		}
	}
}

// CloseExternalRegistryReaders: every draining reader's owner reports its
// closure now.
func (f *Fake) CloseExternalRegistryReaders() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.w.extReal().settle(1 << 62)
}

func (c *fakeConn) ExternalRegistryPage(ctx context.Context, tenant, after string) (ExternalRegistryPage, error) {
	const m = "external-registries"
	if len(after) > 512 {
		return ExternalRegistryPage{}, fail(m, CodeInvalid, "after")
	}
	if err := c.appRead(ctx, m, tenant); err != nil {
		return ExternalRegistryPage{}, err
	}
	defer c.unlock()
	e := c.f.w.extReal()
	e.settle(c.f.now().Unix())
	out := ExternalRegistryPage{RootRevision: e.root}
	for _, k := range sortedKeys(e.rows) {
		x := e.rows[k]
		if x.spec.Tenant != tenant || k <= after {
			continue
		}
		if len(out.Items) == 8 {
			out.Next = out.Items[7].Spec.Key()
			break
		}
		v := control.ExternalRegistryView{Spec: imagesource.Own(x.spec), Revision: x.revision, Deleted: x.deleted}
		if x.reader != nil {
			r := *x.reader
			v.Reader = &r
		}
		out.Items = append(out.Items, v)
	}
	return out, nil
}

// extUses: sfcd's externalRegistryUses for a reader of spec on node.
func extUses(spec imagesource.Source, user string, key [32]byte, node string) map[string][]secrets.Use {
	scope := control.ExternalRegistryScope(spec.Tenant, spec.ID)
	uses := map[string][]secrets.Use{}
	for _, ref := range spec.References() {
		rows := uses[ref.Realm]
		if len(rows) == 0 {
			rows = []secrets.Use{{Purpose: secrets.PurposeRegistrySource, Tenant: spec.Tenant, User: user, App: scope, Deployment: scope, Service: "registry", Node: node,
				NodeKey: pub32(FixtureKey(node)), RequesterKey: key}}
		}
		rows[0].Sources = append(rows[0].Sources, ref.ID)
		uses[ref.Realm] = rows
	}
	return uses
}

func (c *fakeConn) PlanExternalRegistryBind(ctx context.Context, tenant string, q control.ExternalRegistryBindQuery) (control.ExternalRegistryBindPlan, error) {
	const m = "external-registry-bind-plan"
	if !q.Valid() || tenant == "" {
		return control.ExternalRegistryBindPlan{}, fail(m, CodeInvalid, "query")
	}
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return control.ExternalRegistryBindPlan{}, err
	}
	defer c.unlock()
	w := c.f.w
	if !w.canManage(user, tenant) || !w.nodeAllowed(tenant, q.Node) {
		return control.ExternalRegistryBindPlan{}, fail(m, CodeDenied, "")
	}
	e := w.extReal()
	e.settle(c.f.now().Unix())
	x := e.rows[tenant+"/"+q.ID]
	if x == nil {
		return control.ExternalRegistryBindPlan{}, fail(m, CodeDenied, "")
	}
	if x.deleted || !x.spec.Enabled || x.reader != nil {
		return control.ExternalRegistryBindPlan{}, fail(m, CodeConflict, "unbound, enabled source only")
	}
	return control.ExternalRegistryBindPlan{Schema: 1, Cluster: w.cluster, Selection: control.ExternalRegistryBind{Tenant: tenant, ID: q.ID, Node: q.Node, Definition: control.ExternalRegistryDefinition(x.spec)},
		Spec: imagesource.Own(x.spec), Expected: x.revision, RootRevision: e.root, Epoch: 1, Uses: extUses(x.spec, user, c.session.Key, q.Node)}, nil
}

// extOriginUses: a bind-external-registry original's protected Groups (for
// vault-approval-plan / ApproveVault), as originUses for apps.
func (w *world) extOriginUses(origin *UserOperation, sel *AppApprovalSelection) (control.AppBegin, map[string][]string, map[string]string, bool) {
	var q control.ExternalRegistryBind
	if sel != nil || json.Unmarshal(origin.Change.Payload, &q) != nil || q.Tenant == "" || q.ID == "" || q.Node == "" {
		return control.AppBegin{}, nil, nil, false
	}
	x := w.extReal().rows[q.Tenant+"/"+q.ID]
	if x == nil || x.deleted || origin.Change.Expected != x.revision || control.ExternalRegistryDefinition(x.spec) != q.Definition {
		return control.AppBegin{}, nil, nil, false
	}
	scope := control.ExternalRegistryScope(q.Tenant, q.ID)
	b := control.AppBegin{Tenant: q.Tenant, App: scope, Deployment: scope, DefaultNode: q.Node}
	uses := map[string][]string{}
	for _, ref := range x.spec.References() {
		if ref.Realm != q.Tenant {
			continue
		}
		v := w.vaultObject(ref.Realm, ref.ID)
		if v == nil {
			continue
		}
		for _, g := range append([]string{v.Group}, w.vaultAncestors(ref.Realm, v.Parent)...) {
			if _, ok := w.groupVerifiers[ref.Realm+"/"+g]; ok && g != "" {
				uses[g] = []string{"registry"}
			}
		}
	}
	return b, uses, map[string]string{"registry": q.Node}, true
}

// applyRealExternalRegistry: put {Spec}, delete/unbind {Tenant, ID}, bind
// {Tenant, ID, Node, Definition}; Expected = the record Revision.
func (c *fakeConn) applyRealExternalRegistry(op UserOperation, actor string) error {
	w := c.f.w
	e := w.extReal()
	now := c.f.now().Unix()
	e.settle(now)
	ch := op.Change
	var sel control.RegistrySelection
	var put control.ExternalRegistryPut
	var bind control.ExternalRegistryBind
	switch ch.Action {
	case ActionPutExternalRegistry:
		if decodePayload(ch.Payload, &put) != nil || put.Spec.Validate() != nil {
			return errors.New("payload")
		}
		host, _, _ := strings.Cut(put.Spec.Authority, ":")
		if host == builtinRegistryHost {
			return errors.New("payload: built-in registry")
		}
		sel = control.RegistrySelection{Tenant: put.Spec.Tenant, ID: put.Spec.ID}
	case ActionBindExternalRegistry:
		if decodePayload(ch.Payload, &bind) != nil || bind.Tenant == "" || bind.ID == "" || bind.Node == "" || bind.Definition == ([32]byte{}) {
			return errors.New("payload")
		}
		if !w.nodeAllowed(bind.Tenant, bind.Node) {
			return errForbidden
		}
		sel = control.RegistrySelection{Tenant: bind.Tenant, ID: bind.ID}
	default:
		if decodePayload(ch.Payload, &sel) != nil || sel.Tenant == "" || sel.ID == "" {
			return errors.New("payload")
		}
	}
	if !w.canManage(actor, sel.Tenant) {
		return errForbidden
	}
	key := sel.Tenant + "/" + sel.ID
	x := e.rows[key]
	have := uint64(0)
	if x != nil {
		have = x.revision
	}
	if have != ch.Expected {
		return errCAS
	}
	drain := func() {
		if x.reader != nil && !x.reader.Draining {
			x.reader.Draining, x.drainAt = true, now
		}
	}
	switch ch.Action {
	case ActionPutExternalRegistry:
		if x != nil && (x.spec.Authority != put.Spec.Authority || x.spec.Repository != put.Spec.Repository) {
			return errCAS // the scope is fixed: a new scope is a new ID
		}
		for k, o := range e.rows {
			if k != key && o.spec.Tenant == put.Spec.Tenant && o.spec.Authority == put.Spec.Authority && o.spec.Repository == put.Spec.Repository {
				return errCAS
			}
		}
		if x == nil {
			if len(e.rows) >= 256 {
				return errCAS
			}
			x = &extSource{}
			e.rows[key] = x
		}
		drain()
		x.spec, x.deleted = imagesource.Own(put.Spec), false
	case ActionDeleteExternalRegistry:
		if x == nil || x.deleted {
			return errCAS
		}
		x.deleted = true
		drain()
	case ActionUnbindExternalRegistry:
		if x == nil || x.deleted || x.reader == nil || x.reader.Draining {
			return errCAS
		}
		drain()
	case ActionBindExternalRegistry:
		if x == nil || x.deleted || !x.spec.Enabled || x.reader != nil || bind.Definition != control.ExternalRegistryDefinition(x.spec) {
			return errCAS
		}
		if len(w.missingApprovals(op)) > 0 {
			return errCAS // sfcd's Acquire finds no committed approval
		}
		x.reader = &control.ExternalRegistryReaderView{Node: bind.Node, Owner: pub32(FixtureKey(bind.Node)), Generation: x.revision + 1}
	}
	x.revision++
	e.root++
	return nil
}

func (c *fakeConn) ProbeExternalRegistry(ctx context.Context, tenant string, q control.ExternalRegistryProbeQuery) (control.ExternalRegistryProbeResult, error) {
	const m = "registry-login-test"
	if tenant == "" || !q.Valid() {
		return control.ExternalRegistryProbeResult{}, fail(m, CodeInvalid, "query")
	}
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return control.ExternalRegistryProbeResult{}, err
	}
	defer c.unlock()
	w := c.f.w
	if !w.canManage(user, tenant) {
		return control.ExternalRegistryProbeResult{}, fail(m, CodeDenied, "")
	}
	e := w.extReal()
	now := c.f.now().Unix()
	e.settle(now)
	x := e.rows[tenant+"/"+q.ID]
	if x == nil {
		return control.ExternalRegistryProbeResult{}, fail(m, CodeDenied, "")
	}
	if x.deleted || !x.spec.Enabled || x.reader == nil || x.reader.Draining {
		return control.ExternalRegistryProbeResult{}, fail(m, CodeConflict, "bind the source to a server first")
	}
	var normalized, authority, repository string
	if q.Image != "" {
		normalized, authority, repository, _ = registryclient.Normalize(q.Image)
		if _, ok := x.spec.Match(access.Image{Registry: authority, Repository: repository}); !ok {
			return control.ExternalRegistryProbeResult{}, fail(m, CodeDenied, "image is outside this source")
		}
	}
	out := control.ExternalRegistryProbeResult{Selection: control.ExternalRegistryReadSelection{Tenant: tenant, ID: q.ID, Generation: x.reader.Generation}, Owner: x.reader.Owner, At: now}
	switch {
	case w.loginResult[x.spec.Authority] != "":
		out.Code = realLoginCode(w.loginResult[x.spec.Authority])
	case strings.Contains(x.spec.Authority, "unreachable"):
		out.Code = "UNAVAILABLE"
	case x.spec.Credential != nil && !w.extCredentialOK(*x.spec.Credential):
		out.Code = "INVALID_CREDENTIAL"
	default:
		out.Code = "OK"
	}
	if out.Code == "OK" && q.Image != "" {
		digest := "sha256:" + hex.EncodeToString(func() []byte { d := fakeDigest("manifest", normalized); return d[:] }())
		if i := strings.LastIndex(normalized, "@"); i >= 0 {
			digest = normalized[i+1:]
		}
		out.Image = &registryclient.Resolution{Normalized: normalized, Registry: authority, Repository: repository, Pinned: authority + "/" + repository + "@" + digest, Digest: digest,
			MediaType: "application/vnd.oci.image.manifest.v1+json", ManifestBytes: 1024}
		out.Pull = &registryclient.PullCheck{ManifestDigest: digest, Platform: v1.Platform{OS: "linux", Architecture: "amd64"}, Blobs: 3, CompressedBytes: 24 << 20}
	}
	return out, nil
}

func (w *world) extCredentialOK(cr imagesource.Credential) bool {
	v := w.vaultObject(cr.Realm, cr.ID)
	return v != nil && (v.Status == "" || v.Status == "active") && slices.Contains(v.Keys, cr.UsernameKey) && slices.Contains(v.Keys, cr.PasswordKey)
}

// RegistryPulls: `external-registry-pulls`, the latest real pull per
// authority × node (tenant Read), 8 a page.
func (c *fakeConn) RegistryPulls(ctx context.Context, tenant, after string) (control.RegistryPullPage, error) {
	const m = "external-registry-pulls"
	if len(after) > 512 {
		return control.RegistryPullPage{}, fail(m, CodeInvalid, "after")
	}
	if err := c.appRead(ctx, m, tenant); err != nil {
		return control.RegistryPullPage{}, err
	}
	defer c.unlock()
	e := c.f.w.extReal()
	var rows []control.RegistryPullView
	for _, k := range sortedKeys(e.pulls) {
		p := e.pulls[k]
		if p.row.Tenant == tenant {
			rows = append(rows, control.RegistryPullView{RegistryPull: p.row, Node: p.node, ReportedAt: p.row.CompletedAt})
		}
	}
	slices.SortFunc(rows, func(a, b control.RegistryPullView) int {
		return strings.Compare(a.Authority+"\x00"+a.Node, b.Authority+"\x00"+b.Node)
	})
	raw, _ := json.Marshal(rows)
	root := sha256.Sum256(append([]byte("fake-registry-pulls\x00"+tenant+"\x00"), raw...))
	offset := uint32(0)
	if after != "" {
		b, err := base64.RawURLEncoding.DecodeString(after)
		if err != nil || len(b) != 37 || b[0] != 1 {
			return control.RegistryPullPage{}, fail(m, CodeInvalid, "after")
		}
		if [32]byte(b[1:33]) != root {
			return control.RegistryPullPage{}, fail(m, CodeConflict, "pulls changed: read again")
		}
		offset = binary.LittleEndian.Uint32(b[33:])
	}
	out := control.RegistryPullPage{Schema: 1, Tenant: tenant, Root: root, Index: c.f.w.root}
	end := min(len(rows), int(offset)+8)
	if int(offset) < len(rows) {
		out.Rows = rows[offset:end]
	}
	if end < len(rows) {
		out.Next = base64.RawURLEncoding.EncodeToString(binary.LittleEndian.AppendUint32(append([]byte{1}, root[:]...), offset+8))
	}
	return out, nil
}

// RecordExternalPull pretends node pulled image's authority through the
// real source (code from the real vocabulary; "OK" = loaded).
func (f *Fake) RecordExternalPull(tenant, source, node, code string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.w.extReal()
	x := e.rows[tenant+"/"+source]
	if x == nil {
		return
	}
	e.seq++
	stage := "load"
	if code != "OK" {
		stage = "resolve"
	}
	e.pulls[tenant+"/"+x.spec.Authority+"/"+node] = extPull{node: node, row: observability.RegistryPull{Tenant: tenant, Authority: x.spec.Authority, Source: source, Stage: stage,
		Code: code, CompletedAt: uint64(f.now().UnixMilli()), Sequence: e.seq}}
}

// ImageUsages: `image-usages` (tenant Read): the reference core
// (w.imageReferences: app tasks and standalones as app-execution, CD
// candidates as cd-candidate) whose image matches Refs, and
// with ExternalSource only those the named source logs in for. 16 a page.
func (c *fakeConn) ImageUsages(ctx context.Context, tenant string, q control.ImageUsageQuery, after string) (control.ImageUsagesPage, error) {
	const m = "image-usages"
	q, err := q.Canonical()
	if err != nil || len(after) > 512 {
		return control.ImageUsagesPage{}, fail(m, CodeInvalid, "query")
	}
	if err := c.appRead(ctx, m, tenant); err != nil {
		return control.ImageUsagesPage{}, err
	}
	defer c.unlock()
	w := c.f.w
	e := w.extReal()
	var defs []imagesource.Definition
	if q.ExternalSource != "" {
		for _, k := range sortedKeys(e.rows) {
			if x := e.rows[k]; x.spec.Tenant == tenant {
				defs = append(defs, imagesource.Definition{Spec: imagesource.Own(x.spec), Deleted: x.deleted})
			}
		}
		if !slices.ContainsFunc(defs, func(d imagesource.Definition) bool { return d.Spec.ID == q.ExternalSource }) {
			return control.ImageUsagesPage{}, fail(m, CodeDenied, "")
		}
	}
	refs := w.imageReferences(tenant)
	var rows []control.ImageUsage
	seen := map[string]bool{}
	for _, r := range refs {
		ref, err := imagecache.CanonicalReference(r.Image)
		if err != nil {
			continue
		}
		r.Image = ref
		if q.ExternalSource != "" {
			_, authority, repository, _ := registryclient.Normalize(r.Image)
			d, err := imagesource.Lookup(defs, tenant, access.Image{Registry: authority, Repository: repository})
			if err != nil || d == nil || d.Spec.ID != q.ExternalSource {
				continue
			}
		}
		r.ID = imageReferenceID(r)
		match := q.Match(r)
		if match == "" || seen[r.ID] {
			continue
		}
		seen[r.ID] = true
		rows = append(rows, control.ImageUsage{ImageReference: r, Match: match})
	}
	slices.SortFunc(rows, func(a, b control.ImageUsage) int { return strings.Compare(a.ID, b.ID) })
	raw, _ := json.Marshal(struct {
		Q    control.ImageUsageQuery
		Rows []control.ImageUsage
	}{q, rows})
	root := sha256.Sum256(append([]byte("fake-image-usages\x00"+tenant+"\x00"+c.session.User+"\x00"), raw...))
	prev, last, err := control.ImageUsagesCursor(after)
	if err != nil {
		return control.ImageUsagesPage{}, fail(m, CodeInvalid, "after")
	}
	if after != "" && (prev != root || !slices.ContainsFunc(rows, func(r control.ImageUsage) bool { return r.ID == last })) {
		return control.ImageUsagesPage{}, fail(m, CodeConflict, "usages changed: read again")
	}
	out := control.ImageUsagesPage{Schema: 1, Tenant: tenant, Root: root, Index: w.root}
	for _, r := range rows {
		if r.ID <= last {
			continue
		}
		if len(out.Rows) == 16 {
			body, _ := json.Marshal(struct {
				Root  [32]byte
				After string
			}{root, out.Rows[15].ID})
			out.Next = base64.RawURLEncoding.EncodeToString(body)
			break
		}
		out.Rows = append(out.Rows, r)
	}
	return out, nil
}

// imageReferenceID: sfcd's row ID (sha256 of the row without ID).
func imageReferenceID(row control.ImageReference) string {
	row.ID = ""
	raw, _ := json.Marshal(row)
	d := sha256.Sum256(append([]byte("sfc-image-reference-1\x00"), raw...))
	return hex.EncodeToString(d[:])
}
