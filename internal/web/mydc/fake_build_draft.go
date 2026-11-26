// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagebuild"
)

// build-draft in the fake (docs/reference/image-build-contexts.md '편집
// draft의 사용자 메시지', '조각 전송', 'freeze와 보존 버전 게시'). The draft
// of a draft-kind context is its files in the fake world (buildCtx.draft);
// realDraft adds the native draft's revision, empty
// folders, executable bits, edit results, staged file parts and frozen
// archives. Signed kinds carry a DraftProof the Conn signs with the
// session key; the fake checks it with DraftRequest.Authorize, as the
// owner node does. A new draft context is NOT_INITIALIZED until its first
// edit (Expected 1).

type realDraft struct {
	rev    uint64 // 0 = not initialized
	gen    uint64
	dirs   map[string]bool
	exec   map[string]bool
	edits  map[string]draftEditRec // edit ID
	stage  map[[32]byte]map[uint32][]byte
	frozen map[string]frozenRec // freeze plan ID
}

type draftEditRec struct {
	digest [32]byte
	result imagebuild.DraftEditResult
}

type frozenRec struct {
	plan   [32]byte
	frozen imagebuild.FrozenDraft
	files  map[string][]byte
}

func (x *buildCtx) realDraft() *realDraft {
	if x.rd == nil {
		x.rd = &realDraft{gen: max(x.row.Revision, 1), dirs: map[string]bool{}, exec: map[string]bool{}, edits: map[string]draftEditRec{},
			stage: map[[32]byte]map[uint32][]byte{}, frozen: map[string]frozenRec{}}
		if len(x.draft) > 0 {
			x.rd.rev = 1
		}
	}
	if x.draft == nil {
		x.draft = map[string][]byte{}
	}
	return x.rd
}

func (x *buildCtx) draftEntries() []imagebuild.Entry {
	d := x.realDraft()
	entries := contentEntries(x.draft)
	for i := range entries {
		if v, set := d.exec[entries[i].Path]; set && !entries[i].Directory {
			entries[i].Executable = v
		}
	}
	for dir := range d.dirs {
		if !slices.ContainsFunc(entries, func(e imagebuild.Entry) bool { return e.Path == dir }) {
			entries = append(entries, imagebuild.Entry{Path: dir, Directory: true})
		}
		for p := path.Dir(dir); p != "."; p = path.Dir(p) {
			if !slices.ContainsFunc(entries, func(e imagebuild.Entry) bool { return e.Path == p }) {
				entries = append(entries, imagebuild.Entry{Path: p, Directory: true})
			}
		}
	}
	slices.SortFunc(entries, func(a, b imagebuild.Entry) int { return strings.Compare(a.Path, b.Path) })
	return entries
}

func (x *buildCtx) draftDigest(scope imagebuild.DraftScope) [32]byte {
	raw, _ := json.Marshal(struct {
		Data    [32]byte
		Rev     uint64
		Entries []imagebuild.Entry
	}{scope.Data().Digest(), x.realDraft().rev, x.draftEntries()})
	return sha256.Sum256(append([]byte("fake-draft\x00"), raw...))
}

func (w *world) draftScope(x *buildCtx) (imagebuild.DraftScope, bool) {
	pol, prev, deleted, ok := w.imagePolicy(x.row.Tenant)
	spec := w.contextSpec(x)
	if !ok || deleted || x.row.Kind != BuildInline || !spec.Under(pol) {
		return imagebuild.DraftScope{}, false
	}
	return imagebuild.DraftScope{Schema: 1, Tenant: x.row.Tenant, Context: x.row.ID, Root: spec.Root, ContextRevision: x.row.Revision, PolicyRevision: prev,
		Dockerfile: spec.Dockerfile, ExpandedLimit: pol.WorkspaceBytes, Generation: min(x.realDraft().gen, x.row.Revision)}, true
}

func isDir(x *buildCtx, p string) bool {
	return x.realDraft().dirs[p] || slices.ContainsFunc(sortedKeys(x.draft), func(k string) bool { return strings.HasPrefix(k, p+"/") })
}

func parentIsFile(x *buildCtx, p string) bool {
	for d := path.Dir(p); d != "."; d = path.Dir(d) {
		if _, ok := x.draft[d]; ok {
			return true
		}
	}
	return false
}

// applyDraftEdit runs one edit on the draft (data: the whole file of a put).
func applyDraftEdit(x *buildCtx, e imagebuild.DraftEdit, data []byte) error {
	d := x.realDraft()
	_, isFile := x.draft[e.Path]
	switch e.Kind {
	case "put":
		if isDir(x, e.Path) || parentIsFile(x, e.Path) {
			return errCAS
		}
		x.draft[e.Path] = slices.Clone(data)
		d.exec[e.Path] = e.File.Executable
	case "mkdir":
		if isFile || isDir(x, e.Path) || parentIsFile(x, e.Path) {
			return errCAS
		}
		d.dirs[e.Path] = true
	case "delete":
		if !isFile && !isDir(x, e.Path) {
			return errCAS
		}
		for _, k := range sortedKeys(x.draft) {
			if k == e.Path || strings.HasPrefix(k, e.Path+"/") {
				delete(x.draft, k)
			}
		}
		for k := range d.dirs {
			if k == e.Path || strings.HasPrefix(k, e.Path+"/") {
				delete(d.dirs, k)
			}
		}
	case "move":
		if !isFile && !isDir(x, e.Path) {
			return errCAS
		}
		if _, ok := x.draft[e.To]; ok || isDir(x, e.To) || parentIsFile(x, e.To) {
			return errCAS // no merge, no overwrite
		}
		moved := map[string][]byte{}
		for _, k := range sortedKeys(x.draft) {
			if k == e.Path || strings.HasPrefix(k, e.Path+"/") {
				moved[e.To+strings.TrimPrefix(k, e.Path)] = x.draft[k]
				delete(x.draft, k)
			}
		}
		for k, v := range moved {
			x.draft[k] = v
		}
		for k := range d.dirs {
			if k == e.Path || strings.HasPrefix(k, e.Path+"/") {
				delete(d.dirs, k)
				d.dirs[e.To+strings.TrimPrefix(k, e.Path)] = true
			}
		}
	}
	return nil
}

// BuildDraft: `build-draft`. plan, tree and file-status need no proof; the
// other kinds need q.Proof signed with the session key (the signing Conn
// methods below build it).
func (c *fakeConn) BuildDraft(ctx context.Context, tenant string, q imagebuild.DraftRequest) (imagebuild.DraftResponse, error) {
	const m = "build-draft"
	if !q.Valid() || q.Scope != nil && q.Scope.Tenant != tenant {
		return imagebuild.DraftResponse{}, fail(m, CodeInvalid, "request")
	}
	if err := c.appRead(ctx, m, tenant); err != nil {
		return imagebuild.DraftResponse{}, err
	}
	defer c.unlock()
	return c.draft(tenant, q)
}

func (c *fakeConn) draft(tenant string, q imagebuild.DraftRequest) (imagebuild.DraftResponse, error) {
	const m = "build-draft"
	w := c.f.w
	if !w.canManage(c.session.User, tenant) { // a mutable draft is not read with Read alone
		return imagebuild.DraftResponse{}, fail(m, CodeDenied, "")
	}
	x := w.build.find(tenant, q.Context)
	if x == nil || x.row.Kind != BuildInline {
		return imagebuild.DraftResponse{}, fail(m, CodeConflict, "not a draft context")
	}
	scope, ok := w.draftScope(x)
	if !ok {
		return imagebuild.DraftResponse{}, fail(m, CodeConflict, "context outside the build policy")
	}
	d := x.realDraft()
	now := c.f.now().Unix()
	out := imagebuild.DraftResponse{Schema: 1, Scope: scope}
	if q.Kind == "plan" {
		out.Code = "PLAN"
		return out, nil
	}
	if q.Scope == nil {
		return imagebuild.DraftResponse{}, fail(m, CodeInvalid, "scope")
	}
	if *q.Scope != scope && !q.Result() {
		return imagebuild.DraftResponse{}, fail(m, CodeConflict, "scope changed: plan again")
	}
	out.Scope = *q.Scope
	if q.RequiresProof() && q.Authorize(*q.Scope, *c.session, now) != nil {
		return imagebuild.DraftResponse{}, fail(m, CodeDenied, "proof")
	}
	ok200 := func(e imagebuild.DraftEdit, rec draftEditRec) imagebuild.DraftResponse {
		r := rec.result
		out.Code, out.Revision, out.Digest, out.Edit = "OK", r.Revision, &r.Draft, &r
		return out
	}
	// commit runs an edit once: the same ID and content returns its first
	// result; the same ID with other content is refused.
	commit := func(e imagebuild.DraftEdit, data []byte) (imagebuild.DraftResponse, error) {
		if rec, seen := d.edits[e.ID]; seen {
			if rec.digest != e.Digest() {
				return imagebuild.DraftResponse{}, fail(m, CodeConflict, "edit ID reused with other content")
			}
			return ok200(e, rec), nil
		}
		if max(d.rev, 1) != e.Expected {
			return imagebuild.DraftResponse{}, fail(m, CodeConflict, "draft revision")
		}
		if err := applyDraftEdit(x, e, data); err != nil {
			return imagebuild.DraftResponse{}, fail(m, CodeConflict, e.Kind)
		}
		d.rev = e.Expected + 1
		rec := draftEditRec{digest: e.Digest(), result: imagebuild.DraftEditResult{Edit: e.Digest(), Draft: x.draftDigest(scope), Revision: d.rev}}
		d.edits[e.ID] = rec
		w.bumpKey(control.ImageBuildKey)
		w.build.rev[tenant] = w.root
		return ok200(e, rec), nil
	}
	switch q.Kind {
	case "tree":
		if d.rev == 0 {
			out.Code = "NOT_INITIALIZED"
			return out, nil
		}
		digest := x.draftDigest(scope)
		if q.Revision != 0 && (q.Revision != d.rev || *q.Digest != digest) {
			return imagebuild.DraftResponse{}, fail(m, CodeConflict, "draft changed: read the tree again")
		}
		entries := x.draftEntries()
		if q.Offset > uint32(len(entries)) {
			return imagebuild.DraftResponse{}, fail(m, CodeInvalid, "offset")
		}
		end := min(uint32(len(entries)), q.Offset+8)
		out.Code, out.Revision, out.Digest, out.Offset, out.Total, out.Entries = "OK", d.rev, &digest, q.Offset, uint32(len(entries)), entries[q.Offset:end]
		if end < out.Total {
			out.Next = end
		}
		return out, nil
	case "file": // one 24 KiB page of a draft file (FilePage)
		if d.rev == 0 {
			out.Code = "NOT_INITIALIZED"
			return out, nil
		}
		digest := x.draftDigest(scope)
		if q.Revision != d.rev || *q.Digest != digest {
			return imagebuild.DraftResponse{}, fail(m, CodeConflict, "draft changed: read the tree again")
		}
		i := slices.IndexFunc(x.draftEntries(), func(e imagebuild.Entry) bool { return e.Path == q.Path })
		if i < 0 {
			return imagebuild.DraftResponse{}, fail(m, CodeMissing, "file")
		}
		fp, err := filePage(x.draftEntries()[i], x.draft[q.Path], uint64(q.Offset))
		if err != nil {
			return imagebuild.DraftResponse{}, fail(m, CodeInvalid, err.Error())
		}
		out.Code, out.Revision, out.Digest, out.Content = "OK", d.rev, &digest, &fp
		return out, nil
	case "edit":
		return commit(*q.Edit, q.Data)
	case "result":
		rec, seen := d.edits[q.Edit.ID]
		if !seen || rec.digest != q.Edit.Digest() {
			out.Code = "NOT_INITIALIZED"
			return out, nil
		}
		return ok200(*q.Edit, rec), nil
	case "file-part", "file-status", "file-seal":
		e := *q.Edit
		key := e.Digest()
		parts := d.stage[key]
		if q.Kind == "file-part" {
			if rec, seen := d.edits[e.ID]; seen && rec.digest != key {
				return imagebuild.DraftResponse{}, fail(m, CodeConflict, "edit ID reused with other content")
			}
			if parts == nil {
				if max(d.rev, 1) != e.Expected {
					return imagebuild.DraftResponse{}, fail(m, CodeConflict, "draft revision")
				}
				parts = map[uint32][]byte{}
				d.stage[key] = parts
			}
			idx := q.Proof.Transfer.Part.Index
			if old, have := parts[idx]; have && !bytes.Equal(old, q.Data) {
				return imagebuild.DraftResponse{}, fail(m, CodeConflict, "part differs")
			}
			parts[idx] = slices.Clone(q.Data)
		}
		total := uint32((e.File.Bytes + imagebuild.PartBytes - 1) / imagebuild.PartBytes)
		whole := func() []byte {
			var b []byte
			for i := uint32(0); i < total; i++ {
				b = append(b, parts[i]...)
			}
			return b
		}
		complete := uint32(len(parts)) == total && sha256.Sum256(whole()) == e.File.Digest
		if q.Kind == "file-seal" {
			if rec, seen := d.edits[e.ID]; seen && rec.digest == key {
				return ok200(e, rec), nil
			}
			if !complete {
				out.Code = "PENDING"
				return out, nil
			}
			r, err := commit(e, whole())
			if err == nil {
				delete(d.stage, key)
			}
			return r, err
		}
		if parts == nil {
			out.Code = "NOT_INITIALIZED"
			return out, nil
		}
		prog := &imagebuild.DraftFileProgress{Edit: key, Parts: total, Received: uint32(len(parts)), Complete: complete}
		if q.Kind == "file-part" {
			part := *q.Proof.Transfer.Part
			prog.Part = &part
		} else {
			prog.Offset = q.Offset
			for i := q.Offset; i < total; i++ {
				if _, have := parts[i]; !have {
					prog.Missing = append(prog.Missing, i)
					if len(prog.Missing) == 256 {
						if i+1 < total {
							prog.Next = i + 1
						}
						break
					}
				}
			}
		}
		out.Code, out.File = "STAGED", prog
		return out, nil
	case "freeze", "freeze-result":
		plan := *q.Freeze
		if plan.Creator != c.session.User {
			return imagebuild.DraftResponse{}, fail(m, CodeDenied, "creator")
		}
		if f, seen := d.frozen[plan.ID]; seen {
			if f.plan != plan.Digest() {
				return imagebuild.DraftResponse{}, fail(m, CodeConflict, "freeze ID reused")
			}
			fz := f.frozen
			out.Code, out.Frozen = "FROZEN", &fz
			return out, nil
		}
		if q.Kind == "freeze-result" {
			out.Code = "NOT_INITIALIZED"
			return out, nil
		}
		if plan.Revision != d.rev || plan.Draft != x.draftDigest(scope) || uint64(now) < plan.CreatedAt || uint64(now) >= plan.ExpiresAt {
			return imagebuild.DraftResponse{}, fail(m, CodeConflict, "draft changed or plan expired")
		}
		if _, ok := x.draft[scope.Dockerfile]; !ok {
			return imagebuild.DraftResponse{}, fail(m, CodeConflict, "no Dockerfile")
		}
		files := cloneFiles(x.draft)
		entries := x.draftEntries()
		var expanded int64
		for _, e := range entries {
			expanded += e.Bytes
		}
		raw, _ := json.Marshal(entries)
		archive := plan.ArchiveScope(max(int64(len(raw)), 1), sha256.Sum256(raw))
		fact := imagebuild.SealReceipt{Schema: 1, Scope: archive.Hash(), ZIP: archive.Digest, Tree: treeDigest(entries), Entries: uint32(len(entries)), ExpandedBytes: expanded}
		key := FixtureKey(scope.Root.Node)
		fact.Signature = ed25519.Sign(key, imagebuild.SealReceiptBytes(fact))
		fz := imagebuild.FrozenDraft{Schema: 1, Plan: plan, Scope: archive, Fact: fact}
		fz.Signature = ed25519.Sign(key, imagebuild.FrozenDraftBytes(fz))
		d.frozen[plan.ID] = frozenRec{plan: plan.Digest(), frozen: fz, files: files}
		out.Code, out.Frozen = "FROZEN", &fz
		return out, nil
	}
	return imagebuild.DraftResponse{}, fail(m, CodeInvalid, "kind")
}

// --- signed requests (as userauth.Client) ---

func (c *fakeConn) signedDraft(ctx context.Context, scope imagebuild.DraftScope, subject [32]byte, q imagebuild.DraftRequest) (imagebuild.DraftResponse, error) {
	const m = "build-draft"
	if err := c.appRead(ctx, m, scope.Tenant); err != nil {
		return imagebuild.DraftResponse{}, err
	}
	defer c.unlock()
	if c.key == nil {
		return imagebuild.DraftResponse{}, fail(m, CodeNotLoggedIn, "")
	}
	at := c.f.now().Unix()
	p := q.Proof
	p.Schema, p.Scope, p.Edit, p.At, p.ExpiresAt = 1, scope.Digest(), subject, at, min(at+120, c.session.ExpiresAt)
	if !q.Valid() {
		return imagebuild.DraftResponse{}, fail(m, CodeInvalid, "request")
	}
	if _, err := rand.Read(p.Nonce[:]); err != nil {
		return imagebuild.DraftResponse{}, fail(m, CodeTransport, err.Error())
	}
	p.Signature = ed25519.Sign(c.key, imagebuild.DraftProofBytes(*p))
	return c.draft(scope.Tenant, q)
}

func (c *fakeConn) draftEdit(ctx context.Context, scope imagebuild.DraftScope, edit imagebuild.DraftEdit, kind string, data []byte, transfer *imagebuild.DraftTransferProof) (imagebuild.DraftResponse, error) {
	if edit.Validate() != nil {
		return imagebuild.DraftResponse{}, fail("build-draft", CodeInvalid, "edit")
	}
	q := imagebuild.DraftRequest{Context: scope.Context, Kind: kind, Scope: &scope, Edit: &edit, Data: data, Proof: &imagebuild.DraftProof{Transfer: transfer}}
	return c.signedDraft(ctx, scope, edit.Digest(), q)
}

func (c *fakeConn) EditBuildDraft(ctx context.Context, scope imagebuild.DraftScope, edit imagebuild.DraftEdit, data []byte) (imagebuild.DraftResponse, error) {
	return c.draftEdit(ctx, scope, edit, "edit", data, nil)
}

func (c *fakeConn) PutDraftFilePart(ctx context.Context, scope imagebuild.DraftScope, edit imagebuild.DraftEdit, index uint32, data []byte) (imagebuild.DraftResponse, error) {
	part := &imagebuild.DraftFilePart{Index: index, Length: uint32(len(data)), Digest: sha256.Sum256(data)}
	return c.draftEdit(ctx, scope, edit, "file-part", data, &imagebuild.DraftTransferProof{Kind: "file-part", Part: part})
}

func (c *fakeConn) CommitDraftFile(ctx context.Context, scope imagebuild.DraftScope, edit imagebuild.DraftEdit) (imagebuild.DraftResponse, error) {
	return c.draftEdit(ctx, scope, edit, "file-seal", nil, &imagebuild.DraftTransferProof{Kind: "file-seal"})
}

func (c *fakeConn) DraftFileStatus(ctx context.Context, scope imagebuild.DraftScope, edit imagebuild.DraftEdit, offset uint32) (imagebuild.DraftResponse, error) {
	return c.BuildDraft(ctx, scope.Tenant, imagebuild.DraftRequest{Context: scope.Context, Kind: "file-status", Scope: &scope, Edit: &edit, Offset: offset})
}

func (c *fakeConn) DraftEditResult(ctx context.Context, scope imagebuild.DraftScope, edit imagebuild.DraftEdit) (imagebuild.DraftResponse, error) {
	return c.draftEdit(ctx, scope, edit, "result", nil, &imagebuild.DraftTransferProof{Kind: "result"})
}

func (c *fakeConn) draftFreeze(ctx context.Context, plan imagebuild.DraftFreezePlan, kind string) (imagebuild.DraftResponse, error) {
	if plan.Validate() != nil {
		return imagebuild.DraftResponse{}, fail("build-draft", CodeInvalid, "freeze plan")
	}
	q := imagebuild.DraftRequest{Context: plan.Scope.Context, Kind: kind, Scope: &plan.Scope, Freeze: &plan, Proof: &imagebuild.DraftProof{Transfer: &imagebuild.DraftTransferProof{Kind: kind}}}
	return c.signedDraft(ctx, plan.Scope, plan.Digest(), q)
}

func (c *fakeConn) FreezeBuildDraft(ctx context.Context, plan imagebuild.DraftFreezePlan) (imagebuild.DraftResponse, error) {
	return c.draftFreeze(ctx, plan, "freeze")
}

func (c *fakeConn) DraftFreezeResult(ctx context.Context, plan imagebuild.DraftFreezePlan) (imagebuild.DraftResponse, error) {
	return c.draftFreeze(ctx, plan, "freeze-result")
}

// --- publish-build-draft ---

func (c *fakeConn) applyPublishBuildDraft(op UserOperation, actor string, next uint64) error {
	w := c.f.w
	b := &w.build
	var q control.ImageBuildDraftPublish
	if decodePayload(op.Change.Payload, &q) != nil || !q.Frozen.Valid() || q.Tenant != q.Frozen.Scope.Tenant || q.Context != q.Frozen.Scope.Context ||
		q.Frozen.Plan.Creator != actor || q.Frozen.Scope.Cluster != w.cluster || op.Change.Expected != q.Frozen.Plan.Revision {
		return errors.New("payload")
	}
	if !w.canManage(actor, q.Tenant) {
		return errForbidden
	}
	now := uint64(c.f.now().Unix())
	if now < q.Frozen.Plan.CreatedAt || now >= q.Frozen.Plan.ExpiresAt {
		return errors.New("payload: expired")
	}
	x := b.find(q.Tenant, q.Context)
	if x == nil {
		return errCAS
	}
	scope, ok := w.draftScope(x)
	src := q.Frozen.Plan.Scope
	f, have := x.realDraft().frozen[q.Frozen.Plan.ID]
	if !ok || !have || f.plan != q.Frozen.Plan.Digest() || src.Root != scope.Root || src.ContextRevision != scope.ContextRevision || src.PolicyRevision != scope.PolicyRevision ||
		src.Dockerfile != scope.Dockerfile || src.ExpandedLimit != scope.ExpandedLimit || src.Data() != scope.Data() {
		return errCAS
	}
	n := slices.Max(append([]uint64{0}, x.row.Versions...)) + 1
	x.versions[n] = cloneFiles(f.files)
	x.row.Versions = append(x.row.Versions, n)
	x.row.Version = n
	b.real.ready()
	b.real.seals[fmt.Sprintf("%s/%s/%d", x.row.Tenant, x.row.ID, n)] = realSeal{scope: q.Frozen.Scope, seal: q.Frozen.Fact}
	b.rev[q.Tenant] = next
	return nil
}
