// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/userauth"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
)

// REQ-39/40 in mydcd's real shape (docs/reference/lifecycle-sources.md):
// `lifecycle-source-stage` / `lifecycle-module-stage` (descriptor + the
// caller's original nonzero CheckerUpload; the bytes are the kind4 body),
// `lifecycle-source-recover` / `lifecycle-module-recover` (same fields, no
// body, explicit original Node) and `lifecycle-source` pages
// {Name, Revision, Offset}. All need ManageServices on the tenant.
//
// Fake-only:
//   - Node "" picks the first active member. The owner key is
//     FixtureKey(node).
//   - The type check is checkSourceText (syntax, package checker, one Check
//     with the SDK shape, imports); problems are Diagnostics (≤ 32, ≤ 1024
//     bytes, no Source).
//   - Module ZIPs are not inspected; ExpandedBytes is 0. A source with a
//     module lock needs every pin staged first on the same node and Upload
//     (else CodeMissing), as mydcd does.
//   - One Upload is bound to one descriptor: reusing it with other bytes is
//     CodeInvalid; resending the same bytes gives the same fact.

// FailNextLifecycleStage makes the next lifecycle-source-stage answer these
// diagnostics (no fact) whatever the bytes; nil clears it.
func (f *Fake) FailNextLifecycleStage(diags []checker.SourceDiagnostic) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.w.lcNextDiags = slices.Clone(diags)
}

type lcUpload struct {
	tenant  string
	content [32]byte
	source  *checker.SourceFact
	modules map[string]checker.ModuleFact // pin key
}

func lcPinKey(p checker.ModulePin) string {
	return p.Path + "@" + p.Version + "/" + hex.EncodeToString(p.Digest[:])
}

func (w *world) lcUpload(node string, upload [32]byte) *lcUpload {
	if w.lcUploads == nil {
		w.lcUploads = map[string]*lcUpload{}
	}
	return w.lcUploads[node+"/"+hex.EncodeToString(upload[:])]
}

// lcStageCheck: the common request checks; returns the provider node.
func (c *fakeConn) lcStageCheck(ctx context.Context, m, node string, d checker.SourceDescriptor, pin *checker.ModulePin, upload [32]byte, recover bool) (string, error) {
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return "", err
	}
	w := c.f.w
	bad := func(code Code, detail string) (string, error) {
		c.unlock()
		return "", fail(m, code, detail)
	}
	if d.Validate() != nil || upload == ([32]byte{}) || recover && node == "" {
		return bad(CodeInvalid, "request")
	}
	if pin != nil && !slices.Contains(d.Modules, *pin) {
		return bad(CodeInvalid, "module is not in the lock")
	}
	if _, ok := w.tenants[d.Tenant]; !ok || !w.canManage(user, d.Tenant) {
		return bad(CodeDenied, "")
	}
	p, ok := w.lcPolicy(d.Tenant)
	if !recover && (!ok || !p.Enabled) {
		return bad(CodeDenied, "lifecycle policy disabled")
	}
	for _, mp := range d.Modules {
		if !recover && !slices.Contains(p.Resolver.Modules, mp) {
			return bad(CodeInvalid, "module "+mp.Path+"@"+mp.Version+" is not allowed by the policy")
		}
	}
	if node == "" {
		for _, mb := range w.members {
			if mb.Phase == NodePhaseActive {
				node = mb.ID
				break
			}
		}
	}
	i := w.memberIndex(node)
	if i < 0 || w.members[i].Phase != NodePhaseActive {
		return bad(CodeUnavailable, "provider")
	}
	if u := w.lcUpload(node, upload); u != nil && (u.tenant != d.Tenant || u.content != d.ContentDigest()) {
		return bad(CodeInvalid, "upload is bound to another source")
	}
	return node, nil
}

func lcDiagnostics(in []checker.SourceDiagnostic) []checker.SourceDiagnostic {
	var out []checker.SourceDiagnostic
	for _, d := range in {
		if len(out) == checker.MaxSourceDiagnostics {
			break
		}
		msg := strings.NewReplacer("\x00", " ", "\r", " ", "\n", " ").Replace(d.Message)
		for len(msg) > 1024 || !utf8.ValidString(msg) {
			msg = msg[:min(len(msg), 1024)-1]
		}
		line, col := max(d.Line, 0), max(d.Column, 0)
		if line == 0 || col == 0 {
			line, col = 0, 0
		}
		out = append(out, checker.SourceDiagnostic{Line: line, Column: col, Message: msg})
	}
	return out
}

func (w *world) lcRecordUpload(node string, upload [32]byte, d checker.SourceDescriptor) *lcUpload {
	if u := w.lcUpload(node, upload); u != nil {
		return u
	}
	u := &lcUpload{tenant: d.Tenant, content: d.ContentDigest(), modules: map[string]checker.ModuleFact{}}
	w.lcUploads[node+"/"+hex.EncodeToString(upload[:])] = u
	return u
}

// LifecycleSourceStage: `lifecycle-source-stage` with the source bytes.
func (c *fakeConn) LifecycleSourceStage(ctx context.Context, node string, d checker.SourceDescriptor, upload [32]byte, data []byte) (userauth.LifecycleStageResult, error) {
	const m = "lifecycle-source-stage"
	node, err := c.lcStageCheck(ctx, m, node, d, nil, upload, false)
	if err != nil {
		return userauth.LifecycleStageResult{}, err
	}
	defer c.unlock()
	w := c.f.w
	if uint64(len(data)) != d.Length || sha256.Sum256(data) != d.Digest || !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return userauth.LifecycleStageResult{}, fail(m, CodeInvalid, "source bytes do not match the descriptor")
	}
	out := userauth.LifecycleStageResult{Node: node, Owner: pub32(FixtureKey(node)), Descriptor: d.Clone(), Upload: upload}
	if diags := w.lcNextDiags; len(diags) > 0 {
		w.lcNextDiags = nil
		out.Diagnostics = diags
		return out, nil
	}
	if diags := lcDiagnostics(checkSourceText(data, len(d.Modules) > 0)); len(diags) > 0 {
		out.Diagnostics = diags
		return out, nil
	}
	if u := w.lcUpload(node, upload); u != nil && u.source != nil {
		f := *u.source
		out.Source = &f
		return out, nil
	}
	u := w.lcUpload(node, upload)
	for _, pin := range d.Modules {
		if u == nil || u.modules[lcPinKey(pin)].Schema == 0 {
			return userauth.LifecycleStageResult{}, fail(m, CodeMissing, "module "+pin.Path+" not staged")
		}
	}
	key := FixtureKey(node)
	up := upload
	f := checker.SourceFact{Upload: &up, Schema: 1, Cluster: w.cluster, Owner: pub32(key), Tenant: d.Tenant, Digest: d.Digest, Length: d.Length, SDK: d.SDK, Modules: slices.Clone(d.Modules)}
	f.Signature = ed25519.Sign(key, checker.SourceFactBytes(f))
	w.lcRecordUpload(node, upload, d).source = &f
	w.lcStagedText(data)
	fc := f
	out.Source = &fc
	return out, nil
}

// LifecycleModuleStage: `lifecycle-module-stage` with one pinned ZIP.
func (c *fakeConn) LifecycleModuleStage(ctx context.Context, node string, d checker.SourceDescriptor, upload [32]byte, module checker.ModuleArchive) (userauth.LifecycleStageResult, error) {
	const m = "lifecycle-module-stage"
	node, err := c.lcStageCheck(ctx, m, node, d, &module.Pin, upload, false)
	if err != nil {
		return userauth.LifecycleStageResult{}, err
	}
	defer c.unlock()
	w := c.f.w
	if uint64(len(module.ZIP)) != module.Pin.Length || sha256.Sum256(module.ZIP) != module.Pin.Digest || module.Pin.Length > checker.MaxModuleBytes {
		return userauth.LifecycleStageResult{}, fail(m, CodeInvalid, "module bytes do not match the pin")
	}
	u := w.lcRecordUpload(node, upload, d)
	f, ok := u.modules[lcPinKey(module.Pin)]
	if !ok {
		key := FixtureKey(node)
		f = checker.ModuleFact{Schema: 1, Cluster: w.cluster, Owner: pub32(key), Tenant: d.Tenant, Module: module.Pin}
		f.Signature = ed25519.Sign(key, checker.ModuleFactBytes(f))
		u.modules[lcPinKey(module.Pin)] = f
	}
	f = f.Clone()
	return userauth.LifecycleStageResult{Node: node, Owner: f.Owner, Descriptor: d.Clone(), Upload: upload, Module: &f}, nil
}

// LifecycleSourceRecover: `lifecycle-source-recover`, the original fact only.
func (c *fakeConn) LifecycleSourceRecover(ctx context.Context, node string, d checker.SourceDescriptor, upload [32]byte) (userauth.LifecycleStageResult, error) {
	const m = "lifecycle-source-recover"
	node, err := c.lcStageCheck(ctx, m, node, d, nil, upload, true)
	if err != nil {
		return userauth.LifecycleStageResult{}, err
	}
	defer c.unlock()
	u := c.f.w.lcUpload(node, upload)
	if u == nil || u.source == nil {
		return userauth.LifecycleStageResult{}, fail(m, CodeMissing, "")
	}
	f := *u.source
	return userauth.LifecycleStageResult{Node: node, Owner: f.Owner, Descriptor: d.Clone(), Upload: upload, Source: &f}, nil
}

// LifecycleModuleRecover: `lifecycle-module-recover`, the original fact only.
func (c *fakeConn) LifecycleModuleRecover(ctx context.Context, node string, d checker.SourceDescriptor, upload [32]byte, pin checker.ModulePin) (userauth.LifecycleStageResult, error) {
	const m = "lifecycle-module-recover"
	node, err := c.lcStageCheck(ctx, m, node, d, &pin, upload, true)
	if err != nil {
		return userauth.LifecycleStageResult{}, err
	}
	defer c.unlock()
	u := c.f.w.lcUpload(node, upload)
	if u == nil || u.modules[lcPinKey(pin)].Schema == 0 {
		return userauth.LifecycleStageResult{}, fail(m, CodeMissing, "")
	}
	f := u.modules[lcPinKey(pin)].Clone()
	return userauth.LifecycleStageResult{Node: node, Owner: f.Owner, Descriptor: d.Clone(), Upload: upload, Module: &f}, nil
}

// LifecycleSourcePage: `lifecycle-source` one ≤ 24 KiB page of an exact
// (immutable) source revision; retired versions read, deleted are missing.
func (c *fakeConn) LifecycleSourcePage(ctx context.Context, tenant string, q control.LifecycleSourceQuery) (checker.SourcePage, error) {
	const m = "lifecycle-source"
	if tenant == "" || !q.Valid() {
		return checker.SourcePage{}, fail(m, CodeInvalid, "query")
	}
	r, err := c.lcRecord(ctx, m, tenant, q.Name)
	if err != nil {
		return checker.SourcePage{}, err
	}
	defer c.unlock()
	i := slices.IndexFunc(r.versions, func(v lcVersion) bool { return v.revision == q.Revision })
	if i < 0 || r.versions[i].deleted {
		return checker.SourcePage{}, fail(m, CodeMissing, "")
	}
	v := r.versions[i]
	page, err := checker.NewSourcePage(tenant, q.Name, q.Revision, q.Offset, v.source.Descriptor(), []byte(v.text))
	if err != nil {
		return checker.SourcePage{}, fail(m, CodeInvalid, "offset")
	}
	return page, nil
}

// ReadLifecycleSource pages `lifecycle-source` to EOF and checks what the
// SDK's Client.LifecycleSource checks (same Digest/Total on every page,
// total length, SHA-256, UTF-8).
func ReadLifecycleSource(ctx context.Context, c Conn, tenant, name string, revision uint64) (userauth.LifecycleSourceText, error) {
	const m = "lifecycle-source"
	var data []byte
	var first checker.SourcePage
	for offset := uint64(0); ; {
		page, err := c.LifecycleSourcePage(ctx, tenant, control.LifecycleSourceQuery{Name: name, Revision: revision, Offset: offset})
		if err != nil {
			return userauth.LifecycleSourceText{}, err
		}
		if !page.Valid() || page.Offset != offset || offset > 0 && (page.Digest != first.Digest || page.Total != first.Total) {
			return userauth.LifecycleSourceText{}, fail(m, CodeUnknown, "page")
		}
		if offset == 0 {
			first = page
		}
		data = append(data, page.Data...)
		if page.Next == 0 {
			break
		}
		offset = page.Next
	}
	if uint64(len(data)) != first.Total || sha256.Sum256(data) != first.Digest || !utf8.Valid(data) {
		return userauth.LifecycleSourceText{}, fail(m, CodeUnknown, "source digest")
	}
	return userauth.LifecycleSourceText{Tenant: tenant, Name: name, Revision: revision, Digest: first.Digest, Source: string(data)}, nil
}
