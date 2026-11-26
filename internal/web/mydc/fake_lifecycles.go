// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/scanner"
	"go/token"
	"gopkg.in/yaml.v3"
	"slices"
	"strconv"
	"strings"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
	contract "github.com/jay94ks/mydcd/lifecycle/v1"
)

// Lifecycle (state check) scripts with the checker.Catalog rules:
// set-lifecycle-policy appends a policy version (Revision 0 in the payload,
// Expected = current policy revision, Validate); put-lifecycle-script adds
// an active source version to a record (Expected = record revision, 0 for a
// new name; the policy must allow the source and its module lock);
// retire-lifecycle-script makes a version inactive and
// delete-lifecycle-script deletes an inactive, unused one. Every record
// change raises the record revision by one; a new version's revision is
// the record revision after the put. All need ManageServices (tenant
// manager in the fake).

// FixtureLifecycleScript is a script record; versions get revisions 1..n.
type FixtureLifecycleScript struct {
	Tenant, Name string
	Node         string // provider that staged the sources
	Versions     []FixtureLifecycleVersion
}

type FixtureLifecycleVersion struct {
	Source          string
	Modules         []checker.ModulePin
	Active, Deleted bool
	UsedBy          []LifecycleUse // accepted app bindings / build jobs pinning it
}

type lcVersion struct {
	revision        uint64
	source          checker.SourceFact
	text            string // kept by the provider node, not in Raft
	active, deleted bool
}

type lcScript struct {
	tenant, name string
	revision     uint64
	versions     []lcVersion
}

const fixtureCheckSource = `package checker

import (
	"archive/zip"
	"bytes"
	"context"

	lifecycle "github.com/jay94ks/mydcd/lifecycle/v1"
)

func Check(ctx context.Context, in lifecycle.Request, probe lifecycle.Probe) (lifecycle.Result, error) {
	r, err := probe.Healthz(ctx, lifecycle.HTTPProbe{Service: "web", Path: "/healthz"})
	if err != nil {
		return lifecycle.Result{Schema: 1, Status: lifecycle.Unknown, Reason: "probe-error"}, err
	}
	if r.Status != 200 {
		return lifecycle.Result{Schema: 1, Status: lifecycle.Fail, Reason: "not-ready"}, nil
	}
	return lifecycle.Result{Schema: 1, Status: lifecycle.Pass, Reason: "ready"}, nil
}
`

// FixtureModuleZIP is a small module ZIP (go.mod plus one package file in
// the module-cache layout); FixtureModulePin, the module the fixture policy
// allows, pins exactly these bytes, so tests can stage it with
// LifecycleModuleStage.
var FixtureModuleZIP = fixtureModuleZIP()

var FixtureModulePin = checker.ModulePin{Path: "golang.org/x/text", Version: "v0.21.0", Digest: sha256.Sum256(FixtureModuleZIP), Length: uint64(len(FixtureModuleZIP))}

func fixtureModuleZIP() []byte {
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	for _, f := range []struct{ name, body string }{
		{"golang.org/x/text@v0.21.0/go.mod", "module golang.org/x/text\n\ngo 1.21\n"},
		{"golang.org/x/text@v0.21.0/cases/cases.go", "package cases\n\n// Fold is a fixture stand-in.\nfunc Fold(s string) string { return s }\n"},
	} {
		w, err := z.CreateHeader(&zip.FileHeader{Name: f.name, Method: zip.Deflate})
		if err != nil {
			panic(err)
		}
		_, _ = w.Write([]byte(f.body))
	}
	if err := z.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// FixtureLifecyclePolicy is an enabled, interpreted-only policy.
func FixtureLifecyclePolicy(tenant string) checker.TenantPolicy {
	return checker.TenantPolicy{Tenant: tenant, Revision: 1, Enabled: true,
		Execution: checker.ExecutionPolicy{MaxConcurrent: 4, TimeoutMS: 5000, NanoCPU: 500_000_000, MemoryBytes: 64 << 20, MaxPIDs: 32,
			OutputBytes: 64 << 10, ProbeBytes: 64 << 10, Capabilities: []string{"connect", "healthz"}},
		Resolver: checker.ResolverPolicy{Modules: []checker.ModulePin{FixtureModulePin}, SourceCacheBytes: 16 << 20},
	}
}

func fixtureLifecycleScripts() []FixtureLifecycleScript {
	return []FixtureLifecycleScript{{Tenant: "shop", Name: "http-ready", Node: "node-a", Versions: []FixtureLifecycleVersion{
		{Source: strings.Replace(fixtureCheckSource, "/healthz", "/ready", 1)},
		{Source: fixtureCheckSource, Active: true}, // php-shop/web pins it (phpShopYAML)
	}}}
}

// stageSource is what a provider node signs after storing the bytes.
func (w *world) stageSource(tenant, node string, text []byte, modules []checker.ModulePin) (checker.SourceFact, bool) {
	key := FixtureKey(node)
	if !slices.ContainsFunc(w.members, func(m FixtureMember) bool { return m.ID == node }) {
		return checker.SourceFact{}, false
	}
	f := checker.SourceFact{Schema: 1, Cluster: w.cluster, Owner: pub32(key), Tenant: tenant,
		Digest: sha256.Sum256(text), Length: uint64(len(text)), SDK: contract.Schema, Modules: slices.Clone(modules)}
	f.Signature = ed25519.Sign(key, checker.SourceFactBytes(f))
	return f, f.Verify() == nil
}

func (w *world) loadLifecycles(f Fixture) {
	w.lcPolicies = map[string][]checker.TenantPolicy{}
	w.lcScripts = map[string]*lcScript{}
	w.lcUses = map[string][]LifecycleUse{}
	for _, p := range f.LifecyclePolicies {
		w.lcPolicies[p.Tenant] = append(w.lcPolicies[p.Tenant], p.Clone())
	}
	for _, s := range f.LifecycleScripts {
		r := &lcScript{tenant: s.Tenant, name: s.Name}
		for i, v := range s.Versions {
			fact, ok := w.stageSource(s.Tenant, s.Node, []byte(v.Source), v.Modules)
			if !ok {
				panic("fixture lifecycle source " + s.Name)
			}
			rev := uint64(i + 1)
			r.versions = append(r.versions, lcVersion{revision: rev, source: fact, text: v.Source, active: v.Active, deleted: v.Deleted})
			w.lcStagedText([]byte(v.Source))
			for _, u := range v.UsedBy {
				u.Revision = rev
				w.lcUses[s.Tenant+"/"+s.Name] = append(w.lcUses[s.Tenant+"/"+s.Name], u)
			}
		}
		r.revision = uint64(len(s.Versions))
		for _, v := range r.versions {
			if !v.active {
				r.revision++ // retired
			}
			if v.deleted {
				r.revision++
			}
		}
		w.lcScripts[s.Tenant+"/"+s.Name] = r
	}
}

func (w *world) lcPolicy(tenant string) (checker.TenantPolicy, bool) {
	ps := w.lcPolicies[tenant]
	if len(ps) == 0 {
		return checker.TenantPolicy{}, false
	}
	return ps[len(ps)-1].Clone(), true
}

// lifecycleEntries is LifecyclePage's item list for one tenant.
func (w *world) lifecycleEntries(tenant string) []LifecycleEntry {
	var out []LifecycleEntry
	if p, ok := w.lcPolicy(tenant); ok {
		out = append(out, LifecycleEntry{Key: "policy", RecordRevision: p.Revision, Policy: &p})
	}
	for _, r := range w.lcScripts {
		if r.tenant != tenant {
			continue
		}
		for _, v := range r.versions {
			fact := v.source.Clone()
			out = append(out, LifecycleEntry{Key: fmt.Sprintf("script/%s/%020d", r.name, v.revision), Name: r.name,
				RecordRevision: r.revision, SourceRevision: v.revision, Source: &fact, Active: v.active, Deleted: v.deleted})
		}
	}
	return out
}

// SetLifecycleUses replaces every use of a script (app bindings derived from
// the deployed apps included) with uses, until called again; nil clears
// them all. delete-lifecycle-script fails for a pinned version.
func (f *Fake) SetLifecycleUses(tenant, name string, uses []LifecycleUse) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.w.lcOverride == nil {
		f.w.lcOverride = map[string][]LifecycleUse{}
	}
	f.w.lcOverride[tenant+"/"+name] = slices.Clone(uses)
}

func (w *world) lcPinned(tenant, name string, revision uint64) bool {
	return slices.ContainsFunc(w.lcUsesOf(tenant, name), func(u LifecycleUse) bool { return u.Revision == revision })
}

// lcAppDoc: the lifecycle part of app.yaml the fake reads (the paths of
// deployment.AppExtension.Lifecycle and ServiceExtension.Lifecycle).
type lcAppDoc struct {
	XMydc struct {
		Lifecycle struct {
			Scripts   map[string]checker.Script `yaml:"scripts"`
			Templates map[string]struct {
				Script string `yaml:"script"`
			} `yaml:"templates"`
			Checks []lcCheckDoc `yaml:"checks"`
		} `yaml:"lifecycle"`
	} `yaml:"x-mydc"`
	Services map[string]struct {
		XMydc struct {
			Node      string `yaml:"node"`
			Lifecycle struct {
				Checks []lcCheckDoc `yaml:"checks"`
			} `yaml:"lifecycle"`
		} `yaml:"x-mydc"`
	} `yaml:"services"`
}

type lcCheckDoc struct {
	Use    string `yaml:"use"`
	Script string `yaml:"script"`
}

// lcAppUses: app-binding rows of the deployed apps whose current definition
// runs a catalog script (a local script with ref, used by a service check
// directly or through a template; app-level checks count for every
// service). Inline `source:` scripts are not catalog uses.
func (w *world) lcAppUses(tenant, name string) []LifecycleUse {
	var out []LifecycleUse
	for _, k := range sortedKeys(w.apps) {
		a := w.apps[k]
		if a.view.Tenant != tenant || a.view.Retiring || len(a.sources) == 0 {
			continue
		}
		var d lcAppDoc
		if yaml.Unmarshal(a.sources[len(a.sources)-1].Document, &d) != nil {
			continue
		}
		lc := d.XMydc.Lifecycle
		rev := func(c lcCheckDoc) uint64 {
			local := c.Script
			if local == "" && c.Use != "" {
				local = lc.Templates[c.Use].Script
			}
			if s, ok := lc.Scripts[local]; ok && s.Ref != nil && s.Ref.Name == name {
				return s.Ref.Revision
			}
			return 0
		}
		for _, svc := range sortedKeys(d.Services) {
			s := d.Services[svc]
			seen := map[uint64]bool{}
			for _, c := range append(slices.Clone(lc.Checks), s.XMydc.Lifecycle.Checks...) {
				if r := rev(c); r != 0 && !seen[r] {
					seen[r] = true
					out = append(out, LifecycleUse{Revision: r, Kind: "app-binding", App: a.view.App, Service: svc, Node: s.XMydc.Node})
				}
			}
		}
	}
	return out
}

// lcUsesOf: the derived app bindings plus fixture rows (build jobs), or
// what SetLifecycleUses set.
func (w *world) lcUsesOf(tenant, name string) []LifecycleUse {
	if o, ok := w.lcOverride[tenant+"/"+name]; ok {
		return slices.Clone(o)
	}
	out := w.lcAppUses(tenant, name)
	for _, u := range w.lcUses[tenant+"/"+name] {
		if !slices.Contains(out, u) {
			out = append(out, u)
		}
	}
	return out
}

func (c *fakeConn) applyLifecycle(op UserOperation, actor string) error {
	w := c.f.w
	ch := op.Change
	switch ch.Action {
	case ActionSetLifecyclePolicy:
		var q checker.TenantPolicy
		if decodePayload(ch.Payload, &q) != nil {
			return errors.New("payload")
		}
		if !w.canManage(actor, q.Tenant) {
			return errForbidden
		}
		old, _ := w.lcPolicy(q.Tenant)
		if q.Revision != 0 || old.Revision != ch.Expected {
			return errCAS
		}
		q.Revision = ch.Expected + 1
		if q.Validate() != nil {
			return errors.New("policy")
		}
		for _, n := range q.Build.Nodes {
			if !slices.ContainsFunc(w.members, func(m FixtureMember) bool { return m.ID == n }) {
				return errForbidden
			}
		}
		w.lcPolicies[q.Tenant] = append(w.lcPolicies[q.Tenant], q.Clone())
		return nil
	case ActionPutLifecycleScript:
		var q control.LifecycleScriptPut
		if decodePayload(ch.Payload, &q) != nil || q.Source.Tenant != q.Tenant {
			return errors.New("payload")
		}
		if !w.canManage(actor, q.Tenant) {
			return errForbidden
		}
		if q.Source.Verify() != nil || q.Source.Cluster != w.cluster {
			return errors.New("source")
		}
		p, ok := w.lcPolicy(q.Tenant)
		if !ok || !p.AllowsSource(q.Source) || !checker.ValidScriptName(q.Name) {
			return errCAS
		}
		r := w.lcScripts[q.Tenant+"/"+q.Name]
		if r == nil {
			r = &lcScript{tenant: q.Tenant, name: q.Name}
		}
		if r.revision != ch.Expected || len(r.versions) >= 128 {
			return errCAS
		}
		r.revision++
		r.versions = append(r.versions, lcVersion{revision: r.revision, source: q.Source.Clone(), text: w.lcStaged[q.Source.Digest], active: true})
		w.lcScripts[q.Tenant+"/"+q.Name] = r
		return nil
	default: // retire / delete
		var q control.LifecycleScriptSelection
		if decodePayload(ch.Payload, &q) != nil {
			return errors.New("payload")
		}
		if !w.canManage(actor, q.Tenant) {
			return errForbidden
		}
		r := w.lcScripts[q.Tenant+"/"+q.Name]
		if r == nil || r.revision != ch.Expected {
			return errCAS
		}
		i := slices.IndexFunc(r.versions, func(v lcVersion) bool { return v.revision == q.Revision })
		remove := ch.Action == ActionDeleteLifecycleScript
		if i < 0 || r.versions[i].deleted || remove && (r.versions[i].active || w.lcPinned(q.Tenant, q.Name, q.Revision)) {
			return errCAS // ErrPending
		}
		r.revision++
		r.versions[i].active = false
		r.versions[i].deleted = remove
		if remove {
			r.versions[i].text = ""
		}
		return nil
	}
}

// lcStagedText records staged source bytes by digest so a put keeps the text
// a later source read (REQUEST.md) returns.
func (w *world) lcStagedText(text []byte) {
	if w.lcStaged == nil {
		w.lcStaged = map[[32]byte]string{}
	}
	w.lcStaged[sha256.Sum256(text)] = string(text)
}

// checkSourceText is the fake's stand-in for the provider's resolve/type
// check: syntax, package name, one Check(ctx, Request, Probe) (Result,
// error), and imports limited to the standard library and the SDK unless
// modules are locked.
func checkSourceText(src []byte, modules bool) []checker.SourceDiagnostic {
	var out []checker.SourceDiagnostic
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "checker.go", src, parser.AllErrors|parser.SkipObjectResolution)
	if list, ok := err.(scanner.ErrorList); ok {
		for _, e := range list {
			out = append(out, checker.SourceDiagnostic{Line: e.Pos.Line, Column: e.Pos.Column, Message: e.Msg})
		}
	} else if err != nil {
		out = append(out, checker.SourceDiagnostic{Message: err.Error()})
	}
	if file == nil || len(out) > 0 {
		return out
	}
	at := func(p token.Pos, msg string) {
		pos := fset.Position(p)
		out = append(out, checker.SourceDiagnostic{Line: pos.Line, Column: pos.Column, Message: msg})
	}
	if file.Name.Name != "checker" {
		at(file.Name.Pos(), "package must be checker")
	}
	for _, spec := range file.Imports {
		path, _ := strconv.Unquote(spec.Path.Value)
		if path != "github.com/jay94ks/mydcd/lifecycle/v1" && strings.Contains(strings.SplitN(path, "/", 2)[0], ".") && !modules {
			at(spec.Pos(), "import "+strconv.Quote(path)+" needs a module in the lock")
		}
	}
	checks := 0
	for _, d := range file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Name.Name != "Check" {
			continue
		}
		checks++
		if fn.Type.Params.NumFields() != 3 || fn.Type.Results.NumFields() != 2 {
			at(fn.Pos(), "Check must be func(context.Context, lifecycle.Request, lifecycle.Probe) (lifecycle.Result, error)")
		}
	}
	if checks != 1 {
		at(file.Package, "the source must declare exactly one func Check")
	}
	return out
}

// lifecycleUses: the lifecycle-uses rows PublicRead pages; ManageServices.
func (c *fakeConn) lifecycleUses(ctx context.Context, tenant, name string) (LifecycleUses, error) {
	const m = "lifecycle-uses"
	if _, err := c.lcRecord(ctx, m, tenant, name); err != nil {
		return LifecycleUses{}, err
	}
	defer c.unlock()
	items := c.f.w.lcUsesOf(tenant, name)
	if items == nil {
		items = []LifecycleUse{}
	}
	return LifecycleUses{Tenant: tenant, Name: name, Items: items}, nil
}

// lcRecord locks the world (the caller unlocks on success).
func (c *fakeConn) lcRecord(ctx context.Context, m, tenant, name string) (*lcScript, error) {
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return nil, err
	}
	w := c.f.w
	if !w.canManage(user, tenant) {
		c.unlock()
		return nil, fail(m, CodeDenied, "")
	}
	r := w.lcScripts[tenant+"/"+name]
	if r == nil {
		c.unlock()
		return nil, fail(m, CodeMissing, "")
	}
	return r, nil
}
