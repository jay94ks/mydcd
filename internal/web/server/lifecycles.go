// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/web/sfc"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
)

// Lifecycle (state check) scripts and the tenant lifecycle policy (UI-90/91).
// sfcd keeps the catalog (control.LifecycleKey): every rule (policy allows
// the source and its module lock, record CAS, delete only an inactive,
// unpinned version) is sfcd's. The web daemon reads the `lifecycles`
// pages, shapes them per script, and builds the change payloads.

const maxLifecyclePages = 4096 // sfcd returns one entry per page

// lifecycleEntries reads the tenant's entries after `after` while keep says
// so (keys are sorted: "policy" < "script/{name}/{revision:%020d}").
func lifecycleEntries(ctx context.Context, c sfc.Conn, tenant, after string, keep func(sfc.LifecycleEntry) bool) ([]sfc.LifecycleEntry, error) {
	var out []sfc.LifecycleEntry
	for range maxLifecyclePages {
		p, err := c.Lifecycles(ctx, tenant, after)
		if err != nil {
			return nil, err
		}
		for _, e := range p.Items {
			if !keep(e) {
				return out, nil
			}
			out = append(out, e)
		}
		if p.Next == "" {
			return out, nil
		}
		after = p.Next
	}
	return out, nil
}

// currentLifecyclePolicy is the "policy" entry, if the tenant has one.
func currentLifecyclePolicy(ctx context.Context, c sfc.Conn, tenant string) (*checker.TenantPolicy, error) {
	p, err := c.Lifecycles(ctx, tenant, "")
	if err != nil {
		return nil, err
	}
	if len(p.Items) > 0 && p.Items[0].Key == "policy" && p.Items[0].Policy != nil {
		pol := p.Items[0].Policy.Clone()
		return &pol, nil
	}
	return nil, nil
}

func scriptEntries(ctx context.Context, c sfc.Conn, tenant, name string) ([]sfc.LifecycleEntry, error) {
	prefix := "script/" + name + "/"
	return lifecycleEntries(ctx, c, tenant, prefix, func(e sfc.LifecycleEntry) bool { return strings.HasPrefix(e.Key, prefix) })
}

type lcModuleView struct {
	Path    string `json:"path"`
	Version string `json:"version"`
}

// lcLockInput: one module of a put's lock; zip (base64) is its pinned
// archive, staged on the provider before the source.
type lcLockInput struct {
	Path    string `json:"path"`
	Version string `json:"version"`
	ZIP     []byte `json:"zip,omitempty"`
}

type lcVersionView struct {
	Revision uint64         `json:"revision"`
	Active   bool           `json:"active"`
	Deleted  bool           `json:"deleted"`
	Digest   string         `json:"digest"` // sha256 of the source text
	Length   uint64         `json:"length"`
	Modules  []lcModuleView `json:"modules"`
}

type lcScriptView struct {
	Name           string          `json:"name"`
	RecordRevision uint64          `json:"recordRevision"` // expected for put / retire / delete
	ActiveRevision uint64          `json:"activeRevision"` // newest active version, 0 = none
	LatestRevision uint64          `json:"latestRevision"`
	Versions       []lcVersionView `json:"versions"`
}

func scriptViews(entries []sfc.LifecycleEntry) []lcScriptView {
	out := []lcScriptView{}
	for _, e := range entries {
		if e.Source == nil || e.Name == "" {
			continue
		}
		if len(out) == 0 || out[len(out)-1].Name != e.Name {
			out = append(out, lcScriptView{Name: e.Name, Versions: []lcVersionView{}})
		}
		s := &out[len(out)-1]
		s.RecordRevision = e.RecordRevision
		s.LatestRevision = max(s.LatestRevision, e.SourceRevision)
		if e.Active {
			s.ActiveRevision = max(s.ActiveRevision, e.SourceRevision)
		}
		mods := []lcModuleView{}
		for _, m := range e.Source.Modules {
			mods = append(mods, lcModuleView{m.Path, m.Version})
		}
		s.Versions = append(s.Versions, lcVersionView{Revision: e.SourceRevision, Active: e.Active, Deleted: e.Deleted,
			Digest: hex.EncodeToString(e.Source.Digest[:]), Length: e.Source.Length, Modules: mods})
	}
	return out
}

// GET /t/{t}/lifecycle-scripts → {items: [script], policy: {configured,
// enabled, revision}}.
func (s *Server) handleLifecycleScripts(w http.ResponseWriter, r *http.Request, ws *webSession) {
	tenant := r.PathValue("t")
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (map[string]any, error) {
		all, err := lifecycleEntries(ctx, c, tenant, "", func(sfc.LifecycleEntry) bool { return true })
		if err != nil {
			return nil, err
		}
		pol := map[string]any{"configured": false, "enabled": false, "revision": 0}
		for _, e := range all {
			if e.Key == "policy" && e.Policy != nil {
				pol = map[string]any{"configured": true, "enabled": e.Policy.Enabled, "revision": e.Policy.Revision}
			}
		}
		return map[string]any{"items": scriptViews(all), "policy": pol}, nil
	})
}

// GET /t/{t}/lifecycles/{name}?revision= → one script with its versions,
// the selected version's text and the work pinning it.
// The default selection is the active version, else the newest kept one.
func (s *Server) handleLifecycleScript(w http.ResponseWriter, r *http.Request, ws *webSession) {
	tenant, name := r.PathValue("t"), r.PathValue("name")
	var want uint64
	if q := r.URL.Query().Get("revision"); q != "" {
		v, err := strconv.ParseUint(q, 10, 64)
		if err != nil || v == 0 {
			writeError(w, http.StatusBadRequest, "bad-request", "revision must be a positive number")
			return
		}
		want = v
	}
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (map[string]any, error) {
		entries, err := scriptEntries(ctx, c, tenant, name)
		if err != nil {
			return nil, err
		}
		views := scriptViews(entries)
		if len(views) == 0 {
			return nil, &httpErr{http.StatusNotFound, "not-found", "no lifecycle script " + name}
		}
		v := views[0]
		sel := want
		if sel == 0 {
			sel = v.ActiveRevision
			for i := len(v.Versions) - 1; sel == 0 && i >= 0; i-- {
				if !v.Versions[i].Deleted {
					sel = v.Versions[i].Revision
				}
			}
		}
		if want != 0 && !slices.ContainsFunc(v.Versions, func(x lcVersionView) bool { return x.Revision == want }) {
			return nil, &httpErr{http.StatusNotFound, "not-found", "no such revision"}
		}
		out := map[string]any{"script": v, "revision": sel, "source": nil, "sourceAvailable": false, "usedBy": nil, "usedByAvailable": false}
		if sel != 0 {
			if src, err := sfc.ReadLifecycleSource(ctx, c, tenant, name, sel); err == nil {
				out["source"], out["sourceAvailable"] = src.Source, true
			} else if ctx.Err() != nil {
				return nil, err
			}
		}
		if uses, err := readLifecycleUses(ctx, c, tenant, name); err == nil {
			items := []map[string]any{}
			for _, u := range uses {
				item := map[string]any{"revision": u.Revision, "kind": u.Kind, "app": u.App, "service": u.Service, "node": u.Node, "id": u.ID}
				if u.Standalone != "" {
					item["standalone"] = u.Standalone
				}
				items = append(items, item)
			}
			out["usedBy"], out["usedByAvailable"] = items, true
		} else if ctx.Err() != nil {
			return nil, err
		}
		return out, nil
	})
}

// lifecycleUpload: the CheckerUpload of one web operation. It is the same
// on every retry of that opId (sfcd binds an upload to its first bytes and
// keeps its original record), and differs between users and opIds.
func lifecycleUpload(ws *webSession, opID string) [32]byte {
	return sha256.Sum256([]byte("sfc-web-lifecycle-upload\x00" + ws.user.ID + "\x00" + opID))
}

// lostReply: an error that is not one of sfcd's answers (the connection
// or reply was lost), so the original record is read back.
func lostReply(ctx context.Context, err error) bool {
	var me *sfc.Error
	return err != nil && ctx.Err() == nil && !errors.As(err, &me)
}

// compileErr is a 422 with the provider's diagnostics.
type compileErr struct{ items []map[string]any }

func (e *compileErr) Error() string { return "compile-error" }

// PUT /t/{t}/lifecycles/{name} {opId, source, node?, lock?: [{path,
// version}], expected?} → stage the text on a provider node, then
// put-lifecycle-script with the node-signed fact (Expected = record
// revision, 0 for a new name). Lock entries name modules of the policy's
// Resolver.Modules. 422 compile-error carries diagnostics with lines.
func (s *Server) handleLifecyclePut(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID     string        `json:"opId"`
		Source   string        `json:"source"`
		Node     string        `json:"node,omitempty"`
		Lock     []lcLockInput `json:"lock,omitempty"`
		Expected uint64        `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant, name := r.PathValue("t"), r.PathValue("name")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		if !checker.ValidScriptName(name) {
			return "", nil, 0, "", invalid("name: lowercase letters, digits and '-'")
		}
		if req.Source == "" || len(req.Source) > checker.MaxScriptBytes {
			return "", nil, 0, "", invalid("source: 1 byte to 256 KiB")
		}
		pol, err := currentLifecyclePolicy(ctx, c, tenant)
		if err != nil {
			return "", nil, 0, "", err
		}
		if pol == nil || !pol.Enabled {
			return "", nil, 0, "", &httpErr{http.StatusConflict, "policy-disabled", "set and enable the workspace's lifecycle policy first"}
		}
		var lock []checker.ModulePin
		var archives []checker.ModuleArchive
		for _, l := range req.Lock {
			i := slices.IndexFunc(pol.Resolver.Modules, func(m checker.ModulePin) bool { return m.Path == l.Path && m.Version == l.Version })
			if i < 0 {
				return "", nil, 0, "", invalid("lock: " + l.Path + "@" + l.Version + " is not a module of the policy")
			}
			lock = append(lock, pol.Resolver.Modules[i])
			if len(l.ZIP) > 0 {
				archives = append(archives, checker.ModuleArchive{Pin: pol.Resolver.Modules[i], ZIP: l.ZIP})
			}
		}
		slices.SortFunc(lock, func(a, b checker.ModulePin) int { return strings.Compare(a.Path, b.Path) })
		entries, err := scriptEntries(ctx, c, tenant, name)
		if err != nil {
			return "", nil, 0, "", err
		}
		var current uint64
		if len(entries) > 0 {
			current = entries[0].RecordRevision
		}
		data := []byte(req.Source)
		d := checker.SourceDescriptor{Tenant: tenant, Digest: sha256.Sum256(data), Length: uint64(len(data)), SDK: 1, Modules: lock}
		if d.Validate() != nil {
			return "", nil, 0, "", invalid("source")
		}
		upload := lifecycleUpload(ws, req.OpID)
		// Modules first, then the source, all on one provider and upload.
		// node "" lets sfcd pick; its reply's Node is kept for the rest.
		node := req.Node
		for _, a := range archives {
			m, err := c.LifecycleModuleStage(ctx, node, d, upload, a)
			if lostReply(ctx, err) && node != "" {
				m, err = c.LifecycleModuleRecover(ctx, node, d, upload, a.Pin)
			}
			if err != nil {
				return "", nil, 0, "", err
			}
			if m.Module == nil {
				return "", nil, 0, "", &httpErr{http.StatusUnprocessableEntity, "module-invalid", "the provider did not accept the ZIP of " + a.Pin.Path + "@" + a.Pin.Version}
			}
			node = m.Node
		}
		staged, err := c.LifecycleSourceStage(ctx, node, d, upload, data)
		if lostReply(ctx, err) && node != "" {
			// The reply was lost: read the original record, never resend.
			staged, err = c.LifecycleSourceRecover(ctx, node, d, upload)
		}
		if isSfcCode(err, sfc.CodeMissing) && len(lock) > 0 {
			return "", nil, 0, "", &httpErr{http.StatusUnprocessableEntity, "module-missing", "a module of the lock is not on the provider server; send its ZIP in lock[].zip"}
		}
		if err != nil {
			return "", nil, 0, "", err
		}
		if len(staged.Diagnostics) > 0 || staged.Source == nil {
			items := []map[string]any{}
			for _, d := range staged.Diagnostics {
				items = append(items, map[string]any{"line": d.Line, "column": d.Column, "message": d.Message})
			}
			return "", nil, 0, "", &compileErr{items}
		}
		return sfc.ActionPutLifecycleScript, control.LifecycleScriptPut{Tenant: tenant, Name: name, Source: *staged.Source},
			expectedOr(req.Expected, current), "lifecycle/" + name, nil
	})
}

// POST /t/{t}/lifecycles/{name}/retire and DELETE /t/{t}/lifecycles/{name}
// {opId, revision, expected?} → retire-/delete-lifecycle-script
// (Expected = record revision). Delete needs a retired version that no
// accepted work pins: 409 active / in-use / deleted before signing.
func (s *Server) handleLifecycleSelect(action string) func(http.ResponseWriter, *http.Request, *webSession) {
	return func(w http.ResponseWriter, r *http.Request, ws *webSession) {
		var req struct {
			OpID     string `json:"opId"`
			Revision uint64 `json:"revision"`
			Expected uint64 `json:"expected,omitempty"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		tenant, name := r.PathValue("t"), r.PathValue("name")
		body := struct {
			Action string
			Req    any
		}{action, req}
		s.sharedCreate(w, r, ws, req.OpID, body, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
			entries, err := scriptEntries(ctx, c, tenant, name)
			if err != nil {
				return "", nil, 0, "", err
			}
			i := slices.IndexFunc(entries, func(e sfc.LifecycleEntry) bool { return e.SourceRevision == req.Revision })
			if len(entries) == 0 || i < 0 {
				return "", nil, 0, "", &httpErr{http.StatusNotFound, "not-found", "no such script version"}
			}
			e := entries[i]
			switch {
			case e.Deleted:
				return "", nil, 0, "", &httpErr{http.StatusConflict, "deleted", "this version is already deleted"}
			case action == sfc.ActionRetireLifecycleScript && !e.Active:
				return "", nil, 0, "", &httpErr{http.StatusConflict, "not-active", "this version is already retired"}
			case action == sfc.ActionDeleteLifecycleScript && e.Active:
				return "", nil, 0, "", &httpErr{http.StatusConflict, "active", "retire this version before deleting it"}
			}
			if action == sfc.ActionDeleteLifecycleScript {
				uses, err := readLifecycleUses(ctx, c, tenant, name)
				if err == nil && slices.ContainsFunc(uses, func(u control.PublicLifecycleUse) bool { return u.Revision == req.Revision }) {
					return "", nil, 0, "", &httpErr{http.StatusConflict, "in-use", "accepted apps or build jobs still use this version"}
				} else if err != nil && ctx.Err() != nil {
					return "", nil, 0, "", err
				}
			}
			return action, control.LifecycleScriptSelection{Tenant: tenant, Name: name, Revision: req.Revision},
				expectedOr(req.Expected, e.RecordRevision), "lifecycle/" + name, nil
		})
	}
}

// lcModuleInput is a policy module pin with a hex digest.
type lcModuleInput struct {
	Path    string `json:"path"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
	Length  uint64 `json:"length"`
}

// defaultLifecyclePolicy is the starting point when the tenant has none:
// enabled, interpreted only (no build nodes).
func defaultLifecyclePolicy(tenant string) checker.TenantPolicy {
	return checker.TenantPolicy{Tenant: tenant, Enabled: true,
		Execution: checker.ExecutionPolicy{MaxConcurrent: 4, TimeoutMS: 5000, NanoCPU: 500_000_000, MemoryBytes: 64 << 20, MaxPIDs: 32,
			OutputBytes: 64 << 10, ProbeBytes: 64 << 10, Capabilities: []string{"connect", "healthz"}},
		Resolver: checker.ResolverPolicy{SourceCacheBytes: 16 << 20},
	}
}

// GET /t/{t}/lifecycle-policy → {configured, policy} (policy = the current
// one, or the default a first PUT starts from; module digests in hex).
func (s *Server) handleLifecyclePolicy(w http.ResponseWriter, r *http.Request, ws *webSession) {
	tenant := r.PathValue("t")
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (map[string]any, error) {
		pol, err := currentLifecyclePolicy(ctx, c, tenant)
		if err != nil {
			return nil, err
		}
		if pol == nil {
			d := defaultLifecyclePolicy(tenant)
			return map[string]any{"configured": false, "policy": d}, nil
		}
		return map[string]any{"configured": true, "policy": *pol}, nil
	})
}

// PUT /t/{t}/lifecycle-policy {opId, expected?, enabled?, build?,
// execution?, resolver?, compiledCacheBytes?} → set-lifecycle-policy with
// the whole policy: omitted parts keep the current (or default) value.
// Lists are sorted; the result must pass the policy rules (422 otherwise);
// sfcd also checks the build image on every build node.
func (s *Server) handleLifecyclePolicyPut(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID      string                   `json:"opId"`
		Expected  uint64                   `json:"expected,omitempty"`
		Enabled   *bool                    `json:"enabled,omitempty"`
		Build     *checker.BuildPolicy     `json:"build,omitempty"`
		Execution *checker.ExecutionPolicy `json:"execution,omitempty"`
		Resolver  *struct {
			AllowPackages    []string        `json:"allowPackages"`
			DenyPackages     []string        `json:"denyPackages"`
			Modules          []lcModuleInput `json:"modules"`
			SourceCacheBytes uint64          `json:"sourceCacheBytes"`
		} `json:"resolver,omitempty"`
		CompiledCacheBytes *uint64 `json:"compiledCacheBytes,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant := r.PathValue("t")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		cur, err := currentLifecyclePolicy(ctx, c, tenant)
		if err != nil {
			return "", nil, 0, "", err
		}
		p, current := defaultLifecyclePolicy(tenant), uint64(0)
		if cur != nil {
			p, current = *cur, cur.Revision
		}
		if req.Enabled != nil {
			p.Enabled = *req.Enabled
		}
		if req.Build != nil {
			p.Build = *req.Build
		}
		if req.Execution != nil {
			p.Execution = *req.Execution
		}
		if req.CompiledCacheBytes != nil {
			p.CompiledCacheBytes = *req.CompiledCacheBytes
		}
		if q := req.Resolver; q != nil {
			p.Resolver = checker.ResolverPolicy{AllowPackages: q.AllowPackages, DenyPackages: q.DenyPackages, SourceCacheBytes: q.SourceCacheBytes}
			for _, m := range q.Modules {
				d, err := hex.DecodeString(m.Digest)
				if err != nil || len(d) != 32 {
					return "", nil, 0, "", invalid("resolver.modules: digest must be 64 hex characters (sha256 of the module zip)")
				}
				p.Resolver.Modules = append(p.Resolver.Modules, checker.ModulePin{Path: m.Path, Version: m.Version, Digest: [32]byte(d), Length: m.Length})
			}
		}
		for _, l := range [][]string{p.Build.Nodes, p.Build.Targets, p.Execution.Capabilities, p.Resolver.AllowPackages, p.Resolver.DenyPackages} {
			slices.Sort(l)
		}
		slices.SortFunc(p.Resolver.Modules, func(a, b checker.ModulePin) int { return strings.Compare(a.Path, b.Path) })
		p.Tenant = tenant
		p.Revision = 1 // Validate wants a stored revision
		if err := p.Validate(); err != nil {
			return "", nil, 0, "", &httpErr{http.StatusUnprocessableEntity, "invalid-policy", lifecyclePolicyHint(p)}
		}
		p.Revision = 0 // sfcd assigns it
		return sfc.ActionSetLifecyclePolicy, p, expectedOr(req.Expected, current), "lifecycle-policy", nil
	})
}

// lifecyclePolicyHint names the first rule a policy breaks (as Validate).
func lifecyclePolicyHint(p checker.TenantPolicy) string {
	e, b, r := p.Execution, p.Build, p.Resolver
	switch {
	case e.MaxConcurrent < 1 || e.MaxConcurrent > 128:
		return "execution.maxConcurrent: 1 to 128"
	case e.TimeoutMS < 1 || e.NanoCPU < 1:
		return "execution.timeoutMS and execution.nanoCPU must be positive"
	case e.MemoryBytes < 16<<20:
		return "execution.memoryBytes: at least 16 MiB"
	case e.MaxPIDs < 1 || e.MaxPIDs > 1024:
		return "execution.maxPIDs: 1 to 1024"
	case e.OutputBytes < 1 || e.OutputBytes > 1<<20 || e.ProbeBytes < 1 || e.ProbeBytes > 1<<20:
		return "execution.outputBytes, probeBytes: 1 byte to 1 MiB"
	case len(e.Capabilities) == 0 || len(e.Capabilities) > 5:
		return "execution.capabilities: 1 to 5 of connect, dependency, exec, file, healthz"
	case r.SourceCacheBytes < checker.MaxScriptBytes:
		return "resolver.sourceCacheBytes: at least 256 KiB"
	case len(r.Modules) > 64:
		return "resolver.modules: at most 64"
	case len(b.Nodes) == 0 && (b.Image != "" || b.Toolchain != "" || len(b.Targets) != 0):
		return "build: without build nodes, leave image, toolchain and targets empty (interpreted only)"
	case len(b.Nodes) > 0 && (len(b.Targets) == 0 || !strings.HasPrefix(b.Toolchain, "go1.") || b.Image == ""):
		return "build: nodes need targets (linux/amd64, linux/arm64), a go1.x toolchain and a pinned image"
	case len(b.Nodes) > 0 && (b.MaxJobs < 1 || b.MaxJobs > 128 || b.NanoCPU < 1 || b.MemoryBytes < 32<<20 || b.WorkspaceBytes == 0 || b.ArtifactBytes == 0 || b.ArtifactBytes > b.WorkspaceBytes || b.TimeoutMS < 1 || p.CompiledCacheBytes < b.ArtifactBytes):
		return "build: maxJobs 1-128, nanoCPU > 0, memoryBytes >= 32 MiB, artifactBytes <= workspaceBytes, compiledCacheBytes >= artifactBytes, timeoutMS > 0"
	}
	return "the policy breaks a lifecycle policy rule (names, package paths, module pins or image)"
}
