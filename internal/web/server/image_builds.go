// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/hex"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/nodestorage"
	"github.com/jay94ks/mydcd/internal/web/mydc"
)

// Image builds on mydcd's real contract (REQ-19·47, docs/reference/
// image-build-jobs.md, image-build-contexts.md). Every read is the user's
// image-builds / build-context-content / image-build-logs /
// image-build-cache on their own session, every change the signed real
// action; mydcd judges permissions, policy bounds and record CAS. The web
// only reshapes rows (version numbers for 32-byte ids, flattened policy).
//
// Still on the old REQ-19 mock until the fake has them (build-draft with
// session-key proofs, the real zip receipt): the draft tree and file
// reads (version 0), files PUT/DELETE/move/commit and zip uploads
// (builds.go, build_zip_upload.go).

// Real action names shared with the old mock (the fake tells them apart by
// the payload shape).
const (
	actPutBuildContext    = "put-build-context"
	actDeleteBuildContext = "delete-build-context"
	actDeleteBuildVersion = "delete-build-version"
	actPruneBuildCache    = "prune-build-cache"
)

// buildLogPage: one image-build-logs page (the User reply bound).
const buildLogPage = 24 << 10

// maxBuildFileRead: the most of one context file the web passes through.
const maxBuildFileRead = 32 << 20

// buildPart reads every page of one image-builds Part (bounded).
func buildPart(ctx context.Context, c mydc.Conn, tenant string, q control.ImageBuildQuery) (control.ImageBuildPage, error) {
	var out control.ImageBuildPage
	after := ""
	for i := 0; i < incidentMaxPages; i++ {
		p, err := c.ImageBuilds(ctx, tenant, q, after)
		if err != nil {
			return out, err
		}
		if i == 0 {
			out = p
		} else {
			out.Policies = append(out.Policies, p.Policies...)
			out.Contexts = append(out.Contexts, p.Contexts...)
			out.Versions = append(out.Versions, p.Versions...)
			out.Jobs = append(out.Jobs, p.Jobs...)
			out.Caches = append(out.Caches, p.Caches...)
			out.CachePrunes = append(out.CachePrunes, p.CachePrunes...)
		}
		if p.Next == "" {
			out.Next = ""
			return out, nil
		}
		after = p.Next
	}
	return out, nil
}

func currentPolicy(ctx context.Context, c mydc.Conn, tenant string) (*control.ImageBuildPolicyView, error) {
	p, err := buildPart(ctx, c, tenant, control.ImageBuildQuery{Part: "policy"})
	if err != nil {
		return nil, err
	}
	for i := range p.Policies {
		if p.Policies[i].Spec.Tenant == tenant || p.Policies[i].Spec.Tenant == "" {
			return &p.Policies[i], nil
		}
	}
	return nil, nil
}

func realContext(ctx context.Context, c mydc.Conn, tenant, id string) (*control.ImageBuildContextView, error) {
	p, err := buildPart(ctx, c, tenant, control.ImageBuildQuery{Part: "contexts", ID: id})
	if err != nil {
		return nil, err
	}
	for i := range p.Contexts {
		if p.Contexts[i].Spec.ID == id && !p.Contexts[i].Deleted {
			return &p.Contexts[i], nil
		}
	}
	return nil, nil
}

func liveVersions(ctx context.Context, c mydc.Conn, tenant, id string) ([]control.ImageBuildVersionView, error) {
	p, err := buildPart(ctx, c, tenant, control.ImageBuildQuery{Part: "versions", ID: id})
	if err != nil {
		return nil, err
	}
	out := []control.ImageBuildVersionView{}
	for _, v := range p.Versions {
		if !v.Deleted {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b control.ImageBuildVersionView) int { return int(b.Number) - int(a.Number) })
	return out, nil
}

// versionByNumber: the kept version n of a context (404 when none).
func versionByNumber(ctx context.Context, c mydc.Conn, tenant, id string, n uint64) (control.ImageBuildVersionView, error) {
	vs, err := liveVersions(ctx, c, tenant, id)
	if err != nil {
		return control.ImageBuildVersionView{}, err
	}
	for _, v := range vs {
		if v.Number == n {
			return v, nil
		}
	}
	return control.ImageBuildVersionView{}, &httpErr{http.StatusNotFound, "not-found", "no such version"}
}

// --- policy ---

type buildRootView struct {
	ID         string `json:"id"`
	Generation uint64 `json:"generation"`
	Path       string `json:"path"`
}

type buildNodeView struct {
	Node string        `json:"node"`
	Root buildRootView `json:"root"`
}

type buildPolicyView struct {
	Exists         bool                     `json:"exists"`
	Revision       uint64                   `json:"revision"`
	Nodes          []buildNodeView          `json:"nodes"`
	Concurrency    uint32                   `json:"concurrency"`
	Seconds        uint64                   `json:"seconds"`
	CPUMillis      uint64                   `json:"cpuMillis"`
	MemoryBytes    int64                    `json:"memoryBytes"`
	WorkspaceBytes int64                    `json:"workspaceBytes"`
	CacheBytes     int64                    `json:"cacheBytes"`
	Registry       string                   `json:"registry"`
	Platforms      []string                 `json:"platforms"`
	BuilderImage   string                   `json:"builderImage"`
	Cleanup        imagebuild.CleanupPolicy `json:"cleanup"`
	Limits         buildLimits              `json:"limits"`
}

type buildLimits struct {
	ZipBytes      int64 `json:"zipBytes"`
	ExpandedBytes int64 `json:"expandedBytes"`
	FileReadBytes int64 `json:"fileReadBytes"`
	LogPageBytes  int   `json:"logPageBytes"`
}

func limitsView() buildLimits {
	return buildLimits{ZipBytes: imagebuild.MaxZIPBytes, ExpandedBytes: imagebuild.MaxExpandedBytes, FileReadBytes: maxBuildFileRead, LogPageBytes: buildLogPage}
}

// GET /t/{t}/build-policy
func (s *Server) handleBuildPolicy(w http.ResponseWriter, r *http.Request, ws *webSession) {
	read(s, w, r, ws, func(ctx context.Context, c mydc.Conn) (buildPolicyView, error) {
		out := buildPolicyView{Nodes: []buildNodeView{}, Platforms: []string{}, Limits: limitsView()}
		p, err := currentPolicy(ctx, c, r.PathValue("t"))
		if err != nil || p == nil || p.Deleted {
			if p != nil {
				out.Revision = p.Revision
			}
			return out, err
		}
		sp := p.Spec
		out.Exists, out.Revision = true, p.Revision
		for _, n := range sp.Nodes {
			out.Nodes = append(out.Nodes, buildNodeView{Node: n.Node, Root: buildRootView{ID: n.Root.ID, Generation: n.Root.Generation, Path: n.Root.Path}})
		}
		out.Concurrency, out.Seconds, out.CPUMillis, out.MemoryBytes = sp.Concurrency, sp.Seconds, sp.CPUMillis, sp.MemoryBytes
		out.WorkspaceBytes, out.CacheBytes, out.Registry, out.BuilderImage, out.Cleanup = sp.WorkspaceBytes, sp.CacheBytes, sp.Registry, sp.BuilderImage, sp.Cleanup
		out.Platforms = append(out.Platforms, sp.Platforms...)
		return out, nil
	})
}

// rootReference finds the storage root id on node for the policy: the
// policy's current one when it is the same root, else the tenant-storage
// row's full reference, which mydcd fills for roots the tenant
// may build on.
func rootReference(ctx context.Context, c mydc.Conn, tenant string, cur *control.ImageBuildPolicyView, node, id string) (nodestorage.Reference, error) {
	if cur != nil {
		for _, n := range cur.Spec.Nodes {
			if n.Node == node && (id == "" || n.Root.ID == id) {
				return n.Root, nil
			}
		}
	}
	bad := func(msg string) error { return invalidCode("root-unknown", node+": "+msg) }
	if id == "" {
		return nodestorage.Reference{}, bad("pick a storage root")
	}
	after := ""
	for i := 0; i < incidentMaxPages; i++ {
		p, err := c.TenantStoragePage(ctx, tenant, node, after)
		if err != nil {
			return nodestorage.Reference{}, err
		}
		for _, x := range p.Items {
			if x.Node == node && x.ID == id && x.Allowed && !x.Draining && x.Root.ID != "" {
				return x.Root, nil
			}
		}
		if p.Next == "" {
			break
		}
		after = p.Next
	}
	return nodestorage.Reference{}, bad("no storage root " + id + " for this workspace")
}

// PUT /t/{t}/build-policy {opId, policy:{nodes:[{node, root}], concurrency,
// seconds, cpuMillis, memoryBytes, workspaceBytes, cacheBytes, registry,
// platforms, builderImage, cleanup:{highWaterPercent, unusedDays}},
// expected?} → set-image-build-policy.
func (s *Server) handleSetImageBuildPolicy(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID   string `json:"opId"`
		Policy struct {
			Nodes []struct {
				Node string `json:"node"`
				Root string `json:"root"`
			} `json:"nodes"`
			Concurrency    uint32   `json:"concurrency"`
			Seconds        uint64   `json:"seconds"`
			CPUMillis      uint64   `json:"cpuMillis"`
			MemoryBytes    int64    `json:"memoryBytes"`
			WorkspaceBytes int64    `json:"workspaceBytes"`
			CacheBytes     int64    `json:"cacheBytes"`
			Registry       string   `json:"registry"`
			Platforms      []string `json:"platforms"`
			BuilderImage   string   `json:"builderImage"`
			Cleanup        struct {
				HighWaterPercent uint8  `json:"highWaterPercent"`
				UnusedDays       uint32 `json:"unusedDays"`
			} `json:"cleanup"`
		} `json:"policy"`
		Expected uint64 `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant := r.PathValue("t")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c mydc.Conn, sess mydc.Session) (string, any, uint64, string, error) {
		in := req.Policy
		cur, err := currentPolicy(ctx, c, tenant)
		if err != nil {
			return "", nil, 0, "", err
		}
		sp := imagebuild.Policy{Schema: 1, Tenant: tenant, Concurrency: in.Concurrency, Seconds: in.Seconds, CPUMillis: in.CPUMillis,
			MemoryBytes: in.MemoryBytes, WorkspaceBytes: in.WorkspaceBytes, CacheBytes: in.CacheBytes, Registry: in.Registry,
			Platforms: in.Platforms, Cleanup: imagebuild.CleanupPolicy{HighWaterPercent: in.Cleanup.HighWaterPercent, UnusedDays: in.Cleanup.UnusedDays}}
		for _, n := range in.Nodes {
			if !safeParamRE.MatchString(n.Node) {
				return "", nil, 0, "", invalid("nodes: server names")
			}
			ref, err := rootReference(ctx, c, tenant, cur, n.Node, n.Root)
			if err != nil {
				return "", nil, 0, "", err
			}
			sp.Nodes = append(sp.Nodes, imagebuild.NodeRoot{Node: n.Node, Root: ref})
		}
		sp.BuilderImage, err = s.builderDigest(ctx, c, tenant, in.BuilderImage, cur)
		if err != nil {
			return "", nil, 0, "", err
		}
		if sp.Validate(sess.Cluster) != nil {
			return "", nil, 0, "", invalid("policy: at least one server; concurrency 1..32, seconds 1..86400, cpuMillis 1..256000, sizes above 0, cleanup highWaterPercent 1..100 and unusedDays above 0, a registry and platforms")
		}
		var rev uint64
		if cur != nil {
			rev = cur.Revision
		}
		return mydc.ActionSetImageBuildPolicy, control.ImageBuildPolicyPut{Spec: sp}, expectedOr(req.Expected, rev), "build-policy", nil
	})
}

// builderDigest: the builder image pinned by digest. "" keeps the current
// one; name:tag is resolved with image-resolve on the user's session.
func (s *Server) builderDigest(ctx context.Context, c mydc.Conn, tenant, image string, cur *control.ImageBuildPolicyView) (string, error) {
	switch {
	case image == "" && cur != nil:
		return cur.Spec.BuilderImage, nil
	case image == "":
		return "", invalidCode("builder-digest", "builderImage: the builder image")
	case strings.Contains(image, "@sha256:"):
		return image, nil
	}
	res, err := c.ResolveImage(ctx, tenant, control.ImageResolveQuery{Ref: image})
	if err != nil || res.Code != "OK" || res.Image == nil || res.Image.Pinned == "" {
		return "", invalidCode("builder-digest", "builderImage: could not pin "+image+" to a digest; give name@sha256:…")
	}
	return res.Image.Pinned, nil // authority/repository@digest
}

// --- contexts and versions ---

type buildVersionRow struct {
	Number        uint64 `json:"number"`
	ID            string `json:"id"`
	Bytes         int64  `json:"bytes"`
	ExpandedBytes int64  `json:"expandedBytes"`
	Entries       uint32 `json:"entries"`
	At            string `json:"at,omitempty"`
	Commit        string `json:"commit,omitempty"`
}

func versionRow(v control.ImageBuildVersionView) buildVersionRow {
	row := buildVersionRow{Number: v.Number, ID: hex.EncodeToString(v.ID[:]), Bytes: v.Bytes, ExpandedBytes: v.ExpandedBytes, Entries: v.Entries, Commit: v.Commit}
	if v.At > 0 {
		row.At = rfc(v.At)
	}
	return row
}

type buildContextRow struct {
	ID         string                   `json:"id"`
	Kind       string                   `json:"kind"`
	Revision   uint64                   `json:"revision"`
	Node       string                   `json:"node"`
	Root       string                   `json:"root"`
	Dockerfile string                   `json:"dockerfile"`
	Args       map[string]string        `json:"args"`
	Secrets    []imagebuild.SecretMount `json:"secrets"`
	Repository string                   `json:"repository"`
	Tags       []string                 `json:"tags"`
	Platforms  []string                 `json:"platforms"`
	Git        *imagebuild.GitContext   `json:"git,omitempty"`
	GitCheck   *gitCheckView            `json:"gitCheck,omitempty"`
	Version    uint64                   `json:"version"`
	Versions   []buildVersionRow        `json:"versions"`
	LastBuild  *buildJobRow             `json:"lastBuild,omitempty"`
}

type gitCheckView struct {
	Code    string `json:"code"`
	Commit  string `json:"commit,omitempty"`
	At      string `json:"at,omitempty"`
	Entries uint32 `json:"entries"`
}

func contextRow(ctx context.Context, c mydc.Conn, tenant string, x control.ImageBuildContextView) (buildContextRow, error) {
	sp := x.Spec
	row := buildContextRow{ID: sp.ID, Kind: sp.Kind, Revision: x.Revision, Node: sp.Root.Node, Root: sp.Root.ID, Dockerfile: sp.Dockerfile,
		Args: sp.Arguments, Secrets: sp.Secrets, Repository: sp.Repository, Tags: sp.Tags, Platforms: sp.Platforms, Git: sp.Git, Versions: []buildVersionRow{}}
	if row.Args == nil {
		row.Args = map[string]string{}
	}
	if row.Secrets == nil {
		row.Secrets = []imagebuild.SecretMount{}
	}
	if g := x.GitObservation; g != nil {
		row.GitCheck = &gitCheckView{Code: g.Code, Commit: g.Commit, Entries: g.Entries}
		if g.At > 0 {
			row.GitCheck.At = rfc(int64(g.At))
		}
	}
	vs, err := liveVersions(ctx, c, tenant, sp.ID)
	if err != nil {
		return row, err
	}
	for _, v := range vs {
		row.Versions = append(row.Versions, versionRow(v))
	}
	if len(vs) > 0 {
		row.Version = vs[0].Number
	}
	jobs, err := c.ImageBuilds(ctx, tenant, control.ImageBuildQuery{Part: "jobs", ID: sp.ID}, "")
	if err != nil {
		return row, err
	}
	var last *control.ImageBuildJobView
	for i := range jobs.Jobs {
		if j := &jobs.Jobs[i]; !j.Deleted && (last == nil || j.CreatedAt > last.CreatedAt) {
			last = j
		}
	}
	if last != nil {
		jr := jobRow(*last, vs)
		row.LastBuild = &jr
	}
	return row, nil
}

// GET /t/{t}/build-contexts?after=
func (s *Server) handleImageBuildContexts(w http.ResponseWriter, r *http.Request, ws *webSession) {
	read(s, w, r, ws, func(ctx context.Context, c mydc.Conn) (listPage, error) {
		tenant := r.PathValue("t")
		p, err := c.ImageBuilds(ctx, tenant, control.ImageBuildQuery{Part: "contexts"}, r.URL.Query().Get("after"))
		if err != nil {
			return listPage{}, err
		}
		rows := []buildContextRow{}
		for _, x := range p.Contexts {
			if x.Deleted {
				continue
			}
			row, err := contextRow(ctx, c, tenant, x)
			if err != nil {
				return listPage{}, err
			}
			rows = append(rows, row)
		}
		return s.page(rows, p.Next, p.RootRevision), nil
	})
}

// PUT /t/{t}/build-contexts/{id} {opId, context:{kind, node, dockerfile,
// args?, secrets?, repository, tags, platforms, git?}, expected?} →
// put-build-context. The storage root is the policy's root on node.
func (s *Server) handlePutImageBuildContext(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID    string `json:"opId"`
		Context struct {
			Kind       string            `json:"kind"`
			Node       string            `json:"node"`
			Dockerfile string            `json:"dockerfile"`
			Args       map[string]string `json:"args,omitempty"`
			Secrets    []struct {
				ID     string `json:"id"`
				Realm  string `json:"realm"`
				Secret string `json:"secret"`
				Key    string `json:"key"`
			} `json:"secrets,omitempty"`
			Repository string   `json:"repository"`
			Tags       []string `json:"tags"`
			Platforms  []string `json:"platforms"`
			Git        *struct {
				Repository        string `json:"repository"`
				Ref               string `json:"ref"`
				Path              string `json:"path,omitempty"`
				CredentialProfile string `json:"credentialProfile,omitempty"`
				Automatic         bool   `json:"automatic,omitempty"`
			} `json:"git,omitempty"`
		} `json:"context"`
		Expected uint64 `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant, id := r.PathValue("t"), r.PathValue("id")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c mydc.Conn, _ mydc.Session) (string, any, uint64, string, error) {
		in := req.Context
		pol, err := currentPolicy(ctx, c, tenant)
		if err != nil {
			return "", nil, 0, "", err
		}
		if pol == nil || pol.Deleted {
			return "", nil, 0, "", &httpErr{http.StatusConflict, "no-policy", "set the build policy first"}
		}
		sp := imagebuild.ContextSpec{Tenant: tenant, ID: id, Kind: in.Kind, Dockerfile: in.Dockerfile, Arguments: in.Args,
			Repository: in.Repository, Tags: in.Tags, Platforms: in.Platforms}
		found := false
		for _, n := range pol.Spec.Nodes {
			if n.Node == in.Node {
				sp.Root, found = n.Root, true
			}
		}
		if !found {
			return "", nil, 0, "", invalidCode("node-not-in-policy", "node: one of the build policy's servers")
		}
		for _, m := range in.Secrets {
			sp.Secrets = append(sp.Secrets, imagebuild.SecretMount{ID: m.ID, Realm: m.Realm, Secret: m.Secret, Key: m.Key})
		}
		if g := in.Git; g != nil {
			sp.Git = &imagebuild.GitContext{Repository: g.Repository, Ref: g.Ref, Path: g.Path, CredentialProfile: g.CredentialProfile, Automatic: g.Automatic}
		}
		if sp.Validate() != nil {
			return "", nil, 0, "", invalid("context: kind upload|git|draft, a Dockerfile path, repository, tags and platforms; git only for kind git")
		}
		cur, err := realContext(ctx, c, tenant, id)
		if err != nil {
			return "", nil, 0, "", err
		}
		var rev uint64
		if cur != nil {
			rev = cur.Revision
		}
		return actPutBuildContext, control.ImageBuildContextPut{Spec: sp}, expectedOr(req.Expected, rev), "build-context/" + id, nil
	})
}

// POST /t/{t}/build-contexts/{id}/delete {opId, expected?} →
// delete-build-context. mydcd keeps a context while versions remain, so
// those go first: 409 versions-left with their numbers.
func (s *Server) handleDeleteImageBuildContext(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID     string `json:"opId"`
		Expected uint64 `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant, id := r.PathValue("t"), r.PathValue("id")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c mydc.Conn, _ mydc.Session) (string, any, uint64, string, error) {
		cur, err := realContext(ctx, c, tenant, id)
		if err != nil {
			return "", nil, 0, "", err
		}
		if cur == nil {
			return "", nil, 0, "", &httpErr{http.StatusNotFound, "not-found", "no such build context"}
		}
		vs, err := liveVersions(ctx, c, tenant, id)
		if err != nil {
			return "", nil, 0, "", err
		}
		if len(vs) > 0 {
			nums := make([]string, 0, len(vs))
			for _, v := range vs {
				nums = append(nums, strconv.FormatUint(v.Number, 10))
			}
			return "", nil, 0, "", &httpErr{http.StatusConflict, "versions-left", "delete versions " + strings.Join(nums, ", ") + " first"}
		}
		return actDeleteBuildContext, control.ImageBuildSelection{Tenant: tenant, ID: id}, expectedOr(req.Expected, cur.Revision), "build-context/" + id, nil
	})
}

// POST /t/{t}/build-contexts/{id}/versions/{version}/delete {opId} →
// delete-build-version (Expected = the version number).
func (s *Server) handleDeleteImageBuildVersion(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID string `json:"opId"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant, id := r.PathValue("t"), r.PathValue("id")
	n, verr := strconv.ParseUint(r.PathValue("version"), 10, 64)
	s.sharedCreate(w, r, ws, req.OpID, actionBody{"delete-build-version", req}, func(ctx context.Context, c mydc.Conn, _ mydc.Session) (string, any, uint64, string, error) {
		if verr != nil || n == 0 {
			return "", nil, 0, "", invalid("version: a kept version number")
		}
		v, err := versionByNumber(ctx, c, tenant, id, n)
		if err != nil {
			return "", nil, 0, "", err
		}
		return actDeleteBuildVersion, control.ImageBuildVersionSelection{Tenant: tenant, ID: v.ID}, v.Number, "build-context/" + id, nil
	})
}

// GET /t/{t}/build-contexts/{id}/tree?version=N → {version, id, tree,
// entries:[{path, directory, executable, bytes, digest}], dockerfile}.
// Version 0 (the draft) is still the old mock.
func (s *Server) handleImageBuildTree(w http.ResponseWriter, r *http.Request, ws *webSession) {
	n := queryUint(r, "version")
	if n == 0 {
		s.handleDraftTree(w, r, ws)
		return
	}
	type treeView struct {
		Version    uint64             `json:"version"`
		ID         string             `json:"id"`
		Tree       string             `json:"tree"`
		Entries    []imagebuild.Entry `json:"entries"`
		Dockerfile string             `json:"dockerfile"`
	}
	read(s, w, r, ws, func(ctx context.Context, c mydc.Conn) (treeView, error) {
		tenant, id := r.PathValue("t"), r.PathValue("id")
		v, err := versionByNumber(ctx, c, tenant, id, n)
		if err != nil {
			return treeView{}, err
		}
		out := treeView{Version: n, ID: hex.EncodeToString(v.ID[:]), Tree: hex.EncodeToString(v.Tree[:]), Entries: []imagebuild.Entry{}}
		after := ""
		for range 4096 { // 8 rows a page: up to 32768 entries
			p, err := c.BuildContextContent(ctx, tenant, imagebuild.ContentQuery{Version: v.ID, Part: "tree"}, after)
			if err != nil {
				return out, err
			}
			out.Entries = append(out.Entries, p.Page.Entries...)
			if p.Next == "" {
				break
			}
			after = p.Next
		}
		if x, err := realContext(ctx, c, tenant, id); err == nil && x != nil {
			out.Dockerfile = x.Spec.Dockerfile
		}
		return out, nil
	})
}

// GET /t/{t}/build-contexts/{id}/file?version=N&path= → the file's bytes
// (REQ-57 version file pages). Version 0 is still the old mock.
func (s *Server) handleImageBuildFile(w http.ResponseWriter, r *http.Request, ws *webSession) {
	n := queryUint(r, "version")
	path := r.URL.Query().Get("path")
	if path == "" {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "path: a file of the context")
		return
	}
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var data []byte
	var exec bool
	err := ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		if n == 0 {
			var err error
			data, exec, err = draftFile(ctx, c, r.PathValue("t"), r.PathValue("id"), path)
			return err
		}
		v, err := versionByNumber(ctx, c, r.PathValue("t"), r.PathValue("id"), n)
		if err != nil {
			return err
		}
		data = data[:0]
		after := ""
		for {
			p, err := c.BuildContextContent(ctx, r.PathValue("t"), imagebuild.ContentQuery{Version: v.ID, Part: "file", Path: path}, after)
			if err != nil {
				return err
			}
			f := p.Page.File
			if f == nil {
				return &httpErr{http.StatusBadGateway, "bad-page", "mydcd sent no file page"}
			}
			if f.Total > maxBuildFileRead {
				return &httpErr{http.StatusRequestEntityTooLarge, "too-large", "the file is larger than the web passes through; use the CLI"}
			}
			data, exec = append(data, f.Data...), f.Entry.Executable
			if f.Next == 0 || f.Next >= f.Total || p.Next == "" {
				return nil
			}
			after = p.Next
		}
	})
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "sandbox")
	h.Set("Cache-Control", "no-store")
	if exec {
		h.Set("X-MyDC-Executable", "1")
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// POST /t/{t}/build-contexts/{id}/verify → check-build-context (Git).
func (s *Server) handleCheckImageBuildContext(w http.ResponseWriter, r *http.Request, ws *webSession) {
	read(s, w, r, ws, func(ctx context.Context, c mydc.Conn) (control.ImageBuildSourceResult, error) {
		return c.CheckBuildContext(ctx, r.PathValue("t"), control.ImageBuildSourceQuery{ID: r.PathValue("id")})
	})
}

// --- jobs ---

type buildJobRow struct {
	ID        string                `json:"id"`
	Context   string                `json:"context"`
	Node      string                `json:"node"`
	User      string                `json:"user"`
	Phase     string                `json:"phase"`
	Version   uint64                `json:"version"`
	VersionID string                `json:"versionId"`
	Number    uint64                `json:"number"`
	Revision  uint64                `json:"revision"`
	CreatedAt string                `json:"createdAt,omitempty"`
	ClosedAt  string                `json:"closedAt,omitempty"`
	Cancel    bool                  `json:"cancel,omitempty"`
	Result    *imagebuild.JobResult `json:"result,omitempty"`
	Automatic bool                  `json:"automatic,omitempty"`
}

func jobRow(j control.ImageBuildJobView, vs []control.ImageBuildVersionView) buildJobRow {
	row := buildJobRow{ID: j.ID, Context: j.Context, Node: j.Node, User: j.User, Phase: j.Phase, VersionID: hex.EncodeToString(j.Version[:]),
		Number: j.Number, Revision: j.Revision, Cancel: j.Cancel, Result: j.Result, Automatic: j.Automatic}
	for _, v := range vs {
		if v.ID == j.Version {
			row.Version = v.Number
		}
	}
	if j.CreatedAt > 0 {
		row.CreatedAt = rfc(int64(j.CreatedAt))
	}
	if j.ClosedAt > 0 {
		row.ClosedAt = rfc(int64(j.ClosedAt))
	}
	return row
}

func findJob(ctx context.Context, c mydc.Conn, tenant, id string) (*control.ImageBuildJobView, error) {
	p, err := c.ImageBuilds(ctx, tenant, control.ImageBuildQuery{Part: "jobs", Job: id}, "")
	if err != nil {
		return nil, err
	}
	for i := range p.Jobs {
		if p.Jobs[i].ID == id && !p.Jobs[i].Deleted {
			return &p.Jobs[i], nil
		}
	}
	return nil, &httpErr{http.StatusNotFound, "not-found", "no such build"}
}

// POST /t/{t}/build-contexts/{id}/build {opId, build?, version?} →
// image-build-job-plan, then begin-image-build with the plan's change.
// version is a kept version number (default the newest); build is the job
// ID (default "build-<opId>").
func (s *Server) handleBeginImageBuild(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID    string `json:"opId"`
		Build   string `json:"build,omitempty"`
		Version uint64 `json:"version,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if req.Build == "" {
		req.Build = "build-" + req.OpID
	}
	tenant, id := r.PathValue("t"), r.PathValue("id")
	s.sharedCreateHold(w, r, ws, req.OpID, req, func(ctx context.Context, c mydc.Conn, _ mydc.Session) (string, any, uint64, string, error) {
		if !validName(req.Build) {
			return "", nil, 0, "", invalid("build: lowercase letters, digits and -, at most 63")
		}
		vs, err := liveVersions(ctx, c, tenant, id)
		if err != nil {
			return "", nil, 0, "", err
		}
		var v *control.ImageBuildVersionView
		for i := range vs {
			if req.Version == 0 && i == 0 || vs[i].Number == req.Version {
				v = &vs[i]
				break
			}
		}
		if v == nil {
			return "", nil, 0, "", &httpErr{http.StatusConflict, "no-version", "the context has no such kept version to build"}
		}
		plan, err := c.PlanImageBuildJob(ctx, tenant, control.ImageBuildJobQuery{ID: req.Build, Context: id, Version: v.ID})
		if err != nil {
			return "", nil, 0, "", err
		}
		return mydc.ActionBeginImageBuild, plan.Change, 0, "build/" + req.Build, nil
	}, holdBuild(tenant, id, req.Build))
}

// GET /t/{t}/builds?context=&after= → job rows (version numbers filled).
func (s *Server) handleImageBuildJobs(w http.ResponseWriter, r *http.Request, ws *webSession) {
	read(s, w, r, ws, func(ctx context.Context, c mydc.Conn) (listPage, error) {
		tenant, cx := r.PathValue("t"), r.URL.Query().Get("context")
		p, err := c.ImageBuilds(ctx, tenant, control.ImageBuildQuery{Part: "jobs", ID: cx}, r.URL.Query().Get("after"))
		if err != nil {
			return listPage{}, err
		}
		versions := map[string][]control.ImageBuildVersionView{}
		rows := []buildJobRow{}
		for _, j := range p.Jobs {
			if j.Deleted {
				continue
			}
			vs, ok := versions[j.Context]
			if !ok {
				if vs, err = liveVersions(ctx, c, tenant, j.Context); err != nil {
					vs = nil
				}
				versions[j.Context] = vs
			}
			rows = append(rows, jobRow(j, vs))
		}
		slices.SortStableFunc(rows, func(a, b buildJobRow) int { return strings.Compare(b.CreatedAt, a.CreatedAt) })
		return s.page(rows, p.Next, p.RootRevision), nil
	})
}

// GET /t/{t}/builds/{id}/log?after= → one byte page: {text, offset, next,
// total, available, truncated, gap, unclosed, phase, done}. next "" with
// done means the log is complete; otherwise read again with after=next.
func (s *Server) handleImageBuildLog(w http.ResponseWriter, r *http.Request, ws *webSession) {
	type logView struct {
		Text      string `json:"text"`
		Offset    uint32 `json:"offset"`
		Next      string `json:"next"`
		Total     uint32 `json:"total"`
		Available bool   `json:"available"`
		Truncated bool   `json:"truncated"`
		Gap       bool   `json:"gap"`
		Unclosed  bool   `json:"unclosed"`
		Phase     string `json:"phase"`
		Done      bool   `json:"done"`
	}
	read(s, w, r, ws, func(ctx context.Context, c mydc.Conn) (logView, error) {
		q, after := imagebuild.LogQuery{Job: r.PathValue("id"), MaxBytes: buildLogPage}, r.URL.Query().Get("after")
		if t := r.URL.Query().Get("tail"); t != "" && t != "0" {
			if after != "" {
				return logView{}, invalid("tail: not with after")
			}
			q.Tail = true // the last page; its next follows new output
		}
		p, err := c.ImageBuildLogs(ctx, r.PathValue("t"), q, after)
		if err != nil {
			return logView{}, err
		}
		g := p.Page
		return logView{Text: string(g.Data), Offset: g.Offset, Next: p.Next, Total: g.Total, Available: g.Available, Truncated: g.Truncated,
			Gap: g.Gap, Unclosed: g.Unclosed, Phase: p.Phase, Done: !g.Unclosed && p.Next == ""}, nil
	})
}

// jobOp: POST /t/{t}/builds/{id}/cancel and …/delete {opId} →
// cancel-image-build / delete-image-build-job (Expected = job revision).
func (s *Server) jobOp(action string) func(http.ResponseWriter, *http.Request, *webSession) {
	return func(w http.ResponseWriter, r *http.Request, ws *webSession) {
		var req struct {
			OpID string `json:"opId"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		tenant, id := r.PathValue("t"), r.PathValue("id")
		s.sharedCreate(w, r, ws, req.OpID, actionBody{action, req}, func(ctx context.Context, c mydc.Conn, _ mydc.Session) (string, any, uint64, string, error) {
			j, err := findJob(ctx, c, tenant, id)
			if err != nil {
				return "", nil, 0, "", err
			}
			return action, control.ImageBuildSelection{Tenant: tenant, ID: id}, j.Revision, "build/" + id, nil
		})
	}
}

// --- cache ---

type cacheScopeRow struct {
	Cache          string          `json:"cache"`
	Node           string          `json:"node"`
	Context        string          `json:"context"`
	Root           string          `json:"root"`
	Builder        string          `json:"builder"`
	Job            string          `json:"job"`
	ContextDeleted bool            `json:"contextDeleted,omitempty"`
	Code           string          `json:"code,omitempty"`
	Usage          *cacheUsageView `json:"usage,omitempty"`
}

// cacheCleanupView: the last cleanup's steps (times RFC 3339).
type cacheCleanupView struct {
	Job   string            `json:"job"`
	Steps []cacheCleanupRow `json:"steps"`
}

type cacheCleanupRow struct {
	Kind          string `json:"kind"`
	Selected      uint32 `json:"selected"`
	MaxUsedSpace  int64  `json:"maxUsedSpace"`
	SentAt        string `json:"sentAt,omitempty"`
	ReturnedAt    string `json:"returnedAt,omitempty"`
	Code          string `json:"code,omitempty"`
	RemovedCount  uint32 `json:"removedCount"`
	ReportedBytes int64  `json:"reportedBytes"`
}

func cleanupView(c *imagebuild.CacheCleanupStatus) *cacheCleanupView {
	if c == nil {
		return nil
	}
	out := &cacheCleanupView{Job: hex.EncodeToString(c.Job[:]), Steps: []cacheCleanupRow{}}
	for _, st := range c.Steps {
		out.Steps = append(out.Steps, cacheCleanupRow{Kind: st.Kind, Selected: st.Selected, MaxUsedSpace: st.MaxUsedSpace, SentAt: rfcU(st.SentAt),
			ReturnedAt: rfcU(st.ReturnedAt), Code: st.Code, RemovedCount: st.RemovedCount, ReportedBytes: st.ReportedBytes})
	}
	return out
}

// rfcU is rfc for an unsigned Unix time, "" for 0.
func rfcU(t uint64) string {
	if t == 0 {
		return ""
	}
	return rfc(int64(t))
}

// cacheUsageView: a cache scope's last observed usage.
type cacheUsageView struct {
	Recorded        bool                        `json:"recorded"`
	Available       bool                        `json:"available"`
	Borrowed        bool                        `json:"borrowed,omitempty"`
	ObservedAt      string                      `json:"observedAt,omitempty"`
	LastAttemptAt   string                      `json:"lastAttemptAt,omitempty"`
	LastAttemptCode string                      `json:"lastAttemptCode,omitempty"`
	ReportedBytes   int64                       `json:"reportedBytes"`
	Count           uint32                      `json:"count"`
	Kinds           []imagebuild.CacheKindUsage `json:"kinds"`
	Cleanup         *cacheCleanupView           `json:"cleanup,omitempty"`
	// ObservedKind is what took the observation: "" after a build,
	// "cache-prune" after a cleanup.
	ObservedKind string `json:"observedKind,omitempty"`
}

func usageView(u *imagebuild.CacheSummary) *cacheUsageView {
	if u == nil {
		return nil
	}
	v := &cacheUsageView{Recorded: u.Recorded, Available: u.Available, Borrowed: u.Borrowed, ObservedAt: rfcU(u.ObservedAt), LastAttemptAt: rfcU(u.LastAttemptAt),
		LastAttemptCode: u.LastAttemptCode, ReportedBytes: u.ReportedBytes, Count: u.Count, Kinds: u.Kinds, Cleanup: cleanupView(u.Cleanup), ObservedKind: u.ObservedKind}
	if v.Kinds == nil {
		v.Kinds = []imagebuild.CacheKindUsage{}
	}
	return v
}

type cacheNodeRow struct {
	Node          string `json:"node"`
	ReportedBytes int64  `json:"reportedBytes"`
	Entries       uint32 `json:"entries"`
	Scopes        int    `json:"scopes"`
}

type cacheCleaningRow struct {
	ID            string                      `json:"id"`
	Node          string                      `json:"node"`
	Context       string                      `json:"context"`
	Cache         string                      `json:"cache"`
	User          string                      `json:"user"`
	Filter        imagebuild.CachePruneFilter `json:"filter"`
	State         string                      `json:"state"`
	Code          string                      `json:"code,omitempty"`
	AcceptedAt    string                      `json:"acceptedAt,omitempty"`
	ClosedAt      string                      `json:"closedAt,omitempty"`
	RemovedCount  uint64                      `json:"removedCount,omitempty"`
	ReportedBytes int64                       `json:"reportedBytes,omitempty"`
	Automatic     bool                        `json:"automatic,omitempty"`
}

// GET /t/{t}/build-cache → {nodes:[{node, reportedBytes, entries,
// scopes}], caches:[scope rows], cleaning:[prune rows], cacheBytes}.
func (s *Server) handleImageBuildCache(w http.ResponseWriter, r *http.Request, ws *webSession) {
	type cacheView struct {
		CacheBytes int64              `json:"cacheBytes"`
		Cleanup    any                `json:"cleanup,omitempty"`
		Nodes      []cacheNodeRow     `json:"nodes"`
		Caches     []cacheScopeRow    `json:"caches"`
		Cleaning   []cacheCleaningRow `json:"cleaning"`
	}
	read(s, w, r, ws, func(ctx context.Context, c mydc.Conn) (cacheView, error) {
		tenant := r.PathValue("t")
		out := cacheView{Nodes: []cacheNodeRow{}, Caches: []cacheScopeRow{}, Cleaning: []cacheCleaningRow{}}
		if pol, err := currentPolicy(ctx, c, tenant); err == nil && pol != nil && !pol.Deleted {
			out.CacheBytes, out.Cleanup = pol.Spec.CacheBytes, pol.Spec.Cleanup
		}
		caches, err := buildPart(ctx, c, tenant, control.ImageBuildQuery{Part: "caches"})
		if err != nil {
			return out, err
		}
		byNode := map[string]*cacheNodeRow{}
		for _, x := range caches.Caches {
			out.Caches = append(out.Caches, cacheScopeRow{Cache: hex.EncodeToString(x.Cache[:]), Node: x.Node, Context: x.Context, Root: x.Root,
				Builder: x.Builder, Job: x.RepresentativeJob, ContextDeleted: x.ContextDeleted, Code: x.Code, Usage: usageView(x.Usage)})
			n := byNode[x.Node]
			if n == nil {
				n = &cacheNodeRow{Node: x.Node}
				byNode[x.Node] = n
			}
			n.Scopes++
			if x.Usage != nil {
				n.ReportedBytes += x.Usage.ReportedBytes
				n.Entries += x.Usage.Count
			}
		}
		for _, n := range byNode {
			out.Nodes = append(out.Nodes, *n)
		}
		slices.SortFunc(out.Nodes, func(a, b cacheNodeRow) int { return strings.Compare(a.Node, b.Node) })
		prunes, err := buildPart(ctx, c, tenant, control.ImageBuildQuery{Part: "cache-prunes"})
		if err != nil {
			return out, err
		}
		for _, x := range prunes.CachePrunes {
			row := cacheCleaningRow{ID: x.ID, Node: x.Node, Context: x.Context, Cache: hex.EncodeToString(x.Cache[:]), User: x.User, Filter: x.Filter,
				State: x.State, Code: x.Code, RemovedCount: x.RemovedCount, ReportedBytes: x.ReportedBytes, Automatic: x.Automatic}
			if x.At > 0 {
				row.AcceptedAt = rfc(int64(x.At))
			}
			if x.ClosedAt > 0 {
				row.ClosedAt = rfc(int64(x.ClosedAt))
			}
			out.Cleaning = append(out.Cleaning, row)
		}
		slices.SortStableFunc(out.Cleaning, func(a, b cacheCleaningRow) int { return strings.Compare(b.AcceptedAt, a.AcceptedAt) })
		return out, nil
	})
}

func parseHex32(s string) ([32]byte, bool) {
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return out, false
	}
	copy(out[:], b)
	return out, out != [32]byte{}
}

// GET /t/{t}/build-cache/entries?node=&cache=&after= → one page of a cache
// scope's entries (image-build-cache).
func (s *Server) handleImageBuildCacheEntries(w http.ResponseWriter, r *http.Request, ws *webSession) {
	cache, ok := parseHex32(r.URL.Query().Get("cache"))
	node := r.URL.Query().Get("node")
	if !ok || !safeParamRE.MatchString(node) {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "node and cache (hex) of a cache scope")
		return
	}
	type entryRow struct {
		ID         string `json:"id"`
		Kind       string `json:"kind"`
		Bytes      int64  `json:"bytes"`
		CreatedAt  string `json:"createdAt,omitempty"`
		LastUsedAt string `json:"lastUsedAt,omitempty"`
		Uses       uint64 `json:"uses"`
		InUse      bool   `json:"inUse"`
		Mutable    bool   `json:"mutable"`
		Shared     bool   `json:"shared"`
	}
	type entriesView struct {
		Available       bool              `json:"available"`
		Borrowed        bool              `json:"borrowed,omitempty"`
		ObservedAt      string            `json:"observedAt,omitempty"`
		LastAttemptAt   string            `json:"lastAttemptAt,omitempty"`
		LastAttemptCode string            `json:"lastAttemptCode,omitempty"`
		ReportedBytes   int64             `json:"reportedBytes"`
		Count           uint32            `json:"count"`
		Offset          uint32            `json:"offset"`
		Next            string            `json:"next"`
		Entries         []entryRow        `json:"entries"`
		Cleanup         *cacheCleanupView `json:"cleanup,omitempty"`
	}
	read(s, w, r, ws, func(ctx context.Context, c mydc.Conn) (entriesView, error) {
		p, err := c.ImageBuildCacheUsage(ctx, r.PathValue("t"), imagebuild.CacheQuery{Cache: &cache, Node: node}, r.URL.Query().Get("after"))
		if err != nil {
			return entriesView{}, err
		}
		g := p.Page
		out := entriesView{Available: g.Available, Borrowed: g.Borrowed, ObservedAt: rfcU(g.ObservedAt), LastAttemptAt: rfcU(g.LastAttemptAt), LastAttemptCode: g.LastAttemptCode,
			ReportedBytes: g.ReportedBytes, Count: g.Count, Offset: g.Offset, Next: p.Next, Entries: []entryRow{}, Cleanup: cleanupView(g.Cleanup)}
		for _, e := range g.Entries {
			row := entryRow{ID: e.ID, Kind: e.Kind, Bytes: e.Bytes, Uses: e.Uses, InUse: e.InUse, Mutable: e.Mutable, Shared: e.Shared}
			if e.CreatedAt > 0 {
				row.CreatedAt = rfc(e.CreatedAt)
			}
			if e.LastUsedAt > 0 {
				row.LastUsedAt = rfc(e.LastUsedAt)
			}
			out.Entries = append(out.Entries, row)
		}
		return out, nil
	})
}

// POST /t/{t}/build-cache/prune {opId, node, cache, filter:{mode:
// all|unused|entries, ids?, unusedDays?}} → prune-build-cache. Accepted is
// not done: progress is GET /build-cache cleaning.
func (s *Server) handlePruneImageBuildCache(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID   string `json:"opId"`
		Node   string `json:"node"`
		Cache  string `json:"cache"`
		Filter struct {
			Mode       string   `json:"mode"`
			IDs        []string `json:"ids,omitempty"`
			UnusedDays uint32   `json:"unusedDays,omitempty"`
		} `json:"filter"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant := r.PathValue("t")
	s.sharedCreate(w, r, ws, req.OpID, actionBody{"prune-build-cache", req}, func(ctx context.Context, c mydc.Conn, _ mydc.Session) (string, any, uint64, string, error) {
		cache, ok := parseHex32(req.Cache)
		f := imagebuild.CachePruneFilter{Mode: req.Filter.Mode, IDs: slices.Sorted(slices.Values(req.Filter.IDs)), UnusedDays: req.Filter.UnusedDays}
		if len(f.IDs) == 0 {
			f.IDs = nil
		}
		if !ok || !safeParamRE.MatchString(req.Node) || !f.Valid() {
			return "", nil, 0, "", invalid("node, cache (hex) and filter: all | unused with unusedDays | entries with ids (at most 64)")
		}
		ch := control.ImageBuildCachePruneChange{Tenant: tenant, ID: "prune-" + req.OpID, Node: req.Node, Cache: cache, Filter: f}
		return actPruneBuildCache, ch, 0, "build-cache", nil
	})
}
