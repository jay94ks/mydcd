// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"

	"github.com/distribution/reference"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagebuild"
)

// The fake's build world, which the real-contract views
// (fake_image_builds.go, fake_build_draft.go) are made from, and what is
// left of the REQ-19 mock: build-contexts and upload-build-zip for the
// REQ-47 zip upload. No builder runs: begin-image-build checks the version
// (Dockerfile, COPY sources, trusted FROM) and finishes at once, pushing
// the result into the REQ-18 image list and recording cache entries.
// Fake.SetBuildHold keeps new builds running (to cancel or FinishBuild
// them); Fake.SetGitSource sets what a Git repository holds. A Git
// repository containing "unreachable" fails check-build-context.

type buildCtx struct {
	row      BuildContext
	versions map[uint64]map[string][]byte
	draft    map[string][]byte
	rd       *realDraft // build-draft state (fake_build_draft.go)
}

type buildRec struct {
	b   Build
	log []string
	seq uint64
	// real-contract view (fake_image_builds.go): the job spec stamped at
	// start, a cancel request, and delete-image-build-job.
	spec            *imagebuild.JobSpec
	cancel, deleted bool
}

type gitSource struct {
	commit string
	files  map[string][]byte
}

type buildState struct {
	policy      map[string]BuildPolicy
	ctxs        map[string][]*buildCtx
	builds      map[string][]*buildRec
	seq         uint64
	cache       map[string][]BuildCacheEntry
	cachePolicy map[string]BuildCachePolicy
	rev         map[string]uint64
	hold        map[string]bool
	git         map[string]gitSource
	real        realBuildState
}

const fakeBuilder = "docker.io/moby/buildkit:v0.17.0-rootless@sha256:" + "4e3f0c1d2b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"

func defaultGitFiles(repo string) gitSource {
	d := fakeDigest("git", repo)
	return gitSource{commit: hexOf(d[:4]), files: map[string][]byte{
		"Dockerfile":     []byte("FROM docker.io/library/busybox:1.36\nCOPY app/ /app/\nCMD [\"/app/run\"]\n"),
		"app/run":        []byte("#!/bin/sh\necho hello\n"),
		"app/config.ini": []byte("[app]\nname=demo\n"),
	}}
}

func (w *world) seedBuilds(f Fixture) {
	b := &w.build
	*b = buildState{policy: map[string]BuildPolicy{}, ctxs: map[string][]*buildCtx{}, builds: map[string][]*buildRec{}, cache: map[string][]BuildCacheEntry{},
		cachePolicy: map[string]BuildCachePolicy{}, rev: map[string]uint64{}, hold: map[string]bool{}, git: map[string]gitSource{}}
	for _, p := range f.BuildPolicies {
		p.Nodes, p.Platforms, p.Builder = slices.Clone(p.Nodes), slices.Clone(p.Platforms), fakeBuilder
		if p.Revision == 0 {
			p.Revision = 1
		}
		b.policy[p.Tenant] = p
		b.cachePolicy[p.Tenant] = BuildCachePolicy{MaxPercent: 80, IdleDays: 30}
		b.rev[p.Tenant] = p.Revision
	}
	for _, s := range f.BuildContexts {
		c := &buildCtx{row: s.Context, versions: map[uint64]map[string][]byte{}}
		files := map[string][]byte{}
		for k, v := range s.Files {
			files[k] = []byte(v)
		}
		if c.row.Revision == 0 {
			c.row.Revision = 1
		}
		for _, v := range c.row.Versions {
			c.versions[v] = files
		}
		if c.row.Kind == BuildInline {
			c.draft = cloneFiles(files)
		}
		if c.row.Kind == BuildGit && c.row.Git != nil {
			b.git[c.row.Git.Repository] = gitSource{commit: c.row.Git.Commit, files: files}
		}
		b.ctxs[c.row.Tenant] = append(b.ctxs[c.row.Tenant], c)
	}
}

func cloneFiles(m map[string][]byte) map[string][]byte {
	out := map[string][]byte{}
	for k, v := range m {
		out[k] = slices.Clone(v)
	}
	return out
}

func (b *buildState) find(tenant, id string) *buildCtx {
	for _, c := range b.ctxs[tenant] {
		if c.row.ID == id {
			return c
		}
	}
	return nil
}

func (b *buildState) running(tenant string) int {
	n := 0
	for _, r := range b.builds[tenant] {
		if r.b.Status == BuildRunning {
			n++
		}
	}
	return n
}

// dockerfile parses FROM images (stage names and scratch left out) and
// COPY/ADD sources (no --from) with their line numbers.
type dockerfileInfo struct {
	from   []string
	copies map[string][]int // source → lines
}

func parseDockerfile(text string) dockerfileInfo {
	out := dockerfileInfo{copies: map[string][]int{}}
	stages := map[string]bool{}
	for i, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || strings.HasPrefix(f[0], "#") {
			continue
		}
		switch strings.ToUpper(f[0]) {
		case "FROM":
			args := slices.DeleteFunc(slices.Clone(f[1:]), func(s string) bool { return strings.HasPrefix(s, "--") })
			if len(args) == 0 {
				continue
			}
			if len(args) >= 3 && strings.EqualFold(args[1], "AS") {
				stages[strings.ToLower(args[2])] = true
			}
			if img := args[0]; img != "scratch" && !stages[strings.ToLower(img)] {
				out.from = append(out.from, img)
			}
		case "COPY", "ADD":
			args, from := []string{}, false
			for _, a := range f[1:] {
				if strings.HasPrefix(a, "--from=") {
					from = true
				}
				if !strings.HasPrefix(a, "--") {
					args = append(args, a)
				}
			}
			if from || len(args) < 2 || strings.HasPrefix(args[0], "[") {
				continue
			}
			for _, s := range args[:len(args)-1] {
				s = strings.TrimPrefix(path.Clean("/"+s), "/")
				out.copies[s] = append(out.copies[s], i+1)
			}
		}
	}
	return out
}

func srcCovers(src, file string) bool {
	if src == "" || src == "." {
		return true
	}
	if ok, _ := path.Match(src, file); ok {
		return true
	}
	return file == src || strings.HasPrefix(file, src+"/")
}

// missingSources: COPY/ADD sources of the Dockerfile that files lack.
func missingSources(files map[string][]byte, dockerfile string) []string {
	var out []string
	info := parseDockerfile(string(files[dockerfile]))
	for _, src := range sortedKeys(info.copies) {
		if !slices.ContainsFunc(sortedKeys(files), func(f string) bool { return srcCovers(src, f) }) {
			out = append(out, src)
		}
	}
	return out
}

func (w *world) trustedImage(tenant, image string) bool {
	n, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return false
	}
	return slices.ContainsFunc(w.trust[tenant], func(r TrustRule) bool {
		return r.Registry == reference.Domain(n) && (r.Repository == "**" || r.Repository == reference.Path(n))
	})
}

func (w *world) fetchGit(x *buildCtx) (gitSource, string) {
	repo := x.row.Git.Repository
	if strings.Contains(repo, "unreachable") {
		return gitSource{}, BuildSourceFetch
	}
	src, ok := w.build.git[repo]
	if !ok {
		src = defaultGitFiles(repo)
	}
	files := map[string][]byte{}
	prefix := strings.Trim(x.row.Git.Folder, "/")
	for k, v := range src.files {
		if prefix == "" {
			files[k] = v
		} else if rest, ok := strings.CutPrefix(k, prefix+"/"); ok {
			files[rest] = v
		}
	}
	return gitSource{commit: src.commit, files: files}, ""
}

func (b *buildState) cacheInUse(tenant string, e BuildCacheEntry) bool {
	return slices.ContainsFunc(b.builds[tenant], func(r *buildRec) bool {
		return r.b.Status == BuildRunning && r.b.Node == e.Node && slices.Contains(e.Contexts, r.b.Context)
	})
}

// --- injection ---

// SetBuildHold keeps the tenant's new builds running until FinishBuild or
// cancel-build.
func (f *Fake) SetBuildHold(tenant string, hold bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.w.build.hold[tenant] = hold
}

// FinishBuild ends a held build: code "" succeeds, otherwise fails with it.
func (f *Fake) FinishBuild(tenant, id, code string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w := f.w
	w.bumpKey(control.ImageBuildKey)
	for _, r := range w.build.builds[tenant] {
		if r.b.ID == id && r.b.Status == BuildRunning {
			w.finishBuild(r, code, f.now().Unix())
		}
	}
	w.build.rev[tenant] = w.root
}

// SetGitSource sets the files (and commit) a Git repository serves to
// Git build contexts.
func (f *Fake) SetGitSource(repository, commit string, files map[string]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	g := gitSource{commit: commit, files: map[string][]byte{}}
	for k, v := range files {
		g.files[k] = []byte(v)
	}
	f.w.build.git[repository] = g
}

// --- actions ---

func validFilePath(p string) bool {
	return p != "" && !strings.HasPrefix(p, "/") && !strings.HasSuffix(p, "/") && path.Clean(p) == p && p != "." && !strings.HasPrefix(p, "../") && p != ".."
}

// unzipContext refuses entries outside the root, links, devices and
// anything but regular files and folders.
func unzipContext(data []byte) (map[string][]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, errors.New("payload: not a zip")
	}
	files := map[string][]byte{}
	var total uint64
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if !f.Mode().IsRegular() || !validFilePath(f.Name) {
			return nil, errors.New("payload: zip entry " + f.Name)
		}
		total += f.UncompressedSize64
		if total > uint64(imagebuild.MaxZIPBytes) {
			return nil, errors.New("payload: zip too large")
		}
		rc, err := f.Open()
		if err != nil {
			return nil, errors.New("payload: zip entry " + f.Name)
		}
		b, err := io.ReadAll(io.LimitReader(rc, imagebuild.MaxZIPBytes+1))
		rc.Close()
		if err != nil {
			return nil, errors.New("payload: zip entry " + f.Name)
		}
		files[f.Name] = b
	}
	return files, nil
}

func (w *world) cancelBuild(r *buildRec, actor string, now int64) {
	r.b.Status, r.b.FinishedAt, r.cancel = BuildCanceled, now, true
	r.log = append(r.log, "canceled by "+w.users[actor].rec.Username)
	for j := range r.b.Steps {
		if r.b.Steps[j].Status == BuildRunning || r.b.Steps[j].Status == BuildQueued {
			r.b.Steps[j].Status = BuildCanceled
		}
	}
}

// startBuild runs job id of the context's version (begin-image-build: no
// Git refetch, the planned version is built).
func (c *fakeConn) startBuild(tenant, context, id, actor string, now int64, version uint64) error {
	w := c.f.w
	b := &w.build
	x := b.find(tenant, context)
	p := b.policy[tenant]
	if x == nil || len(p.Nodes) == 0 || slices.ContainsFunc(b.builds[tenant], func(r *buildRec) bool { return r.b.ID == id }) {
		return errCAS
	}
	if b.running(tenant) >= p.Concurrent {
		return errCAS
	}
	b.seq++
	r := &buildRec{seq: b.seq, b: Build{Tenant: tenant, ID: id, Context: context, Node: p.Nodes[(b.seq-1)%uint64(len(p.Nodes))],
		Status: BuildRunning, Submitter: w.users[actor].rec.Username, StartedAt: now,
		Steps: []BuildStep{{Name: "source", Status: BuildQueued}, {Name: "base", Status: BuildQueued}, {Name: "build", Status: BuildQueued}, {Name: "push", Status: BuildQueued}}}}
	b.builds[tenant] = append(b.builds[tenant], r)
	step := func(i int, status string) {
		r.b.Steps[i].Status = status
		if r.b.Steps[i].StartedAt == 0 {
			r.b.Steps[i].StartedAt = now
		}
		if status != BuildRunning {
			r.b.Steps[i].FinishedAt = now
		}
	}
	fail := func(i int, code, msg string) {
		step(i, BuildFailed)
		r.log = append(r.log, "error: "+msg)
		w.finishBuild(r, code, now)
	}
	// source
	step(0, BuildRunning)
	defer w.stampJob(r)
	files := x.versions[version]
	if x.row.Git != nil && version == x.row.Version {
		r.b.Commit = x.row.Git.Commit
	}
	r.b.ContextVersion = version
	if files == nil {
		fail(0, BuildBuildFailed, "the context has no version yet")
		return nil
	}
	missing := missingSources(files, x.row.Dockerfile)
	if _, ok := files[x.row.Dockerfile]; !ok || len(missing) > 0 {
		fail(0, BuildBuildFailed, "Dockerfile or COPY source missing: "+strings.Join(missing, ", "))
		return nil
	}
	r.log = append(r.log, fmt.Sprintf("context v%d: %d files", r.b.ContextVersion, len(files)))
	step(0, BuildSucceeded)
	// base
	step(1, BuildRunning)
	info := parseDockerfile(string(files[x.row.Dockerfile]))
	for _, f := range info.from {
		if !w.trustedImage(tenant, f) {
			fail(1, BuildUntrustedBase, "FROM "+f+" is not a trusted source of "+tenant)
			return nil
		}
		r.log = append(r.log, "FROM "+f)
	}
	step(1, BuildSucceeded)
	// build
	step(2, BuildRunning)
	for _, a := range x.row.Args {
		if a.Secret != nil {
			r.log = append(r.log, "ARG "+a.Name+"=*** (vault "+a.Secret.Realm+"/"+a.Secret.Object+" key "+a.Secret.Key+")")
		} else {
			r.log = append(r.log, "ARG "+a.Name+"="+a.Value)
		}
	}
	for _, s := range x.row.Secrets {
		r.log = append(r.log, "secret mount "+s.ID+" ← vault "+s.Realm+"/"+s.Object+" key "+s.Key)
	}
	w.touchCache(tenant, r, files, now)
	if b.hold[tenant] {
		return nil
	}
	w.finishBuild(r, "", now)
	return nil
}

func (w *world) touchCache(tenant string, r *buildRec, files map[string][]byte, now int64) {
	b := &w.build
	var size uint64
	for _, v := range files {
		size += uint64(len(v))
	}
	for _, kind := range []string{BuildCacheExec, BuildCacheBase, BuildCacheMount, BuildCacheSource} {
		d := fakeDigest("build-cache", tenant, r.b.Node, r.b.Context, kind)
		id := hexOf(d[:6])
		i := slices.IndexFunc(b.cache[tenant], func(e BuildCacheEntry) bool { return e.ID == id })
		bytes := map[string]uint64{BuildCacheExec: 120 << 20, BuildCacheBase: 40 << 20, BuildCacheMount: 16 << 20, BuildCacheSource: size}[kind]
		if i < 0 {
			b.cache[tenant] = append(b.cache[tenant], BuildCacheEntry{ID: id, Node: r.b.Node, Kind: kind, Summary: kind + " cache of " + r.b.Context, Contexts: []string{r.b.Context}, Bytes: bytes, LastUsed: now})
		} else {
			b.cache[tenant][i].LastUsed, b.cache[tenant][i].Bytes = now, bytes
		}
	}
}

func (w *world) finishBuild(r *buildRec, code string, now int64) {
	x := w.build.find(r.b.Tenant, r.b.Context)
	r.b.FinishedAt = now
	for i := range r.b.Steps {
		if r.b.Steps[i].Status == BuildRunning {
			r.b.Steps[i].Status, r.b.Steps[i].FinishedAt = BuildSucceeded, now
			if code != "" {
				r.b.Steps[i].Status = BuildFailed
			}
		}
	}
	if code != "" {
		r.b.Status, r.b.Code = BuildFailed, code
		for i := range r.b.Steps {
			if r.b.Steps[i].Status == BuildQueued {
				r.b.Steps[i].Status = BuildCanceled
			}
		}
		r.log = append(r.log, "build failed: "+code)
		return
	}
	if x == nil {
		r.b.Status, r.b.Code = BuildFailed, BuildBuildFailed
		return
	}
	tag := x.row.TagRule
	tag = strings.ReplaceAll(tag, "{version}", fmt.Sprintf("v%d", r.b.ContextVersion))
	tag = strings.ReplaceAll(tag, "{commit}", r.b.Commit)
	tag = strings.ReplaceAll(tag, "{build}", r.b.ID)
	sum := fakeDigest("build", r.b.Tenant, r.b.ID)
	r.b.Digest, r.b.Bytes = "sha256:"+hexOf(sum[:]), 64<<20+uint64(len(x.versions[r.b.ContextVersion]))*4096
	r.b.Image = x.row.Repository + ":" + tag
	r.b.Steps[3] = BuildStep{Name: "push", Status: BuildSucceeded, StartedAt: now, FinishedAt: now}
	r.b.Status = BuildSucceeded
	r.log = append(r.log, "pushed "+builtinRegistryHost+"/"+r.b.Image+"@"+r.b.Digest)
	imgs := w.img.images[r.b.Tenant]
	for i := range imgs {
		if imgs[i].Repository == x.row.Repository {
			imgs[i].Tags = slices.DeleteFunc(imgs[i].Tags, func(t string) bool { return t == tag })
		}
	}
	w.img.images[r.b.Tenant] = append(imgs, RegistryImage{Registry: ImageRegistryBuiltin, Repository: x.row.Repository, Digest: r.b.Digest, Tags: []string{tag}, Bytes: r.b.Bytes, PushedAt: now})
}
