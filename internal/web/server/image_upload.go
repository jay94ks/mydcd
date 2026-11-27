// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/jay94ks/seafield/internal/web/sfc"
)

// Image upload (UI-88): the browser sends an image archive in chunks (it
// can resume after a reload), the web lists the images in it, and pushes
// the chosen one to a built-in registry under the name and tag the user
// picks. The archive lives in the web's data folder until it is deleted or
// a day passes. Pushing needs a push credential sfcd issues for the
// repository; the web only gates the use of its disk on the workspace
// manager role sfcd reports.

const (
	uploadChunkBytes = 8 << 20
	maxUploadBytes   = 10 << 30
	uploadTTL        = 24 * time.Hour
	maxUploadsUser   = 3
)

var uploadIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

type layerProgress struct {
	Digest string `json:"digest"`
	Bytes  int64  `json:"bytes"`
	Done   int64  `json:"done"`
	State  string `json:"state"` // waiting / checking / skipped / uploading / uploaded
}

type pushState struct {
	Item       int             `json:"item"`
	Repository string          `json:"repository"`
	Tag        string          `json:"tag"`
	State      string          `json:"state"` // preparing / pushing / done / failed / canceled
	Digest     string          `json:"digest,omitempty"`
	Error      string          `json:"error,omitempty"`
	Layers     []layerProgress `json:"layers"`
	StartedAt  time.Time       `json:"startedAt"`
	FinishedAt *time.Time      `json:"finishedAt,omitempty"`
}

type inspectState struct {
	State string        `json:"state"` // running / done / failed
	Error string        `json:"error,omitempty"`
	Items []archiveItem `json:"items,omitempty"`
}

// uploadMeta is saved as meta.json next to the data.
type uploadMeta struct {
	ID, User, Tenant, Registry string
	FileName                   string
	Bytes                      int64
	Received                   []bool
	CreatedAt                  time.Time
	Inspect                    *inspectState
	Push                       *pushState
}

type imageUploadRec struct {
	mu     sync.Mutex
	dir    string
	meta   uploadMeta
	arch   *imageArchive
	cancel context.CancelFunc
}

type uploadSet struct {
	mu sync.Mutex
	m  map[string]*imageUploadRec
}

func (s *Server) uploadRoot() string {
	if s.opt.DataDir == "" {
		return ""
	}
	return filepath.Join(s.opt.DataDir, "image-uploads")
}

func (u *imageUploadRec) save() error {
	raw, _ := json.Marshal(u.meta)
	tmp := filepath.Join(u.dir, "meta.json.tmp")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(u.dir, "meta.json"))
}

func (u *imageUploadRec) chunks() int {
	return int((u.meta.Bytes + uploadChunkBytes - 1) / uploadChunkBytes)
}

func (u *imageUploadRec) complete() bool { return !slices.Contains(u.meta.Received, false) }

// loadUpload finds an upload by ID (memory, then disk after a restart).
func (s *Server) loadUpload(id string) *imageUploadRec {
	if !uploadIDRE.MatchString(id) || s.uploadRoot() == "" {
		return nil
	}
	s.uploads.mu.Lock()
	defer s.uploads.mu.Unlock()
	if u := s.uploads.m[id]; u != nil {
		return u
	}
	dir := filepath.Join(s.uploadRoot(), id)
	raw, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return nil
	}
	u := &imageUploadRec{dir: dir}
	if json.Unmarshal(raw, &u.meta) != nil || u.meta.ID != id {
		return nil
	}
	// Work that was running when the daemon stopped did not finish.
	if u.meta.Inspect != nil && u.meta.Inspect.State == "running" {
		u.meta.Inspect = nil
	}
	if p := u.meta.Push; p != nil && (p.State == "preparing" || p.State == "pushing") {
		p.State, p.Error = "failed", "the web daemon restarted during the push"
	}
	if s.uploads.m == nil {
		s.uploads.m = map[string]*imageUploadRec{}
	}
	s.uploads.m[id] = u
	return u
}

// sweepUploads removes expired uploads and returns the caller's live ones.
func (s *Server) sweepUploads(user string) []*imageUploadRec {
	root := s.uploadRoot()
	ents, _ := os.ReadDir(root)
	var mine []*imageUploadRec
	for _, e := range ents {
		u := s.loadUpload(e.Name())
		if u == nil {
			continue
		}
		u.mu.Lock()
		expired := s.now().Sub(u.meta.CreatedAt) > uploadTTL && (u.meta.Push == nil || u.meta.Push.State != "pushing")
		owner := u.meta.User
		u.mu.Unlock()
		if expired {
			s.removeUpload(u)
			continue
		}
		if owner == user {
			mine = append(mine, u)
		}
	}
	return mine
}

func (s *Server) removeUpload(u *imageUploadRec) {
	u.mu.Lock()
	if u.cancel != nil {
		u.cancel()
	}
	if u.arch != nil {
		u.arch.Close()
		u.arch = nil
	}
	id := u.meta.ID
	u.mu.Unlock()
	s.uploads.mu.Lock()
	delete(s.uploads.m, id)
	s.uploads.mu.Unlock()
	_ = os.RemoveAll(u.dir)
}

type uploadView struct {
	ID         string        `json:"id"`
	Registry   string        `json:"registry"`
	FileName   string        `json:"fileName"`
	Bytes      int64         `json:"bytes"`
	ChunkBytes int64         `json:"chunkBytes"`
	Chunks     int           `json:"chunks"`
	Received   int           `json:"received"`
	Missing    []int         `json:"missing"` // first 200
	CreatedAt  string        `json:"createdAt"`
	ExpiresAt  string        `json:"expiresAt"`
	Inspect    *inspectState `json:"inspect,omitempty"`
	Push       *pushState    `json:"push,omitempty"`
}

func viewUpload(u *imageUploadRec) uploadView {
	v := uploadView{ID: u.meta.ID, Registry: u.meta.Registry, FileName: u.meta.FileName, Bytes: u.meta.Bytes, ChunkBytes: uploadChunkBytes,
		Chunks: u.chunks(), Missing: []int{}, CreatedAt: rfc3339(u.meta.CreatedAt), ExpiresAt: rfc3339(u.meta.CreatedAt.Add(uploadTTL)),
		Inspect: u.meta.Inspect}
	for i, ok := range u.meta.Received {
		if ok {
			v.Received++
		} else if len(v.Missing) < 200 {
			v.Missing = append(v.Missing, i)
		}
	}
	if u.meta.Push != nil {
		p := *u.meta.Push
		p.Layers = slices.Clone(p.Layers)
		v.Push = &p
	}
	return v
}

// upload returns the caller's upload of this tenant/registry, or writes 404.
func (s *Server) upload(w http.ResponseWriter, r *http.Request, ws *webSession) *imageUploadRec {
	u := s.loadUpload(r.PathValue("uid"))
	if u != nil {
		u.mu.Lock()
		ok := u.meta.User == ws.user.ID && u.meta.Tenant == r.PathValue("t") && u.meta.Registry == r.PathValue("id")
		u.mu.Unlock()
		if ok {
			return u
		}
	}
	writeError(w, http.StatusNotFound, "not-found", "no such upload")
	return nil
}

// POST /t/{t}/registries/{id}/uploads {fileName, bytes} → the upload: send
// its chunks (chunkBytes each, the last one shorter) with PUT …/chunks/{n}.
func (s *Server) handleCreateUpload(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		FileName string `json:"fileName"`
		Bytes    int64  `json:"bytes"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if s.uploadRoot() == "" {
		writeError(w, http.StatusServiceUnavailable, "no-data-dir", "the web has no data folder for uploads")
		return
	}
	if req.Bytes < 1 || req.Bytes > maxUploadBytes || len(req.FileName) > 255 {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "bytes: 1 byte .. 10 GiB; fileName: at most 255 characters")
		return
	}
	tenant := r.PathValue("t")
	if !s.requireRole(w, r, ws, tenant, true) {
		return
	}
	if len(s.sweepUploads(ws.user.ID)) >= maxUploadsUser {
		writeError(w, http.StatusConflict, "too-many-uploads", "finish or delete an earlier upload first (at most 3)")
		return
	}
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	id := hex.EncodeToString(b)
	dir := filepath.Join(s.uploadRoot(), id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "could not prepare the upload folder")
		return
	}
	f, err := os.Create(filepath.Join(dir, "data"))
	if err == nil {
		err = f.Truncate(req.Bytes)
		f.Close()
	}
	u := &imageUploadRec{dir: dir, meta: uploadMeta{ID: id, User: ws.user.ID, Tenant: tenant, Registry: r.PathValue("id"), FileName: req.FileName,
		Bytes: req.Bytes, CreatedAt: s.now()}}
	u.meta.Received = make([]bool, u.chunks())
	if err == nil {
		err = u.save()
	}
	if err != nil {
		_ = os.RemoveAll(dir)
		writeError(w, http.StatusInsufficientStorage, "no-space", "the web could not reserve space for the upload")
		return
	}
	s.uploads.mu.Lock()
	if s.uploads.m == nil {
		s.uploads.m = map[string]*imageUploadRec{}
	}
	s.uploads.m[id] = u
	s.uploads.mu.Unlock()
	writeJSON(w, http.StatusCreated, viewUpload(u))
}

// GET /t/{t}/registries/{id}/uploads → {items}: the caller's uploads here.
func (s *Server) handleListUploads(w http.ResponseWriter, r *http.Request, ws *webSession) {
	items := []uploadView{}
	for _, u := range s.sweepUploads(ws.user.ID) {
		u.mu.Lock()
		if u.meta.Tenant == r.PathValue("t") && u.meta.Registry == r.PathValue("id") {
			items = append(items, viewUpload(u))
		}
		u.mu.Unlock()
	}
	writeJSON(w, http.StatusOK, s.page(items, "", 0))
}

// GET /t/{t}/registries/{id}/uploads/{uid} → the upload with its inspect
// and push progress.
func (s *Server) handleGetUpload(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if u := s.upload(w, r, ws); u != nil {
		u.mu.Lock()
		v := viewUpload(u)
		u.mu.Unlock()
		writeJSON(w, http.StatusOK, v)
	}
}

// DELETE /t/{t}/registries/{id}/uploads/{uid}: cancels a push and removes
// the archive.
func (s *Server) handleDeleteUpload(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if u := s.upload(w, r, ws); u != nil {
		s.removeUpload(u)
		w.WriteHeader(http.StatusNoContent)
	}
}

// PUT /t/{t}/registries/{id}/uploads/{uid}/chunks/{n} with the chunk as the
// body (exactly chunkBytes, the last one the rest) → {received, missing}.
// Sending a chunk again overwrites it.
func (s *Server) handleUploadChunk(w http.ResponseWriter, r *http.Request, ws *webSession) {
	u := s.upload(w, r, ws)
	if u == nil {
		return
	}
	n, err := strconv.Atoi(r.PathValue("n"))
	u.mu.Lock()
	chunks, total, busy := u.chunks(), u.meta.Bytes, u.meta.Inspect != nil
	u.mu.Unlock()
	if err != nil || n < 0 || n >= chunks {
		writeError(w, http.StatusBadRequest, "bad-request", "no such chunk")
		return
	}
	if busy {
		writeError(w, http.StatusConflict, "inspected", "the archive was already read; start a new upload")
		return
	}
	want := int64(uploadChunkBytes)
	if n == chunks-1 {
		want = total - int64(n)*uploadChunkBytes
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, want))
	if err != nil || int64(len(data)) != want {
		writeError(w, http.StatusBadRequest, "bad-request", "the chunk must be exactly "+strconv.FormatInt(want, 10)+" bytes")
		return
	}
	f, err := os.OpenFile(filepath.Join(u.dir, "data"), os.O_WRONLY, 0)
	if err == nil {
		_, err = f.WriteAt(data, int64(n)*uploadChunkBytes)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}
	if err != nil {
		writeError(w, http.StatusInsufficientStorage, "no-space", "the web could not write the chunk")
		return
	}
	u.mu.Lock()
	u.meta.Received[n] = true
	err = u.save()
	v := viewUpload(u)
	u.mu.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "could not save the upload state")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"received": v.Received, "missing": v.Missing})
}

// POST /t/{t}/registries/{id}/uploads/{uid}/inspect → 202 with
// inspect.state running; read the upload until it is done (items) or
// failed (error).
func (s *Server) handleInspectUpload(w http.ResponseWriter, r *http.Request, ws *webSession) {
	u := s.upload(w, r, ws)
	if u == nil {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.complete() {
		writeError(w, http.StatusConflict, "incomplete", "some chunks are still missing")
		return
	}
	if u.meta.Inspect != nil && u.meta.Inspect.State != "failed" {
		writeJSON(w, http.StatusOK, viewUpload(u))
		return
	}
	u.meta.Inspect = &inspectState{State: "running"}
	_ = u.save()
	go s.inspectUpload(u)
	writeJSON(w, http.StatusAccepted, viewUpload(u))
}

func (s *Server) inspectUpload(u *imageUploadRec) {
	set := func(st inspectState, a *imageArchive) {
		u.mu.Lock()
		u.meta.Inspect = &st
		u.arch = a
		_ = u.save()
		u.mu.Unlock()
	}
	tarPath, err := plainTar(filepath.Join(u.dir, "data"), filepath.Join(u.dir, "data.tar"))
	if err != nil {
		set(inspectState{State: "failed", Error: err.Error()}, nil)
		return
	}
	a, err := openImageArchive(tarPath)
	if err != nil {
		set(inspectState{State: "failed", Error: err.Error()}, nil)
		return
	}
	items, err := a.items()
	if err == nil && len(items) == 0 {
		err = errors.New("the archive holds no complete image")
	}
	if err != nil {
		a.Close()
		set(inspectState{State: "failed", Error: err.Error()}, nil)
		return
	}
	set(inspectState{State: "done", Items: items}, a)
}

// archiveOf reopens the archive after a restart (u.mu held).
func (u *imageUploadRec) archiveOf() (*imageArchive, error) {
	if u.arch != nil {
		return u.arch, nil
	}
	p := filepath.Join(u.dir, "data.tar")
	if _, err := os.Stat(p); err != nil {
		p = filepath.Join(u.dir, "data")
	}
	a, err := openImageArchive(p)
	if err != nil {
		return nil, err
	}
	u.arch = a
	return a, nil
}

// POST /t/{t}/registries/{id}/uploads/{uid}/push {item, repository, tag,
// overwrite?} → 202 with push progress (read the upload until state done
// or failed). A tag that already points at another image answers 409
// tag-exists {current, usage} unless overwrite is true.
func (s *Server) handlePushUpload(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Item       int    `json:"item"`
		Repository string `json:"repository"`
		Tag        string `json:"tag"`
		Overwrite  bool   `json:"overwrite,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !tagRE.MatchString(req.Tag) {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "tag: letters, digits, _ . - (at most 128, not starting with . or -)")
		return
	}
	u := s.upload(w, r, ws)
	if u == nil {
		return
	}
	u.mu.Lock()
	if u.meta.Inspect == nil || u.meta.Inspect.State != "done" || req.Item < 0 || req.Item >= len(u.meta.Inspect.Items) {
		u.mu.Unlock()
		writeError(w, http.StatusConflict, "not-inspected", "inspect the archive and choose one of its items")
		return
	}
	if p := u.meta.Push; p != nil && (p.State == "preparing" || p.State == "pushing") {
		u.mu.Unlock()
		writeError(w, http.StatusConflict, "pushing", "a push of this upload is running")
		return
	}
	a, err := u.archiveOf()
	var plan *pushPlan
	if err == nil {
		var items []archiveItem
		if items, err = a.items(); err == nil && req.Item < len(items) {
			plan = items[req.Item].plan
		}
	}
	u.mu.Unlock()
	if plan == nil {
		writeError(w, http.StatusConflict, "archive", "the archive cannot be read again; start a new upload")
		return
	}
	tenant, id := r.PathValue("t"), r.PathValue("id")
	ctx, cancel := s.callCtx(r)
	c, err := s.registryClient(ctx, ws, tenant, id, req.Repository, "pull", "push")
	if err == nil && !req.Overwrite {
		var cur string
		if cur, err = c.headManifest(ctx, req.Tag); err == nil && cur != "" && (plan.Manifests[0].Digest == "" || cur != plan.digest()) {
			err = s.tagConflict(ctx, ws, c, tenant, req.Repository, req.Tag, cur)
		}
	}
	cancel()
	if err != nil {
		s.writeTagError(w, ws, err)
		return
	}
	u.mu.Lock()
	pctx, pcancel := context.WithCancel(context.Background())
	u.cancel = pcancel
	u.meta.Push = &pushState{Item: req.Item, Repository: req.Repository, Tag: req.Tag, State: "preparing", Layers: []layerProgress{}, StartedAt: s.now()}
	_ = u.save()
	v := viewUpload(u)
	u.mu.Unlock()
	go s.runPush(pctx, u, c, plan, tenant, id, req.Tag)
	writeJSON(w, http.StatusAccepted, v)
}

var tagRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)

// tagConflictErr: the tag points at another image.
type tagConflictErr struct {
	Current string    `json:"current"`
	Usage   *imageUse `json:"usage,omitempty"`
}

type imageUse = imageUseView

func (e *tagConflictErr) Error() string { return "tag-exists" }

func (s *Server) tagConflict(ctx context.Context, ws *webSession, c *regClient, tenant, repo, tag, cur string) error {
	e := &tagConflictErr{Current: cur}
	ref := c.authority() + "/" + repo + ":" + tag
	_ = ws.do(ctx, func(ctx context.Context, mc sfc.Conn) error {
		arch, err := s.archivedImages(tenant)
		if err != nil {
			return err
		}
		v, err := s.usageOf(ctx, mc, tenant, ref, arch)
		if err != nil {
			return err
		}
		e.Usage = &v
		return nil
	})
	return e
}

func (s *Server) writeTagError(w http.ResponseWriter, ws *webSession, err error) {
	var tc *tagConflictErr
	if errors.As(err, &tc) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": apiError{Code: "tag-exists", Message: "the tag already points at another image"},
			"current": tc.Current, "usage": tc.Usage})
		return
	}
	s.writeOpOutcome(w, ws, nil, 0, err)
}

func (c *regClient) authority() string {
	_, a, _ := cutScheme(c.base)
	return a
}

func cutScheme(base string) (string, string, bool) {
	for _, p := range []string{"https://", "http://"} {
		if len(base) > len(p) && base[:len(p)] == p {
			return p, base[len(p):], true
		}
	}
	return "", base, false
}

// runPush uploads the plan's blobs (skipping what the registry has), then
// its manifests; the last one under the tag.
func (s *Server) runPush(ctx context.Context, u *imageUploadRec, c *regClient, plan *pushPlan, tenant, id, tag string) {
	update := func(fn func(p *pushState)) {
		u.mu.Lock()
		fn(u.meta.Push)
		_ = u.save()
		u.mu.Unlock()
	}
	fail := func(err error) {
		state := "failed"
		if errors.Is(err, context.Canceled) {
			state = "canceled"
		}
		update(func(p *pushState) {
			now := s.now()
			p.State, p.Error, p.FinishedAt = state, pushErrorText(err), &now
		})
	}
	u.mu.Lock()
	a := u.arch
	u.mu.Unlock()
	if a == nil {
		fail(errors.New("the archive is not open"))
		return
	}
	if err := a.finishLegacy(plan); err != nil {
		fail(err)
		return
	}
	seen := map[string]bool{}
	var blobs []pushBlob
	for _, b := range plan.Blobs {
		if !seen[b.Digest] {
			seen[b.Digest] = true
			blobs = append(blobs, b)
		}
	}
	update(func(p *pushState) {
		p.State = "pushing"
		for _, b := range blobs {
			p.Layers = append(p.Layers, layerProgress{Digest: b.Digest, Bytes: b.Size, State: "waiting"})
		}
	})
	for i, b := range blobs {
		setLayer := func(state string, done int64) {
			update(func(p *pushState) { p.Layers[i].State, p.Layers[i].Done = state, done })
		}
		setLayer("checking", 0)
		ok, err := c.blobExists(ctx, b.Digest)
		if err != nil {
			fail(err)
			return
		}
		if ok {
			setLayer("skipped", b.Size)
			continue
		}
		setLayer("uploading", 0)
		var last time.Time
		err = c.pushBlob(ctx, b.Digest, b.Size, func() (io.Reader, error) {
			r, err := b.open()
			if err != nil {
				return nil, err
			}
			return &progressReader{r: r, fn: func(n int64) {
				if time.Since(last) > time.Second {
					last = time.Now()
					setLayer("uploading", n)
				}
			}}, nil
		})
		if err != nil {
			fail(err)
			return
		}
		setLayer("uploaded", b.Size)
	}
	for i, m := range plan.Manifests {
		ref := m.Digest
		if i == len(plan.Manifests)-1 {
			ref = tag
		}
		if err := c.putManifest(ctx, ref, m.MediaType, m.Body); err != nil {
			fail(err)
			return
		}
	}
	s.images.drop(tenant, id)
	update(func(p *pushState) {
		now := s.now()
		p.State, p.Digest, p.FinishedAt = "done", plan.digest(), &now
	})
}

func pushErrorText(err error) string {
	var he *httpErr
	if errors.As(err, &he) {
		return he.msg
	}
	var me *sfc.Error
	if errors.As(err, &me) {
		return "sfcd refused the registry credential (" + string(me.Code) + ")"
	}
	return err.Error()
}

type progressReader struct {
	r  io.Reader
	n  int64
	fn func(int64)
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.n += int64(n)
	p.fn(p.n)
	return n, err
}
