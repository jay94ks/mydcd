// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/web/mydc"
	"github.com/jay94ks/mydcd/internal/web/store"
)

// Files in a tenant volume (REQ-28, docs/reference/volume-files.md). Every
// list/get/put/delete is a signed volume-file op of the session user
// (volume_file_jobs.go): the op holds the path, size and digest, never the
// content, which goes on its own purpose18 stream. mydcd checks the path,
// the capacity and who may touch it (tenant manager, or a
// volume-file-grant on a path prefix).

// maxVolumeFileWeb: the largest file one web request uploads or downloads
// (held in memory while it streams).
const maxVolumeFileWeb = 64 << 20

// GET /t/{t}/volumes/{name}/files?prefix=&after= → {items:[{path, bytes,
// modifiedAt}], next}: one 64-entry page (one volume-file-list op).
func (s *Server) handleVolumeFiles(w http.ResponseWriter, r *http.Request, ws *webSession) {
	q := r.URL.Query()
	tenant, volume := r.PathValue("t"), r.PathValue("name")
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var items []vfEntry
	var next string
	err := ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		lq := control.VolumeFileQuery{Volume: volume, Path: q.Get("prefix"), Method: mydc.ActionListVolumeFiles, After: q.Get("after")}
		res, err := s.runVolumeFile(ctx, c, ws, vfJob{tenant: tenant, q: lq, o: newVolumeFileOp(ws, "", tenant, lq, nil)})
		if err != nil {
			return volumeFileErr(err)
		}
		if err := replyErr(res.reply); err != nil {
			return err
		}
		for _, e := range res.reply.Entries {
			items = append(items, vfEntry{Path: e.Path, Bytes: e.Size, ModifiedAt: e.ModifiedAt})
		}
		next = res.reply.Next
		return nil
	})
	if err != nil {
		s.writeVolumeFileError(w, ws, err)
		return
	}
	if items == nil {
		items = []vfEntry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next": next})
}

// GET /t/{t}/volumes/{name}/file?path= → the file's bytes (attachment,
// never rendered, at most 64 MiB), X-MyDC-Digest = its SHA-256. The bytes
// are sent only after their length and digest match mydcd's reply.
func (s *Server) handleVolumeFileGet(w http.ResponseWriter, r *http.Request, ws *webSession) {
	path := r.URL.Query().Get("path")
	if path == "" {
		writeError(w, http.StatusBadRequest, "bad-request", "path is required")
		return
	}
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var res vfResult
	err := ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		var err error
		res, err = s.volumeFileGet(ctx, c, ws, r.PathValue("t"), r.PathValue("name"), path, maxVolumeFileWeb, nil)
		if err != nil {
			return volumeFileErr(err)
		}
		return replyErr(res.reply)
	})
	if err != nil {
		s.writeVolumeFileError(w, ws, err)
		return
	}
	defer clear(res.data)
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Disposition", "attachment")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "sandbox")
	h.Set("Cache-Control", "no-store")
	h.Set("X-MyDC-Digest", "sha256:"+hex.EncodeToString(res.reply.Result.Digest[:]))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(res.data)
}

// PUT /t/{t}/volumes/{name}/file?path=&opId=&overwrite=1 with the content as
// the body (at most 64 MiB) → {op, file:{path, bytes, digest}}. The same
// opId with the same content resumes that op's stream instead of signing
// again (after a lost reply, 502 volume-file-unknown).
func (s *Server) handlePutVolumeFile(w http.ResponseWriter, r *http.Request, ws *webSession) {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxVolumeFileWeb))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "too-large", "a file uploaded through the web is at most 64 MiB")
		return
	}
	defer clear(data)
	q := r.URL.Query()
	path := q.Get("path")
	if path == "" || len(path) > 1024 {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "path: a file path in the volume")
		return
	}
	pq := control.VolumeFileQuery{Volume: r.PathValue("name"), Path: path, Method: mydc.ActionPutVolumeFile, Size: int64(len(data)),
		MaxBytes: maxVolumeFileWeb, Digest: sha256.Sum256(data), Overwrite: q.Get("overwrite") == "1"}
	s.volumeFileWrite(w, r, ws, q.Get("opId"), pq, data)
}

// DELETE /t/{t}/volumes/{name}/file {opId, path} → {op, file}.
func (s *Server) handleDeleteVolumeFile(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID string `json:"opId"`
		Path string `json:"path"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if req.Path == "" {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "path: a file path in the volume")
		return
	}
	s.volumeFileWrite(w, r, ws, req.OpID, control.VolumeFileQuery{Volume: r.PathValue("name"), Path: req.Path, Method: mydc.ActionDeleteVolumeFile}, nil)
}

// volumeFileWrite runs a put or delete under the person's opId.
func (s *Server) volumeFileWrite(w http.ResponseWriter, r *http.Request, ws *webSession, opID string, q control.VolumeFileQuery, body []byte) {
	if !uuidRE.MatchString(opID) {
		writeError(w, http.StatusBadRequest, "bad-request", "opId must be a lowercase UUID v4")
		return
	}
	tenant := r.PathValue("t")
	o := newVolumeFileOp(ws, opID, tenant, q, nil)
	if old, err := s.opt.Store.GetOp(ws.user.ID, opID); err == nil {
		if old.Digest != o.Digest {
			writeError(w, http.StatusConflict, "op-conflict", "this opId was already used for a different change")
			return
		}
		o = old
	} else if !errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var res vfResult
	err := ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		var err error
		res, err = s.runVolumeFile(ctx, c, ws, vfJob{tenant: tenant, q: q, body: body, o: o})
		if err != nil {
			return volumeFileErr(err)
		}
		return replyErr(res.reply)
	})
	if err != nil {
		s.writeVolumeFileError(w, ws, err)
		return
	}
	file := map[string]any{"path": q.Path}
	if rr := res.reply.Result; rr != nil {
		file["bytes"], file["digest"] = rr.Size, "sha256:"+hex.EncodeToString(rr.Digest[:])
	}
	writeJSON(w, http.StatusOK, map[string]any{"op": viewOp(res.op), "file": file})
}

func (s *Server) writeVolumeFileError(w http.ResponseWriter, ws *webSession, err error) {
	var he *httpErr
	if errors.As(err, &he) {
		writeError(w, he.status, he.code, he.msg)
		return
	}
	s.writeBackendError(w, ws, err)
}

// POST /t/{t}/volumes/{name}/file-grants {opId, prefix, user} →
// volume-file-grant; DELETE the same → volume-file-revoke. prefix ends with
// "/"; user is the account's user ID (an automation account), who must be
// a member of the workspace (mydcd refuses otherwise). Expected is the
// access catalog revision of the tenant members read (Page.Collection =
// TenantMembersRevision; Page.Revision is the tenant's own).
func (s *Server) handleVolumeFileGrant(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID   string `json:"opId"`
		Prefix string `json:"prefix"`
		User   string `json:"user"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	action := mydc.ActionGrantVolumeFiles
	if r.Method == http.MethodDelete {
		action = mydc.ActionRevokeVolumeFileGrant
	}
	tenant, volume := r.PathValue("t"), r.PathValue("name")
	s.sharedCreate(w, r, ws, req.OpID, actionBody{action, req}, func(ctx context.Context, c mydc.Conn, _ mydc.Session) (string, any, uint64, string, error) {
		if len(req.Prefix) < 2 || req.Prefix[len(req.Prefix)-1] != '/' || req.User == "" {
			return "", nil, 0, "", invalid("prefix: a folder ending with /, user: the account's user ID")
		}
		p, err := c.TenantMembers(ctx, tenant, "")
		if err != nil {
			return "", nil, 0, "", err
		}
		return action, access.VolumeFileFolderGrant{Tenant: tenant, Volume: volume, Prefix: req.Prefix, User: req.User}, p.Collection, "volume/" + volume, nil
	})
}
